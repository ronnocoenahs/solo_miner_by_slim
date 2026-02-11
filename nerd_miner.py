import socket
import json
import hashlib
import binascii
import time
import sys
import threading
import queue
import struct
import os
import multiprocessing
import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta

# --- CONFIGURATION ---
POOL_URL = "solo.ckpool.org"
POOL_PORT = 3333
BTC_ADDRESS = "YOUR_WALLET"
WORKER_NAME = "WORKER"
PASSWORD = "x"
# ---------------------

def sha256d(data):
    """Double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def swap_endian_word(hex_word):
    """Swaps endianness of a 4-byte hex string."""
    return "".join(reversed([hex_word[i:i+2] for i in range(0, len(hex_word), 2)]))

def swap_endian_hex(hex_str):
    """Swaps endianness of a longer hex string by 4-byte words."""
    s = ""
    for i in range(0, len(hex_str), 8):
        s += swap_endian_word(hex_str[i:i+8])
    return s

# --- WORKER PROCESS ---
def worker_process(worker_id, shared_job_dict, result_queue, log_queue, stats_counter, blocks_found_counter):
    try:
        packer = struct.Struct('<I')
        last_job_id = None
        local_job = None
        
        start_nonce_base = worker_id * 100000000
        
        while True:
            try:
                current_job_id = shared_job_dict.get('job_id')
            except:
                current_job_id = None

            if current_job_id != last_job_id and current_job_id is not None:
                local_job = dict(shared_job_dict)
                last_job_id = current_job_id

            if not local_job:
                time.sleep(0.1)
                continue

            header_prefix = local_job['header_prefix']
            target = local_job['target']
            extranonce2 = local_job['extranonce2']
            ntime = local_job['ntime']
            
            batch_size = 50000
            current_time_seed = int(time.time()) % 10000
            start_nonce = start_nonce_base + (current_time_seed * 1000)

            for nonce in range(start_nonce, start_nonce + batch_size):
                nonce_bin = packer.pack(nonce)
                block_header = header_prefix + nonce_bin
                block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()
                hash_int = int.from_bytes(block_hash[::-1], 'big')
                
                if hash_int < target:
                    nonce_hex = binascii.hexlify(nonce_bin).decode()
                    log_queue.put(f"[!!!] GOLDEN TICKET FOUND by Worker {worker_id}!")
                    
                    # Increment Blocks Found
                    with blocks_found_counter.get_lock():
                        blocks_found_counter.value += 1
                        
                    result_queue.put({
                        'job_id': local_job['job_id'],
                        'extranonce2': extranonce2,
                        'ntime': ntime,
                        'nonce': nonce_hex
                    })
                    last_job_id = None 
                    break

            with stats_counter.get_lock():
                stats_counter.value += batch_size

    except Exception as e:
        log_queue.put(f"[Worker {worker_id}] Error: {e}")

# --- MAIN STRATUM CLIENT ---
class StratumClient(threading.Thread):
    def __init__(self, shared_job_dict, result_queue, log_queue):
        super().__init__()
        self.shared_job_dict = shared_job_dict
        self.result_queue = result_queue
        self.log_queue = log_queue
        self.sock = None
        self.msg_id = 1
        self.extranonce1 = None
        self.running = True
        self.connected = False

    def log(self, msg):
        self.log_queue.put(msg)

    def connect(self):
        self.log(f"[*] Connecting to {POOL_URL}:{POOL_PORT}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((POOL_URL, POOL_PORT))
            self.connected = True
            self.log("[*] Connected! Sending handshake...")
        except Exception as e:
            self.connected = False
            self.log(f"[!] Connection failed: {e}")
            raise e

    def send_message(self, method, params):
        if not self.sock: return
        msg = {"id": self.msg_id, "method": method, "params": params}
        line = json.dumps(msg) + "\r\n"
        try:
            self.sock.sendall(line.encode())
            self.msg_id += 1
        except:
            self.connected = False

    def receive_lines(self):
        while self.running and self.connected:
            try:
                chunk = self.sock.recv(4096).decode()
                if not chunk:
                    self.connected = False
                    break
                if "\n" in chunk:
                    lines = chunk.split("\n")
                    for line in lines:
                        line = line.strip()
                        if line:
                            try:
                                yield json.loads(line)
                            except: pass
            except socket.timeout:
                continue
            except Exception as e:
                self.connected = False
                break

    def subscribe(self):
        self.send_message("mining.subscribe", ["NerdMiner/2.0"])

    def authorize(self):
        self.send_message("mining.authorize", [BTC_ADDRESS, PASSWORD])

    def submit_share(self, share_data):
        params = [
            WORKER_NAME, 
            share_data['job_id'], 
            share_data['extranonce2'], 
            share_data['ntime'], 
            share_data['nonce']
        ]
        self.send_message("mining.submit", params)
        self.log("[*] Share submitted to pool!")

    def handle_mining_notify(self, params):
        job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs = params
        
        nbits_bytes = binascii.unhexlify(nbits)
        exponent = nbits_bytes[0]
        coefficient = int.from_bytes(nbits_bytes[1:], byteorder='big')
        target = coefficient * (256 ** (exponent - 3))
        
        extranonce2 = "00000000"
        coinbase = coinb1 + self.extranonce1 + extranonce2 + coinb2
        coinbase_bin = binascii.unhexlify(coinbase)
        coinbase_hash = sha256d(coinbase_bin)
        
        merkle_root = coinbase_hash
        for branch_hash in merkle_branch:
            branch_bin = binascii.unhexlify(branch_hash)
            merkle_root = sha256d(merkle_root + branch_bin)
        
        merkle_root_hex = binascii.hexlify(merkle_root).decode()

        version_swapped = swap_endian_word(version)
        prevhash_swapped = swap_endian_hex(prevhash)
        merkle_swapped = swap_endian_hex(merkle_root_hex)
        ntime_swapped = swap_endian_word(ntime)
        nbits_swapped = swap_endian_word(nbits)

        header_prefix_hex = version_swapped + prevhash_swapped + merkle_swapped + ntime_swapped + nbits_swapped
        header_prefix_bin = binascii.unhexlify(header_prefix_hex)

        self.shared_job_dict.update({
            "header_prefix": header_prefix_bin,
            "target": target,
            "job_id": job_id,
            "extranonce2": extranonce2,
            "ntime": ntime,
            "difficulty": 0x00000000FFFF0000000000000000000000000000000000000000000000000000 / target
        })

    def run(self):
        while self.running:
            try:
                self.connect()
                self.subscribe()
                for response in self.receive_lines():
                    while not self.result_queue.empty():
                        share = self.result_queue.get()
                        self.submit_share(share)

                    if 'result' in response and response['result']:
                         if isinstance(response['result'], list):
                            for item in response['result']:
                                if isinstance(item, str) and len(item) >= 4:
                                    self.extranonce1 = item
                            if not self.extranonce1 and len(response['result']) > 1:
                                if isinstance(response['result'][1], str):
                                    self.extranonce1 = response['result'][1]
                            if self.extranonce1:
                                self.log(f"[*] Subscribed! ID: {self.extranonce1}")
                                self.authorize()
                    
                    if 'method' in response and response['method'] == 'mining.notify':
                        self.handle_mining_notify(response['params'])
            except Exception as e:
                self.log(f"[!] Error: {e}. Reconnecting in 5s...")
                self.connected = False
                time.sleep(5)

# --- GUI CLASS ---
class MinerGUI:
    def __init__(self, root, log_queue, shared_stats, shared_job_dict, shared_blocks_found):
        self.root = root
        self.log_queue = log_queue
        self.shared_stats = shared_stats
        self.shared_job_dict = shared_job_dict
        self.shared_blocks_found = shared_blocks_found
        
        cpu_count = multiprocessing.cpu_count()
        self.root.title(f"Solo Miner by Slim v1.1")
        self.root.geometry("500x380")
        
        # --- DARK THEME SETUP ---
        bg_color = "#121212"
        fg_color = "#E0E0E0"
        accent_color = "#03DAC6"
        card_bg = "#1E1E1E"

        self.root.configure(bg=bg_color)
        
        style = ttk.Style()
        style.theme_use('clam') 
        
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color, font=("Segoe UI", 10))
        style.configure("Stats.TLabel", background=card_bg, foreground=fg_color, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=bg_color, foreground=accent_color)
        
        style.configure("Card.TFrame", background=card_bg, relief="flat")

        # --- LAYOUT ---
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Cursive Header
        header_font = ("Segoe Script", 24, "bold") 
        ttk.Label(main_frame, text="Solo Miner by Slim", style="Header.TLabel", font=header_font).pack(pady=(0, 5))
        
        # Subtitle
        ttk.Label(main_frame, text=f"Worker: {WORKER_NAME}", foreground="gray", font=("Consolas", 9)).pack(pady=(0, 20))

        # Stats Card
        stats_frame = ttk.Frame(main_frame, style="Card.TFrame", padding="15")
        stats_frame.pack(fill=tk.X)

        # --- GRID LAYOUT FOR STATS ---
        
        # Row 0: Speed
        ttk.Label(stats_frame, text="Hashrate", style="Stats.TLabel", foreground="gray").grid(row=0, column=0, sticky="w", pady=5)
        self.lbl_speed = ttk.Label(stats_frame, text="0.00 H/s", style="Stats.TLabel", font=("Segoe UI", 14, "bold"), foreground=accent_color)
        self.lbl_speed.grid(row=0, column=1, sticky="e", pady=5, padx=(20, 0))
        
        # Row 1: Difficulty
        ttk.Label(stats_frame, text="Difficulty", style="Stats.TLabel", foreground="gray").grid(row=1, column=0, sticky="w", pady=5)
        self.lbl_diff = ttk.Label(stats_frame, text="0", style="Stats.TLabel", font=("Segoe UI", 12))
        self.lbl_diff.grid(row=1, column=1, sticky="e", pady=5)

        # Row 2: Total Hashes
        ttk.Label(stats_frame, text="Total Hashes", style="Stats.TLabel", foreground="gray").grid(row=2, column=0, sticky="w", pady=5)
        self.lbl_total = ttk.Label(stats_frame, text="0", style="Stats.TLabel", font=("Segoe UI", 12))
        self.lbl_total.grid(row=2, column=1, sticky="e", pady=5)

        # Row 3: Blocks Found (Session)
        ttk.Label(stats_frame, text="My Blocks Found", style="Stats.TLabel", foreground="gray").grid(row=3, column=0, sticky="w", pady=5)
        self.lbl_blocks = ttk.Label(stats_frame, text="0", style="Stats.TLabel", font=("Segoe UI", 12), foreground="#FFD700") # Gold color
        self.lbl_blocks.grid(row=3, column=1, sticky="e", pady=5)

        # Row 4: Cores
        ttk.Label(stats_frame, text="Active Cores", style="Stats.TLabel", foreground="gray").grid(row=4, column=0, sticky="w", pady=5)
        self.lbl_cores = ttk.Label(stats_frame, text=f"{cpu_count}", style="Stats.TLabel", font=("Segoe UI", 12))
        self.lbl_cores.grid(row=4, column=1, sticky="e", pady=5)
        
        stats_frame.columnconfigure(1, weight=1)

        # Log file setup
        self.log_file = open("miner_log.txt", "a", encoding="utf-8")
        self.log_file.write(f"\n--- SESSION START: {datetime.now()} ---\n")
        self.log_file.flush()

        self.last_hashes = 0
        self.last_time = time.time()
        
        self.update_gui()



    def update_gui(self):
        # 1. Drain Queue to File
        while not self.log_queue.empty():
            try:
                msg = self.log_queue.get_nowait()
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.log_file.write(f"[{timestamp}] {msg}\n")
            except: break
        self.log_file.flush()

        # 2. Update Stats
        current_total = self.shared_stats.value
        blocks_found = self.shared_blocks_found.value
        
        now = time.time()
        dt = now - self.last_time
        
        if dt > 1.0:
            d_hashes = current_total - self.last_hashes
            speed = d_hashes / dt
            self.last_hashes = current_total
            self.last_time = now
            
            if speed < 1000:
                speed_str = f"{speed:.2f} H/s"
            elif speed < 1000000:
                speed_str = f"{speed/1000:.2f} kH/s"
            else:
                speed_str = f"{speed/1000000:.2f} MH/s"
            self.lbl_speed.config(text=speed_str)

        try:
            diff = self.shared_job_dict.get('difficulty', 0)
            self.lbl_diff.config(text=f"{diff:,.0f}")
        except: pass

        self.lbl_total.config(text=f"{current_total:,}")
        self.lbl_blocks.config(text=f"{blocks_found}")
        
        self.root.after(500, self.update_gui)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    
    if BTC_ADDRESS == "YOUR_BTC_ADDRESS_HERE":
        pass
    else:
        manager = multiprocessing.Manager()
        shared_job_dict = manager.dict()
        
        log_queue = multiprocessing.Queue()
        result_queue = multiprocessing.Queue()
        shared_stats = multiprocessing.Value('i', 0)
        shared_blocks_found = multiprocessing.Value('i', 0)

        client = StratumClient(shared_job_dict, result_queue, log_queue)
        client.daemon = True
        client.start()

        processes = []
        cpu_count = multiprocessing.cpu_count()
        
        for i in range(cpu_count):
            p = multiprocessing.Process(
                target=worker_process, 
                args=(i, shared_job_dict, result_queue, log_queue, shared_stats, shared_blocks_found)
            )
            p.daemon = True
            p.start()
            processes.append(p)

        try:
            root = tk.Tk()
            app = MinerGUI(root, log_queue, shared_stats, shared_job_dict, shared_blocks_found)
            root.mainloop()
        except KeyboardInterrupt:
            for p in processes:

                p.terminate()
