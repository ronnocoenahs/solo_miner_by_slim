Solo Miner by Slim ⛏️

Solo Miner by Slim is a high-performance, educational Bitcoin miner written in Python. It is designed to run on your CPU and connects directly to the solo.ckpool.org mining pool.

While it functions as a real miner, please note that solo mining with a CPU is effectively a "Bitcoin Lottery." The odds of finding a block are incredibly low, but this tool provides a great way to understand how the Stratum protocol and hashing algorithms work, all wrapped in a sleek, dark-themed interface.

🌟 Features

High Performance: Uses Python's multiprocessing to utilize every core of your CPU for maximum hashrate.

Sleek GUI: A custom Dark Mode interface built with Tkinter, featuring a stylish cursive header.

Live Statistics: Real-time tracking of:

Hashrate (H/s, kH/s, MH/s)

Network Difficulty

Total Hashes calculated

Session Blocks Found (The Golden Ticket!)

Global Winner Tracker: Connects to the pool API to track how many people worldwide have successfully solo-mined a block (updates weekly).

System Integration:

Run at Startup: Option to automatically launch silently when Windows starts.

Minimize to Taskbar: Keep the miner running in the background without cluttering your screen.

Logging: automatically saves detailed logs to miner_log.txt.

🚀 Getting Started

Prerequisites

OS: Windows (Required for "Run at Startup" features due to Registry usage).

Python: Version 3.x installed.

Installation

Download the script: Download nerd_miner.py (or clone this repository).

No dependencies needed: This script uses only standard Python libraries (no pip install required!).

Configuration

Before running, you must add your Bitcoin address:

Open nerd_miner.py in a text editor (Notepad, VS Code, etc.).

Locate the configuration section near the top:

# --- CONFIGURATION ---
POOL_URL = "solo.ckpool.org"
POOL_PORT = 3333
BTC_ADDRESS = "YOUR_BTC_ADDRESS_HERE"  # <--- REPLACE THIS WITH YOUR ADDRESS
WORKER_NAME = "slimpy"


Replace YOUR_BTC_ADDRESS_HERE with your actual Bitcoin wallet address.

Save the file.

How to Run

Method 1: The Batch Launcher (Recommended)
Create a file named run_miner.bat in the same folder with the following content to launch it without a command prompt window:

@echo off
start "" pythonw nerd_miner.py
exit


Method 2: Command Line
Open your terminal/command prompt and run:

python nerd_miner.py


⚙️ Settings

Once the application is running, click the Settings tab to:

Enable Run at Windows Startup.

Toggle Minimize to Taskbar on Close.

Use the STOP MINING & EXIT button to fully close the application and stop all background processes.

⚠️ Disclaimer

This software is for educational purposes. Solo mining on a CPU (even a powerful one) is statistically unlikely to ever yield a Bitcoin block reward. It is intended to demonstrate the mechanics of cryptocurrency mining, threading, and network socket communication in Python.

Use at your own risk. running your CPU at 100% load for extended periods generates heat. Ensure your cooling system is adequate.
