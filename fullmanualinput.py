#!/usr/bin/env python3
"""
python_miner_manual_args.py

Same structure as python_miner.py but instead of using argparse,
we will manually prompt the user for arguments before starting the workers.

User will input:
- address
- base_url
- daemon_host
- daemon_port
- workers
- submit (True/False)
- csv_file

After input is finished, press ENTER to start.

All other structure remains unchanged.
"""

# ======= (KEEP ORIGINAL IMPORTS) =======
import requests
import socket
import threading
import time
import random
import sys
import csv
import os
import json
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, List
from datetime import datetime, timezone

# -------- CONFIG / defaults --------
BASE_URL = "https://scavenger.prod.gd.midnighttge.io"
DAEMON_HOST = "127.0.0.1"
DAEMON_PORT = 4002
SOCKET_TIMEOUT = 5.0
NONCE_BATCH = 1024
# -----------------------------------

# -------- (KEEP Stats CLASS) --------
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.hashes = 0
        self.solutions = 0
        self.starts = 0
        self.last_report = time.time()

    def add_hashes(self, n):
        with self.lock:
            self.hashes += n

    def inc_solutions(self):
        with self.lock:
            self.solutions += 1

    def snapshot(self):
        with self.lock:
            return self.hashes, self.solutions

    def reset(self):
        with self.lock:
            self.hashes = 0
            self.solutions = 0
            self.starts = 0
            self.last_report = time.time()

stats = Stats()
stop_event = threading.Event()

# Error logging
class ErrorLogger:
    def __init__(self):
        self.errors: List[Dict] = []
        self.lock = threading.Lock()
    
    def log_error(self, address: str, challenge_id: str, nonce: str, error: str):
        with self.lock:
            self.errors.append({
                'timestamp': now_iso(),
                'address': address,
                'challenge_id': challenge_id,
                'nonce': nonce,
                'error': error
            })
    
    def save_errors_to_file(self, address: str):
        if not self.errors:
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{address}.{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                for error in self.errors:
                    f.write(f"{error['timestamp']} - {error['address']}/{error['challenge_id']}/{error['nonce']} - {error['error']}\n")
            print(f"Saved {len(self.errors)} error logs to {filename}")
        except Exception as e:
            print(f"Failed to save error log: {e}")

error_logger = ErrorLogger()

# ----------------- utilities -----------------
def hex64_nonce():
    return "{:016x}".format(random.getrandbits(64))

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def post_solution(base_url: str, address: str, challenge_id: str, nonce: str):
    url = f"{base_url.rstrip('/')}/solution/{address}/{challenge_id}/{nonce}"
    try:
        r = requests.post(url, json={}, timeout=10)
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text
    except Exception as e:
        error_msg = str(e)
        error_logger.log_error(address, challenge_id, nonce, error_msg)
        return None, {"error": error_msg}

def build_preimage(nonce_hex: str, address: str, challenge: dict) -> str:
    parts = [
        nonce_hex,
        address,
        challenge["challenge_id"],
        challenge["difficulty"],
        challenge["no_pre_mine"],
        challenge["latest_submission"],
        str(challenge.get("no_pre_mine_hour", "")),
    ]
    return "".join(parts)

def hash_meets_difficulty(hash_hex: str, difficulty_hex: str) -> bool:
    if not hash_hex or len(hash_hex) < 8:
        return False
    try:
        left4 = int(hash_hex[0:8], 16)
        mask = int(difficulty_hex, 16)
    except Exception:
        return False
    return (left4 & (~mask & 0xFFFFFFFF)) == 0

def read_challenges_from_csv(csv_file: str):
    challenges = []
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                if len(row) < 5:
                    continue
                challenge = {
                    "challenge_id": row[0].strip() if len(row) > 0 else "",
                    "difficulty": row[1].strip() if len(row) > 1 else "",
                    "no_pre_mine": row[2].strip() if len(row) > 2 else "",
                    "no_pre_mine_hour": row[3].strip() if len(row) > 3 else "",
                    "latest_submission": row[4].strip() if len(row) > 4 else "2099-12-31T23:59:59.000Z"
                }
                if challenge["challenge_id"] and challenge["difficulty"] and challenge["no_pre_mine"]:
                    challenges.append(challenge)
        print(f"Loaded {len(challenges)} challenges from {csv_file}")
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)
    return challenges

# ----------------- worker -----------------
class Worker:
    def __init__(self, id:int, host:str, port:int, base_url:str, address:str, challenge_getter, submit_on_find:bool):
        self.id = id
        self.host = host
        self.port = port
        self.base_url = base_url
        self.address = address
        self.challenge_getter = challenge_getter
        self.submit_on_find = submit_on_find
        self.sock = None
        self.sock_lock = threading.Lock()

    def _ensure_socket(self):
        if self.sock:
            return True
        try:
            s = socket.create_connection((self.host, self.port), timeout=SOCKET_TIMEOUT)
            s.settimeout(SOCKET_TIMEOUT)
            self.sock = s
            return True
        except:
            self.sock = None
            return False

    def _send_pre_and_recv_hash(self, preimage: str) -> Optional[str]:
        if not self._ensure_socket():
            time.sleep(0.1)
            return None
        try:
            data = preimage + "\n"
            with self.sock_lock:
                self.sock.sendall(data.encode("utf-8"))
                buf = bytearray()
                while True:
                    b = self.sock.recv(4096)
                    if not b:
                        raise ConnectionError("daemon closed")
                    buf.extend(b)
                    if b.find(b"\n") != -1:
                        break
                line = buf.split(b"\n",1)[0].decode("utf-8").strip()
            return line
        except:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            return None

    def run(self):
        print(f"[worker {self.id}] started")
        while not stop_event.is_set():
            challenge = self.challenge_getter()
            if challenge is None:
                time.sleep(0.5)
                continue
            if "latest_submission" not in challenge:
                time.sleep(0.5)
                continue

            difficulty = challenge["difficulty"]
            challenge_id = challenge["challenge_id"]
            latest_submission = challenge["latest_submission"]
            try:
                ls = latest_submission
                if ls.endswith("Z"):
                    ls = ls[:-1] + "+00:00"
                latest_ts = datetime.fromisoformat(ls).timestamp()
            except:
                latest_ts = None

            tries = 0
            for _ in range(NONCE_BATCH):
                if stop_event.is_set():
                    break
                if latest_ts and time.time() > latest_ts:
                    break
                nonce = hex64_nonce()
                pre = build_preimage(nonce, self.address, challenge)
                rom = challenge.get("no_pre_mine", "")
                pre_with_rom = f"{rom}|{pre}"
                hash_hex = self._send_pre_and_recv_hash(pre_with_rom)
                if hash_hex is None:
                    time.sleep(0.01)
                    continue
                tries += 1
                stats.add_hashes(1)
                if hash_meets_difficulty(hash_hex, difficulty):
                    print(f"[worker {self.id}] FOUND nonce={nonce} hash={hash_hex} challenge={challenge_id}")
                    stats.inc_solutions()
                    if self.submit_on_find:
                        sc, resp = post_solution(self.base_url, self.address, challenge_id, nonce)
                        print(f"[worker {self.id}] submit returned: {sc} {resp}")
                        try:
                            if sc == 201:
                                stop_event.set()
                        except:
                            pass
                    time.sleep(0.5)
                    break
            time.sleep(0.001)
        print(f"[worker {self.id}] stopping")

# --------------- orchestrator ---------------
class Orchestrator:
    def __init__(self, base_url, address, daemon_host, daemon_port, workers, submit_on_find):
        self.base_url = base_url
        self.address = address
        self.daemon_host = daemon_host
        self.daemon_port = daemon_port
        self.workers_count = workers
        self.submit_on_find = submit_on_find
        self.current_challenge = None
        self.challenge_lock = threading.Lock()
        self.workers = []
        self.executor = None

    def challenge_getter(self):
        with self.challenge_lock:
            return self.current_challenge

    def set_challenge(self, challenge):
        with self.challenge_lock:
            self.current_challenge = challenge

    def start_workers(self):
        self.executor = ThreadPoolExecutor(max_workers=self.workers_count)
        for i in range(self.workers_count):
            w = Worker(i, self.daemon_host, self.daemon_port, self.base_url, self.address, self.challenge_getter, self.submit_on_find)
            self.executor.submit(w.run)
            self.workers.append(w)
        print(f"[orchestrator] started {self.workers_count} workers")

    def stop_workers(self):
        stop_event.set()
        if self.executor:
            self.executor.shutdown(wait=True)

    def run(self, stats_interval=5.0):
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        ch = self.current_challenge
        if not ch:
            print(f"[{timestamp}] [orchestrator] No challenge set")
            return
        print(f"[{timestamp}] [orchestrator] Starting with challenge: id={ch['challenge_id']} difficulty={ch['difficulty']} expires={ch.get('latest_submission','N/A')}")
