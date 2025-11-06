#!/usr/bin/env python3
"""
python_miner.py

Python coordinator for Scavenger Mine:
- GET /challenge
- spawn workers that talk to local AshMaize daemon (TCP) to get hash
- check difficulty
- POST /solution when found
"""

import argparse
import requests
import socket
import threading
import time
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from datetime import datetime, timezone

# -------- CONFIG / defaults --------
BASE_URL = "https://scavenger.prod.gd.midnighttge.io"
DAEMON_HOST = "127.0.0.1"
DAEMON_PORT = 4002
SOCKET_TIMEOUT = 5.0  # seconds
NONCE_BATCH = 1024  # number of nonces a worker loops before refreshing challenge check
# -----------------------------------

# thread-safe counters
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

stats = Stats()
stop_event = threading.Event()

# ----------------- utilities -----------------
def hex64_nonce():
    """Return 64-bit hex nonce (16 hex chars)"""
    return "{:016x}".format(random.getrandbits(64))

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def safe_get_challenge(base_url: str):
    url = base_url.rstrip("/") + "/challenge"
    try:
        r = requests.get(url, timeout=10)
        return r.status_code, r.json()
    except Exception as e:
        return None, {"error": str(e)}

def post_solution(base_url: str, address: str, challenge_id: str, nonce: str):
    url = f"{base_url.rstrip('/')}/solution/{address}/{challenge_id}/{nonce}"
    try:
        r = requests.post(url, json={}, timeout=10)
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text
    except Exception as e:
        return None, {"error": str(e)}

def build_preimage(nonce_hex: str, address: str, challenge: dict) -> str:
    """
    Build preimage EXACT order:
    nonce + address + challenge_id + difficulty + no_pre_mine + latest_submission + no_pre_mine_hour
    All concatenated as plain UTF-8 strings (no delimiters).
    """
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
    """
    Reproduce the left-4-bytes zero-bit test used earlier:
    Convert left 4 bytes of hash to uint32 = left4
    Convert difficulty_hex to uint32 = mask
    Requirement used: bits that are zero in mask MUST be zero in left4
    Equivalent: (left4 & (~mask & 0xFFFFFFFF)) == 0
    """
    if not hash_hex or len(hash_hex) < 8:
        return False
    try:
        left4 = int(hash_hex[0:8], 16)
        mask = int(difficulty_hex, 16)
    except Exception:
        return False
    return (left4 & (~mask & 0xFFFFFFFF)) == 0

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
        # maintain a persistent socket per worker to daemon
        if self.sock:
            return True
        try:
            s = socket.create_connection((self.host, self.port), timeout=SOCKET_TIMEOUT)
            s.settimeout(SOCKET_TIMEOUT)
            self.sock = s
            return True
        except Exception as e:
            # print(f"[worker {self.id}] cannot connect daemon: {e}")
            self.sock = None
            return False

    def _send_pre_and_recv_hash(self, preimage: str) -> Optional[str]:
        # ensure socket
        if not self._ensure_socket():
            # small backoff
            time.sleep(0.1)
            return None
        try:
            # send line with newline
            data = preimage + "\n"
            with self.sock_lock:
                self.sock.sendall(data.encode("utf-8"))
                # read until newline
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
        except Exception:
            # drop socket, attempt reconnect next time
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            return None

    def run(self):
        # main loop: keep trying with current challenge until stop_event or new challenge
        print(f"[worker {self.id}] started")
        while not stop_event.is_set():
            challenge = self.challenge_getter()
            if challenge is None:
                time.sleep(0.5)
                continue
            # check active window
            if "latest_submission" not in challenge:
                # maybe not active
                time.sleep(0.5)
                continue

            difficulty = challenge["difficulty"]
            challenge_id = challenge["challenge_id"]
            latest_submission = challenge["latest_submission"]
            # parse latest_submission time to epoch if needed to stop timely:
            try:
                # accept ISO like "2025-10-30T23:59:59Z"
                # Python's fromisoformat does not parse ending Z, handle:
                ls = latest_submission
                if ls.endswith("Z"):
                    ls = ls[:-1] + "+00:00"
                latest_ts = datetime.fromisoformat(ls).timestamp()
            except Exception:
                latest_ts = None

            # inner loop: try many nonces
            tries = 0
            for _ in range(NONCE_BATCH):
                if stop_event.is_set():
                    break
                # quick time check
                if latest_ts and time.time() > latest_ts:
                    # expired
                    break
                nonce = hex64_nonce()
                pre = build_preimage(nonce, self.address, challenge)
                # Prefix the preimage with the challenge's no_pre_mine so the
                # daemon can initialize/reuse the ROM without separate --rom.
                rom = challenge.get("no_pre_mine", "")
                pre_with_rom = f"{rom}|{pre}"
                hash_hex = self._send_pre_and_recv_hash(pre_with_rom)
                if hash_hex is None:
                    # no response from daemon, small backoff
                    time.sleep(0.01)
                    continue
                tries += 1
                stats.add_hashes(1)
                # check difficulty
                if hash_meets_difficulty(hash_hex, difficulty):
                    print(f"[worker {self.id}] FOUND nonce={nonce} hash={hash_hex} challenge={challenge_id}")
                    stats.inc_solutions()
                    if self.submit_on_find:
                        sc, resp = post_solution(self.base_url, self.address, challenge_id, nonce)
                        print(f"[worker {self.id}] submit returned: {sc} {resp}")
                    # optionally continue searching (do not stop others) or wait for orchestration to refresh challenge
                    # we'll sleep short to let orchestrator refresh
                    time.sleep(0.5)
                    # break out to re-fetch challenge (in case server accepted and difficulty changed)
                    break
            # small yield
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

    def refresh_challenge(self):
        sc, resp = safe_get_challenge(self.base_url)
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Chỉ log lỗi hoặc khi có thay đổi trạng thái
        if sc != 200 or not isinstance(resp, dict):
            print(f"[{timestamp}] [orchestrator] GET /challenge failed: status={sc}, response={resp}")
            return False
            
        code = resp.get("code")
        
        # Log khi có lỗi hoặc thay đổi trạng thái
        if code in ("before", "after"):
            print(f"[{timestamp}] [orchestrator] Challenge status: {code}")
            with self.challenge_lock:
                self.current_challenge = None
            return False
            
        if code != "active":
            print(f"[{timestamp}] [orchestrator] Unexpected challenge code: {code}")
            with self.challenge_lock:
                self.current_challenge = None
            return False

        ch = resp.get("challenge", {})
        required = ("challenge_id", "difficulty", "no_pre_mine", "latest_submission", "no_pre_mine_hour")
        if not all(k in ch for k in required):
            print(f"[{timestamp}] [orchestrator] Invalid challenge format, missing fields")
            return False

        # Chỉ log khi có challenge mới hoặc thay đổi
        with self.challenge_lock:
            current_id = self.current_challenge.get("challenge_id") if self.current_challenge else None
            if current_id != ch["challenge_id"]:
                print(f"[{timestamp}] [orchestrator] New challenge: id={ch['challenge_id']} difficulty={ch['difficulty']} "
                      f"expires={ch['latest_submission']}")
            self.current_challenge = ch
            
        return True

    def start_workers(self):
        self.executor = ThreadPoolExecutor(max_workers=self.workers_count)
        for i in range(self.workers_count):
            w = Worker(i, self.daemon_host, self.daemon_port, self.base_url, self.address, self.challenge_getter, self.submit_on_find)
            # run worker.run in thread
            self.executor.submit(w.run)
            self.workers.append(w)
        print(f"[orchestrator] started {self.workers_count} workers")

    def stop_workers(self):
        stop_event.set()
        if self.executor:
            self.executor.shutdown(wait=True)

    def run(self, stats_interval=5.0):
        print("[orchestrator] Starting with single challenge fetch")
        
        # Fetch challenge once at start
        sc, resp = safe_get_challenge(self.base_url)
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        if sc != 200 or not isinstance(resp, dict) or resp.get("code") != "active":
            print(f"[{timestamp}] [orchestrator] Failed to get active challenge: {resp}")
            return
            
        ch = resp.get("challenge", {})
        required = ("challenge_id", "difficulty", "no_pre_mine", "latest_submission")
        if not all(k in ch for k in required):
            print(f"[{timestamp}] [orchestrator] Invalid challenge format")
            return
            
        print(f"[{timestamp}] [orchestrator] Starting with challenge: id={ch['challenge_id']} "
              f"difficulty={ch['difficulty']} expires={ch['latest_submission']}")
        
        # Set the challenge for workers
        with self.challenge_lock:
            self.current_challenge = ch
        
        # Start workers
        self.start_workers()
        last_stats = time.time()
        
        try:
            while not stop_event.is_set():
                # Just keep printing stats until interrupted
                current_time = time.time()
                if current_time - last_stats >= stats_interval:
                    h, s = stats.snapshot()
                    elapsed = max(0.001, current_time - stats.last_report)
                    hps = h / elapsed if elapsed > 0 else 0
                    print(f"[stats] hashes={h} ({hps:.1f} H/s) solutions={s}")
                    stats.last_report = current_time
                    last_stats = current_time
                
                # Small sleep to prevent busy waiting
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\n[orchestrator] Stopping...")
        except Exception as e:
            print(f"[orchestrator] Error: {e}")
        finally:
            print("[orchestrator] Stopping workers...")
            self.stop_workers()

# --------------- CLI ---------------
def parse_args():
    p = argparse.ArgumentParser(description="Scavenger Mine Python Miner (uses local ashmaize daemon)")
    p.add_argument("--address", default="addr1q8wh05mzkuevknvj7qntjz2lhvqdehw4r2lvywlj4sk9fs3ls46ux04j58v6t06mqph0p4q09z4gsvlw6hx52ademcys89he6t", 
                   help="Cardano address (default: addr1q8wh05mzkuevknvj7qntjz2lhvqdehw4r2lvywlj4sk9fs3ls46ux04j58v6t06mqph0p4q09z4gsvlw6hx52ademcys89he6t)")
    p.add_argument("--base-url", default=BASE_URL, help="Scavenger API base URL")
    p.add_argument("--daemon-host", default=DAEMON_HOST, help="Local ashmaize daemon host")
    p.add_argument("--daemon-port", default=DAEMON_PORT, type=int, help="Local ashmaize daemon port")
    p.add_argument("--workers", default=8, type=int, help="Number of worker threads (default: 8)")
    p.add_argument("--submit", action="store_true", default=True, help="Submit found solutions to server (default: True)")
    p.add_argument("--poll", default=5.0, type=float, help="Poll /challenge interval (sec) (default: 5.0)")
    return p.parse_args()

# --------------- main ---------------
def main():
    args = parse_args()
    print(f"Starting miner for address {args.address}")
    orch = Orchestrator(args.base_url, args.address, args.daemon_host, args.daemon_port, args.workers, args.submit)
    orch.run(stats_interval=10.0)  # Đã bỏ poll_interval

if __name__ == "__main__":
    main()
