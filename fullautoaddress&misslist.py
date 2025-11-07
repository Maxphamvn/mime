#!/usr/bin/env python3
"""
python_miner.py

Python coordinator for Scavenger Mine:
- Read challenges from CSV file
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
import csv
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, List
from datetime import datetime, timezone
import argparse
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

# Initialize console for logging
console = Console()

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

    def reset(self):
        with self.lock:
            self.hashes = 0
            self.solutions = 0
            self.starts = 0
            self.last_report = time.time()

stats = Stats()
stop_event = threading.Event()
# Ensure only one worker performs the initial challenge GET/save
challenge_fetch_lock = threading.Lock()
challenge_fetched = threading.Event()

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
    """Return 64-bit hex nonce (16 hex chars)"""
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


def log_nonce_to_file(nonce: str, challenge_id: str, address: str, filename: str = "nounce.txt"):
    """Append found nonce, challenge_id and address to a logfile (CSV-style).
    Format: timestamp,nonce,challenge_id,address\n
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    line = f"{timestamp},{nonce},{challenge_id},{address}\n"
    # write to file in append mode
    with open(filename, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()

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

def read_challenges_from_csv(csv_file: str):
    """
    Read challenges from CSV file
    CSV format: 
    Column A: challengeId
    Column B: difficulty
    Column C: noPreMine
    Column D: noPreMineHour
    Column E: latest_submission (NEW)
    
    Returns list of challenge dicts
    """
    challenges = []
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)  # Read header row
            
            for row in reader:
                if len(row) < 5:  # At least 4 columns required
                    continue
                    
                # Map CSV columns to challenge dict
                challenge = {
                    "challenge_id": row[0].strip() if len(row) > 0 else "",
                    "difficulty": row[1].strip() if len(row) > 1 else "",
                    "no_pre_mine": row[2].strip() if len(row) > 2 else "",
                    "no_pre_mine_hour": row[3].strip() if len(row) > 3 else "",
                    "latest_submission": row[4].strip() if len(row) > 4 else "2099-12-31T23:59:59.000Z"
                }
                
                # Validate required fields
                if challenge["challenge_id"] and challenge["difficulty"] and challenge["no_pre_mine"]:
                    challenges.append(challenge)
                    
        print(f"Loaded {len(challenges)} challenges from {csv_file}")
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)
    return challenges


def safe_get_challenge(base_url: str):
    """Safely GET the current challenge from the server.
    Returns (status_code, data) where data is parsed JSON on success or text/error dict on failure.
    """
    url = f"{base_url.rstrip('/')}/challenge"
    try:
        print(f"[debug] safe_get_challenge: GET {url}")
        r = requests.get(url, timeout=6)
        try:
            data = r.json()
        except Exception:
            data = r.text
        print(f"[debug] safe_get_challenge: {r.status_code} -> {str(data)[:200]}")
        return r.status_code, data
    except Exception as e:
        print(f"[debug] safe_get_challenge: ERROR {e}")
        return None, {"error": str(e)}

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

    def _save_challenge_to_csv(self, challenge):
        """Save challenge info to getchallenge.csv if not already exists"""
        csv_file = "getchallenge.csv"
        
        # Check if challenge_id already exists in CSV
        challenge_id = challenge.get("challenge_id", "")
        if not challenge_id:
            return
        
        existing_ids = set()
        file_exists = os.path.isfile(csv_file)
        
        print(f"[worker {self.id}] _save_challenge_to_csv: cwd={os.getcwd()} path={os.path.abspath(csv_file)} file_exists={file_exists}")
        if file_exists:
            try:
                with open(csv_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        existing_ids.add((row.get("challenge_id") or "").strip())
            except Exception as e:
                print(f"[worker {self.id}] error reading CSV: {e} -- will attempt to append anyway")
        
        # If challenge_id already exists, skip
        print(f"[worker {self.id}] _save_challenge_to_csv: challenge_id={challenge_id} existing_count={len(existing_ids)}")
        if challenge_id in existing_ids:
            print(f"[worker {self.id}] _save_challenge_to_csv: already present, skipping")
            return
        
        # Prepare row data - theo format getchallenge.csv
        row = {
            "challenge_id": challenge_id,
            "difficulty": challenge.get("difficulty", ""),
            "no_pre_mine": challenge.get("no_pre_mine", ""),
            "no_pre_mine_hour": challenge.get("no_pre_mine_hour", ""),
            "latest_submission": challenge.get("latest_submission", "")
        }
        
        # Write to CSV
        try:
            with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                fieldnames = ["challenge_id", "difficulty", "no_pre_mine", "no_pre_mine_hour", "latest_submission"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                # Write header if file is new
                if not file_exists or os.path.getsize(csv_file) == 0:
                    writer.writeheader()
                
                writer.writerow(row)
            print(f"[worker {self.id}] saved challenge {challenge_id} to CSV")
        except Exception as e:
            print(f"[worker {self.id}] error writing to CSV: {e}")

    def _fetch_and_save_challenge(self):
        """Fetch challenge from API and save to CSV"""
        # Only one worker should fetch/save the challenge to avoid duplicate API calls
        if challenge_fetched.is_set():
            # already fetched by another worker
            return

        with challenge_fetch_lock:
            if challenge_fetched.is_set():
                return
            try:
                print(f"[worker {self.id}] _fetch_and_save_challenge: calling safe_get_challenge({self.base_url})")
                sc, data = safe_get_challenge(self.base_url)
                print(f"[worker {self.id}] _fetch_and_save_challenge: got status={sc} data_type={type(data)}")
                # API may return {"code":..., "challenge": { ... }} or the challenge dict directly
                challenge_obj = None
                if sc == 200 and isinstance(data, dict):
                    if 'challenge' in data and isinstance(data['challenge'], dict):
                        challenge_obj = data['challenge']
                    elif 'challenge_id' in data:
                        challenge_obj = data
                    else:
                        # maybe nested differently; log and skip
                        print(f"[worker {self.id}] _fetch_and_save_challenge: unexpected payload keys: {list(data.keys())}")

                if challenge_obj:
                    print(f"[worker {self.id}] _fetch_and_save_challenge: extracted challenge_id={challenge_obj.get('challenge_id')}")
                    self._save_challenge_to_csv(challenge_obj)
                else:
                    print(f"[worker {self.id}] _fetch_and_save_challenge: no valid challenge object to save ({sc})")
            except Exception as e:
                print(f"[worker {self.id}] _fetch_and_save_challenge: EXCEPTION {e}")
            finally:
                # mark fetched (even on error) to avoid repeated attempts by all workers
                challenge_fetched.set()

    def run(self):
        # main loop: keep trying with current challenge until stop_event or new challenge
        print(f"[worker {self.id}] started")
        
        # Fetch and save challenge when worker starts
        self._fetch_and_save_challenge()
        
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
                        attempts = 0
                        sc = None  # ensure sc exists

                        while attempts < 3:
                            try:
                                sc, resp = post_solution(self.base_url, self.address, challenge_id, nonce)
                                print(f"[worker {self.id}] submit returned: {sc} {resp}")

                                if sc == 201:
                                    stop_event.set()
                                    break

                                attempts += 1
                                print(f"[worker {self.id}] submit retry {attempts}/3...")
                                time.sleep(1)

                            except Exception as e:
                                attempts += 1
                                print(f"[worker {self.id}] ERROR submit attempt {attempts}/3 — {e}")
                                time.sleep(1)

                        # Nếu sau 3 lần vẫn fail → dừng để tránh mất valid nonce
                        if sc != 201:
                            print(f"[worker {self.id}] ❌ FAILED TO SUBMIT VALID NONCE — STOPPING TO AVOID LOSING IT")
                            stop_event.set()

                    # optionally continue searching (do not stop others) or wait for orchestration to refresh challenge
                    time.sleep(0.5)
                    break  # re-fetch challenge since server may rotate difficulty

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

    def set_challenge(self, challenge):
        """Set current challenge for workers"""
        with self.challenge_lock:
            # Debug: Print the challenge being set
            print(f"[debug] Setting challenge: {challenge}")
            if isinstance(challenge, dict):
                print(f"[debug] Challenge keys: {list(challenge.keys())}")
            self.current_challenge = challenge

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
        """Run orchestrator with current challenge"""
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        ch = self.current_challenge
        if not ch:
            print(f"[{timestamp}] [orchestrator] No challenge set")
            return
        
        # Debug: Print the challenge object structure
        print(f"[debug] Challenge object keys: {list(ch.keys())}")
        print(f"[debug] Challenge object: {ch}")
        
        # Safely get values with fallbacks
        challenge_id = ch.get('challenge_id', 'unknown')
        difficulty = ch.get('difficulty', 'unknown')
        expires = ch.get('latest_submission', 'N/A')
        
        print(f"[{timestamp}] [orchestrator] Starting with challenge: id={challenge_id} "
              f"difficulty={difficulty} expires={expires}")
        
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
    p.add_argument("--address", default="addr1q8cecrzfwenw6du5sflmq5svju9vv2m9nhlayq5rk33wqrhgg7emy76r8nrqhg76vfwlg74k5wsrfekal3ltqlyt8qxqqca792", 
                   help="Cardano address (default: addr1q8cecrzfwenw6du5sflmq5svju9vv2m9nhlayq5rk33wqrhgg7emy76r8nrqhg76vfwlg74k5wsrfekal3ltqlyt8qxqqca792)")
    p.add_argument("--base-url", default=BASE_URL, help="Scavenger API base URL")
    p.add_argument("--daemon-host", default=DAEMON_HOST, help="Local ashmaize daemon host")
    p.add_argument("--daemon-port", default=DAEMON_PORT, type=int, help="Local ashmaize daemon port")
    p.add_argument("--workers", default=64, type=int, help="Number of worker threads (default: 8)")
    p.add_argument("--submit", action="store_true", default=True, help="Submit found solutions to server (default: True)")
    # Default to the workspace CSV if present (was a Windows path). Use a relative path so the
    # script works inside this container/workspace.
    p.add_argument("--csv-file", default="./getchallenge.csv", help="CSV file containing challenges (default: ./getchallenge.csv)")
    return p.parse_args()

# ---------------- CSV Reader ----------------
def read_challenges_from_csv(file_path, console):
    import csv
    challenges = []
    try:
        with open(file_path, newline="", encoding="utf-8") as csvfile:
            # Read the first line to check if it's a header
            first_line = csvfile.readline()
            csvfile.seek(0)  # Reset file pointer to beginning
            
            if 'challenge_id' not in first_line:
                # If no header, add the header row
                reader = csv.DictReader(csvfile, fieldnames=[
                    'challenge_id', 'difficulty', 'no_pre_mine', 
                    'no_pre_mine_hour', 'latest_submission'
                ])
            else:
                # If header exists, use it
                reader = csv.DictReader(csvfile)
            
            for row in reader:
                # Clean up keys by removing BOM and extra quotes/whitespace
                cleaned_row = {}
                for k, v in row.items():
                    # Remove BOM and extra quotes/whitespace from keys
                    clean_key = k.strip('"\'\ufeff ')
                    cleaned_row[clean_key] = v
                challenges.append(cleaned_row)
                
            console.log(f"[green]Successfully loaded {len(challenges)} challenges from CSV")
            if challenges:
                console.log(f"[dim]First challenge: {challenges[0]}")
                
    except Exception as e:
        console.log(f"[red][ERROR] Failed to read CSV: {e}")
        raise  # Re-raise the exception to stop execution
        
    if not challenges:
        raise ValueError("No challenges found in the CSV file")
        
    return challenges

def remove_challenge_from_csv(file_path: str, challenge_id: str, console: Optional[Console] = None) -> bool:
    """Remove rows with given challenge_id from CSV file.

    Returns True if at least one row was removed, False otherwise.
    The CSV will be rewritten with a header of expected columns.
    """
    fieldnames = ['challenge_id', 'difficulty', 'no_pre_mine', 'no_pre_mine_hour', 'latest_submission']
    try:
        # Read existing rows
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            first_line = csvfile.readline()
            csvfile.seek(0)
            if 'challenge_id' not in first_line:
                reader = csv.DictReader(csvfile, fieldnames=fieldnames)
            else:
                reader = csv.DictReader(csvfile)
            rows = list(reader)

        # Filter rows
        filtered = [r for r in rows if (r.get('challenge_id') or '').strip() != challenge_id]
        removed = len(rows) - len(filtered)

        # Write back (always include header)
        tmp_path = f"{file_path}.tmp"
        with open(tmp_path, 'w', newline='', encoding='utf-8') as outcsv:
            writer = csv.DictWriter(outcsv, fieldnames=fieldnames)
            writer.writeheader()
            for r in filtered:
                # Ensure all keys exist
                row = {k: (r.get(k) if r.get(k) is not None else '') for k in fieldnames}
                writer.writerow(row)

        # Atomic replace
        os.replace(tmp_path, file_path)
        if console:
            console.log(f"[green]Removed {removed} rows with challenge_id={challenge_id} from {file_path}")
        return removed > 0
    except FileNotFoundError:
        if console:
            console.log(f"[red]CSV file not found: {file_path}")
        return False
    except Exception as e:
        if console:
            console.log(f"[red]Failed to remove challenge from CSV: {e}")
        return False


# --------------- main ---------------
def main():
    # Initialize console
    console = Console()
    
    args = parse_args()
    
    # ✅ List address bạn cung cấp
    address_list = [
"addr1q9z8hfnatl55vreujm35q3knnxd4hrzy8yeu3tzvhjnh6x505glrcflcgwfcx9patcul4a5ejvgczdhpjtq2c6d0a0asrzzl0r",
    "addr1q8hxeplaz0ksfcp6qdju3wxutxe43zjj7fq5uhfegjsq5nnzvqp3l4tlhc55sph9z725cpygj060qhuvvj8a68vkswgq09de72",
    "addr1q8ejau40e0erjlepyvl30sndf8np6pqg6xzrjmyyfm03vnn23wflk4qmfkslvnwr8gxjjk7me3wf3lzgyetk25qm9f4svtdekh",
    "addr1q9qux8uesw3ck8dfkd7xn6n68ddypsmn9tyc56v586qnqn6m7pwyw3vlxjx693lhuaeat8vx0guclnf7hjq7cfcf76xqf22llg",
    "addr1qxy0td0rvuhm4ddvp2svr6mx9w7hhwge2t02s3flr8zq8e9lp8j9268wjj4rzddw8czwwpe3h3jqjppq7shp9l0yrgeqh5rd2e",
    "addr1q8znuqf74ndn0n2rm6hqpejf7lzjy2cku8335axcy98g4r2r3nyevctvtajc9656w06wk5kucp4a4spl0sw3d6g7um4s38ymqr",
     ]

    # Register cleanup
    import atexit
    atexit.register(lambda: error_logger.save_errors_to_file("MULTIADDR"))

    try:
        challenges = read_challenges_from_csv(args.csv_file, console)
        if not challenges:
            console.log("[red]No challenges found in CSV")
            return
            
        # Debug: Print the first challenge to see its structure
        if challenges:
            console.log(f"[yellow]First challenge in list: {challenges[0]}")
            console.log(f"[yellow]Challenge keys: {list(challenges[0].keys())}")
    except Exception as e:
        console.log(f"[red]Error loading challenges: {e}")
        return

    print(f"✅ TOTAL challenges: {len(challenges)}")
    print(f"✅ TOTAL addresses: {len(address_list)}")

    # ---------------- Progress Loop ----------------
    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:

        challenge_task = progress.add_task("Processing Challenges", total=len(challenges))
        
        for c_idx, challenge in enumerate(challenges, start=1):
            progress.update(challenge_task, description=f"Challenge {c_idx}/{len(challenges)}")
            # Debug: Print the challenge object to see its structure
            print(f"\nDebug - challenge object: {challenge}")
            # Safely get challenge_id or use a default value
            challenge_id = challenge.get('challenge_id', f'unknown_{c_idx}')
            console.log(f"\n[bold green]Starting Challenge {c_idx}: {challenge_id}")

            addr_task = progress.add_task("Processing Addresses", total=len(address_list))
            for a_idx, addr in enumerate(address_list, start=1):
                progress.update(addr_task, description=f"Addr {a_idx}/{len(address_list)}")
                stop_event.clear()
                stats.reset()

                orch = Orchestrator(
                    args.base_url,
                    addr,
                    args.daemon_host,
                    args.daemon_port,
                    args.workers,
                    args.submit
                )
                orch.set_challenge(challenge)
                start_time = time.time()
                orch.run(stats_interval=10.0)
                elapsed = time.time() - start_time

                console.log(f"✅ Done mining for address {addr} in {elapsed:.1f}s")
                progress.advance(addr_task)
                time.sleep(1)

            console.log(f"✅ Done Challenge {challenge['challenge_id']}")
            progress.advance(challenge_task)
            time.sleep(1)

    console.log("\n✅✅ ALL COMPLETED ✅✅")

if __name__ == "__main__":
    main()