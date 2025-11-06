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

# --------------- Worker ---------------
import random

class Worker:
    def __init__(self, worker_id, daemon_host, daemon_port, base_url, address, 
                 challenge_getter, submit_on_find, start_nonce=None, end_nonce=None):
        self.worker_id = worker_id
        self.daemon_host = daemon_host
        self.daemon_port = daemon_port
        self.base_url = base_url
        self.address = address
        self.challenge_getter = challenge_getter
        self.submit_on_find = submit_on_find
        self.start_nonce = start_nonce if start_nonce is not None else 0
        self.end_nonce = end_nonce if end_nonce is not None else 2**64
        
    def run(self):
        """Worker main loop - gửi range đến daemon để search"""
        print(f"[worker {self.worker_id}] Starting with search range: "
              f"{hex(self.start_nonce)} → {hex(self.end_nonce)}")
        
        while not stop_event.is_set():
            challenge = self.challenge_getter()
            if not challenge:
                time.sleep(0.1)
                continue
            
            try:
                # ✅ GỬI REQUEST với start/end nonce range
                response = self.call_daemon_with_range(challenge)
                
                if response and 'nonce' in response:
                    nonce_found = response['nonce']
                    print(f"[worker {self.worker_id}] FOUND nonce={nonce_found}")
                    stats.increment_solutions()
                    
                    if self.submit_on_find:
                        self.submit_solution(challenge, nonce_found)
                    
                    # Found nonce → stop để lấy challenge mới
                    break
                    
            except Exception as e:
                print(f"[worker {self.worker_id}] Error: {e}")
                time.sleep(0.5)
    
    def call_daemon_with_range(self, challenge):
        """Gọi daemon với nonce range cụ thể"""
        import socket
        import json
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.daemon_host, self.daemon_port))
            
            # Gửi request với range
            request = {
                "challenge": challenge,
                "start_nonce": self.start_nonce,
                "end_nonce": self.end_nonce,
                "worker_id": self.worker_id,
                "address": self.address
            }
            
            sock.sendall(json.dumps(request).encode() + b'\n')
            
            # Nhận response
            response_data = b''
            while not stop_event.is_set():
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                stats.increment_hashes(1000)  # Estimate hashes
                
            sock.close()
            
            if response_data:
                return json.loads(response_data.decode())
                
        except Exception as e:
            print(f"[worker {self.worker_id}] Daemon call error: {e}")
            return None
    
    def submit_solution(self, challenge, nonce):
        """Submit solution to server"""
        import requests
        
        try:
            challenge_id = challenge.get('challenge_id', 'unknown')
            url = f"{self.base_url}/submit"
            
            payload = {
                "challenge_id": challenge_id,
                "nonce": nonce,
                "address": self.address
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                print(f"[worker {self.worker_id}] ✅ Submit SUCCESS: {result}")
            else:
                print(f"[worker {self.worker_id}] ❌ Submit FAILED: {response.status_code}")
                
        except Exception as e:
            print(f"[worker {self.worker_id}] Submit error: {e}")

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
            print(f"[debug] Setting challenge: {challenge}")
            if isinstance(challenge, dict):
                print(f"[debug] Challenge keys: {list(challenge.keys())}")
            self.current_challenge = challenge

    def start_workers(self):
        """✅ BẢN MỚI - CHIA ĐỀU SEARCH SPACE CHO CÁC WORKERS"""
        self.executor = ThreadPoolExecutor(max_workers=self.workers_count)
        
        # ✅ TÍNH TOÁN SEARCH RANGE CHO MỖI WORKER
        TOTAL_NONCE_SPACE = 2**64
        chunk_size = TOTAL_NONCE_SPACE // self.workers_count
        
        print(f"\n[orchestrator] ===== STARTING {self.workers_count} WORKERS =====")
        print(f"[orchestrator] Total search space: {hex(TOTAL_NONCE_SPACE)}")
        print(f"[orchestrator] Chunk per worker: {hex(chunk_size)}\n")
        
        for i in range(self.workers_count):
            # ✅ MỖI WORKER CÓ RANGE RIÊNG BIỆT
            start_nonce = i * chunk_size
            
            # Worker cuối cùng search đến hết space
            if i == self.workers_count - 1:
                end_nonce = TOTAL_NONCE_SPACE
            else:
                end_nonce = (i + 1) * chunk_size
            
            # ✅ THÊM RANDOM OFFSET để tránh workers cùng bắt đầu từ đầu chunk
            random_offset = random.randint(0, chunk_size // 100)  # 1% random
            start_nonce += random_offset
            
            w = Worker(
                worker_id=i,
                daemon_host=self.daemon_host,
                daemon_port=self.daemon_port,
                base_url=self.base_url,
                address=self.address,
                challenge_getter=self.challenge_getter,
                submit_on_find=self.submit_on_find,
                start_nonce=start_nonce,  # ✅ THÊM RANGE
                end_nonce=end_nonce        # ✅ THÊM RANGE
            )
            
            self.executor.submit(w.run)
            self.workers.append(w)
            
            # Debug log
            print(f"[orchestrator] Worker {i}: {hex(start_nonce)} → {hex(end_nonce)} "
                  f"(size: {hex(end_nonce - start_nonce)})")
        
        print(f"\n[orchestrator] ===== ALL WORKERS STARTED =====\n")

    def stop_workers(self):
        stop_event.set()
        if self.executor:
            print("[orchestrator] Shutting down workers...")
            self.executor.shutdown(wait=True)
            print("[orchestrator] All workers stopped")

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
        
        # ✅ Start workers với range đã chia
        self.start_workers()
        last_stats = time.time()
        
        try:
            while not stop_event.is_set():
                # Print stats
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
    p.add_argument("--workers", default=8, type=int, help="Number of worker threads (default: 8)")
    p.add_argument("--submit", action="store_true", default=True, help="Submit found solutions to server (default: True)")
    p.add_argument("--csv-file", default=r"D:\midnight\getchallenge.csv", help="CSV file containing challenges (default: D:\\midnight\\getchallenge.csv)")
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

# --------------- main ---------------
def main():
    # Initialize console
    console = Console()
    
    args = parse_args()
    
    # ✅ List address bạn cung cấp
    address_list = [
    "addr1q9fhk5c40yndvu980g86nhqfyp6nnfezwzuj4qa7p7cjytysszyvma8p94zc850du9xfnvwq0tw5luq4k7gn3g5jalss3rcwq3",
    "addr1qy3758ga98ccaztylrnue8ej63ynskmgurrljaddsjq5tpwe7dncxgt6cnppgkjn2x3r48s26tu2nwphygep9fzm3kusyayuqf",
    "addr1qywhtq522evxxjx7h6h5xxqhvz8wvtu0tytmfzlt8gzy0rathsfku293m6p7d00yat90qng90qp8qadwrtes7zvwq36qf6nxp7",
    "addr1q9fkdnrldlsug8rg2m7ttj6xyg80qhln36uffnsgvnfd55udx0gae2m5q9r0fm37svhkj4dl0mcfh7j7s7ucrkrjn8cqq9jwl9",
    "addr1q8cecrzfwenw6du5sflmq5svju9vv2m9nhlayq5rk33wqrhgg7emy76r8nrqhg76vfwlg74k5wsrfekal3ltqlyt8qxqqca792",
    "addr1q9zny6jp7q5qpvsau4kxm5zej2jkqyl636z5r0vr8zv5jgxfsmrypree946u3c4n4mdk9yxna42d3q8kphp2feze7zjst9cg39",
    "addr1qyl2rwjccaddqyfc349csr6ncyctl8r0y55hew000emdlj0tqgtur6wyxm9ga8q5n64x0x88az8ynsleh4ux8h9kwsnqjudc20",
    "addr1qxykvjrygtq2seaukx3365xehmf3d6vjrjd827qxk7dppjzy8kvwk4tz59l4t89zpend0825jx3fj62qwjlvyqml7juqurly9a",
    "addr1q9g5trnvtpwh2svwjzttz4kr4rjxxwu4627zrnqlmcn0j5s59y0hma20lnne3xfcnx3rz35fgtdkveqhggk4ft770cqsswfut5",
    "addr1q9h53yserrylwdy5884s603vxx5vcdzde85c237ux4nkp86tfvq49ukm536m8mdk7v457ffqp5gxl55jw9ekh3a2mfdsdpq670",
    "addr1q8wh05mzkuevknvj7qntjz2lhvqdehw4r2lvywlj4sk9fs3ls46ux04j58v6t06mqph0p4q09z4gsvlw6hx52ademcys89he6t",
    "addr1q8x0pahx00vu9c86w365dunm8rmy0rg4fuq0g3zxmz4zavyj626uuqqvgk39syqksc6jx5u49qzkt8h7pz0px82usz9q8tcwnv",
    "addr1qydf4f3wvr02tfrd77uc5j0kqer0mvh6hxpnk6psel9pmgy84s0m063g0qjf5u8hsfu4tsm2xwlwx3erwzcnwyp7u8astpkrrn",
    "addr1qypzt0yuehh7903n03yfsrgmldvg0ek9etktagwgnunfulf6692udw27m5lhqvxw5ayw085em8wr6ejyuuqjqe4c9pws9ytg3d",
    "addr1qxj2d0tnnuprevdh5xumj36c2rj0gchrw2kr8qsna6a8g8242smpmfh7pvtur99e6nc7pgahhwvhqt566srdq3f5tdpsx3w4lf",
    "addr1qyaqtgqlds95r3ajsn2e73l9nx9ywzhysyntaavk7087z33j7n2uyqnvpxdeh6mlasnlkmymyt3uv3yr2avypdmz5hgst6c22f",
    "addr1q8x0pahx00vu9c86w365dunm8rmy0rg4fuq0g3zxmz4zavyj626uuqqvgk39syqksc6jx5u49qzkt8h7pz0px82usz9q8tcwnv",
    "addr1qxeastf6h0qlzmwpk4eq4j0k2pp6fzchzlzlz4humeyrn0fv0rhkpjr90ml3dd9rl6rnc7xgerwpc647euep93vykreq704hp8",
    "addr1qypkwzcq24y2ma0w7l8v0vv6524nv2fh8raulqchq6suj7f6lj02e8ehjdf3ed8npdv72yk8ppp7l8757sfq9zyn48kscyusqu",
    "addr1qy7eycs367w56qk7qtjzwtejjaz4nzd5ah6gqd5svq5vn88gwa4rem8mqeqlrtudkyj23hg4gzncm2dp5rqrlx9sjzvqguw4fa",
    "addr1qy3csmd20n5v6ncc779jerzfqsvxw9xly3vmjfr8spx0npkxthj9g2s0cgecdpsjlr55vtdjmm2squk69p95cklncv2qeu0cm0",
    "addr1q9hgm8vn3tz7hn64tnezsctjwgxuw4vgl2803ekc06fu4mvz446fd46z4ze2czy85nnd2lealnuzsrtft0hs35vjknhscf5ffw",
    "addr1qyrr03yzez8yps9na8n7xtgnfknshzp4gqzyzyq9y45rke3nuhvu9qvwetv6v3kxd5qkzxwrwpn8xelejhd0r0td2z3qcqpkcf",
    "addr1q93tzy3dm8r7t2x8nttjsdufql35gzqvnnmxt2qwq7h2jrzgxm7hcz868mdrkrag9luefz3hqxavc5h87gx0ydv07fuse88pe2"
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