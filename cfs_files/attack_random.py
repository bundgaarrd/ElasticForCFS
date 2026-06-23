import subprocess
import csv
from datetime import datetime, timezone
import time
import random

random.seed(42)

time_for_start_program = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

# Configuration
timer_for_normal_aktør = 8  # Number of hours where data is generated for normal operation
timer_for_attacker = 2     # Number of hours where data is generated where there is an attacker as well as normal operation

sandsynlighed_for_normal_aktør = 0.5  # The rest is not sending

# Attacker probabilities
anomaly_start = 0.01
anomaly_end = 0.05
sandsynlighed_for_attacks = [0.33,0.33,0.33]  # [dos, lifecycle, storage]

time_normal_aktør = 3600 * timer_for_normal_aktør
time_attack_aktør = 3600 * timer_for_attacker

attack_life_count = 0
attack_dos_count = 0
attack_storage_count = 0

# Send function and log
def sendCMDUTIL(pktid, cmdcode, anomaly, kind_of_anomaly, ekstra=None):
    global attack_dos_count, attack_life_count, attack_storage_count # Access to counts from outside the function
    cmd = ["./cmdUtil", "--host=127.0.0.1", "--port=1234",
           f"--pktid={pktid}", f"--cmdcode={cmdcode}"]
    if ekstra:
        cmd.extend(ekstra)
    subprocess.run(cmd)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"Attack dos: {attack_dos_count}")
    print(f"Attack life: {attack_life_count}")
    print(f"Attack storage exhuastion: {attack_storage_count}")
    print(f"Time: {timestamp}")
    with open(f"log{time_for_start_program}.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, pktid, cmdcode, anomaly, kind_of_anomaly, f"Attack dos count: {attack_dos_count}", f"Attack lifecycle: {attack_life_count}"])


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


# Attack: DoS - flood with NOOPs
def dos():
    global attack_dos_count
    attack_dos_count += 1
    for _ in range(50):
        sendCMDUTIL("0x1806", 0, True, "dos")


# Attack: Lifecycle - restart of apps
def lifecycle_restart_sample_app():
    sendCMDUTIL("0x1806", 4, True, "lifecycle_restart_sample_app",
                ekstra=["--string=20:SAMPLE_APP"])

def lifecycle_burst_sample():
    # 3 quick restarts - the app does not get time to stabilize
    for _ in range(3):
        sendCMDUTIL("0x1806", 4, True, "lifecycle_burst_sample",
                    ekstra=["--string=20:SAMPLE_APP"])
        time.sleep(0.1)

def lifecycle_restart_ci_lab():
    # Restart command-ingest (ci_lab)
    sendCMDUTIL("0x1806", 4, True, "lifecycle_restart_ci_lab",
                ekstra=["--string=20:CI_LAB"])

def lifecycle_restart_to_lab():
    # Restart to_lab
    sendCMDUTIL("0x1806", 4, True, "lifecycle_restart_to_lab",
                ekstra=["--string=20:TO_LAB"])

def storage_exhaustion():
    global attack_storage_count
    attack_storage_count += 1
    for i in range(50):
        sendCMDUTIL("0x1806", 11, True, "storage_exhaustion",
                    ekstra=[f"--string=64:/cf/exhaust_{i:04d}.log"])

attack_vairants = [
    lifecycle_restart_sample_app,
    lifecycle_burst_sample,
    lifecycle_restart_ci_lab,
    lifecycle_restart_to_lab,
]

def lifecycle():
    global attack_life_count
    attack_life_count += 1
    variant = random.choice(attack_vairants)
    variant()


attacks = [dos, lifecycle, storage_exhaustion]


# Loops
def normal_aktør_loop(time_normal_aktør):
    start_normal_data = time.monotonic()
    while time.monotonic() - start_normal_data < time_normal_aktør:
        r = random.random()
        if r < sandsynlighed_for_normal_aktør:
            pktid, cmdcode = random.choice(normal_data)
            sendCMDUTIL(pktid, cmdcode, False, "normal")
        time.sleep(1)


def attacker_loop(time_attack_aktør):
    start_time = time.monotonic()
    while time.monotonic() - start_time < time_attack_aktør:
        tid_kørt = time.monotonic() - start_time
        stigning = tid_kørt / time_attack_aktør

        # Exponential in how aggressive it is
        current_anomaly_sandsynlighed = anomaly_start + (anomaly_end - anomaly_start) * (stigning ** 2)

        r = random.random()
        if r < current_anomaly_sandsynlighed:
            # Choose a random attack based on the weights
            r2 = random.random()
            if r2 < sandsynlighed_for_attacks[0]:
                dos()
            elif r2 < sandsynlighed_for_attacks[0] + sandsynlighed_for_attacks[1]:
                lifecycle()
            else:
                storage_exhaustion()
                
        elif r < sandsynlighed_for_normal_aktør:
            # Normal data also during the attack phase
            pktid, cmdcode = random.choice(normal_data)
            sendCMDUTIL(pktid, cmdcode, False, "normal")

        time.sleep(1)

# Run
normal_aktør_loop(time_normal_aktør)
attacker_loop(time_attack_aktør)