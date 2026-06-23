# cfs_files

Scripts for sending command traffic to a running cFS instance and capturing its telemetry.

## Requirements
- cFS running on "127.0.0.1" (commands on port `1234`)
- "cmdUtil" in this directory
- Python 3

## Usage
1. Start the telemetry receiver (UDP port 2234, writes `telemetry_dashboard.json`):
   python3 reciever.py
   (Remember to enable TO_LAB otherwise it wouldnt recieve any data: ~/src/cFS/build/exe/host/cmdUtil --host=localhost --port=1234 --pktid=0x1880 --cmdcode=6 --string="16:127.0.0.1")
2. In another terminal, run a traffic generator:
   python3 attack_systematic.py or attack_random.py

Each command sent is logged to `log<start-time>.csv` with anomaly labels. Settings (durations, probabilities) are at the top of each script.