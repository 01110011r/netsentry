#!/usr/bin/env bash
# usage: ./measure-report-latency.sh <attack_start_time> <report_json_path>
START_TIME=$1
LOG_PATH=$2
python3 - "$START_TIME" "$LOG_PATH" <<'EOF'
import sys, json
start_time = int(sys.argv[1])
with open(sys.argv[2]) as f:
    for line in f:
        e = json.loads(line)
        if e["event"] == "anomaly and e["ts"] >= start_time:
            print(f"latency: {e['ts'] - start_time}s (z={e['z_score']}, rate={e['rate']})")
            break
    else:
        print("No anomaly detcted in this run")
EOF
