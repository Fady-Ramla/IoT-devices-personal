#!/usr/bin/env python3
"""Run the LB proxy inside the Mininet gateway namespace during LB outage/block.

The gateway owns the floating 10.10.20.100/32 only while this helper is active.
Ryu communicates the explicit Security block through the shared JSON state file;
a stale main-LB heartbeat also triggers automatic fallback after a process failure.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time

VIP = "10.10.20.100/32"
VIP_IP = "10.10.20.100"
INTERFACE = "gw-eth0.20"
HEARTBEAT_TIMEOUT = max(3.0, float(os.getenv("LB_HEARTBEAT_TIMEOUT", "4")))
POLL_INTERVAL = 0.5


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def main_lb_alive(heartbeat_file, now=None):
    heartbeat = read_json(heartbeat_file)
    try:
        timestamp = float(heartbeat.get("timestamp", 0))
    except (TypeError, ValueError):
        return False
    now = time.time() if now is None else now
    return timestamp > 0 and 0 <= now - timestamp <= HEARTBEAT_TIMEOUT


def want_fallback(state_file, heartbeat_file):
    state = read_json(state_file)
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as handle:
                parsed = json.load(handle)
            if not isinstance(parsed, dict):
                return True
        except (OSError, ValueError, TypeError):
            return True
    return bool(state.get("lb_blocked")) or not main_lb_alive(heartbeat_file)


def run(args):
    process = None
    log_handle = None
    active = False
    stopping = False

    def stop_handler(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    while not stopping:
        should_run = want_fallback(args.state_file, args.heartbeat_file)
        if should_run and not active:
            add = subprocess.run(["ip", "addr", "add", VIP, "dev", INTERFACE],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if add.returncode != 0 and "File exists" not in add.stderr:
                print("[lb-fallback] could not claim VIP: " + add.stderr.strip(), flush=True)
                time.sleep(POLL_INTERVAL)
                continue
            env = os.environ.copy()
            env.update({
                "SECUREIOT_LB_STATE_FILE": args.state_file,
                "SECUREIOT_LB_HEARTBEAT_FILE": args.heartbeat_file,
                "LB_LISTEN_IP": VIP_IP,
                "LB_HEARTBEAT_ENABLED": "0",
            })
            log_handle = open(args.log_file, "a", buffering=1)
            process = subprocess.Popen([sys.executable, args.lb_script], env=env,
                                       stdout=log_handle, stderr=subprocess.STDOUT)
            active = True
            print("[lb-fallback] activated on gateway VIP %s" % VIP_IP, flush=True)

        elif should_run and active and process is not None and process.poll() is not None:
            print("[lb-fallback] proxy exited; restarting", flush=True)
            if log_handle is not None:
                log_handle.close()
                log_handle = None
            env = os.environ.copy()
            env.update({
                "SECUREIOT_LB_STATE_FILE": args.state_file,
                "SECUREIOT_LB_HEARTBEAT_FILE": args.heartbeat_file,
                "LB_LISTEN_IP": VIP_IP,
                "LB_HEARTBEAT_ENABLED": "0",
            })
            log_handle = open(args.log_file, "a", buffering=1)
            process = subprocess.Popen([sys.executable, args.lb_script], env=env,
                                       stdout=log_handle, stderr=subprocess.STDOUT)

        elif not should_run and active:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            process = None
            if log_handle is not None:
                log_handle.close()
                log_handle = None
            subprocess.run(["ip", "addr", "del", VIP, "dev", INTERFACE],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            active = False
            print("[lb-fallback] deactivated; main LB heartbeat recovered and is unblocked", flush=True)

        time.sleep(POLL_INTERVAL)

    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
    if active:
        subprocess.run(["ip", "addr", "del", VIP, "dev", INTERFACE],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if log_handle is not None:
        log_handle.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lb-script", required=True)
    parser.add_argument("--state-file", default="/tmp/secureiot_lb_state.json")
    parser.add_argument("--heartbeat-file", default="/tmp/secureiot_lb_heartbeat.json")
    parser.add_argument("--log-file", default="/tmp/secureiot-lb-gateway-proxy.log")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
