#!/usr/bin/env python3
"""Lightweight, safe IoT telemetry simulator for SecureIoT Mininet hosts.

Each Mininet IoT host runs one instance. It periodically POSTs role-specific,
synthetic sensor readings to the approved Web/API service over TCP/5000.
This is a simulator, not a physical sensor driver.
"""

import argparse
import json
import random
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def make_reading(role, rng):
    """Return plausible synthetic readings for a device role."""
    if role == "fire_alarm_controller":
        return {"smoke_level": round(rng.uniform(0.0, 0.12), 3), "alarm": False}
    if role == "smoke_heat_gateway":
        return {"smoke_level": round(rng.uniform(0.0, 0.15), 3), "temperature_c": round(rng.uniform(19, 27), 2)}
    if role == "hvac_controller":
        return {"room_temperature_c": round(rng.uniform(20, 25), 2), "target_temperature_c": 22.0, "mode": "auto"}
    if role == "temperature_humidity":
        return {"temperature_c": round(rng.uniform(18, 29), 2), "humidity_pct": round(rng.uniform(30, 65), 2)}
    if role == "ip_camera":
        return {"camera_status": "online", "fps": rng.choice([15, 20, 24, 25]), "motion_detected": rng.random() < 0.08}
    if role == "smart_door_access":
        return {"door_state": "closed", "lock_state": "locked", "access_events_last_minute": rng.randint(0, 2)}
    if role == "smart_lighting":
        return {"brightness_pct": rng.randint(25, 85), "occupancy_detected": rng.random() < 0.35}
    if role == "smart_energy_meter":
        return {"power_w": round(rng.uniform(80, 850), 2), "voltage_v": round(rng.uniform(218, 242), 2), "energy_kwh": round(rng.uniform(0.1, 80), 3)}
    if role == "ups_monitor":
        return {"battery_pct": round(rng.uniform(88, 100), 2), "load_pct": round(rng.uniform(15, 65), 2), "on_battery": False}
    if role == "server_room_temperature":
        return {"temperature_c": round(rng.uniform(18, 27), 2), "humidity_pct": round(rng.uniform(25, 55), 2)}
    if role == "water_leak_detector":
        return {"water_detected": False, "sensor_status": "normal"}
    if role == "vibration_sensor":
        return {"vibration_mm_s": round(rng.uniform(0.1, 2.5), 3), "machine_status": "normal"}
    return {"status": "online", "value": round(rng.random(), 4)}


def post_json(url, payload, timeout):
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "SecureIoT-Simulator/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read()
        return response.status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--server", default="10.10.20.2")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--max-events", type=int, default=0, help="0 means run until stopped")
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    if args.max_events < 0:
        parser.error("--max-events cannot be negative")

    rng = random.Random(f"{args.device_id}-{time.time_ns()}")
    endpoint = f"http://{args.server}:{args.port}/api/iot/telemetry"
    sequence = 0
    print(f"IOT_SIMULATOR_READY device={args.device_id} role={args.role} endpoint={endpoint} interval={args.interval}s", flush=True)
    while args.max_events == 0 or sequence < args.max_events:
        sequence += 1
        payload = {
            "device_id": args.device_id,
            "device_role": args.role,
            "sequence": sequence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "telemetry": make_reading(args.role, rng),
        }
        try:
            status = post_json(endpoint, payload, args.timeout)
            print(f"IOT_TELEMETRY_SENT device={args.device_id} sequence={sequence} http_status={status}", flush=True)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"IOT_TELEMETRY_FAILED device={args.device_id} sequence={sequence} error={exc}", flush=True)
        if args.max_events == 0 or sequence < args.max_events:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
