#!/usr/bin/env python3
"""Generate role-specific, benign IoT telemetry inside a Mininet host.

Each instance is launched in one host namespace by Real_network_topology.py.
It sends HTTP POST telemetry to the demo Web/API backend (h2:5000). The
resulting packets traverse the configured VLAN gateway and can be captured by
Ryu/traffic_monitor_merged.py. This program does not generate attack traffic.
"""

import argparse
import json
import logging
import os
import random
import time
import urllib.error
import urllib.request


ROLE_INTERVAL_MULTIPLIER = {
    "alarm_sensor": 1.0,
    "temperature_sensor": 1.0,
    "hvac_controller": 1.5,
    "humidity_sensor": 1.2,
    "ip_camera": 0.8,
    "smoke_fire_alarm": 1.0,
    "smart_light_bulb": 1.8,
    "smart_door_lock": 2.0,
    "environment_sensor": 1.3,
    "smart_printer": 2.5,
    "voip_phone": 0.6,
    "vibration_sensor": 0.9,
}


def telemetry_for(role, device_id):
    """Create harmless synthetic values appropriate to the configured role."""
    # The production Web API expects device identity at the top level and
    # all measured values/metadata grouped inside the telemetry object.
    telemetry = {
        "timestamp": round(time.time(), 3),
        "sequence": int(time.monotonic() * 1000),
        "simulation": True,
    }
    if role == "alarm_sensor":
        telemetry.update(alarm_state=random.choice(["normal", "normal", "normal", "triggered"]),
                    battery_pct=random.randint(65, 100))
    elif role == "temperature_sensor":
        telemetry.update(temperature_c=round(random.uniform(18.0, 31.0), 2),
                    battery_pct=random.randint(40, 100))
    elif role == "hvac_controller":
        telemetry.update(mode=random.choice(["auto", "cool", "heat", "fan"]),
                    setpoint_c=round(random.uniform(19.0, 25.0), 1),
                    running=random.choice([True, False]))
    elif role == "humidity_sensor":
        telemetry.update(humidity_pct=round(random.uniform(25.0, 75.0), 2))
    elif role == "ip_camera":
        telemetry.update(stream_state="active", fps=random.choice([15, 20, 25, 30]),
                    bitrate_kbps=random.randint(500, 2500))
    elif role == "smoke_fire_alarm":
        telemetry.update(smoke_detected=False, alarm_state="normal",
                    sensor_health=random.choice(["ok", "ok", "ok", "check"]))
    elif role == "smart_light_bulb":
        telemetry.update(power_state=random.choice(["on", "off"]),
                    brightness_pct=random.randint(0, 100))
    elif role == "smart_door_lock":
        telemetry.update(lock_state=random.choice(["locked", "locked", "unlocked"]),
                    battery_pct=random.randint(50, 100))
    elif role == "environment_sensor":
        telemetry.update(air_quality_index=random.randint(5, 120),
                    co2_ppm=random.randint(400, 1200))
    elif role == "smart_printer":
        telemetry.update(printer_state=random.choice(["idle", "idle", "printing"]),
                    toner_pct=random.randint(10, 100), paper_ok=True)
    elif role == "voip_phone":
        telemetry.update(call_state=random.choice(["idle", "idle", "in_call"]),
                    codec="opus", jitter_ms=round(random.uniform(1, 25), 2))
    elif role == "vibration_sensor":
        telemetry.update(vibration_rms=round(random.uniform(0.01, 1.5), 3),
                    frequency_hz=round(random.uniform(10, 200), 1))
    else:
        telemetry.update(sensor_state="normal", value=round(random.random(), 4))
    return {
        "device_id": device_id,
        "device_role": role,
        "telemetry": telemetry,
    }


def send_telemetry(url, payload):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "SecureIoT-Lab-Simulator/1.0"}
    token = os.environ.get("IOT_INGEST_TOKEN", "")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=3) as response:
        response.read(4096)
        return response.status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-id", required=True, help="Mininet host ID, e.g. h5")
    parser.add_argument("--role", required=True, help="Role configured in vlan_config_38host.py")
    parser.add_argument("--server", default="10.10.20.2")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--interval", type=float, default=10.0)
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    url = "http://%s:%d/api/iot/telemetry" % (args.server, args.port)
    interval = args.interval * ROLE_INTERVAL_MULTIPLIER.get(args.role, 1.0)
    logging.info("starting device=%s role=%s destination=%s interval=%.2fs",
                 args.device_id, args.role, url, interval)
    while True:
        payload = telemetry_for(args.role, args.device_id)
        try:
            status = send_telemetry(url, payload)
            logging.info("telemetry sent device=%s role=%s http_status=%s seq=%s",
                         args.device_id, args.role, status,
                         payload["telemetry"].get("sequence"))
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            logging.warning("telemetry failed device=%s destination=%s error=%s",
                            args.device_id, url, exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
