#!/usr/bin/env python3
"""Lightweight IoT sensor simulator for SecureIoT Mininet hosts.

In server-polling mode each host exposes GET /sensor/readings and GET /health.
The Web/API server polls those private endpoints; the device never calls ngrok
and never pushes telemetry directly to the dashboard API.
"""
import argparse
import json
import random
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_reading(role, rng):
    if role in {"fire_alarm_controller", "smoke_fire_alarm", "alarm_sensor"}:
        return {"smoke_level": round(rng.uniform(0.0, 0.12), 3), "alarm": False}
    if role in {"smoke_heat_gateway", "environment_sensor"}:
        return {"smoke_level": round(rng.uniform(0.0, 0.15), 3), "temperature_c": round(rng.uniform(19, 27), 2)}
    if role == "hvac_controller":
        return {"room_temperature_c": round(rng.uniform(20, 25), 2), "target_temperature_c": 22.0, "mode": "auto"}
    if role in {"temperature_humidity", "temperature_sensor", "humidity_sensor"}:
        return {"temperature_c": round(rng.uniform(18, 29), 2), "humidity_pct": round(rng.uniform(30, 65), 2)}
    if role == "ip_camera":
        return {"camera_status": "online", "fps": rng.choice([15, 20, 24, 25]), "motion_detected": rng.random() < 0.08}
    if role in {"smart_door_access", "smart_door_lock"}:
        return {"door_state": "closed", "lock_state": "locked", "access_events_last_minute": rng.randint(0, 2)}
    if role in {"smart_lighting", "smart_light_bulb"}:
        return {"brightness_pct": rng.randint(25, 85), "occupancy_detected": rng.random() < 0.35}
    if role in {"smart_energy_meter", "smart_printer", "voip_phone"}:
        return {"power_w": round(rng.uniform(80, 850), 2), "status": "online"}
    if role == "vibration_sensor":
        return {"vibration_mm_s": round(rng.uniform(0.1, 2.5), 3), "machine_status": "normal"}
    return {"status": "online", "value": round(rng.random(), 4)}


def serve_sensor(device_id, role, listen_host, listen_port):
    rng = random.Random(f"{device_id}-{time.time_ns()}")
    sequence = 0
    lock = threading.Lock()

    class SensorHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal sequence
            if self.path == "/health":
                body = {"status": "healthy", "device_id": device_id, "service": "iot-sensor"}
            elif self.path == "/sensor/readings":
                with lock:
                    sequence += 1
                    body = {
                        "device_id": device_id,
                        "device_role": role,
                        "readings": make_reading(role, rng),
                        "sequence": sequence,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "status": "online",
                        "simulation": True,
                        "source": "mininet",
                    }
            else:
                self.send_error(404)
                return
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer((listen_host, listen_port), SensorHandler)
    print(f"IOT_SENSOR_READY device={device_id} role={role} address={listen_host}:{listen_port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--serve", action="store_true", help="serve private sensor HTTP endpoints")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=8081)
    args = parser.parse_args()
    if not args.serve:
        parser.error("--serve is required; IoT devices expose readings for the server poller")
    if not 1 <= args.listen_port <= 65535:
        parser.error("--listen-port must be between 1 and 65535")
    serve_sensor(args.device_id, args.role, args.listen_host, args.listen_port)


if __name__ == "__main__":
    main()
