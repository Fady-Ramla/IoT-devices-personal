#!/usr/bin/env python3
"""Shared SQLite store for live Mininet IoT telemetry.

The Flask service in a Mininet host namespace and the Ryu API run on the same
VM filesystem. SQLite provides atomic cross-process writes without opening a
second network listener or forwarding arbitrary Mininet traffic to Ryu.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

DEFAULT_DB_PATH = "/var/lib/secureiot/iot-telemetry.sqlite3"
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_MAX_READINGS = 64
_MAX_JSON_BYTES = 16 * 1024


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_recent(timestamp: str, max_age_sec: int = 60) -> bool:
    try:
        text = str(timestamp).strip()
        try:
            value = datetime.fromtimestamp(float(text), tz=timezone.utc)
        except ValueError:
            value = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - value.astimezone(timezone.utc)).total_seconds()
        return 0 <= age <= max_age_sec
    except (TypeError, ValueError, OverflowError, OSError):
        return False


def _json_safe(value: Any) -> Any:
    encoded = json.dumps(value, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError("telemetry payload is too large")
    return json.loads(encoded)


class IoTTelemetryStore:
    """Small process-safe telemetry store with bounded history and idempotency."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.environ.get("SECUREIOT_IOT_DB", DEFAULT_DB_PATH)
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, mode=0o750, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5.0)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS iot_devices (
                device_id TEXT PRIMARY KEY,
                device_role TEXT NOT NULL,
                status TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS iot_telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                device_role TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                sequence INTEGER,
                simulation INTEGER NOT NULL DEFAULT 0,
                readings_json TEXT NOT NULL,
                UNIQUE(device_id, sequence, timestamp)
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_iot_telemetry_device_id ON iot_telemetry(device_id, id)")

    @staticmethod
    def _validate_id(value: Any, field: str) -> str:
        text = str(value or "").strip()
        if not _ID_RE.fullmatch(text):
            raise ValueError(f"{field} must be a non-empty identifier")
        return text

    @staticmethod
    def _normalize(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        device_id = IoTTelemetryStore._validate_id(payload.get("device_id"), "device_id")
        role = IoTTelemetryStore._validate_id(payload.get("device_role", payload.get("role", "iot_device")), "device_role")
        nested = payload.get("telemetry")
        if isinstance(nested, dict):
            readings = dict(nested)
            timestamp = payload.get("timestamp") or readings.pop("timestamp", None) or now_utc()
            sequence = payload.get("sequence", readings.pop("sequence", None))
            simulation = bool(payload.get("simulation", readings.pop("simulation", False)))
        else:
            readings = payload.get("readings")
            if readings is None and "sensor_id" in payload and "value" in payload:
                readings = {str(payload["sensor_id"]): payload["value"]}
                if payload.get("unit") is not None:
                    readings[f"{payload['sensor_id']}_unit"] = payload["unit"]
            if not isinstance(readings, dict) or not readings:
                raise ValueError("telemetry object, readings object, or sensor_id/value is required")
            readings = dict(readings)
            timestamp = payload.get("timestamp") or now_utc()
            sequence = payload.get("sequence")
            simulation = bool(payload.get("simulation", False))
        if not isinstance(readings, dict) or not readings or len(readings) > _MAX_READINGS:
            raise ValueError(f"telemetry must contain 1..{_MAX_READINGS} readings")
        normalized = {}
        for key, value in readings.items():
            name = IoTTelemetryStore._validate_id(key, "reading name")
            normalized[name] = _json_safe(value)
        timestamp = str(timestamp).strip()
        if not timestamp or len(timestamp) > 80:
            raise ValueError("timestamp must be 1..80 characters")
        try:
            sequence = None if sequence is None else int(sequence)
        except (TypeError, ValueError):
            raise ValueError("sequence must be an integer")
        if sequence is not None and not 0 <= sequence <= 2**63 - 1:
            raise ValueError("sequence is outside the supported range")
        return {"device_id": device_id, "device_role": role, "timestamp": timestamp,
                "sequence": sequence, "simulation": simulation, "readings": normalized}

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        return {"id": int(row["id"]), "device_id": row["device_id"],
                "device_role": row["device_role"], "timestamp": row["timestamp"],
                "sequence": row["sequence"], "simulation": bool(row["simulation"]),
                "readings": json.loads(row["readings_json"])}

    def record(self, payload: Any) -> dict[str, Any]:
        item = self._normalize(payload)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""INSERT INTO iot_devices(device_id, device_role, status, last_seen)
                          VALUES(?, ?, 'online', ?)
                          ON CONFLICT(device_id) DO UPDATE SET
                            device_role=excluded.device_role, status='online', last_seen=excluded.last_seen""",
                       (item["device_id"], item["device_role"], item["timestamp"]))
            db.execute("""INSERT INTO iot_telemetry
                          (device_id, device_role, timestamp, sequence, simulation, readings_json)
                          VALUES(?, ?, ?, ?, ?, ?)
                          ON CONFLICT(device_id, sequence, timestamp) DO NOTHING""",
                       (item["device_id"], item["device_role"], item["timestamp"], item["sequence"],
                        int(item["simulation"]), json.dumps(item["readings"], separators=(",", ":"))))
            row = db.execute("SELECT * FROM iot_telemetry WHERE device_id=? AND timestamp=? AND sequence IS ?",
                             (item["device_id"], item["timestamp"], item["sequence"])).fetchone()
            db.execute("""DELETE FROM iot_telemetry WHERE id IN (
                          SELECT id FROM iot_telemetry ORDER BY id DESC LIMIT -1 OFFSET 10000)""")
        return self._row(row)

    def devices(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("""SELECT d.device_id, d.device_role, d.status, d.last_seen,
                    COUNT(DISTINCT t.id) AS sample_count
                    FROM iot_devices d LEFT JOIN iot_telemetry t USING(device_id)
                    GROUP BY d.device_id ORDER BY d.device_id""").fetchall()
        return [{"device_id": r["device_id"], "device_role": r["device_role"],
                 "status": "online" if _is_recent(r["last_seen"]) else "stale",
                 "last_seen": r["last_seen"], "sample_count": int(r["sample_count"])} for r in rows]

    def sensors(self) -> list[dict[str, Any]]:
        latest: dict[tuple[str, str], dict[str, Any]] = {}
        with self._connect() as db:
            rows = db.execute("SELECT * FROM iot_telemetry ORDER BY id ASC").fetchall()
        for row in rows:
            item = self._row(row)
            for sensor_id, value in item["readings"].items():
                key = (item["device_id"], sensor_id)
                latest[key] = {"device_id": item["device_id"], "device_role": item["device_role"],
                               "sensor_id": sensor_id, "value": value,
                               "last_seen": item["timestamp"],
                               "status": "online" if _is_recent(item["timestamp"]) else "stale"}
        return list(latest.values())

    def telemetry(self, device_id: str | None = None, sensor_id: str | None = None,
                  limit: int | str = 100) -> list[dict[str, Any]]:
        try:
            count = max(1, min(int(limit), 1000))
        except (TypeError, ValueError):
            count = 100
        query = "SELECT * FROM iot_telemetry"
        params: list[Any] = []
        if device_id:
            query += " WHERE device_id=?"
            params.append(str(device_id))
        query += " ORDER BY id DESC LIMIT ?"
        params.append(10000 if sensor_id else count)
        with self._connect() as db:
            rows = db.execute(query, params).fetchall()
        result = [self._row(row) for row in rows]
        if sensor_id:
            result = [row for row in result if sensor_id in row["readings"]]
        result = result[:count]
        return list(reversed(result))


__all__ = ["IoTTelemetryStore", "DEFAULT_DB_PATH"]
