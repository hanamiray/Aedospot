"""
AEDOSPOT - VALIDATING SERIAL RECEIVER
Arduino -> local raw CSV -> one-minute Flask/Supabase upload.

Keep this file in the same folder as app.py.
Set AEDOSPOT_DEVICE_API_KEY in the terminal before running.
"""

import csv
import json
import math
import os
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

from dotenv import load_dotenv

# The .env file is in the project root; this script lives in data_collection/.
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_DIR, ".env"))

try:
    import serial
except ImportError:
    raise SystemExit("Missing pyserial. Install it with: python -m pip install pyserial")

# ---------------- CONFIGURATION ----------------
SERIAL_PORT = "COM5"
BAUD_RATE = 9600
DEVICE_ID = 7
API_URL = "https://aedospot.onrender.com/api/sensor_readings"
API_KEY = os.getenv("AEDOSPOT_DEVICE_API_KEY", "").strip()

OUTPUT_FILE = "raw_sensor_readings.csv"
VALIDATION_FILE = "receiver_validation_log.csv"
UPLOAD_INTERVAL_SECONDS = 60
EXPECTED_INTERVAL_MS = 2000
INTERVAL_MIN_MS = 500
INTERVAL_MAX_MS = 10000

# Provisional values: verify with controlled bucket-tip and reference wind tests.
RAIN_MM_PER_TIP = 0.3
RAIN_PULSES_PER_TIP = 1
WIND_MPS_PER_HZ = 0.0875
WIND_SPEED_OFFSET_MPS = 0.0

# Require at least 90% of expected 2-second samples for every required measurement.
MIN_BATCH_VALID_PERCENT = 90.0

RAW_COLUMNS = [
    "timestamp", "temperature", "humidity",
    "rainfall_pulses", "rainfall_mm",
    "wind_pulses", "wind_frequency_hz", "wind_speed",
    "interval_ms", "validation_status", "validation_reasons"
]
LOG_COLUMNS = ["timestamp", "event", "details"]


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def ensure_csv(path, columns):
    """Create a CSV or safely expand an older header without losing old rows."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=columns).writeheader()
        return

    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        old_columns = reader.fieldnames or []
        if old_columns == columns:
            return
        rows = list(reader)

    temp_path = path + ".tmp"
    with open(temp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in columns})
    os.replace(temp_path, path)


def log_event(event, details):
    with open(VALIDATION_FILE, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=LOG_COLUMNS).writerow({
            "timestamp": now_iso(), "event": event, "details": str(details)
        })


def finite_number(value):
    try:
        number = float(value)
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def validate_packet(packet):
    """Return normalized fields, status and explicit reasons. Never silently coerce bad values."""
    reasons = []
    if not isinstance(packet, dict):
        return None, ["JSON root must be an object"]

    temp = finite_number(packet.get("temperature"))
    humidity = finite_number(packet.get("humidity"))
    rain = finite_number(packet.get("rainfall_pulses"))
    wind = finite_number(packet.get("wind_pulses"))
    interval = finite_number(packet.get("interval_ms"))

    if temp is None:
        reasons.append("temperature_missing_or_non_numeric")
    elif not -40 <= temp <= 80:
        reasons.append("temperature_out_of_DHT22_range")

    if humidity is None:
        reasons.append("humidity_missing_or_non_numeric")
    elif not 0 <= humidity <= 100:
        reasons.append("humidity_out_of_range")

    if rain is None:
        reasons.append("rainfall_pulses_missing_or_non_numeric")
    elif rain < 0 or not rain.is_integer():
        reasons.append("rainfall_pulses_must_be_nonnegative_integer")

    if wind is None:
        reasons.append("wind_pulses_missing_or_non_numeric")
    elif wind < 0 or not wind.is_integer():
        reasons.append("wind_pulses_must_be_nonnegative_integer")

    if interval is None:
        reasons.append("interval_missing_or_non_numeric")
    elif not INTERVAL_MIN_MS <= interval <= INTERVAL_MAX_MS:
        reasons.append("interval_out_of_accepted_range")

    if reasons:
        return {
            "temperature": temp, "humidity": humidity,
            "rainfall_pulses": rain, "wind_pulses": wind,
            "interval_ms": interval
        }, reasons

    rain_mm = (rain / RAIN_PULSES_PER_TIP) * RAIN_MM_PER_TIP
    interval_seconds = interval / 1000.0
    wind_hz = wind / interval_seconds
    wind_speed = wind_hz * WIND_MPS_PER_HZ + WIND_SPEED_OFFSET_MPS

    normalized = {
        "temperature": temp, "humidity": humidity,
        "rainfall_pulses": int(rain), "rainfall_mm": rain_mm,
        "wind_pulses": int(wind), "wind_frequency_hz": wind_hz,
        "wind_speed": wind_speed, "interval_ms": int(interval)
    }
    return normalized, []


def append_raw(row):
    with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=RAW_COLUMNS).writerow(row)


class MinuteBatch:
    def __init__(self):
        self.received = 0
        self.valid_temp = []
        self.valid_humidity = []
        self.valid_rain = []
        self.valid_wind = []
        self.invalid_packets = 0

    def add(self, values, reasons):
        self.received += 1
        if reasons:
            self.invalid_packets += 1
        if values:
            interval = values.get("interval_ms")
            if interval and INTERVAL_MIN_MS <= interval <= INTERVAL_MAX_MS:
                if values.get("temperature") is not None and -40 <= values["temperature"] <= 80:
                    self.valid_temp.append((values["temperature"], interval))
                if values.get("humidity") is not None and 0 <= values["humidity"] <= 100:
                    self.valid_humidity.append((values["humidity"], interval))
                if values.get("rainfall_pulses") is not None and values["rainfall_pulses"] >= 0 and float(values["rainfall_pulses"]).is_integer():
                    self.valid_rain.append((values["rainfall_pulses"], values.get("rainfall_mm", 0.0)))
                wind_speed = values.get("wind_speed")

                if (
                    wind_speed is not None
                    and isinstance(wind_speed, (int, float))
                    and math.isfinite(wind_speed)
                    and interval is not None
                    and INTERVAL_MIN_MS <= interval <= INTERVAL_MAX_MS
                ):
                    self.valid_wind.append((wind_speed, interval))
    @staticmethod
    def weighted_mean(items):
        if not items:
            return None
        denominator = sum(weight for _, weight in items)
        return sum(value * weight for value, weight in items) / denominator

    def summary(self):
        expected = max(1, round(UPLOAD_INTERVAL_SECONDS * 1000 / EXPECTED_INTERVAL_MS))
        def pct(items):
            return len(items) / expected * 100.0
        coverage = {
            "temperature": round(pct(self.valid_temp), 1),
            "humidity": round(pct(self.valid_humidity), 1),
            "rainfall": round(pct(self.valid_rain), 1),
            "wind": round(pct(self.valid_wind), 1)
        }
        ready = all(v >= MIN_BATCH_VALID_PERCENT for v in coverage.values())
        if not ready:
            return None, coverage, expected

        payload = {
            "device_id": DEVICE_ID,
            "temperature": self.weighted_mean(self.valid_temp),
            "humidity": self.weighted_mean(self.valid_humidity),
            "rainfall_mm": sum(mm for _, mm in self.valid_rain),
            "wind_speed": self.weighted_mean(self.valid_wind)
        }
        return payload, coverage, expected


def upload(payload):
    if not API_KEY:
        raise RuntimeError("AEDOSPOT_DEVICE_API_KEY environment variable is not set")
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        API_URL, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status, response.read().decode("utf-8", errors="replace")


def main():
    ensure_csv(OUTPUT_FILE, RAW_COLUMNS)
    ensure_csv(VALIDATION_FILE, LOG_COLUMNS)

    if not API_KEY:
        print("WARNING: API key is not set. Local CSV logging will work, but uploads will fail.")
    print("AEDOSPOT validating receiver starting...")
    print(f"Serial: {SERIAL_PORT} @ {BAUD_RATE}")
    print(f"Upload: {API_URL} every {UPLOAD_INTERVAL_SECONDS} seconds")
    print("Raw readings are saved locally, including invalid readings and reasons.")

    batch = MinuteBatch()
    last_upload = time.monotonic()

    try:
        with serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=2) as ser:
            time.sleep(2)
            while True:
                line = ser.readline().decode("utf-8", errors="replace").strip()
                if line:
                    try:
                        packet = json.loads(line)
                        values, reasons = validate_packet(packet)
                    except json.JSONDecodeError as exc:
                        values, reasons = None, [f"invalid_json:{exc.msg}"]

                    timestamp = now_iso()
                    batch.add(values, reasons)

                    row = {col: "" for col in RAW_COLUMNS}
                    row["timestamp"] = timestamp
                    if values:
                        for key in RAW_COLUMNS:
                            if key in values:
                                row[key] = values[key]
                    row["validation_status"] = "VALID" if not reasons else "INVALID_OR_PARTIAL"
                    row["validation_reasons"] = ";".join(reasons)
                    append_raw(row)

                    if reasons:
                        log_event("INVALID_READING", f"{timestamp}: {';'.join(reasons)}")
                        print(f"[INVALID] {line} | {', '.join(reasons)}")
                    else:
                        print(
                            f"[VALID] T={values['temperature']:.1f} C, "
                            f"RH={values['humidity']:.1f}%, "
                            f"rain pulses={values['rainfall_pulses']}, "
                            f"wind={values['wind_speed']:.3f} m/s"
                        )

                if time.monotonic() - last_upload >= UPLOAD_INTERVAL_SECONDS:
                    payload, coverage, expected = batch.summary()
                    if payload is None:
                        details = f"batch not uploaded; expected about {expected} samples; valid coverage={coverage}"
                        log_event("BATCH_REJECTED", details)
                        print("[BATCH REJECTED]", details)
                    else:
                        try:
                            status, response_text = upload(payload)
                            log_event("UPLOAD_SUCCESS", f"HTTP {status}; {response_text[:500]}; coverage={coverage}")
                            print(f"[UPLOAD OK] HTTP {status}; coverage={coverage}")
                        except (urllib.error.URLError, TimeoutError, RuntimeError, OSError) as exc:
                            log_event("UPLOAD_FAILED", f"{type(exc).__name__}: {exc}; payload={payload}")
                            print(f"[UPLOAD FAILED] {exc}")
                    # Do not silently carry a bad minute into the next one.
                    # All raw readings remain in CSV for recovery/reprocessing.
                    batch = MinuteBatch()
                    last_upload = time.monotonic()

    except KeyboardInterrupt:
        print("\nReceiver stopped by user.")
    except serial.SerialException as exc:
        log_event("SERIAL_ERROR", exc)
        raise SystemExit(f"Serial connection error: {exc}")


if __name__ == "__main__":
    main()
