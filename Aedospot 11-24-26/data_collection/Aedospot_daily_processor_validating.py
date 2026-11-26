"""
AEDOSPOT - DAILY DATA PROCESSOR WITH DATA-QUALITY DIAGNOSTICS

Reads raw_sensor_readings.csv produced by the validating serial receiver.
Writes:
  daily_environmental_data.csv
  daily_data_diagnostics.csv
  rejected_sensor_readings.csv

Only completed days meeting the configured quality rules enter the model-ready file.
"""

import os
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_FILE = os.path.join(BASE_DIR, "raw_sensor_readings.csv")
DAILY_FILE = os.path.join(BASE_DIR, "daily_environmental_data.csv")
DIAGNOSTICS_FILE = os.path.join(BASE_DIR, "daily_data_diagnostics.csv")
REJECTED_FILE = os.path.join(BASE_DIR, "rejected_sensor_readings.csv")

TIMEZONE = "Asia/Manila"
EXPECTED_INTERVAL_SECONDS = 2
MIN_DAILY_COVERAGE = 90.0
MAX_GAP_SECONDS = 10.0

# Keep these False until each sensor has been physically verified/calibrated.
RAIN_GAUGE_OPERATIONAL = False
ANEMOMETER_OPERATIONAL = False

# Provisional calibration only. Verify before enabling the operational flags.
RAIN_MM_PER_TIP = 0.3
RAIN_PULSES_PER_TIP = 1
WIND_MPS_PER_HZ = 0.0875
WIND_SPEED_OFFSET_MPS = 0.0


def load_and_validate():
    if not os.path.exists(RAW_FILE):
        raise FileNotFoundError(f"Raw sensor file not found: {RAW_FILE}")

    df = pd.read_csv(RAW_FILE)
    required = [
        "timestamp", "temperature", "humidity",
        "rainfall_pulses", "wind_pulses", "interval_ms"
    ]
    missing_columns = [c for c in required if c not in df.columns]
    if missing_columns:
        raise ValueError(f"CSV is missing required columns: {missing_columns}")

    df["timestamp_original"] = df["timestamp"]
    parsed = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["timestamp"] = parsed.dt.tz_convert(TIMEZONE)

    numeric = ["temperature", "humidity", "rainfall_pulses", "wind_pulses", "interval_ms"]
    for col in numeric:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Count duplicate timestamps before removing them.
    duplicate_mask = df["timestamp"].notna() & df["timestamp"].duplicated(keep="first")
    duplicate_count = int(duplicate_mask.sum())
    duplicates = df.loc[duplicate_mask].copy()

    # Invalid timestamps cannot be assigned to a day; retain them in rejected output.
    invalid_timestamp = df["timestamp"].isna()
    rejected_parts = [df.loc[invalid_timestamp].assign(rejection_reason="invalid_timestamp")]
    df = df.loc[~invalid_timestamp].copy()
    df = df.sort_values("timestamp")
    df = df.drop_duplicates(subset=["timestamp"], keep="last")

    # Use explicit value and timestamp checks. Missing is not the same as zero.
    df["temperature_valid"] = df["temperature"].between(-40, 80)
    df["humidity_valid"] = df["humidity"].between(0, 100)
    df["rain_valid"] = (
        df["rainfall_pulses"].notna()
        & (df["rainfall_pulses"] >= 0)
        & (df["rainfall_pulses"] % 1 == 0)
    )
    df["wind_valid"] = (
        df["wind_pulses"].notna()
        & (df["wind_pulses"] >= 0)
        & (df["wind_pulses"] % 1 == 0)
    )
    df["interval_valid"] = df["interval_ms"].between(500, 10000)

    df["record_valid"] = (
        df["temperature_valid"] & df["humidity_valid"]
        & df["rain_valid"] & df["wind_valid"] & df["interval_valid"]
    )

    # Flag implausible consecutive timestamp gaps. This is a gap check,
    # not a substitute for a hardware uptime log.
    df["timestamp_gap_seconds"] = (
        df["timestamp"].diff().dt.total_seconds()
    )
    df["gap_detected"] = df["timestamp_gap_seconds"] > MAX_GAP_SECONDS

    # Preserve every row that failed any field-level validation.
    for idx, row in df.loc[~df["record_valid"]].iterrows():
        reasons = []
        for col, label in [
            ("temperature_valid", "temperature_missing_or_out_of_range"),
            ("humidity_valid", "humidity_missing_or_out_of_range"),
            ("rain_valid", "rainfall_pulses_missing_or_invalid"),
            ("wind_valid", "wind_pulses_missing_or_invalid"),
            ("interval_valid", "interval_missing_or_out_of_range"),
        ]:
            if not bool(row[col]):
                reasons.append(label)
        rejected_parts.append(df.loc[[idx]].assign(rejection_reason=";".join(reasons)))

    rejected = pd.concat(rejected_parts, ignore_index=True) if rejected_parts else pd.DataFrame()
    return df, rejected, duplicate_count, len(duplicates)


def weighted_mean(values, weights):
    valid = values.notna() & weights.notna() & (weights > 0)
    if not valid.any():
        return np.nan
    return float(np.average(values[valid], weights=weights[valid]))


def process_days(df, duplicate_count):
    df = df.copy()
    df["date"] = df["timestamp"].dt.date
    today = pd.Timestamp.now(tz=TIMEZONE).date()
    expected_records = int(86400 / EXPECTED_INTERVAL_SECONDS)

    daily_rows = []
    diagnostics = []

    for date, group in df.groupby("date", sort=True):
        group = group.sort_values("timestamp")
        total = len(group)

        # Count actual time coverage from intervals, but cap each interval at
        # the expected interval so long gaps cannot falsely inflate coverage.
        interval_seconds = (group["interval_ms"] / 1000.0).where(group["interval_valid"], 0)
        covered_seconds = float(np.minimum(interval_seconds.fillna(0), EXPECTED_INTERVAL_SECONDS).sum())
        coverage = min(100.0, covered_seconds / 86400.0 * 100.0)

        valid_temp = group.loc[group["temperature_valid"], "temperature"]
        valid_rh = group.loc[group["humidity_valid"], "humidity"]
        valid_rain = group.loc[group["rain_valid"], "rainfall_pulses"]
        valid_wind = group.loc[group["wind_valid"] & group["interval_valid"]]

        temp_pct = len(valid_temp) / max(total, 1) * 100
        rh_pct = len(valid_rh) / max(total, 1) * 100
        rain_pct = len(valid_rain) / max(total, 1) * 100
        wind_pct = len(valid_wind) / max(total, 1) * 100

        gaps = int(group["gap_detected"].sum())
        max_gap = group["timestamp_gap_seconds"].max()
        mean_temp = float(valid_temp.mean()) if len(valid_temp) else np.nan
        mean_rh = float(valid_rh.mean()) if len(valid_rh) else np.nan

        rainfall = np.nan
        if RAIN_GAUGE_OPERATIONAL and rain_pct >= MIN_DAILY_COVERAGE:
            rainfall = float(valid_rain.sum() / RAIN_PULSES_PER_TIP * RAIN_MM_PER_TIP)

        wind_speed = np.nan
        if ANEMOMETER_OPERATIONAL and wind_pct >= MIN_DAILY_COVERAGE:
            seconds = valid_wind["interval_ms"] / 1000.0
            hz = valid_wind["wind_pulses"] / seconds
            speeds = hz * WIND_MPS_PER_HZ + WIND_SPEED_OFFSET_MPS
            wind_speed = weighted_mean(speeds, valid_wind["interval_ms"])

        is_finished_day = date != today
        quality_pass = (
            coverage >= MIN_DAILY_COVERAGE
            and temp_pct >= MIN_DAILY_COVERAGE
            and rh_pct >= MIN_DAILY_COVERAGE
            and rain_pct >= MIN_DAILY_COVERAGE
            and wind_pct >= MIN_DAILY_COVERAGE
            and is_finished_day
            and RAIN_GAUGE_OPERATIONAL
            and ANEMOMETER_OPERATIONAL
            and np.isfinite(rainfall)
            and np.isfinite(wind_speed)
        )

        diagnostics.append({
            "date": str(date),
            "records_after_deduplication": total,
            "expected_records_2s": expected_records,
            "coverage_percent_by_intervals": round(coverage, 2),
            "temperature_valid_percent": round(temp_pct, 2),
            "humidity_valid_percent": round(rh_pct, 2),
            "rainfall_valid_percent": round(rain_pct, 2),
            "wind_valid_percent": round(wind_pct, 2),
            "timestamp_gaps_over_10s": gaps,
            "maximum_timestamp_gap_seconds": (
                round(float(max_gap), 2) if pd.notna(max_gap) else None
            ),
            "duplicate_timestamps_in_file": duplicate_count,
            "rain_gauge_operational_flag": RAIN_GAUGE_OPERATIONAL,
            "anemometer_operational_flag": ANEMOMETER_OPERATIONAL,
            "is_finished_day": is_finished_day,
            "accepted_for_ai": bool(quality_pass),
            "rejection_reason": (
                "accepted" if quality_pass else
                "incomplete_current_day" if not is_finished_day else
                "coverage_below_threshold_or_sensor_data_invalid_or_calibration_unconfirmed"
            )
        })

        if quality_pass:
            daily_rows.append({
                "date": str(date),
                "RAINFALL": round(rainfall, 4),
                "TMEAN": round(mean_temp, 4),
                "RH": round(mean_rh, 4),
                "WIND_SPEED": round(wind_speed, 4)
            })

    return daily_rows, diagnostics


def main():
    print("=" * 55)
    print("AEDOSPOT DAILY DATA QUALITY CHECK")
    print("=" * 55)

    df, rejected, duplicate_count, duplicate_rows = load_and_validate()
    print(f"Unique timestamped records: {len(df)}")
    print(f"Duplicate timestamp rows detected: {duplicate_rows}")
    print(f"Rows with invalid/missing fields: {int((~df['record_valid']).sum())}")
    print(f"Timestamp gaps over {MAX_GAP_SECONDS:g} seconds: {int(df['gap_detected'].sum())}")

    daily_rows, diagnostics = process_days(df, duplicate_count)
    model_columns = ["date", "RAINFALL", "TMEAN", "RH", "WIND_SPEED"]

    pd.DataFrame(daily_rows, columns=model_columns).to_csv(DAILY_FILE, index=False)
    pd.DataFrame(diagnostics).to_csv(DIAGNOSTICS_FILE, index=False)
    rejected.to_csv(REJECTED_FILE, index=False)

    print(f"\nDays accepted for AI: {len(daily_rows)}")
    print(f"Daily diagnostics: {DIAGNOSTICS_FILE}")
    print(f"Rejected raw rows: {REJECTED_FILE}")
    print(f"Model-ready daily data: {DAILY_FILE}")

    if not RAIN_GAUGE_OPERATIONAL or not ANEMOMETER_OPERATIONAL:
        print("\nWARNING: Rain gauge/anemometer operational flags are still False.")
        print("No day will be accepted for the four-feature AI model until calibration/status is confirmed.")
    if not daily_rows:
        print("\nNo AI-ready days yet. This is intentional when quality or calibration checks fail.")


if __name__ == "__main__":
    main()
