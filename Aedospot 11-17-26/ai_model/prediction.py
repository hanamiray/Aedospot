
import os, json
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf

FEATURES = ["RAINFALL", "TMEAN", "RH", "WIND_SPEED"]
REQUIRED = ["date", "rainfall", "tmean", "rh", "wind_speed"]

class AedospotPredictor:
    def __init__(self, model_dir=None, load_lstm=True):
        model_dir = model_dir or os.path.dirname(os.path.abspath(__file__))
        self.lr = joblib.load(os.path.join(model_dir, "aedospot_logreg.joblib"))
        self.lr_scaler = joblib.load(os.path.join(model_dir, "logreg_scaler.joblib"))
        self.config = json.load(open(os.path.join(model_dir, "model_config.json")))
        self.lstm = None
        self.lstm_scaler = None
        lstm_path = os.path.join(model_dir, "aedospot_lstm.keras")
        if load_lstm and os.path.exists(lstm_path):
            self.lstm = tf.keras.models.load_model(lstm_path)
            self.lstm_scaler = joblib.load(os.path.join(model_dir, "lstm_scaler.joblib"))

    def _prepare(self, records):
        df = records.copy() if isinstance(records, pd.DataFrame) else pd.DataFrame(records)
        df.columns = [str(c).lower() for c in df.columns]
        missing = [c for c in REQUIRED if c not in df.columns]
        if missing:
            raise ValueError(f"Missing columns: {missing}")
        df = df[REQUIRED].copy()
        df["date"] = pd.to_datetime(df["date"], errors="coerce")
        for c in REQUIRED[1:]:
            df[c] = pd.to_numeric(df[c], errors="coerce")
        df = df.dropna(subset=["date"]).sort_values("date")
        if df["date"].duplicated().any():
            raise ValueError("Duplicate daily dates.")
        if len(df) < 30:
            raise ValueError("At least 30 daily records are required.")
        df = df.tail(30).reset_index(drop=True)
        expected = pd.date_range(df.date.iloc[0], periods=30, freq="D")
        if not df.date.reset_index(drop=True).equals(pd.Series(expected)):
            raise ValueError("The latest 30 records are not consecutive calendar days.")
        if df[REQUIRED[1:]].isna().any().any():
            raise ValueError("Missing environmental measurements in the 30-day window.")
        if (df.rainfall < 0).any() or not df.tmean.between(-10, 60).all():
            raise ValueError("Invalid rainfall or temperature.")
        if not df.rh.between(0,100).all() or not df.wind_speed.between(0,75).all():
            raise ValueError("Invalid humidity or wind speed.")
        return df

    def predict(self, records):
        df = self._prepare(records)
        X = df[["rainfall","tmean","rh","wind_speed"]].to_numpy(dtype=float)
        X_lr = self.lr_scaler.transform(X).reshape(1, 120)
        lr_prob = float(self.lr.predict_proba(X_lr)[0,1])
        lr_thr = float(self.config["lr_threshold"])
        result = {
            "status": "ok",
            "window_start": df.date.iloc[0].date().isoformat(),
            "window_end": df.date.iloc[-1].date().isoformat(),
            "applies_to_month": (df.date.iloc[-1] + pd.Timedelta(days=1)).replace(day=1).date().isoformat(),
            "logistic_regression": {
                "probability_high": round(lr_prob, 6),
                "threshold": lr_thr,
                "risk": "HIGH" if lr_prob >= lr_thr else "LOW"
            }
        }
        if self.lstm is not None:
            X_lstm = self.lstm_scaler.transform(X).reshape(1,30,4)
            lstm_prob = float(self.lstm.predict(X_lstm, verbose=0)[0,0])
            lstm_thr = float(self.config["lstm_threshold"])
            result["lstm"] = {
                "probability_high": round(lstm_prob, 6),
                "threshold": lstm_thr,
                "risk": "HIGH" if lstm_prob >= lstm_thr else "LOW"
            }
        else:
            result["lstm"] = {"status":"not_loaded"}
        return result
