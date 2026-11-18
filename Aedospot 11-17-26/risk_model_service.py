import importlib.abc
import importlib.machinery
import os
import sys
import threading
import time
import traceback
import types

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ai_model')
WINDOW_DAYS = 30
RETRY_AFTER_SECONDS = 60          # a failed load is retried after this long (no restart needed once fixed)
REQUIRED_FILES = ('prediction.py', 'model_config.json', 'aedospot_logreg.joblib', 'logreg_scaler.joblib')

_predictor = None
_load_error = None
_load_failed_at = 0.0
_tensorflow_real = None           # None = not checked yet, True/False after the first load attempt
_lock = threading.Lock()


# ── TensorFlow stub ─────────────────────────────────────────────────────────────────────
# prediction.py imports tensorflow at the top. Without TensorFlow (e.g. Python 3.14 has no
# TensorFlow build yet) that import would make even the Logistic Regression fail to load.
# This stub accepts ANY `import tensorflow...` / `from tensorflow.keras.models import load_model`,
# and only raises when something is actually CALLED, which is caught below so that the app
# keeps running on Logistic Regression only.
class _UnavailableMeta(type):
    def __getattr__(cls, name):
        if name.startswith('__'):
            raise AttributeError(name)
        return _Unavailable


class _Unavailable(metaclass=_UnavailableMeta):
    def __init__(self, *args, **kwargs):
        raise RuntimeError('TensorFlow is not installed in this Python environment.')


class _TfStubModule(types.ModuleType):
    __path__ = []

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
        return _Unavailable


class _TfStubFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path, target=None):
        if fullname == 'tensorflow' or fullname.startswith('tensorflow.'):
            return importlib.machinery.ModuleSpec(fullname, self, is_package=True)
        return None

    def create_module(self, spec):
        return _TfStubModule(spec.name)

    def exec_module(self, module):
        module.__path__ = []


def _ensure_tensorflow_or_stub():
    """Uses the real TensorFlow when it imports; otherwise installs the stub. Returns True if real."""
    try:
        import tensorflow  # noqa: F401
        return True
    except Exception as e:
        print(f"⚠️ TensorFlow is not available ({type(e).__name__}: {e}). "
              f"Running Python {sys.version_info.major}.{sys.version_info.minor}. The LSTM needs TensorFlow installed on a "
              f"Python version it supports (check tensorflow.org/install). Logistic Regression still works.")
        for name in [n for n in sys.modules if n == 'tensorflow' or n.startswith('tensorflow.')]:
            del sys.modules[name]                 # drop half-imported leftovers
        if not any(isinstance(f, _TfStubFinder) for f in sys.meta_path):
            sys.meta_path.append(_TfStubFinder())
        return False


def _missing_files():
    if not os.path.isdir(MODEL_DIR):
        return [f"folder '{MODEL_DIR}'"]
    return [f for f in REQUIRED_FILES if not os.path.exists(os.path.join(MODEL_DIR, f))]


def _get_predictor():
    """Loads the models ONCE, then reuses them. A failed load is retried every RETRY_AFTER_SECONDS."""
    global _predictor, _load_error, _load_failed_at, _tensorflow_real
    if _predictor is not None:
        return _predictor
    if _load_error is not None and (time.time() - _load_failed_at) < RETRY_AFTER_SECONDS:
        return None
    with _lock:
        if _predictor is not None:
            return _predictor
        if _load_error is not None and (time.time() - _load_failed_at) < RETRY_AFTER_SECONDS:
            return None
        _load_error = None
        try:
            missing = _missing_files()
            if missing:
                raise FileNotFoundError('Missing in ai_model/: ' + ', '.join(missing))
            if MODEL_DIR not in sys.path:
                sys.path.insert(0, MODEL_DIR)
            _tensorflow_real = _ensure_tensorflow_or_stub()
            from prediction import AedospotPredictor  # type: ignore[import-not-found]  (lives in ai_model/, added to sys.path above)
            try:
                _predictor = AedospotPredictor(model_dir=MODEL_DIR, load_lstm=_tensorflow_real)
                if not _tensorflow_real:
                    print("ℹ️ Running on Logistic Regression only (no TensorFlow).")
            except Exception as lstm_err:
                # TensorFlow incompatible / LSTM file unreadable: keep Logistic Regression working.
                print(f"⚠️ LSTM could not be loaded ({type(lstm_err).__name__}: {lstm_err}); using Logistic Regression only.")
                _predictor = AedospotPredictor(model_dir=MODEL_DIR, load_lstm=False)
        except Exception as e:
            _load_error = f"{type(e).__name__}: {e}"
            _load_failed_at = time.time()
            print(f"❌ AI model could not be loaded: {_load_error}")
            traceback.print_exc()
    return _predictor


def predict_from_daily_rows(rows):
    """
    rows: daily rows (dicts) from load_device_daily_rows(), any order, with
          reading_date, temperature, humidity, rainfall_mm, wind_speed.
    Returns a JSON-friendly dict. Never raises.
    """
    predictor = _get_predictor()
    if predictor is None:
        return {'status': 'model_unavailable', 'message': _load_error or 'Model not loaded.'}

    records = [{
        'date': str(r['reading_date'])[:10],
        'rainfall': r['rainfall_mm'],
        'tmean': r['temperature'],
        'rh': r['humidity'],
        'wind_speed': r['wind_speed'],
    } for r in rows]
    records.sort(key=lambda r: r['date'])         # oldest -> newest, whatever order the rows came in

    if len(records) < WINDOW_DAYS:
        return {'status': 'insufficient_data', 'days_available': len(records), 'days_required': WINDOW_DAYS,
                'message': f'Need {WINDOW_DAYS} consecutive daily readings, only {len(records)} found.'}
    try:
        result = predictor.predict(records)      # uses the latest 30 consecutive days
    except ValueError as e:                       # gaps, missing values, out-of-range values
        return {'status': 'insufficient_data', 'days_available': len(records), 'days_required': WINDOW_DAYS,
                'message': str(e)}
    except Exception as e:
        print(f"❌ AI model prediction failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        return {'status': 'error', 'message': f'Prediction failed: {type(e).__name__}: {e}'}
    return result