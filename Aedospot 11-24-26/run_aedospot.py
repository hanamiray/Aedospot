
import os
import sys
import threading
import traceback

from waitress import serve

# Make sure the project directory is the working directory.
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_DIR)

# Import the existing Flask application and its startup functions.
import app as aedospot


def initialize_aedospot():
    """Initialize the existing database and application background services."""

    print("=" * 55)
    print("AEDOSPOT PRODUCTION STARTUP")
    print("=" * 55)

    # Initialize existing database tables and settings.
    print("\n[1/5] Initializing database...")
    aedospot.init_db()

    # Preserve the existing daily rainfall migration.
    print("\n[2/5] Checking daily rainfall records...")
    try:
        count = aedospot.migrate_daily_rainfall_to_total()
        print(f"Rainfall migration completed: {count} row(s).")
    except Exception as exc:
        print(f"Rainfall migration warning: {exc}")
        traceback.print_exc()

    # Preserve the existing LSTM confidence history update.
    print("\n[3/5] Updating LSTM confidence history...")
    try:
        count = aedospot.recompute_lstm_confidence_history()
        print(f"LSTM confidence history updated: {count} week(s).")
    except Exception as exc:
        print(f"LSTM history warning: {exc}")
        traceback.print_exc()

    # Start the existing risk monitoring loop once.
    print("\n[4/5] Starting risk monitor...")
    risk_thread = threading.Thread(
        target=aedospot.risk_monitor_loop,
        name="aedospot-risk-monitor",
        daemon=True
    )
    risk_thread.start()

    # Start the existing Arduino receiver once.
    print("\n[5/5] Starting sensor collection...")
    aedospot.start_aedospot_serial_receiver()

    # Start the existing daily processor loop once.
    daily_thread = threading.Thread(
        target=aedospot.aedospot_daily_processor_loop,
        name="aedospot-daily-processor",
        daemon=True
    )
    daily_thread.start()

    print("\nAll startup tasks have been launched.")


if __name__ == "__main__":

    # Do not run the Mini PC hardware services on Render.
    if os.getenv("RENDER"):
        raise RuntimeError(
            "This production startup script is intended for the local Windows Mini PC."
        )

    initialize_aedospot()

    print("\n" + "=" * 55)
    print("AEDOSPOT WEBSITE IS RUNNING")
    print("Server: http://127.0.0.1:5000")
    print("Web server: Waitress")
    print("=" * 55 + "\n")

    # Keep Flask accessible only locally.
    # Cloudflare Tunnel will forward public requests to this address.
    serve(
        aedospot.app,
        host="127.0.0.1",
        port=5000,
        threads=8
    )
