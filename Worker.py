import threading
import time
from database import log_event

_worker_thread = None
_running = False

def worker_loop(delay):
    global _running
    log_event("Worker started successfully")

    while _running:
        log_event("Worker heartbeat running...")
        time.sleep(delay)

    log_event("Worker stopped")

def start_worker(delay):
    global _worker_thread, _running

    if _running:
        return

    _running = True
    _worker_thread = threading.Thread(target=worker_loop, args=(delay,), daemon=True)
    _worker_thread.start()

def stop_worker():
    global _running
    _running = False

def worker_status():
    return "Running" if _running else "Stopped"
