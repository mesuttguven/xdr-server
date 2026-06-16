"""
XDR Client Agent v1.0
─────────────────────────────────────────────────────────────────────────────
Monitors Downloads, Desktop and Temp folders for new executable files.
Sends each file to the XDR Server for analysis (Layer 0 + Layer 1 static).
Takes action based on verdict and confidence score:

  Score > 85%  (MALICIOUS)  → Auto-quarantine + analyst notification
  Score 50-85% (SUSPICIOUS) → Quarantine + analyst notification (awaits review)
  Score < 50%  (BENIGN)     → Allow + log

Quarantine = move file to C:\\XDR_Quarantine\\ and prevent execution.
The file is NEVER deleted automatically — analyst decides final action.

Usage:
    python agent.py                    # uses config.json
    python agent.py --server 192.168.1.10
    python agent.py --setup            # interactive first-run setup
"""

import os
import sys
import json
import time
import shutil
import hashlib
import logging
import argparse
import threading
import subprocess
from datetime import datetime
from pathlib import Path

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Optional: Windows toast notifications ────────────────────────────────────
try:
    from plyer import notification
    NOTIFY_AVAILABLE = True
except ImportError:
    NOTIFY_AVAILABLE = False

# ── Optional: Windows-specific process kill ──────────────────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "server_url":              "http://192.168.1.100:8000",
    "model":                   "ensemble",
    "quarantine_dir":          "C:\\XDR_Quarantine",
    "log_file":                "C:\\XDR_Agent\\agent.log",
    "auto_quarantine_threshold": 0.50,   # quarantine anything ≥ 50%
    "auto_delete_threshold":     0.85,   # flag for immediate action ≥ 85%
    "scan_on_startup":           True,   # scan existing files at start
    "monitored_extensions": [
        ".exe", ".dll", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".jar", ".msi", ".scr"
    ],
    "monitored_folders": [
        "Downloads",
        "Desktop",
        "AppData\\Local\\Temp"
    ],
    "excluded_hashes": [],               # analyst-approved safe hashes
    "api_timeout_seconds": 120,
    "retry_attempts": 2,
}

CONFIG_PATH = Path("C:\\XDR_Agent\\config.json")
LOG_DIR     = Path("C:\\XDR_Agent")

# ─────────────────────────────────────────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    """Load config from file, fall back to defaults."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r") as f:
                cfg = json.load(f)
            # Merge with defaults to handle new keys
            merged = {**DEFAULT_CONFIG, **cfg}
            return merged
        except Exception as e:
            print(f"[WARN] Could not read config: {e} — using defaults")
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"Config saved to {CONFIG_PATH}")


def setup_logging(cfg: dict):
    log_path = Path(cfg["log_file"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ]
    )


def interactive_setup():
    """First-run interactive configuration."""
    print("\n" + "="*60)
    print("  XDR AGENT — FIRST RUN SETUP")
    print("="*60)

    cfg = DEFAULT_CONFIG.copy()

    server = input(f"\nXDR Server IP/URL [{cfg['server_url']}]: ").strip()
    if server:
        if not server.startswith("http"):
            server = f"http://{server}:8000"
        cfg["server_url"] = server

    qdir = input(f"Quarantine folder [{cfg['quarantine_dir']}]: ").strip()
    if qdir:
        cfg["quarantine_dir"] = qdir

    print(f"\nThresholds:")
    print(f"  Quarantine if score ≥ {cfg['auto_quarantine_threshold']*100:.0f}%")
    print(f"  Auto-flag if score ≥ {cfg['auto_delete_threshold']*100:.0f}%")
    change = input("Change thresholds? (y/N): ").strip().lower()
    if change == 'y':
        try:
            q = float(input("  Quarantine threshold (0-1) [0.50]: ") or 0.50)
            d = float(input("  Auto-flag threshold (0-1) [0.85]: ") or 0.85)
            cfg["auto_quarantine_threshold"] = q
            cfg["auto_delete_threshold"] = d
        except ValueError:
            print("  Invalid input, keeping defaults.")

    save_config(cfg)
    print("\nSetup complete! Run 'python agent.py' to start monitoring.")
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# CORE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def compute_sha256(filepath: str) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return ""


def kill_process_using_file(filepath: str):
    """
    Kill any running process that opened the given file.
    Prevents malware from executing while we quarantine it.
    """
    if not PSUTIL_AVAILABLE:
        return
    filepath_lower = filepath.lower()
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.info['exe'] and proc.info['exe'].lower() == filepath_lower:
                logging.warning(f"[AGENT] Killing process PID {proc.pid} ({proc.info['name']}) using {filepath}")
                proc.kill()
                time.sleep(0.5)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def quarantine_file(filepath: str, cfg: dict, verdict: str, score: float) -> bool:
    """
    Move file to quarantine directory.
    Renames with timestamp + verdict so analyst can identify it.
    Returns True if successful.
    """
    try:
        qdir = Path(cfg["quarantine_dir"])
        qdir.mkdir(parents=True, exist_ok=True)

        filename   = Path(filepath).name
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        score_pct  = int(score * 100)
        new_name   = f"[{verdict.upper()}_{score_pct}%]_{timestamp}_{filename}.quarantine"
        dest       = qdir / new_name

        # Kill any running instance first
        kill_process_using_file(filepath)
        time.sleep(0.3)

        shutil.move(filepath, str(dest))
        logging.warning(f"[QUARANTINE] {filename} → {dest}")

        # Write metadata file alongside
        meta = {
            "original_path": filepath,
            "quarantine_path": str(dest),
            "verdict": verdict,
            "score": score,
            "timestamp": timestamp,
            "status": "quarantined"
        }
        with open(str(dest) + ".meta.json", "w") as mf:
            json.dump(meta, mf, indent=2)

        return True

    except Exception as e:
        logging.error(f"[AGENT] Quarantine failed for {filepath}: {e}")
        return False


def send_notification(title: str, message: str, urgent: bool = False):
    """Send Windows toast notification."""
    if NOTIFY_AVAILABLE:
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="XDR Agent",
                timeout=10 if urgent else 5
            )
        except Exception:
            pass
    # Always log regardless
    logging.info(f"[NOTIFY] {title}: {message}")


def analyze_file(filepath: str, cfg: dict) -> dict:
    """
    Send file to XDR Server for analysis.
    Returns result dict or None on failure.
    """
    server_url = cfg["server_url"].rstrip("/")
    timeout    = cfg.get("api_timeout_seconds", 120)
    retries    = cfg.get("retry_attempts", 2)

    for attempt in range(retries):
        try:
            with open(filepath, "rb") as f:
                files = {"file": (Path(filepath).name, f, "application/octet-stream")}
                data  = {"model_name": cfg.get("model", "ensemble")}
                resp  = requests.post(
                    f"{server_url}/api/analyze",
                    files=files,
                    data=data,
                    timeout=timeout
                )
            if resp.status_code == 200:
                return resp.json()
            else:
                logging.warning(f"[AGENT] Server returned {resp.status_code} (attempt {attempt+1})")
        except requests.exceptions.ConnectionError:
            logging.error(f"[AGENT] Cannot reach server at {server_url}")
        except requests.exceptions.Timeout:
            logging.error(f"[AGENT] Request timed out after {timeout}s (attempt {attempt+1})")
        except Exception as e:
            logging.error(f"[AGENT] Request error: {e}")

        if attempt < retries - 1:
            time.sleep(3)

    return None


def process_file(filepath: str, cfg: dict):
    """
    Main processing pipeline for a detected file.
    Layer 0+1 analysis → tiered response.
    """
    filename = Path(filepath).name

    # Skip if already quarantined
    if ".quarantine" in filepath:
        return

    # Skip excluded extensions
    ext = Path(filepath).suffix.lower()
    if ext not in cfg.get("monitored_extensions", [".exe"]):
        return

    # Wait for file to finish writing
    time.sleep(1.5)
    if not os.path.exists(filepath):
        return

    # Compute hash
    sha256 = compute_sha256(filepath)
    if not sha256:
        logging.warning(f"[AGENT] Could not hash {filename}")
        return

    # Skip analyst-approved safe hashes
    if sha256 in cfg.get("excluded_hashes", []):
        logging.info(f"[AGENT] SKIPPED (approved hash): {filename}")
        return

    logging.info(f"[AGENT] Analyzing: {filename} ({sha256[:12]}...)")

    # Send to XDR Server
    result = analyze_file(filepath, cfg)

    if result is None:
        logging.error(f"[AGENT] Analysis failed for {filename} — file left in place")
        send_notification(
            "⚠️ XDR Agent — Analysis Failed",
            f"Could not analyze {filename}. Check server connection.",
            urgent=True
        )
        return

    # Extract verdict info
    final   = result.get("final_verdict", {})
    verdict = final.get("verdict", "UNKNOWN").upper()
    risk    = final.get("risk_level", "UNKNOWN")
    conf    = final.get("confidence", 0)
    rec     = final.get("recommendation", "")

    # Layer 1 score for threshold decisions
    layer1     = result.get("layer1", {})
    raw_score  = layer1.get("weighted_score") or layer1.get("score") or 0
    score      = float(raw_score) if raw_score else 0

    q_thresh = cfg.get("auto_quarantine_threshold", 0.50)
    d_thresh = cfg.get("auto_delete_threshold", 0.85)

    logging.info(f"[AGENT] Result: {verdict} | Risk: {risk} | Score: {score:.1%} | File: {filename}")

    # ── TIERED RESPONSE ────────────────────────────────────────────────────────

    if score >= q_thresh:
        # Quarantine the file
        quarantined = quarantine_file(filepath, cfg, verdict, score)

        if score >= d_thresh:
            # HIGH confidence malicious
            logging.warning(f"[AGENT] HIGH THREAT — AUTO-QUARANTINED: {filename} ({score:.1%})")
            send_notification(
                "☠️ XDR — MALICIOUS FILE QUARANTINED",
                f"{filename}\nScore: {score:.1%} | Risk: {risk}\n{rec}",
                urgent=True
            )
        else:
            # SUSPICIOUS — quarantined but needs analyst review
            logging.warning(f"[AGENT] SUSPICIOUS — QUARANTINED (analyst review needed): {filename} ({score:.1%})")
            send_notification(
                "⚠️ XDR — Suspicious File Quarantined",
                f"{filename}\nScore: {score:.1%}\nAwaiting analyst review.",
                urgent=True
            )

        if not quarantined:
            send_notification(
                "❌ XDR — Quarantine FAILED",
                f"Could not quarantine {filename}. Manual action required!",
                urgent=True
            )

    else:
        # Benign
        logging.info(f"[AGENT] BENIGN: {filename} ({score:.1%}) — allowed")


# ─────────────────────────────────────────────────────────────────────────────
# FILE SYSTEM WATCHER
# ─────────────────────────────────────────────────────────────────────────────

class XDREventHandler(FileSystemEventHandler):
    """Watchdog event handler — triggered on new or modified files."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._processing = set()
        self._lock = threading.Lock()

    def _should_process(self, filepath: str) -> bool:
        ext = Path(filepath).suffix.lower()
        return ext in self.cfg.get("monitored_extensions", [".exe"])

    def on_created(self, event):
        if event.is_directory:
            return
        filepath = event.src_path
        if not self._should_process(filepath):
            return
        with self._lock:
            if filepath in self._processing:
                return
            self._processing.add(filepath)
        try:
            logging.info(f"[WATCHER] New file detected: {Path(filepath).name}")
            threading.Thread(
                target=self._safe_process,
                args=(filepath,),
                daemon=True
            ).start()
        except Exception as e:
            logging.error(f"[WATCHER] Error handling {filepath}: {e}")

    def on_moved(self, event):
        """Also catch files moved/downloaded into monitored folders."""
        if event.is_directory:
            return
        filepath = event.dest_path
        if not self._should_process(filepath):
            return
        with self._lock:
            if filepath in self._processing:
                return
            self._processing.add(filepath)
        threading.Thread(
            target=self._safe_process,
            args=(filepath,),
            daemon=True
        ).start()

    def _safe_process(self, filepath: str):
        try:
            process_file(filepath, self.cfg)
        except Exception as e:
            logging.error(f"[AGENT] Unhandled error processing {filepath}: {e}")
        finally:
            with self._lock:
                self._processing.discard(filepath)


def get_monitored_paths(cfg: dict) -> list:
    """Build list of actual folder paths to monitor."""
    paths = []
    user_home = Path.home()

    folder_map = {
        "Downloads":            user_home / "Downloads",
        "Desktop":              user_home / "Desktop",
        "AppData\\Local\\Temp": user_home / "AppData" / "Local" / "Temp",
        "Temp":                 Path("C:\\Windows\\Temp"),
    }

    for folder in cfg.get("monitored_folders", ["Downloads", "Desktop"]):
        # Check if it's an absolute path
        p = Path(folder)
        if p.is_absolute():
            if p.exists():
                paths.append(str(p))
            else:
                logging.warning(f"[AGENT] Monitored folder not found: {folder}")
        else:
            mapped = folder_map.get(folder)
            if mapped and mapped.exists():
                paths.append(str(mapped))
            else:
                logging.warning(f"[AGENT] Monitored folder not found: {folder}")

    return paths


def scan_existing_files(cfg: dict):
    """On startup, scan existing files in monitored folders."""
    logging.info("[AGENT] Scanning existing files...")
    paths = get_monitored_paths(cfg)
    exts  = cfg.get("monitored_extensions", [".exe"])
    count = 0

    for folder in paths:
        for root, _, files in os.walk(folder):
            for fname in files:
                if Path(fname).suffix.lower() in exts:
                    fpath = os.path.join(root, fname)
                    logging.info(f"[STARTUP SCAN] {fname}")
                    threading.Thread(
                        target=process_file,
                        args=(fpath, cfg),
                        daemon=True
                    ).start()
                    count += 1
                    time.sleep(0.5)  # throttle

    logging.info(f"[AGENT] Startup scan queued {count} files.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def check_server(cfg: dict) -> bool:
    """Check if XDR server is reachable."""
    try:
        r = requests.get(f"{cfg['server_url'].rstrip('/')}/api/health", timeout=5)
        if r.status_code == 200:
            data = r.json()
            logging.info(f"[AGENT] Server OK — TF:{data.get('tensorflow')} | Models:{data.get('models_loaded')}")
            return True
    except Exception:
        pass
    logging.error(f"[AGENT] Cannot reach XDR server at {cfg['server_url']}")
    return False


def main():
    parser = argparse.ArgumentParser(description="XDR Client Agent")
    parser.add_argument("--setup",  action="store_true", help="Run interactive setup")
    parser.add_argument("--server", type=str, help="Override server URL")
    parser.add_argument("--model",  type=str, default="ensemble", help="Model to use")
    parser.add_argument("--noscan", action="store_true", help="Skip startup scan")
    args = parser.parse_args()

    if args.setup:
        cfg = interactive_setup()
    else:
        cfg = load_config()

    if args.server:
        url = args.server
        if not url.startswith("http"):
            url = f"http://{url}:8000"
        cfg["server_url"] = url

    if args.model:
        cfg["model"] = args.model

    # Create quarantine dir
    Path(cfg["quarantine_dir"]).mkdir(parents=True, exist_ok=True)

    setup_logging(cfg)

    logging.info("=" * 60)
    logging.info("  XDR CLIENT AGENT v1.0 — Starting")
    logging.info("=" * 60)
    logging.info(f"  Server:     {cfg['server_url']}")
    logging.info(f"  Model:      {cfg['model']}")
    logging.info(f"  Quarantine: {cfg['quarantine_dir']}")
    logging.info(f"  Q.Threshold:{cfg['auto_quarantine_threshold']*100:.0f}%  |  Flag:{cfg['auto_delete_threshold']*100:.0f}%")

    # Check server connectivity
    server_ok = check_server(cfg)
    if not server_ok:
        logging.warning("[AGENT] Server unreachable — monitoring will continue but analysis will fail until server is available")

    # Get folders to monitor
    monitored = get_monitored_paths(cfg)
    if not monitored:
        logging.error("[AGENT] No valid monitored folders found. Exiting.")
        sys.exit(1)

    for path in monitored:
        logging.info(f"  Monitoring: {path}")

    # Startup scan
    if cfg.get("scan_on_startup") and not args.noscan:
        threading.Thread(target=scan_existing_files, args=(cfg,), daemon=True).start()

    # Start file system watchers
    handler  = XDREventHandler(cfg)
    observer = Observer()

    for path in monitored:
        observer.schedule(handler, path, recursive=False)

    observer.start()
    logging.info("[AGENT] Monitoring active. Press Ctrl+C to stop.")
    send_notification("🛡️ XDR Agent Started", f"Monitoring {len(monitored)} folders.", urgent=False)

    try:
        while True:
            time.sleep(5)
            # Periodic server health check every 5 minutes
            if int(time.time()) % 300 < 5:
                check_server(cfg)
    except KeyboardInterrupt:
        logging.info("[AGENT] Stopping...")
        observer.stop()

    observer.join()
    logging.info("[AGENT] Stopped.")


if __name__ == "__main__":
    main()
