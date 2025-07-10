import os
import subprocess
import logging

# Virtual environment location and cuckoo CLI path
CUCKOO_DIR = os.path.expanduser("~/cuckoo3")
CUCKOO_VENV_PATH = os.path.join(CUCKOO_DIR, "venv", "bin", "cuckoo")

# Logging configuration
LOG_DIR = "/home/cuckoo/TA_AnalisisMalware/Logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "submission_log.txt")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_submission(status, file_path, message=""):
    logging.info(f"{status.upper()} - {file_path} - {message}")

def submit_to_cuckoo(file_path):
    """Submit file to Cuckoo. Returns (True, message) if successful, (False, error) if failed."""

    if not os.path.exists(file_path):
        msg = "❌ File not found."
        log_submission("error", file_path, msg)
        return False, msg

    if os.path.getsize(file_path) < 133:
        msg = "❌ File is too small (<133 bytes)."
        log_submission("error", file_path, msg)
        return False, msg

    if not os.path.exists(CUCKOO_VENV_PATH):
        msg = "❌ Cuckoo CLI not found in the virtual environment."
        log_submission("error", file_path, msg)
        return False, msg

    try:
        bash_command = f"""
        cd "{CUCKOO_DIR}" && \
        source venv/bin/activate && \
        cuckoo submit "{file_path}"
        """
        subprocess.run(
            bash_command,
            shell=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            executable="/bin/bash"
        )

        log_submission("submitted", file_path, "Successfully submitted to Cuckoo.")
        return True, "✅ File successfully submitted to sandbox."

    except subprocess.CalledProcessError as e:
        msg = "❌ Failed to submit file to Cuckoo (process error)."
        log_submission("error", file_path, f"Subprocess error: {e}")
        return False, msg

    except Exception as e:
        msg = f"❌ Failed to submit file: {e}"
        log_submission("error", file_path, f"Exception: {e}")
        return False, msg
