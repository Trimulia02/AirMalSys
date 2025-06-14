import os
import subprocess
import shutil
import logging

# ─── Konfigurasi Path ─────────────────────────────────────────────────────────
CUCKOO_DIR = os.path.expanduser("~/cuckoo3")  # Lokasi root Cuckoo
CUCKOO_VENV_PATH = os.path.join(CUCKOO_DIR, "venv", "bin", "cuckoo")
ACCEPTED_FOLDER = os.path.join(CUCKOO_DIR, "Sample-Malware")

# ─── Logging ke Folder Logs ───────────────────────────────────────────────────
LOG_DIR = "/home/cuckoo/TA_AnalisisMalware/Logs"
os.makedirs(LOG_DIR, exist_ok=True)  # Pastikan direktori Logs ada
LOG_FILE = os.path.join(LOG_DIR, "submission_log.txt")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_submission(status, file_path, message=""):
    logging.info(f"{status.upper()} - {file_path} - {message}")

# ─── Fungsi Submit ke Cuckoo ──────────────────────────────────────────────────
def submit_to_cuckoo(file_path, status_label, progress_bar):
    if not os.path.exists(file_path):
        status_label.setText("❌ File tidak ditemukan.")
        status_label.setStyleSheet("color: #ff4444;")
        log_submission("error", file_path, "File tidak ditemukan.")
        return

    if os.path.getsize(file_path) == 0:
        status_label.setText("❌ File kosong.")
        status_label.setStyleSheet("color: #ff4444;")
        log_submission("error", file_path, "File kosong.")
        return

    if not os.path.exists(CUCKOO_VENV_PATH):
        status_label.setText("❌ Cuckoo CLI tidak ditemukan di virtual environment.")
        status_label.setStyleSheet("color: #ff4444;")
        log_submission("error", file_path, "Cuckoo CLI tidak ditemukan.")
        return

    filename = os.path.basename(file_path)
    if not file_path.startswith(ACCEPTED_FOLDER):
        dst_path = os.path.join(ACCEPTED_FOLDER, filename)
        try:
            shutil.copy(file_path, dst_path)
            file_path = dst_path
            log_submission("copied", file_path, "File disalin ke Sample-Malware.")
        except Exception as e:
            status_label.setText(f"❌ Gagal menyalin file: {e}")
            status_label.setStyleSheet("color: #ff4444;")
            log_submission("error", file_path, f"Gagal salin: {e}")
            return

    # Status awal UI
    status_label.setText("📤 Mengirim file ke sandbox...")
    status_label.setStyleSheet("color: #ffaa00;")
    progress_bar.setValue(40)

    try:
        # Jalankan perintah submit menggunakan virtualenv
        bash_command = f"""
        cd "{CUCKOO_DIR}" && \
        source venv/bin/activate && \
        cuckoo submit "{file_path}"
        """
        subprocess.Popen(
            bash_command,
            shell=True,
            executable="/bin/bash"
        )

        progress_bar.setValue(100)
        status_label.setText("✅ File berhasil dikirim ke sandbox.")
        status_label.setStyleSheet("color: #00ff99;")
        log_submission("submitted", file_path, "Dikirim via subprocess Popen.")
    except Exception as e:
        status_label.setText(f"❌ Gagal mengirim file: {e}")
        status_label.setStyleSheet("color: #ff4444;")
        log_submission("error", file_path, f"Exception saat submit: {e}")