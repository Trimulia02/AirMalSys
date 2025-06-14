import subprocess
import os
import time

CUCKOO_DIR = os.path.expanduser("~/cuckoo3")
SETUP_DONE_FLAG = "/tmp/setup_vmcloak_bridge_done.flag"
REPORT_GENERATOR_PATH = "/home/cuckoo/TA_AnalisisMalware/reportModule/report_generator.py"

def open_terminal_for_su_tak():
    if os.path.exists(SETUP_DONE_FLAG):
        print("✅ Setup bridge sudah pernah dilakukan.")
        return

    print("🔐 Membuka terminal untuk setup bridge (login sebagai tak)...")
    command_script = f"""
echo "🔐 Menjalankan setup bridge..."
su - tak -c 'cd ~ && ./setup_vmcloak_bridge.sh && touch {SETUP_DONE_FLAG}'
"""
    subprocess.run([
        "gnome-terminal", "--", "bash", "-c", command_script
    ])

    while not os.path.exists(SETUP_DONE_FLAG):
        print("⏳ Menunggu setup selesai...")
        time.sleep(1)

def kill_port_2042():
    try:
        subprocess.run(["fuser", "-k", "2042/tcp"], check=True)
        print("⚠️ Port 2042 ditutup untuk menghindari konflik.")
    except subprocess.CalledProcessError:
        print("✅ Port 2042 tidak aktif, aman.")

def open_cuckoo_background():
    kill_port_2042()
    command = f"""
cd "{CUCKOO_DIR}" && \
source venv/bin/activate && \
echo "🧹 Membersihkan socket dan log lama..." && \
rm -rf ~/.cuckoocwd/operational/sockets/* && \
rm -rf ~/.cuckoocwd/log/* && \
echo "🚀 Menjalankan Cuckoo..." && \
cuckoo -d
"""
    subprocess.Popen(command, shell=True, executable="/bin/bash")
    print("🚀 Cuckoo dijalankan di background.")

def start_report_generator():
    print("📄 Memulai report_generator.py...")
    subprocess.Popen([
        "gnome-terminal", "--", "bash", "-c",
        f"python3 {REPORT_GENERATOR_PATH}; exec bash"
    ])

def main():
    open_terminal_for_su_tak()
    open_cuckoo_background()
    time.sleep(10)  # tunggu Cuckoo siap
    start_report_generator()

if __name__ == "__main__":
    main()