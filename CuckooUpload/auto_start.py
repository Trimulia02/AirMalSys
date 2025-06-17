#!/usr/bin/env python3
import os
import subprocess
import time

CUCKOO_DIR = os.path.expanduser("~/cuckoo3")
SETUP_DONE_FLAG = "/tmp/setup_vmcloak_bridge_done.flag"
REPORT_GENERATOR_PATH = "/home/cuckoo/TA_AnalisisMalware/reportModule/report_generator.py"

def setup_vmcloak_bridge():
    if os.path.exists(SETUP_DONE_FLAG):
        print("✅ Bridge sudah disiapkan sebelumnya.")
        return

    print("🔧 Membuka terminal untuk setup bridge (input password)...")
    bridge_cmd = f"""
    echo '[🔐] Masukkan password untuk setup bridge VMcloak'; \
    sudo /home/cuckoo/vmcloak/bin/vmcloak-qemubridge br0 192.168.30.1/24 && \
    sudo mkdir -p /etc/qemu/ && echo 'allow br0' | sudo tee /etc/qemu/bridge.conf > /dev/null && \
    sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper && \
    sudo mkdir -p /mnt/win10x64 && sudo mount -o loop,ro /home/cuckoo/win10x64.iso /mnt/win10x64 && \
    sudo adduser cuckoo kvm && sudo chmod 666 /dev/kvm && \
    touch {SETUP_DONE_FLAG}
    """
    subprocess.Popen([
        "gnome-terminal", "--", "bash", "-c", bridge_cmd
    ])

    while not os.path.exists(SETUP_DONE_FLAG):
        print("⏳ Menunggu bridge selesai disiapkan...")
        time.sleep(2)

def kill_port_2042():
    try:
        subprocess.run(["fuser", "-k", "2042/tcp"], check=True, capture_output=True)
        print("⚠️ Port 2042 dibebaskan.")
    except subprocess.CalledProcessError:
        print("✅ Port 2042 sudah kosong.")

def kill_port_8000():
    """Mencari dan mematikan proses yang menggunakan port 8000."""
    try:
        subprocess.run(["fuser", "-k", "8000/tcp"], check=True, capture_output=True)
        print("⚠️ Port 8000 dibebaskan.")
    except subprocess.CalledProcessError:
        print("✅ Port 8000 sudah kosong.")

def start_cuckoo_engine():
    print("🚀 Menjalankan Cuckoo Engine...")
    command = f"""
    cd "{CUCKOO_DIR}" && \
    source venv/bin/activate && \
    echo '🧹 Membersihkan socket dan log lama...' && \
    rm -rf ~/.cuckoocwd/operational/sockets/* && \
    rm -rf ~/.cuckoocwd/log/* && \
    echo '⚙️  Menjalankan Cuckoo Engine...' && \
    cuckoo -d &
    """
    subprocess.call(command, shell=True, executable="/bin/bash")

def start_cuckoo_web():
    print("🌐 Menjalankan Cuckoo Web Interface...")
    command = f"""
    cd "{CUCKOO_DIR}" && \
    source venv/bin/activate && \
    echo '🌍 Menjalankan Web Interface...' && \
    cuckoo web --host 127.0.0.1 --port 8000 &
    """
    subprocess.call(command, shell=True, executable="/bin/bash")

def start_report_generator():
    print("📄 Menjalankan report_generator.py...")
    command = f"python3 {REPORT_GENERATOR_PATH} &"
    subprocess.call(command, shell=True, executable="/bin/bash")

def main():
    setup_vmcloak_bridge()

    # Tunggu setup selesai
    print("✅ Setup bridge selesai. Melanjutkan ke proses berikutnya...\n")
    
    # Membebaskan port yang dibutuhkan
    kill_port_2042()
    kill_port_8000()

    start_cuckoo_engine()
    time.sleep(5)  # beri jeda agar engine siap
    
    start_cuckoo_web()
    time.sleep(5)  # beri jeda agar web tidak crash
    
    start_report_generator()

if __name__ == "__main__":
    main()