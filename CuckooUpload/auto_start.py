#!/usr/bin/env python3
"""
Cuckoo3 Automation Script
Mengatur bridge VMcloak, membebaskan port, dan menjalankan Cuckoo Engine & Web Interface
"""

import os
import subprocess
import time

# Konstanta konfigurasi
CUCKOO_DIR = os.path.expanduser("~/cuckoo3")
SETUP_DONE_FLAG = "/tmp/setup_vmcloak_bridge_done.flag"


def setup_vmcloak_bridge():
    """Mengatur bridge VMcloak jika belum dilakukan sebelumnya."""
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

    # Menunggu hingga setup selesai
    while not os.path.exists(SETUP_DONE_FLAG):
        print("⏳ Menunggu bridge selesai disiapkan...")
        time.sleep(2)


def kill_port(port_number):
    """Membebaskan port yang digunakan oleh proses lain."""
    try:
        subprocess.run(
            ["fuser", "-k", f"{port_number}/tcp"], 
            check=True, 
            capture_output=True
        )
        print(f"⚠️ Port {port_number} dibebaskan.")
    except subprocess.CalledProcessError:
        print(f"✅ Port {port_number} sudah kosong.")


def execute_bash_command(description, command):
    """Menjalankan perintah bash dengan deskripsi."""
    print(f"🚀 {description}...")
    subprocess.call(command, shell=True, executable="/bin/bash")


def start_cuckoo_engine():
    """Menjalankan Cuckoo Engine."""
    command = f"""
cd "{CUCKOO_DIR}" && \
source venv/bin/activate && \
echo '🧹 Membersihkan socket dan log lama...' && \
rm -rf ~/.cuckoocwd/operational/sockets/* && \
rm -rf ~/.cuckoocwd/log/* && \
echo '⚙️ Menjalankan Cuckoo Engine...' && \
cuckoo -d &
"""
    execute_bash_command("Menjalankan Cuckoo Engine", command)


def start_cuckoo_web():
    """Menjalankan Cuckoo Web Interface."""
    command = f"""
cd "{CUCKOO_DIR}" && \
source venv/bin/activate && \
echo '🌍 Menjalankan Web Interface...' && \
cuckoo web --host 127.0.0.1 --port 8000 &
"""
    execute_bash_command("Menjalankan Cuckoo Web Interface", command)


def main():
    """Fungsi utama untuk menjalankan seluruh proses otomatisasi."""
    setup_vmcloak_bridge()
    print("✅ Setup bridge selesai. Melanjutkan ke proses berikutnya...\n")
    
    kill_port(2042)
    kill_port(8000)
    
    start_cuckoo_engine()
    time.sleep(5)
    
    start_cuckoo_web()
    time.sleep(5)


if __name__ == "__main__":
    main()