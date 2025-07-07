import os
import subprocess
import time

# Konstanta konfigurasi
CUCKOO_DIR = os.path.expanduser("~/cuckoo3")
SETUP_DONE_FLAG = "/tmp/setup_vmcloak_bridge_done.flag"

def stop_existing_cuckoo():
    """Mencari dan menghentikan semua proses cuckoo yang mungkin sedang berjalan."""
    print("🛑 Menghentikan proses Cuckoo dari sesi sebelumnya (jika ada)...")
    
    # Menggunakan pkill untuk menghentikan proses berdasarkan nama commandnya.
    # Opsi -f mencocokkan dengan seluruh argumen command line, membuatnya lebih akurat.
    # Tidak akan ada error jika proses tidak ditemukan, jadi ini aman dijalankan.
    subprocess.run(["pkill", "-f", "cuckoo -d"], capture_output=True)
    subprocess.run(["pkill", "-f", "cuckoo web"], capture_output=True)
    
    # Beri waktu jeda agar sistem operasi bisa membersihkan proses sepenuhnya.
    time.sleep(2)
    print("✅ Proses lama berhasil dihentikan.\n")


def setup_vmcloak_bridge():
    """Mengatur bridge VMcloak jika belum dilakukan sebelumnya."""
    if os.path.exists(SETUP_DONE_FLAG):
        print("✅ Bridge sudah disiapkan sebelumnya.")
        return

    print("🔧 Menyiapkan bridge VMcloak (input password di terminal ini jika diminta)...")
    
    bridge_cmd = f"""
echo '[🔐] Masukkan password untuk setup bridge VMcloak'; \
sudo /home/cuckoo/vmcloak/bin/vmcloak-qemubridge br0 192.168.30.1/24 && \
sudo mkdir -p /etc/qemu/ && echo 'allow br0' | sudo tee /etc/qemu/bridge.conf > /dev/null && \
sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper && \
sudo mkdir -p /mnt/win10x64 && sudo mount -o loop,ro /home/cuckoo/win10x64.iso /mnt/win10x64 && \
sudo adduser cuckoo kvm && sudo chmod 666 /dev/kvm && \
touch {SETUP_DONE_FLAG}
"""

    # Jalankan langsung di shell, tanpa membuka terminal baru
    subprocess.run(bridge_cmd, shell=True, executable="/bin/bash")

    # Verifikasi bahwa flag sudah dibuat
    while not os.path.exists(SETUP_DONE_FLAG):
        print("⏳ Menunggu bridge selesai disiapkan...")
        time.sleep(2)


def execute_bash_command(description, command):
    """Menjalankan perintah bash dengan deskripsi."""
    print(f"🚀 {description}...")
    # Menggunakan Popen agar tidak memblokir, karena kita menjalankan dengan '&'
    subprocess.Popen(command, shell=True, executable="/bin/bash")


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
    # LANGKAH 1: Selalu hentikan Cuckoo yang lama terlebih dahulu.
    stop_existing_cuckoo()
    
    # LANGKAH 2: Lakukan setup seperti biasa.
    setup_vmcloak_bridge()
    print("✅ Setup bridge selesai. Melanjutkan ke proses berikutnya...\n")
    
    # LANGKAH 3: Jalankan Cuckoo yang baru.
    start_cuckoo_engine()
    print("⏳ Memberi waktu 5 detik bagi engine untuk siap...")
    time.sleep(5)
    
    start_cuckoo_web()
    time.sleep(2) # Sedikit jeda setelah web dijalankan

    print("\n🎉 Cuckoo berhasil di-restart dan siap digunakan.")


if __name__ == "__main__":
    main()
