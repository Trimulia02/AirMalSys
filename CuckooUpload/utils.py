import subprocess                                     # Untuk menjalankan perintah sistem

def notify(title, message):                           # Fungsi untuk kirim notifikasi desktop di Linux
    """Mengirim notifikasi desktop (Linux) menggunakan notify-send."""
    try:
        subprocess.run(["notify-send", title, message])  # Jalankan perintah notify-send
    except Exception as e:
        print(f"[Notifikasi Gagal] {e}")               # Cetak pesan error jika gagal kirim notifikasi