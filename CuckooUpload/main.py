import os                                        # Import modul OS untuk konfigurasi environment
os.environ["QT_QPA_PLATFORM"] = "xcb"           # Paksa PyQt5 pakai platform 'xcb' (X11), berguna di Linux

from ui import run_app                           # Import fungsi utama untuk menjalankan aplikasi dari modul ui

if __name__ == "__main__":                       # Cek apakah file ini dijalankan langsung
    run_app()                                    # Jalankan aplikasi desktop