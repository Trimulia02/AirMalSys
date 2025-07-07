from PyQt5.QtWidgets import (                      # Import komponen UI dari PyQt5
    QWidget, QVBoxLayout, QLabel, QSpacerItem,
    QSizePolicy, QHBoxLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal   # Import core PyQt seperti thread dan sinyal
from PyQt5.QtGui import QMovie                     # Untuk menampilkan animasi GIF
import subprocess                                  # Untuk menjalankan script eksternal
import os                                          # Untuk path dan file handling

class SetupThread(QThread):                        # Thread khusus untuk menjalankan auto_start.py
    finished = pyqtSignal()                        # Sinyal yang dikirim saat thread selesai

    def run(self):                                 # Fungsi yang akan dijalankan saat thread mulai
        print("🛠️ [SetupThread] Menjalankan auto_start.py")
        subprocess.call(["python3", "auto_start.py"])   # Jalankan script setup
        print("✅ [SetupThread] Selesai")
        self.finished.emit()                       # Kirim sinyal bahwa proses selesai

class LoadingWidget(QWidget):                      # Widget untuk tampilan loading saat setup
    def __init__(self):
        super().__init__()
        self.setFixedSize(400, 320)                # Ukuran tetap
        self.setStyleSheet("background-color: #1e1e1e; color: white;")  # Gaya tampilan

        layout = QVBoxLayout()                     # Layout utama vertikal
        layout.setAlignment(Qt.AlignCenter)

        layout.addSpacerItem(QSpacerItem(20, 30, QSizePolicy.Minimum, QSizePolicy.Expanding))  # Spacer atas

        gif_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../assets/loading1.gif"))  # Path ke GIF
        self.loading_gif = QLabel()                # Label untuk tampilan GIF
        self.movie = QMovie(gif_path)              # Load GIF

        if not self.movie.isValid():               # Kalau GIF gagal dimuat
            self.loading_gif.setText("❌ Gagal memuat GIF!")
        else:
            self.loading_gif.setMovie(self.movie)  # Set GIF ke label
            self.loading_gif.setFixedSize(120, 120)  # Ukuran GIF
            self.loading_gif.setScaledContents(True) # Otomatis sesuaikan ukuran
            self.movie.start()                     # Mulai animasi GIF

            gif_and_label_layout = QVBoxLayout()   # Layout vertikal untuk GIF dan teks
            gif_and_label_layout.setAlignment(Qt.AlignHCenter)

            self.label = QLabel("🔧 Setting Up System...\nPlease Wait...")  # Teks status
            self.label.setAlignment(Qt.AlignHCenter)

            gif_and_label_layout.addWidget(self.loading_gif, alignment=Qt.AlignHCenter)  # Tambah GIF
            gif_and_label_layout.addWidget(self.label, alignment=Qt.AlignHCenter)        # Tambah teks

            gif_container = QHBoxLayout()           # Layout horizontal untuk memosisikan GIF ke kiri
            gif_container.setAlignment(Qt.AlignLeft)
            gif_container.addSpacing(60)            # Spasi kiri
            gif_container.addLayout(gif_and_label_layout)  # Tambah layout vertikal ke dalam horizontal

            layout.addLayout(gif_container)         # Tambah ke layout utama

        layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))  # Spacer bawah

        self.setLayout(layout)                      # Set layout utama ke widget