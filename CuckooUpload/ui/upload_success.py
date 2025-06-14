from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QSizePolicy  # Komponen UI
from PyQt5.QtCore import Qt, QTimer              # Qt untuk alignment dan timer
from PyQt5.QtGui import QMovie                   # Untuk menampilkan animasi GIF
import os                                        # Untuk manipulasi path

class UploadSuccessWidget(QWidget):              # Widget yang muncul setelah file berhasil diunggah
    def __init__(self):
        super().__init__()

        self.setStyleSheet("background-color: #1e1e1e; color: white; font-size: 14px;")  # Warna latar & teks

        main_layout = QVBoxLayout()              # Layout vertikal utama
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        gif_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../assets/loading5.gif"))  # Path GIF
        self.gif_label = QLabel()                # Label untuk tampilan GIF
        self.gif_label.setFixedSize(220, 124)    # Ukuran tetap
        self.gif_label.setScaledContents(True)   # GIF menyesuaikan ukuran label
        self.gif_label.setStyleSheet("background: transparent; border: none;")  # Tanpa latar & border
        self.gif_label.setAlignment(Qt.AlignCenter)

        self.movie = QMovie(gif_path)            # Load GIF
        if os.path.exists(gif_path) and self.movie.isValid():  # Cek apakah GIF tersedia & valid
            self.gif_label.setMovie(self.movie)
            self.movie.start()
        else:
            self.gif_label.setText("✅ File berhasil diunggah")  # Alternatif jika GIF tidak tersedia

        gif_wrapper = QHBoxLayout()              # Bungkus GIF agar berada di tengah horizontal
        gif_wrapper.setAlignment(Qt.AlignCenter)
        gif_wrapper.addWidget(self.gif_label)

        main_layout.addLayout(gif_wrapper)       # Tambahkan wrapper ke layout utama

        self.text = QLabel("📤 File berhasil diunggah.\nMenyiapkan analisis...")  # Label status
        self.text.setAlignment(Qt.AlignCenter)
        self.text.setStyleSheet("font-size: 13px; color: #f0f0f0;")

        main_layout.addWidget(self.text)         # Tambahkan label ke layout
        self.setLayout(main_layout)              # Terapkan layout ke widget

        self.timer = QTimer(self)                # Timer untuk delay sebelum lanjut
        self.timer.setSingleShot(True)           # Timer hanya jalan sekali
        self.timer.timeout.connect(self.go_to_analysis)  # Setelah timeout → lanjut ke analisis

    def showEvent(self, event):                  # Dipanggil saat widget ditampilkan
        self.timer.start(3200)                   # Timer mulai saat muncul (3.2 detik)
        super().showEvent(event)                 # Jalankan fungsi bawaan juga

    def go_to_analysis(self):                    # Fungsi untuk ganti ke halaman analisis
        window = self.window()                   # Ambil window utama
        if hasattr(window, "switch_to_analysis_progress"):  # Pastikan ada fungsi tersebut
            window.switch_to_analysis_progress() # Panggil fungsi untuk ganti tampilan