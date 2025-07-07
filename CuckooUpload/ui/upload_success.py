from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QMovie
import os

class UploadSuccessWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.setStyleSheet("background-color: #1e1e1e; color: white; font-size: 14px;")

        # Layout utama
        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # Label GIF animasi
        gif_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../assets/loading5.gif"))
        self.gif_label = QLabel()
        self.gif_label.setFixedSize(220, 124)
        self.gif_label.setScaledContents(True)
        self.gif_label.setStyleSheet("background: transparent; border: none;")
        self.gif_label.setAlignment(Qt.AlignCenter)

        self.movie = QMovie(gif_path)
        if os.path.exists(gif_path) and self.movie.isValid():
            self.gif_label.setMovie(self.movie)
            self.movie.start()
        else:
            self.gif_label.setText("✅ File Upload Successfully")

        gif_wrapper = QHBoxLayout()
        gif_wrapper.setAlignment(Qt.AlignCenter)
        gif_wrapper.addWidget(self.gif_label)
        main_layout.addLayout(gif_wrapper)

        # Teks status
        self.text = QLabel("📤 File Uploaded Succesfully\nStarting Analysis...")
        self.text.setAlignment(Qt.AlignCenter)
        self.text.setStyleSheet("font-size: 13px; color: #f0f0f0;")
        main_layout.addWidget(self.text)

        self.setLayout(main_layout)

        # Timer untuk transisi otomatis
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)

    def start_timer(self, on_proceed_callback):
        """Dipanggil dari MainWindow setelah UploadSuccessWidget selesai fade-in."""
        try:
            self.timer.stop()
            self.timer.timeout.disconnect()
        except Exception:
            pass  # Aman kalau belum pernah connect

        self.timer.timeout.connect(lambda: self._proceed(on_proceed_callback))
        self.timer.start(3200)

    def _proceed(self, on_proceed_callback):
        print("⏩ UploadSuccessWidget: Timer selesai, memanggil callback...")
        if on_proceed_callback:
            print("✅ Callback ditemukan. Menjalankan...")
            on_proceed_callback()
        else:
            print("⚠️ Tidak ada callback yang diberikan.")