import os
import sys

os.environ["QT_QPA_PLATFORM"] = "wayland"

from ui import run_app

if __name__ == "__main__":
    run_app()