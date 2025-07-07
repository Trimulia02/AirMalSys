import os
import sys
from ui import run_app

os.environ["QT_QPA_PLATFORM"] = "xcb"

if __name__ == "__main__":
    run_app()