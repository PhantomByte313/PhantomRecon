#!/usr/bin/env python3
"""
◈ Phantom Recon — Advanced Network Reconnaissance Tool
Entry point
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QFont
        app = QApplication(sys.argv)
        app.setApplicationName("Phantom Recon")
        app.setFont(QFont("Segoe UI", 10))
        from ui.app import PhantomRecon
        win = PhantomRecon()
        win.show()
        sys.exit(app.exec())
    except ImportError as e:
        print(f"[ERROR] Missing dependency: {e}")
        print("Install: pip install -r requirements.txt")
        sys.exit(1)

if __name__ == "__main__":
    main()
