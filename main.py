# main.py

import sys
from PyQt5.QtWidgets import QApplication
from gui import IPScannerGUI

def main():
    app = QApplication(sys.argv)
    gui = IPScannerGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
