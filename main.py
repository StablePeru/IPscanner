import sys
from PyQt5.QtWidgets import QApplication
from gui.gui import IPScannerGUI
from utils.logger import setup_logger

def main():
    logger = setup_logger()
    logger.info("Aplicación iniciada.")
    app = QApplication(sys.argv)
    gui = IPScannerGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
