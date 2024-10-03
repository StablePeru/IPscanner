# gui.py

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QProgressBar,
    QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView, QDialog, QTextEdit
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QIcon
import sys
from scanner import Scanner
import csv
import openpyxl
import ipaddress
import re

class IPTableWidgetItem(QTableWidgetItem):
    def __init__(self, ip, *args, **kwargs):
        super().__init__(ip, *args, **kwargs)  # Establecer el texto del item
        try:
            self.ip = ipaddress.ip_address(ip)
        except ValueError:
            self.ip = None  # Manejar IPs inválidas si las hay

    def __lt__(self, other):
        if isinstance(other, IPTableWidgetItem):
            if self.ip and other.ip:
                return self.ip < other.ip
            return super().__lt__(other)
        return super().__lt__(other)

class Worker(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(dict)
    update_progress = pyqtSignal(int)
    stop_scan = False

    def __init__(self, target, ports):
        super().__init__()
        self.target = target
        self.ports = ports
        self.scanner = Scanner()

    def run_scan(self):
        hosts = self.scanner.scan_hosts(self.target, self.ports)
        total = len(hosts)
        for i, host in enumerate(hosts, 1):
            if self.stop_scan:
                break
            info = self.scanner.get_host_info(host)
            if info:
                self.progress.emit(info)
            self.update_progress.emit(int((i / total) * 100))
        self.finished.emit()

    def stop(self):
        self.stop_scan = True

class DetailDialog(QDialog):
    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Detalles de {data.get('ip', '')}")
        self.setGeometry(150, 150, 400, 300)
        layout = QVBoxLayout()

        details = f"""
        <b>IP:</b> {data.get('ip', '')}<br>
        <b>Hostname:</b> {data.get('hostname', 'Desconocido')}<br>
        <b>Estado:</b> {data.get('state', 'Desconocido')}<br>
        <b>Puertos Abiertos:</b> {', '.join([str(port) for port, details in data.get('ports', {}).items() if details['state'] == 'open']) or 'Ninguno'}<br>
        <b>Servicios:</b> {', '.join([details['service'] for port, details in data.get('ports', {}).items() if details['state'] == 'open']) or 'Ninguno'}<br>
        <b>Sistemas Operativos:</b> {', '.join([f"{os['name']} ({os['accuracy']}%)" for os in data.get('os', [])]) or 'Desconocido'}
        """
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setHtml(details)
        layout.addWidget(self.detail_text)

        self.setLayout(layout)

class IPScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("IP Scanner Profesional")
        self.setGeometry(100, 100, 1200, 700)  # Aumentamos el ancho para acomodar la tabla

        main_layout = QVBoxLayout()

        # Entrada de IP
        ip_layout = QHBoxLayout()
        ip_label = QLabel("Dirección IP / Rango:")
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Ejemplo: 192.168.1.1 o 192.168.1.1-254")
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_input)
        main_layout.addLayout(ip_layout)

        # Entrada de Puertos
        port_layout = QHBoxLayout()
        port_label = QLabel("Puertos (Ej: 22-80,443):")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Ejemplo: 22-80,443")
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        main_layout.addLayout(port_layout)

        # Botones
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Iniciar Escaneo")
        self.scan_button.clicked.connect(self.start_scan)
        self.export_button = QPushButton("Exportar Resultados")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)  # Deshabilitado inicialmente
        self.stop_button = QPushButton("Detener Escaneo")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)  # Deshabilitado inicialmente
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.export_button)
        main_layout.addLayout(button_layout)

        # Barra de Progreso
        self.progress_bar = QProgressBar()
        main_layout.addWidget(self.progress_bar)

        # Campo de Búsqueda
        search_layout = QHBoxLayout()
        search_label = QLabel("Buscar:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar por IP, Hostname, etc.")
        self.search_input.textChanged.connect(self.filter_table)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        main_layout.addLayout(search_layout)

        # Área de Resultados: QTableWidget
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels([
            "IP", "Hostname", "Estado", "Puertos Abiertos", "Servicios", "Sistemas Operativos"
        ])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.result_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.result_table.setSelectionMode(QTableWidget.SingleSelection)
        self.result_table.setSortingEnabled(True)
        self.result_table.cellDoubleClicked.connect(self.show_host_details)
        main_layout.addWidget(self.result_table)

        self.setLayout(main_layout)

        # Aplicar estilos desde el archivo .qss
        self.apply_styles()

    def apply_styles(self):
        try:
            with open("style.qss", "r") as f:
                with open("style.qss", "r", encoding="utf-8") as f:
                    self.setStyleSheet(f.read())
        except FileNotFoundError:
            QMessageBox.warning(self, "Archivo de Estilos No Encontrado", "El archivo style.qss no se encontró. La aplicación usará estilos predeterminados.")

    def start_scan(self):
        target = self.ip_input.text().strip()
        ports = self.port_input.text().strip()
        if not self.validate_ip_input(target):
            QMessageBox.warning(self, "Entrada Inválida", "Por favor, ingresa una dirección IP o rango válido.")
            return
        if ports and not self.validate_ports_input(ports):
            QMessageBox.warning(self, "Puertos Inválidos", "Por favor, ingresa puertos en un formato válido (Ej: 22-80,443).")
            return
        if not ports:
            ports = '22-443'  # Puertos por defecto

        self.scan_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.result_table.setRowCount(0)  # Limpiar la tabla
        self.progress_bar.setValue(0)

        # Configurar el worker en un QThread separado
        self.thread = QThread()
        self.worker = Worker(target, ports)
        self.worker.moveToThread(self.thread)

        # Conectar señales y slots
        self.thread.started.connect(self.worker.run_scan)
        self.worker.progress.connect(self.update_results)
        self.worker.update_progress.connect(self.update_progress_bar)
        self.worker.finished.connect(self.scan_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def update_results(self, data):
        """
        Añade una fila a la tabla con los datos del host escaneado.
        """
        # Depuración: Verificar los datos recibidos
        print(f"Datos recibidos: {data}")

        row_position = self.result_table.rowCount()
        self.result_table.insertRow(row_position)

        ip = data.get('ip', '')
        ip_item = IPTableWidgetItem(ip)
        hostname_item = QTableWidgetItem(data.get('hostname', 'Desconocido'))
        state_item = QTableWidgetItem(data.get('state', 'Desconocido'))

        # Puertos Abiertos
        ports = data.get('ports', {})
        open_ports = ', '.join([str(port) for port, details in ports.items() if details['state'] == 'open']) or 'Ninguno'
        ports_item = QTableWidgetItem(open_ports)

        # Servicios
        services = ', '.join([details['service'] for port, details in ports.items() if details['state'] == 'open']) or 'Ninguno'
        services_item = QTableWidgetItem(services)

        # Sistemas Operativos
        os_list = data.get('os', [])
        os_info = ', '.join([f"{os['name']} ({os['accuracy']}%)" for os in os_list]) if os_list else 'Desconocido'
        os_item = QTableWidgetItem(os_info)

        self.result_table.setItem(row_position, 0, ip_item)
        self.result_table.setItem(row_position, 1, hostname_item)
        self.result_table.setItem(row_position, 2, state_item)
        self.result_table.setItem(row_position, 3, ports_item)
        self.result_table.setItem(row_position, 4, services_item)
        self.result_table.setItem(row_position, 5, os_item)

        # Depuración: Verificar los datos insertados
        print(f"Añadida IP: {ip}, Hostname: {data.get('hostname', 'Desconocido')}")

    def update_progress_bar(self, value):
        """
        Actualiza la barra de progreso.
        """
        self.progress_bar.setValue(value)

    def scan_finished(self):
        """
        Rehabilita el botón de escaneo y habilita el botón de exportación si hay resultados.
        """
        self.scan_button.setEnabled(True)
        self.export_button.setEnabled(self.result_table.rowCount() > 0)
        self.stop_button.setEnabled(False)
        QMessageBox.information(self, "Escaneo Completo", "El escaneo se ha completado.")

    def filter_table(self, text):
        """
        Filtra las filas de la tabla según el texto ingresado.
        """
        for row in range(self.result_table.rowCount()):
            match = False
            for column in range(self.result_table.columnCount()):
                item = self.result_table.item(row, column)
                if item and text.lower() in item.text().lower():
                    match = True
                    break
            self.result_table.setRowHidden(row, not match)

    def export_results(self):
        """
        Exporta los resultados de la tabla a un archivo CSV o XLSX.
        """
        if self.result_table.rowCount() == 0:
            QMessageBox.warning(self, "Sin Datos", "No hay resultados para exportar.")
            return

        options = QFileDialog.Options()
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Guardar Resultados", "", "CSV (*.csv);;Excel (*.xlsx)", options=options
        )
        if file_path:
            try:
                if selected_filter == "CSV (*.csv)":
                    with open(file_path, 'w', newline='', encoding='utf-8') as file:
                        writer = csv.writer(file)
                        # Escribir encabezados
                        headers = [self.result_table.horizontalHeaderItem(i).text() for i in range(self.result_table.columnCount())]
                        writer.writerow(headers)
                        # Escribir filas
                        for row in range(self.result_table.rowCount()):
                            row_data = []
                            for column in range(self.result_table.columnCount()):
                                item = self.result_table.item(row, column)
                                row_data.append(item.text() if item else "")
                            writer.writerow(row_data)
                else:
                    wb = openpyxl.Workbook()
                    ws = wb.active
                    # Escribir encabezados
                    headers = [self.result_table.horizontalHeaderItem(i).text() for i in range(self.result_table.columnCount())]
                    ws.append(headers)
                    # Escribir filas
                    for row in range(self.result_table.rowCount()):
                        row_data = []
                        for column in range(self.result_table.columnCount()):
                            item = self.result_table.item(row, column)
                            row_data.append(item.text() if item else "")
                        ws.append(row_data)
                    wb.save(file_path)
                QMessageBox.information(self, "Exportación Exitosa", f"Resultados exportados a {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error de Exportación", f"No se pudo exportar los resultados:\n{e}")

    def show_host_details(self, row, column):
        """
        Muestra una ventana emergente con detalles del host seleccionado.
        """
        data = {
            'ip': self.result_table.item(row, 0).text(),
            'hostname': self.result_table.item(row, 1).text(),
            'state': self.result_table.item(row, 2).text(),
            'ports': self.parse_ports(self.result_table.item(row, 3).text(), self.result_table.item(row, 4).text()),
            'os': self.parse_os(self.result_table.item(row, 5).text())
        }
        dialog = DetailDialog(data, self)
        dialog.exec_()

    def parse_ports(self, ports_text, services_text):
        """
        Convierte los textos de puertos y servicios en un diccionario.
        """
        ports = {}
        if ports_text != 'Ninguno' and services_text != 'Ninguno':
            ports_list = ports_text.split(', ')
            services_list = services_text.split(', ')
            for port, service in zip(ports_list, services_list):
                ports[port] = {'state': 'open', 'service': service}
        return ports

    def parse_os(self, os_text):
        """
        Convierte el texto de sistemas operativos en una lista de diccionarios.
        """
        if os_text == 'Desconocido':
            return []
        os_list = []
        os_entries = os_text.split(', ')
        for entry in os_entries:
            match = re.match(r'^(.*)\s\((\d+)%\)$', entry)
            if match:
                name, accuracy = match.groups()
                os_list.append({'name': name, 'accuracy': accuracy})
        return os_list

    def stop_scan(self):
        """
        Detiene el proceso de escaneo.
        """
        if hasattr(self, 'worker'):
            self.worker.stop()
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            QMessageBox.information(self, "Escaneo Detenido", "El escaneo ha sido detenido.")

    def validate_ip_input(self, ip_input):
        """
        Valida si la entrada de IP es una dirección IP válida o un rango.
        """
        try:
            if '-' in ip_input:
                base_ip, end = ip_input.split('-')
                base_ip = base_ip.strip()
                end = end.strip()
                # Validar base IP
                ipaddress.ip_address(base_ip)
                # Validar el último octeto
                last_octet = base_ip.split('.')[-1]
                if not last_octet.isdigit():
                    return False
                start = int(last_octet)
                end = int(end)
                if not (0 < end <= 255 and start <= end):
                    return False
            elif ',' in ip_input:
                ips = ip_input.split(',')
                for ip in ips:
                    ipaddress.ip_address(ip.strip())
            else:
                ipaddress.ip_address(ip_input)
            return True
        except ValueError:
            return False

    def validate_ports_input(self, ports_input):
        """
        Valida si la entrada de puertos está en un formato válido.
        """
        # Permitir formatos como 22, 80,443, 1000-2000
        ports = ports_input.split(',')
        for port in ports:
            port = port.strip()
            if '-' in port:
                start, end = port.split('-')
                if not (start.isdigit() and end.isdigit()):
                    return False
                if not (0 < int(start) <= 65535 and 0 < int(end) <= 65535):
                    return False
                if int(start) > int(end):
                    return False
            else:
                if not port.isdigit():
                    return False
                if not (0 < int(port) <= 65535):
                    return False
        return True

def main():
    app = QApplication(sys.argv)
    gui = IPScannerGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
