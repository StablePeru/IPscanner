# scanner.py

import nmap

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_hosts(self, target, ports='22-443', arguments='-sV -O'):
        """
        Escanea los hosts en el target especificado con detección de servicios y OS.

        :param target: Dirección IP o rango a escanear
        :param ports: Puertos a escanear
        :param arguments: Argumentos adicionales para Nmap
        :return: Lista de hosts escaneados
        """
        try:
            self.nm.scan(hosts=target, ports=ports, arguments=arguments)
            return self.nm.all_hosts()
        except Exception as e:
            print(f"Error al escanear: {e}")
            return []

    def get_host_info(self, host):
        """
        Obtiene información detallada de un host.

        :param host: Dirección IP del host
        :return: Diccionario con información del host
        """
        if host in self.nm.all_hosts():
            info = {
                'ip': host,
                'hostname': self.nm[host].hostname() or 'Desconocido',
                'state': self.nm[host].state(),
                'protocols': self.nm[host].all_protocols(),
                'ports': {},
                'os': []
            }
            for proto in info['protocols']:
                lport = list(self.nm[host][proto].keys())
                for port in lport:
                    port_info = self.nm[host][proto][port]
                    info['ports'][port] = {
                        'state': port_info['state'],
                        'service': port_info['name']
                    }
            # Detección de OS
            if 'osmatch' in self.nm[host]:
                for osmatch in self.nm[host]['osmatch']:
                    info['os'].append({
                        'name': osmatch['name'],
                        'accuracy': osmatch['accuracy']
                    })
            return info
        else:
            return None
