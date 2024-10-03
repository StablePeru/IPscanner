import nmap
import logging

logger = logging.getLogger('ip_scanner')

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_hosts(self, target, ports='22-443', arguments='-sV -O'):
        try:
            self.nm.scan(hosts=target, ports=ports, arguments=arguments)
            hosts = self.nm.all_hosts()
            logger.info(f"Hosts escaneados: {hosts}")
            return hosts
        except Exception as e:
            logger.error(f"Error al escanear: {e}")
            return []

    def get_host_info(self, host):
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
            if 'osmatch' in self.nm[host]:
                for osmatch in self.nm[host]['osmatch']:
                    info['os'].append({
                        'name': osmatch['name'],
                        'accuracy': osmatch['accuracy']
                    })
            logger.debug(f"Información del host {host}: {info}")
            return info
        else:
            logger.warning(f"El host {host} no está en la lista de hosts escaneados.")
            return None
