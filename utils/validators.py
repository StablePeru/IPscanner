import ipaddress

def validate_ip_input(ip_input):
    """
    Valida si la entrada de IP es una dirección IP válida o un rango.
    """
    try:
        if '-' in ip_input:
            base_ip, end = ip_input.split('-')
            base_ip = base_ip.strip()
            end = end.strip()
            ipaddress.ip_address(base_ip)
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

def validate_ports_input(ports_input):
    """
    Valida si la entrada de puertos está en un formato válido.
    """
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
