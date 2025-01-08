import socket
from time import time
from urllib.parse import urlparse

from celery import shared_task

from scannerhandling.scanner_utils import scanner


@shared_task
def run_scanner_task(url):
    context = {}
    scanner(url, context)
    return context


@shared_task
def run_port_scan_task(host, start_port=1, end_port=12):
    open_ports = []
    print("prot scanning start")
    # Extract the host from the URL
    host = urlparse(host).netloc or host
    if ':' in host:
        host = host.split(':')[0]
    print("start ip socket")
    try:
        # Resolve hostname
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {'error': f"Hostname resolution failed for {host}"}
    print("start scan port")
    try:
        start_time = time()
        # Scan ports
        for port in range(start_port, end_port + 1):
            print("start scan port", start_port+1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)  # Adjust timeout
                try:
                    s.connect((ip, port))
                    open_ports.append(port)
                except:
                    pass
        print("end scan port")
        elapsed_time = time() - start_time
        print("end scan port", elapsed_time)
    except Exception as e:
        return {'error': f"Error: {str(e)}"}

    return {
        'host': host,
        'ports': open_ports,
        'elapsed_time': f"Scanning completed in {elapsed_time:.2f} seconds",
    }
