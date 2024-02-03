#!/usr/bin/env python

import socket
import argparse
import threading
from queue import Queue

def scan_port(ip_address, port, open_ports, verbose=False, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)
                if verbose:
                    print("[+] Port {} is open".format(port))
    except Exception as e:
        if verbose:
            print("[-] Error occurred:", e)

def parse_ports(ports_str):
    ports = []
    for port_range in ports_str.split(','):
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(port_range))
    return ports

def scan_worker(ip_address, port_queue, open_ports, verbose=False, timeout=1, output_file=None):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(ip_address, port, open_ports, verbose, timeout)
        if output_file:
            with open(output_file, 'a') as f:
                f.write(str(port) + '\n')
        port_queue.task_done()

def scan_target(ip_address, ports_str, threads=10, verbose=False, timeout=1, output_file=None):
    ports = parse_ports(ports_str)
    port_queue = Queue()
    open_ports = []

    for port in ports:
        port_queue.put(port)

    for _ in range(threads):
        thread = threading.Thread(target=scan_worker, args=(ip_address, port_queue, open_ports, verbose, timeout, output_file))
        thread.daemon = True
        thread.start()

    port_queue.join()
    if open_ports:
        print("Open ports:", open_ports)
    else:
        print("Port Scanned is closed or filtered.")

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")
    parser.add_argument("targets", help="Target IP address(es) (comma-separated)")
    parser.add_argument("-p", "--ports", help="Port(s) to scan (comma-separated or range with '-')")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-T", "--timeout", type=float, default=1, help="Connection timeout in seconds (default: 1)")
    parser.add_argument("-o", "--output-file", help="Output file")

    args = parser.parse_args()

    if args.ports and not any([args.verbose, args.timeout, args.output_file]):
        targets = args.targets.split(',')
        for target in targets:
            print("Scanning target:", target)
            scan_target(target, args.ports, args.threads)
    else:
        targets = args.targets.split(',')
        for target in targets:
            print("Scanning target:", target)
            scan_target(target, args.ports, args.threads, args.verbose, args.timeout, args.output_file)

if __name__ == "__main__":
    main()

