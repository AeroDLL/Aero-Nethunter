#!/usr/bin/env python3
"""
NetHunter v2.1 - Advanced Network Discovery & Security Scanner
Author: Security Research Team
"""

import scapy.all as scapy
from colorama import Fore, Style, init
from mac_vendor_lookup import MacLookup
import argparse
import socket
import psutil  # netifaces yerine eklendi
import json
import time
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Initialize
init(autoreset=True)

class NetHunter:
    def __init__(self):
        self.results = []
        self.mac_lookup = MacLookup()
        self.scan_start_time = None
        self.total_devices = 0
        
    def print_banner(self):
        banner = f"""{Fore.CYAN}
              ╔═══════════════════════════════════════════════════════════════╗
              ║                  AERO NETHUNTER v1.0 (CLI)                    ║
              ║          Advanced Network Discovery & Security Scanner        ║
              ╚═══════════════════════════════════════════════════════════════╝
        {Style.RESET_ALL}"""
        print(banner)
        print(f"{Fore.GREEN}[+] Loading modules...{Style.RESET_ALL}\n")
        time.sleep(0.5)

    def get_local_ip(self):
        """Get local machine's IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "Unknown"

    def get_network_interface_info(self):
        """Get detailed network interface information using psutil"""
        print(f"\n{Fore.CYAN}[*] Network Interface Information:{Style.RESET_ALL}")
        print("=" * 70)
        
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface, addrs in interfaces.items():
            print(f"{Fore.GREEN}Interface: {iface}{Style.RESET_ALL}")
            if iface in stats:
                is_up = "UP" if stats[iface].isup else "DOWN"
                speed = stats[iface].speed
                print(f"  Status: {is_up} | Speed: {speed}MB")

            for addr in addrs:
                if addr.family == socket.AF_INET:
                    print(f"  IP Address: {addr.address}")
                    print(f"  Netmask: {addr.netmask}")
                elif addr.family == psutil.AF_LINK: # MAC Address
                    print(f"  MAC Address: {addr.address}")
            print()

    def get_arguments(self):
        parser = argparse.ArgumentParser(description="NetHunter - Advanced Network Scanner")
        parser.add_argument("-t", "--target", dest="target", help="Target IP Range")
        parser.add_argument("-p", "--port-scan", dest="port_scan", action="store_true", help="Enable port scanning")
        parser.add_argument("-o", "--output", dest="output", help="Save results to file")
        parser.add_argument("--timeout", dest="timeout", type=int, default=2, help="Scan timeout")
        parser.add_argument("--auto", dest="auto", action="store_true", help="Auto-detect network")
        parser.add_argument("--detailed", dest="detailed", action="store_true", help="Enable detailed OS detection")
        
        options = parser.parse_args()
        
        if options.auto:
            local_ip = self.get_local_ip()
            ip_parts = local_ip.split('.')
            target = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            print(f"{Fore.GREEN}[+] Auto-detected network: {target}{Style.RESET_ALL}")
            return target, options
        
        if not options.target:
            print(f"{Fore.YELLOW}[!] No IP range specified.{Style.RESET_ALL}")
            target_ip = input(f"{Fore.CYAN}[?] Enter target IP range (e.g., 192.168.1.0/24): {Style.RESET_ALL}")
            return target_ip, options
        
        return options.target, options

    def scan_network(self, ip, timeout=2):
        print(f"\n{Fore.GREEN}[*] Starting ARP scan on: {ip}...{Style.RESET_ALL}")
        self.scan_start_time = time.time()
        
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        print(f"{Fore.CYAN}[*] Sending ARP packets...{Style.RESET_ALL}")
        answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
        
        self.total_devices = len(answered_list)
        print(f"{Fore.GREEN}[+] Found {self.total_devices} active devices{Style.RESET_ALL}\n")
        
        clients_list = []
        try:
            self.mac_lookup.update_vendors()
        except:
            pass
        
        for element in answered_list:
            client_dict = {
                "ip": element[1].psrc,
                "mac": element[1].hwsrc,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            try:
                vendor = self.mac_lookup.lookup(client_dict["mac"])
            except:
                vendor = "Unknown"
            client_dict["vendor"] = vendor
            
            try:
                hostname = socket.gethostbyaddr(client_dict["ip"])[0]
                client_dict["hostname"] = hostname
            except:
                client_dict["hostname"] = "N/A"
            
            clients_list.append(client_dict)
        
        self.results = clients_list
        return clients_list

    def port_scan(self, ip, ports=[22, 80, 443, 445, 3389, 8080]):
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    open_ports.append({"port": port, "service": service})
                sock.close()
            except:
                pass
        return open_ports

    def advanced_scan(self, clients_list, port_scan=False):
        print(f"\n{Fore.CYAN}[*] Performing advanced device analysis...{Style.RESET_ALL}\n")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for client in clients_list:
                if port_scan:
                    future = executor.submit(self.port_scan, client["ip"])
                    futures.append((future, client))
            if port_scan:
                for future, client in futures:
                    try:
                        open_ports = future.result(timeout=5)
                        client["open_ports"] = open_ports
                    except:
                        client["open_ports"] = []

    def categorize_device(self, vendor, hostname):
        vendor_lower = vendor.lower()
        hostname_lower = hostname.lower()
        if "apple" in vendor_lower or "iphone" in hostname_lower:
            return "📱 Mobile (iOS)", Fore.MAGENTA
        elif "samsung" in vendor_lower or "xiaomi" in vendor_lower:
            return "📱 Mobile (Android)", Fore.YELLOW
        elif "intel" in vendor_lower or "dell" in vendor_lower or "hp" in vendor_lower:
            return "💻 Computer", Fore.BLUE
        elif "router" in hostname_lower or "gateway" in hostname_lower:
            return "🌐 Router/Gateway", Fore.GREEN
        else:
            return "❓ Unknown", Fore.WHITE

    def print_results(self, results_list, detailed=False):
        scan_duration = time.time() - self.scan_start_time
        print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                    SCAN RESULTS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Total Devices: {len(results_list)} | Duration: {scan_duration:.2f}s{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}{'IP Address':<18} {'MAC Address':<20} {'Vendor':<30} {'Type'}{Style.RESET_ALL}")
        print("-" * 85)
        
        results_list.sort(key=lambda x: [int(n) for n in x["ip"].split('.')])
        for client in results_list:
            device_type, color = self.categorize_device(client["vendor"], client["hostname"])
            print(f"{color}{client['ip']:<18} {client['mac']:<20} {client['vendor'][:29]:<30} {device_type}{Style.RESET_ALL}")
            if "open_ports" in client and client["open_ports"]:
                ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in client["open_ports"]])
                print(f"  {Fore.RED}└─ Open Ports: {ports_str}{Style.RESET_ALL}")

    def save_results(self, filename):
        if not self.results: return
        try:
            with open(filename, 'w') as f:
                json.dump({"devices": self.results}, f, indent=4)
            print(f"\n{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    def run(self):
        self.print_banner()
        self.get_network_interface_info()
        target_ip, options = self.get_arguments()
        results = self.scan_network(target_ip, timeout=options.timeout)
        if not results:
            print(f"{Fore.RED}[!] No devices found.{Style.RESET_ALL}")
            return
        if options.port_scan or options.detailed:
            self.advanced_scan(results, port_scan=options.port_scan)
        self.print_results(results, detailed=options.detailed)
        if options.output:
            self.save_results(options.output)

if __name__ == "__main__":
    try:
        NetHunter().run()
    except KeyboardInterrupt:
        sys.exit(0)