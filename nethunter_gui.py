#!/usr/bin/env python3
"""
Project: Aero Nethunter
Version: v1.0 (Initial Release)
Description: Open-source network analysis and monitoring tool.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import scapy.all as scapy
from mac_vendor_lookup import MacLookup
import socket
import json
import csv
import psutil
import time
import os
import subprocess

# --- YAPILANDIRMA / İSİMLENDİRME ---
APP_VERSION = "v1.0"
APP_NAME = "Aero Nethunter"  # <--- İSİM BURADA GÜNCELLENDİ

# --- DİL PAKETİ ---
LANG = {
    "en": {
        "title": f"{APP_NAME} {APP_VERSION}",
        "ctrl_panel": "⚙️ DASHBOARD",
        "target": "Target Network:",
        "auto": "🔍 Auto-Detect",
        "ports": "Target Ports:",
        "chk_port": "Enable Service Scan",
        "btn_scan": "▶ START SCAN",
        "btn_stop": "⏹ STOP SCAN",
        "btn_monitor": "📊 TRAFFIC MONITOR",
        "btn_stop_mon": "⏸ PAUSE MONITOR",
        "btn_web": "🌐 WEB UI",
        "btn_export": "💾 EXPORT CSV",
        "lbl_stats": "Devices Found: {} | Active Traffic: {}",
        "col_ip": "IP Address",
        "col_mac": "MAC Address",
        "col_vendor": "Vendor",
        "col_host": "Hostname",
        "col_type": "Device Type",
        "col_ports": "Open Services",
        "col_rx": "↓ Download",
        "col_tx": "↑ Upload",
        "status_ready": "Ready to scan.",
        "status_scan": "Scanning network...",
        "ctx_known": "Mark as Known",
        "ctx_unauth": "Mark as Unknown",
        "ctx_wol": "Send Wake-on-LAN"
    },
    "tr": {
        "title": f"{APP_NAME} {APP_VERSION}",
        "ctrl_panel": "⚙️ KONTROL PANELİ",
        "target": "Hedef Ağ:",
        "auto": "🔍 Otomatik Bul",
        "ports": "Hedef Portlar:",
        "chk_port": "Servis Taraması",
        "btn_scan": "▶ TARAMAYI BAŞLAT",
        "btn_stop": "⏹ DURDUR",
        "btn_monitor": "📊 TRAFİK İZLE",
        "btn_stop_mon": "⏸ DURAKLAT",
        "btn_web": "🌐 WEB ARAYÜZÜ",
        "btn_export": "💾 DIŞA AKTAR",
        "lbl_stats": "Bulunan: {} | Aktif Trafik: {}",
        "col_ip": "IP Adresi",
        "col_mac": "MAC Adresi",
        "col_vendor": "Üretici",
        "col_host": "Cihaz Adı",
        "col_type": "Cihaz Tipi",
        "col_ports": "Açık Servisler",
        "col_rx": "↓ İndirme",
        "col_tx": "↑ Yükleme",
        "status_ready": "Taramaya hazır.",
        "status_scan": "Ağ taranıyor...",
        "ctx_known": "Tanıdık İşaretle",
        "ctx_unauth": "Yabancı İşaretle",
        "ctx_wol": "Wake-on-LAN Gönder"
    }
}

class AeroNethunterGUI:  # <--- SINIF İSMİ GÜNCELLENDİ
    def __init__(self, root):
        self.root = root
        self.lang_code = "tr"
        self.t = LANG[self.lang_code]
        
        # Pencere Başlığı Ayarı
        self.root.title(self.t["title"])
        self.root.geometry("1300x800")
        
        # Değişkenler
        self.scanning = False
        self.monitoring = False
        self.known_macs = set()
        self.current_devices = {} 
        self.traffic_stats = {}
        self.mac_lookup = MacLookup()
        
        # Renk Teması (Dark Mode)
        self.colors = {
            "bg_main": "#1e1e2e", 
            "bg_side": "#11111b", 
            "accent": "#89b4fa",
            "text": "#cdd6f4",
            "success": "#a6e3a1", 
            "warn": "#f9e2af", 
            "err": "#f38ba8"
        }
        
        self.load_data()
        self.setup_ui()
        self.auto_detect_network()

    def switch_language(self):
        self.lang_code = "en" if self.lang_code == "tr" else "tr"
        self.t = LANG[self.lang_code]
        self.refresh_ui_text()

    def setup_ui(self):
        # Stil Ayarları
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", 
                        background=self.colors["bg_main"], 
                        foreground="white", 
                        fieldbackground=self.colors["bg_main"],
                        rowheight=30, borderwidth=0, font=("Consolas", 10)) 
        style.configure("Treeview.Heading", 
                        background=self.colors["bg_side"], 
                        foreground=self.colors["accent"], 
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", self.colors["accent"])])

        main_frame = tk.Frame(self.root, bg=self.colors["bg_main"])
        main_frame.pack(fill="both", expand=True)

        # --- YAN MENÜ (SIDEBAR) ---
        side = tk.Frame(main_frame, bg=self.colors["bg_side"], width=300)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        # --- LOGO / BAŞLIK BÖLÜMÜ ---
        # Burası arayüzde görünen "Aero Nethunter" yazısıdır.
        tk.Label(side, text=APP_NAME, font=("Segoe UI", 24, "bold"), bg=self.colors["bg_side"], fg="white").pack(pady=(30, 5))
        
        # Versiyon Bilgisi
        tk.Label(side, text=f"Version {APP_VERSION}", font=("Consolas", 10), bg=self.colors["bg_side"], fg=self.colors["accent"]).pack(pady=(0, 20))

        # Dil Değiştirme Butonu
        self.btn_lang = tk.Button(side, text="TR / EN", command=self.switch_language, bg="#313244", fg="white", relief="flat", width=10)
        self.btn_lang.pack(pady=5)

        tk.Label(side, text="Target / Hedef", font=("Segoe UI", 10, "bold"), bg=self.colors["bg_side"], fg="gray").pack(pady=(20, 5), anchor="w", padx=20)

        # Giriş Alanları
        self.entry_target = tk.Entry(side, bg="#313244", fg="white", relief="flat", font=("Consolas", 11))
        self.entry_target.pack(fill="x", padx=20, pady=5)

        self.btn_auto = tk.Button(side, text=self.t["auto"], command=self.auto_detect_network, bg="#45475a", fg="white", relief="flat")
        self.btn_auto.pack(fill="x", padx=20, pady=2)

        self.entry_ports = tk.Entry(side, bg="#313244", fg="white", relief="flat", font=("Consolas", 11))
        self.entry_ports.insert(0, "22,80,443,3389")
        self.entry_ports.pack(fill="x", padx=20, pady=(15, 5))

        self.chk_var = tk.BooleanVar(value=True)
        self.chk_port = tk.Checkbutton(side, text=self.t["chk_port"], variable=self.chk_var, bg=self.colors["bg_side"], fg="white", selectcolor=self.colors["bg_side"], activebackground=self.colors["bg_side"])
        self.chk_port.pack(fill="x", padx=15, pady=5)

        # Aksiyon Butonları
        tk.Label(side, text="Actions / İşlemler", font=("Segoe UI", 10, "bold"), bg=self.colors["bg_side"], fg="gray").pack(pady=(20, 5), anchor="w", padx=20)

        self.btn_scan = tk.Button(side, text=self.t["btn_scan"], command=self.toggle_scan, bg=self.colors["success"], fg="#1e1e2e", font=("Segoe UI", 11, "bold"), height=2, relief="flat", cursor="hand2")
        self.btn_scan.pack(fill="x", padx=20, pady=5)

        self.btn_monitor = tk.Button(side, text=self.t["btn_monitor"], command=self.toggle_monitoring, bg=self.colors["accent"], fg="#1e1e2e", font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2")
        self.btn_monitor.pack(fill="x", padx=20, pady=5)

        # Alt Butonlar
        btn_frame = tk.Frame(side, bg=self.colors["bg_side"])
        btn_frame.pack(fill="x", padx=20, pady=10)
        
        self.btn_web = tk.Button(btn_frame, text="WEB UI", command=self.launch_web_server, bg="#f38ba8", fg="#1e1e2e", font=("Segoe UI", 9, "bold"), relief="flat", width=12)
        self.btn_web.pack(side="left", padx=(0, 5))
        
        self.btn_export = tk.Button(btn_frame, text="CSV", command=self.export_data, bg=self.colors["warn"], fg="#1e1e2e", font=("Segoe UI", 9, "bold"), relief="flat", width=12)
        self.btn_export.pack(side="right")

        self.lbl_stats = tk.Label(side, text="Idle", font=("Consolas", 9), bg=self.colors["bg_side"], fg="gray")
        self.lbl_stats.pack(side="bottom", pady=20)

        # --- ANA İÇERİK (TABLO) ---
        content = tk.Frame(main_frame, bg=self.colors["bg_main"])
        content.pack(side="right", fill="both", expand=True)

        cols = ("col_ip", "col_mac", "col_vendor", "col_host", "col_type", "col_ports", "col_rx", "col_tx")
        self.tree = ttk.Treeview(content, columns=cols, show="headings")
        
        widths = [130, 150, 160, 130, 110, 180, 100, 100]
        for i, col in enumerate(cols):
            self.tree.heading(col, text=self.t[col])
            self.tree.column(col, width=widths[i], anchor="center")

        self.tree.pack(fill="both", expand=True, padx=20, pady=20)

        # Renkli Etiketler
        self.tree.tag_configure('new', background=self.colors["err"], foreground="#1e1e2e")
        self.tree.tag_configure('known', background=self.colors["bg_main"], foreground="white")
        self.tree.tag_configure('me', background=self.colors["accent"], foreground="#1e1e2e")

        # Sağ Tık Menüsü
        self.ctx_menu = tk.Menu(self.root, tearoff=0)
        self.ctx_menu.add_command(label=self.t["ctx_known"], command=lambda: self.mark_device(True))
        self.ctx_menu.add_command(label=self.t["ctx_unauth"], command=lambda: self.mark_device(False))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label=self.t["ctx_wol"], command=self.send_wol)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def refresh_ui_text(self):
        # Pencere başlığını güncelle
        self.root.title(self.t["title"])
        self.btn_auto.config(text=self.t["auto"])
        self.chk_port.config(text=self.t["chk_port"])
        self.btn_scan.config(text=self.t["btn_stop"] if self.scanning else self.t["btn_scan"])
        self.btn_monitor.config(text=self.t["btn_stop_mon"] if self.monitoring else self.t["btn_monitor"])
        self.btn_web.config(text="WEB UI") 
        self.btn_export.config(text="CSV") 
        
        cols = ("col_ip", "col_mac", "col_vendor", "col_host", "col_type", "col_ports", "col_rx", "col_tx")
        for col in cols:
            self.tree.heading(col, text=self.t[col])
            
        self.ctx_menu.entryconfigure(0, label=self.t["ctx_known"])
        self.ctx_menu.entryconfigure(1, label=self.t["ctx_unauth"])
        self.ctx_menu.entryconfigure(3, label=self.t["ctx_wol"])

    def auto_detect_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
            parts = self.local_ip.split('.')
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            self.entry_target.delete(0, tk.END)
            self.entry_target.insert(0, network)
        except: pass

    def toggle_scan(self):
        if self.scanning:
            self.scanning = False
            self.btn_scan.config(text=self.t["btn_scan"], bg=self.colors["success"])
        else:
            self.scanning = True
            self.btn_scan.config(text=self.t["btn_stop"], bg=self.colors["err"])
            threading.Thread(target=self.scan_loop, daemon=True).start()

    def scan_loop(self):
        target = self.entry_target.get()
        while self.scanning:
            try:
                arp_req = scapy.ARP(pdst=target)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                answered = scapy.srp(broadcast/arp_req, timeout=2, verbose=False)[0]
                
                for elem in answered:
                    ip = elem[1].psrc
                    mac = elem[1].hwsrc
                    
                    if mac not in self.current_devices:
                        self.register_device(ip, mac)
                    else:
                        self.current_devices[mac]["ip"] = ip
                
                self.save_live_data()
                self.root.after(0, self.refresh_tree)
                time.sleep(3)
            except Exception as e:
                print(e)
                self.scanning = False

    def register_device(self, ip, mac):
        try: vendor = self.mac_lookup.lookup(mac)
        except: vendor = "Unknown"
        try: hostname = socket.gethostbyaddr(ip)[0]
        except: hostname = "?"
        
        v_low = vendor.lower()
        if "apple" in v_low or "samsung" in v_low: dtype = "📱 Mobile"
        elif "intel" in v_low or "msi" in v_low: dtype = "💻 PC"
        elif "router" in v_low or "gateway" in v_low: dtype = "🌐 Net"
        else: dtype = "❓ Unknown"

        is_known = mac in self.known_macs

        self.current_devices[mac] = {
            "ip": ip, "mac": mac, "vendor": vendor, "host": hostname,
            "type": dtype, "ports": "", "is_known": is_known
        }
        
        if self.chk_var.get():
            threading.Thread(target=self.scan_services, args=(ip, mac), daemon=True).start()

    def scan_services(self, ip, mac):
        ports_str = self.entry_ports.get()
        target_ports = [int(p) for p in ports_str.split(',') if p.isdigit()]
        found_services = []
        
        for p in target_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                result = s.connect_ex((ip, p))
                if result == 0:
                    try: banner = s.recv(1024).decode().strip()
                    except: banner = ""
                    
                    svc_name = socket.getservbyport(p)
                    info = f"{p} ({svc_name})"
                    if banner:
                        clean_banner = banner[:15].replace("SSH-2.0-", "")
                        info += f" [{clean_banner}]"
                    found_services.append(info)
                s.close()
            except: pass
        
        if mac in self.current_devices:
            self.current_devices[mac]["ports"] = ", ".join(found_services) if found_services else ""
            self.root.after(0, self.refresh_tree)

    def toggle_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.btn_monitor.config(text=self.t["btn_monitor"], bg=self.colors["accent"])
        else:
            self.monitoring = True
            self.btn_monitor.config(text=self.t["btn_stop_mon"], bg=self.colors["warn"])
            threading.Thread(target=self.monitor_loop, daemon=True).start()

    def monitor_loop(self):
        while self.monitoring:
            def packet_handler(pkt):
                if not self.monitoring: return
                try:
                    if pkt.haslayer(scapy.Ether):
                        src = pkt[scapy.Ether].src
                        dst = pkt[scapy.Ether].dst
                        length = len(pkt)
                        if src in self.traffic_stats: self.traffic_stats[src]["tx"] += length
                        else: self.traffic_stats[src] = {"rx": 0, "tx": length}
                        if dst in self.traffic_stats: self.traffic_stats[dst]["rx"] += length
                        else: self.traffic_stats[dst] = {"rx": length, "tx": 0}
                except: pass
            scapy.sniff(prn=packet_handler, timeout=2, store=0)
            self.root.after(0, self.refresh_tree)

    def refresh_tree(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        total_rx = 0
        total_tx = 0
        
        for mac, d in self.current_devices.items():
            stats = self.traffic_stats.get(mac, {"rx": 0, "tx": 0})
            rx_fmt = f"{stats['rx']/1024:.1f} KB"
            tx_fmt = f"{stats['tx']/1024:.1f} KB"
            total_rx += stats['rx']
            total_tx += stats['tx']

            if mac == self.get_my_mac(): tag = "me"
            elif d["is_known"]: tag = "known"
            else: tag = "new"

            self.tree.insert("", "end", values=(
                d["ip"], d["mac"], d["vendor"], d["host"], 
                d["type"], d["ports"], rx_fmt, tx_fmt
            ), tags=(tag,))
            
        self.lbl_stats.config(text=self.t["lbl_stats"].format(len(self.current_devices), f"↓{total_rx/1024:.1f}KB ↑{total_tx/1024:.1f}KB"))

    def launch_web_server(self):
        try:
            if os.name == 'nt': subprocess.Popen(["python", "web_server.py"], shell=True)
            else: subprocess.Popen(["python3", "web_server.py"])
            messagebox.showinfo("Web Server", "Server started at: http://localhost:5000")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def save_live_data(self):
        data = {"devices": list(self.current_devices.values())}
        try:
            with open("live_data.json", "w") as f: json.dump(data, f)
        except: pass

    def get_my_mac(self):
        try: return scapy.get_if_hwaddr(scapy.conf.iface)
        except: return ""

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.ctx_menu.post(event.x_root, event.y_root)

    def mark_device(self, is_known):
        sel = self.tree.selection()
        if sel:
            mac = self.tree.item(sel[0])['values'][1]
            if mac in self.current_devices:
                self.current_devices[mac]["is_known"] = is_known
                if is_known: self.known_macs.add(mac)
                else: self.known_macs.discard(mac)
                self.save_data()
                self.refresh_tree()

    def send_wol(self):
        sel = self.tree.selection()
        if sel:
            mac = self.tree.item(sel[0])['values'][1]
            packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.IP(dst="255.255.255.255")/scapy.UDP(dport=9)/scapy.Raw(load=bytes.fromhex('FF'*6 + mac.replace(':','')*16))
            scapy.sendp(packet, verbose=0)
            messagebox.showinfo("WOL", f"Magic Packet sent to {mac}")

    def load_data(self):
        if os.path.exists("known.json"):
            with open("known.json") as f: self.known_macs = set(json.load(f))

    def save_data(self):
        with open("known.json", "w") as f: json.dump(list(self.known_macs), f)

    def export_data(self):
        f = filedialog.asksaveasfilename(defaultextension=".csv")
        if f:
            with open(f, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["IP", "MAC", "Vendor", "Hostname", "Type", "Ports"])
                for mac, d in self.current_devices.items():
                    writer.writerow([d["ip"], d["mac"], d["vendor"], d["host"], d["type"], d["ports"]])
            messagebox.showinfo("Export", "Saved successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = AeroNethunterGUI(root)
    root.mainloop()