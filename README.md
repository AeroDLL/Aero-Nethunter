# 🦅 Aero Nethunter v1.0

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

[🇺🇸 English](#-english) | [🇹🇷 Türkçe](#-türkçe)

---

## 🇺🇸 English

**Aero Nethunter** is an open-source network analysis and security tool developed with **Python** and **Tkinter**. It allows you to discover devices on your local network, analyze security vulnerabilities, and monitor instant network traffic.

### 📋 Requirements

**requirements.txt**
```text
scapy>=2.5.0
colorama>=0.4.6
mac-vendor-lookup>=0.1.12
psutil
flask
## 🚀 Installation

### Linux/macOS
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install system dependencies (Linux)
sudo apt-get install python3-tk

# Grant necessary permissions
sudo setcap cap_net_raw+ep $(which python3)
```

### Windows
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Npcap (required for Scapy)
# Download from: https://npcap.com/#download

# Run as Administrator
```

## 💻 Usage

### Command Line Interface (CLI)

#### Basic Scan
```bash
sudo python3 nethunter_main.py -t 192.168.1.0/24
```

#### Auto-Detect Network
```bash
sudo python3 nethunter_main.py --auto
```

#### Advanced Scan with Port Detection
```bash
sudo python3 nethunter_main.py -t 192.168.1.0/24 -p --detailed
```

#### Save Results
```bash
sudo python3 nethunter_main.py -t 192.168.1.0/24 -o results.json
sudo python3 nethunter_main.py --auto -p -o report.txt
```

#### Custom Timeout
```bash
sudo python3 nethunter_main.py -t 192.168.1.0/24 --timeout 5
```

### Graphical User Interface (GUI)

```bash
sudo python3 nethunter_gui.py
```

## 🎯 Features

### Core Features
- ✅ **ARP Network Scanning** - Discover all devices on local network
- ✅ **MAC Address Vendor Lookup** - Identify device manufacturers
- ✅ **Hostname Resolution** - Resolve device names
- ✅ **Device Categorization** - Auto-classify devices (Mobile, PC, Router, etc.)
- ✅ **Port Scanning** - Detect open ports on discovered devices
- ✅ **Auto Network Detection** - Automatically identify your network range
- ✅ **Multi-threaded Scanning** - Fast concurrent operations
- ✅ **Export Results** - Save to JSON or TXT format

### GUI Features
- 🎨 Modern dark-themed interface
- 📊 Real-time scan progress
- 🔍 Interactive results table
- 💾 One-click export
- ⚙️ Configurable scan options
- 📈 Live statistics display

## 📊 Command Line Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--target` | `-t` | Target IP range | `-t 192.168.1.0/24` |
| `--port-scan` | `-p` | Enable port scanning | `-p` |
| `--output` | `-o` | Save results to file | `-o report.json` |
| `--timeout` | - | Scan timeout in seconds | `--timeout 3` |
| `--auto` | - | Auto-detect network | `--auto` |
| `--detailed` | - | Enable detailed analysis | `--detailed` |

## 🔍 Output Examples

### CLI Output
```
╔═══════════════════════════════════════════════════════════════╗
║                         NETHUNTER v2.0                        ║
║          Advanced Network Discovery & Security Scanner        ║
╚═══════════════════════════════════════════════════════════════╝

[*] Network Interface Information:
====================================================================
Interface: eth0
  IP Address: 192.168.1.100
  Netmask: 255.255.255.0
  MAC Address: aa:bb:cc:dd:ee:ff

[*] Starting ARP scan on: 192.168.1.0/24...
[+] Found 8 active devices

================================================================================
                    SCAN RESULTS SUMMARY
================================================================================

[*] Total Devices Found: 8
[*] Scan Duration: 3.45 seconds
[*] Scan Time: 2024-12-23 15:30:45

IP Address         MAC Address          Vendor                        Type
-------------------------------------------------------------------------------------
192.168.1.1        00:11:22:33:44:55    TP-Link Technologies         🌐 Router/Gateway
192.168.1.10       aa:bb:cc:dd:ee:01    Apple Inc.                   📱 Mobile (iOS)
192.168.1.15       aa:bb:cc:dd:ee:02    Samsung Electronics          📱 Mobile (Android)
192.168.1.20       aa:bb:cc:dd:ee:03    Intel Corporate              💻 Computer
192.168.1.25       aa:bb:cc:dd:ee:04    Dell Inc.                    💻 Computer
```

### JSON Output
```json
{
    "scan_time": "2024-12-23 15:30:45",
    "total_devices": 8,
    "devices": [
        {
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:01",
            "vendor": "Apple Inc.",
            "hostname": "iPhone-12",
            "timestamp": "2024-12-23 15:30:45",
            "open_ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}
            ]
        }
    ]
}
```

## 🛡️ Security & Ethics

### ⚠️ LEGAL NOTICE
This tool is designed for:
- ✅ Educational purposes
- ✅ Authorized penetration testing
- ✅ Network administration on YOUR OWN networks
- ✅ Security research in controlled environments

### ❌ PROHIBITED USES
- Unauthorized network scanning
- Attacking networks you don't own
- Violating privacy laws
- Any illegal activities

**Always obtain written permission before scanning networks you don't own!**

## 🔧 Troubleshooting

### Permission Denied
```bash
# Linux/macOS
sudo python3 nethunter_main.py

# Or set capabilities
sudo setcap cap_net_raw+ep $(which python3)
```

### "Module not found" Error
```bash
pip install -r requirements.txt --upgrade
```

### No Devices Found
- Check if you're on the correct network
- Verify target IP range is correct
- Increase timeout value
- Ensure no firewall is blocking ARP packets

### GUI Not Opening
```bash
# Install tkinter
sudo apt-get install python3-tk  # Linux
brew install python-tk            # macOS
```

## 📚 Technical Details

### How It Works
1. **ARP Discovery**: Sends ARP requests to all IPs in range
2. **MAC Lookup**: Queries OUI database for vendor information
3. **Hostname Resolution**: Performs reverse DNS lookup
4. **Port Scanning**: TCP connection attempts to common ports
5. **Categorization**: Analyzes vendor/hostname to classify devices

### Scanned Ports (Port Scan Mode)
- 22 (SSH)
- 80 (HTTP)
- 443 (HTTPS)
- 445 (SMB)
- 3389 (RDP)
- 8080 (HTTP Alt)

## 🎓 Educational Use Cases

- **Network Administration**: Map your home/office network
- **Security Auditing**: Identify unauthorized devices
- **Device Inventory**: Track network-connected equipment
- **Learning**: Understand network protocols (ARP, TCP)
- **IoT Management**: Discover smart devices

## 📝 License & Credits

**Tool**: NetHunter v2.0  
**Purpose**: Educational & Authorized Security Testing  
**Dependencies**: Scapy, Colorama, MAC Vendor Lookup  

**Remember**: With great power comes great responsibility! 🕷️

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section
2. Review Scapy documentation
3. Ensure proper permissions
4. Test on isolated network first

---

**Happy Ethical Hacking! 🎯**

*Always scan responsibly and within legal boundaries.*
