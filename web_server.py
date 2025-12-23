#!/usr/bin/env python3
from flask import Flask, render_template_string, jsonify
import json
import os

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Aero Nethunter Web Panel</title> <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="5"> <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 20px; }
        h1 { color: #89b4fa; border-bottom: 2px solid #313244; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #11111b; }
        th { background: #313244; color: #89b4fa; padding: 12px; text-align: left; }
        td { padding: 12px; border-bottom: 1px solid #313244; }
        .known { border-left: 5px solid #a6e3a1; }
        .unknown { border-left: 5px solid #f38ba8; }
        .me { border-left: 5px solid #89b4fa; }
    </style>
</head>
<body>
    <h1>🦅 Aero Nethunter Live Monitor</h1>
    <div id="status">Waiting for data...</div>
    <div id="table-container"></div>
    <script>
        function fetchData() {
            fetch('/api/devices')
                .then(response => response.json())
                .then(data => {
                    if (!data.devices || data.devices.length === 0) {
                        document.getElementById('status').innerText = "No devices detected yet...";
                        return;
                    }
                    document.getElementById('status').innerText = `Last Update: ${new Date().toLocaleTimeString()} | Devices: ${data.devices.length}`;
                    
                    let html = '<table><tr><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Type</th><th>Services</th></tr>';
                    
                    data.devices.forEach(d => {
                        let cls = d.is_known ? "known" : "unknown";
                        html += `<tr class="${cls}">
                            <td>${d.ip}</td>
                            <td>${d.mac}</td>
                            <td>${d.vendor}</td>
                            <td>${d.type}</td>
                            <td>${d.ports || "-"}</td>
                        </tr>`;
                    });
                    html += '</table>';
                    document.getElementById('table-container').innerHTML = html;
                })
                .catch(err => console.error(err));
        }
        setInterval(fetchData, 2000);
        fetchData();
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/devices")
def api_devices():
    # DÜZELTME: GUI'nin oluşturduğu doğru dosyayı okuyor
    if os.path.exists("live_data.json"):
        try:
            with open("live_data.json", "r") as f:
                data = json.load(f)
            return jsonify(data)
        except:
            return jsonify({"devices": []})
    return jsonify({"devices": []})

if __name__ == "__main__":
    print("🌐 Web panel: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000)