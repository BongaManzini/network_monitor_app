# Phase 1: Backend Core for Flask-Based Network Monitor

import subprocess
import socket
import time
import threading
import psutil
from scapy.all import sniff, DNSQR, IP, ARP
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
import json

app = Flask(__name__)
app.secret_key = 'secret_key_here'

# Global store for device info
devices_info = {}
blacklist_domains = {"shady.ru", "malware.tk", "badhost.cn"}

# Load users from JSON
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f)

# Get WiFi signal strength and network name
def get_wifi_info():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True).decode(errors='ignore')
        ssid_line = next(line for line in result.split("\n") if "SSID" in line and "BSSID" not in line)
        signal_line = next(line for line in result.split("\n") if "Signal" in line)
        ssid = ssid_line.split(":")[1].strip()
        signal = signal_line.split(":")[1].strip()
        return ssid, signal
    except Exception as e:
        print(f"Wi-Fi Info Error: {e}")
        return "Unknown", "N/A"

# Get connected devices from ARP table
def scan_devices():
    global devices_info
    devices_info.clear()
    arp_table = subprocess.check_output("arp -a", shell=True).decode().split("\n")
    for line in arp_table:
        if "dynamic" in line:
            parts = line.split()
            ip = parts[0]
            mac = parts[1]
            hostname = get_hostname(ip)
            devices_info[ip] = {
                "hostname": hostname,
                "domains": set(),
                "bandwidth": 0,
                "type": "Unknown",
                "signal": "TBD",
                "flags": {}
            }

# Reverse IP to hostname
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# DNS Sniffer to track accessed domains
def dns_sniffer(packet):
    if packet.haslayer(DNSQR) and packet.haslayer(IP):
        ip = packet[IP].src
        domain = packet[DNSQR].qname.decode().strip('.')
        if ip in devices_info:
            devices_info[ip]['domains'].add(domain)
            if domain in blacklist_domains:
                devices_info[ip]['flags']['domain'] = True

# Monitor bandwidth usage
last_counters = {}
def update_bandwidth():
    global last_counters
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            ip = conn.raddr.ip
            if ip in devices_info:
                try:
                    proc = psutil.Process(conn.pid)
                    bytes_sent = proc.io_counters().bytes_sent
                    if ip not in last_counters:
                        last_counters[ip] = bytes_sent
                    delta = bytes_sent - last_counters[ip]
                    devices_info[ip]['bandwidth'] += delta / 1024
                    last_counters[ip] = bytes_sent
                    if devices_info[ip]['bandwidth'] > 50000:
                        devices_info[ip]['flags']['bandwidth'] = True
                except:
                    continue

# Ping sweep to populate ARP cache
def ping_sweep():
    try:
        ip_base = socket.gethostbyname(socket.gethostname()).rsplit('.', 1)[0]
        for i in range(1, 255):
            subprocess.Popen(f"ping -n 1 -w 100 {ip_base}.{i}", shell=True, stdout=subprocess.DEVNULL)
    except:
        pass

# Periodic threat monitoring
def monitor():
    while True:
        scan_devices()
        update_bandwidth()
        time.sleep(10)

# Start background threads
threading.Thread(target=monitor, daemon=True).start()
threading.Thread(target=ping_sweep, daemon=True).start()
sniff_thread = threading.Thread(target=lambda: sniff(filter="udp port 53", prn=dns_sniffer, store=False))
sniff_thread.daemon = True
sniff_thread.start()

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return "User already exists."
        users[username] = password
        save_users(users)
        return redirect(url_for('login'))
    return render_template("signup.html")

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    ssid, signal = get_wifi_info()
    return render_template("dashboard.html", 
        devices=devices_info, 
        ssid=ssid, 
        signal=signal, 
        user=session['username'], 
        blacklist_domains=blacklist_domains,
        refresh_count=len(devices_info))  # This is point 4

@app.route('/api/data')
def api_data():
    return jsonify(devices_info)

if __name__ == '__main__':
    app.run(debug=True)
