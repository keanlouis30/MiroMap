import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import threading
import time
import requests
import json
import os
import subprocess
import re
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
from collections import defaultdict

# Load environment variables
load_dotenv()

MIRO_ACCESS_TOKEN = os.getenv("MIRO_ACCESS_TOKEN")
MIRO_BOARD_ID = os.getenv("MIRO_BOARD_ID")

class NetworkScanner:
    def __init__(self):
        self.discovered_devices = {}  # {mac: {ip, vendor, status, last_seen}}
        self.ip_to_mac_history = defaultdict(list)  # {ip: [(mac, timestamp), ...]}
        self.security_alerts = []  # [{type, severity, message, timestamp, details}]
        self.lock = threading.Lock()
        self.running = True
        self.alert_shape_map = {}  # {alert_id: shape_id} for tracking created alert shapes
        
    def start(self):
        # Start passive sniffing in a separate thread
        sniff_thread = threading.Thread(target=self.sniff_network)
        sniff_thread.daemon = True
        sniff_thread.start()
        
        # Start active scanning in a separate thread
        scan_thread = threading.Thread(target=self.active_scan_loop)
        scan_thread.daemon = True
        scan_thread.start()

    def active_scan_loop(self):
        """Actively scan the network to discover devices quickly"""
        print("[SCANNER] Starting active ARP scan...")
        
        # Initial scan on startup
        self.perform_arp_scan()
        
        # Then scan periodically
        while self.running:
            time.sleep(30)  # Scan every 30 seconds
            self.perform_arp_scan()
    
    def perform_arp_scan(self):
        """Perform ARP scan to discover all devices on local network"""
        try:
            # Get local network range (e.g., 192.168.1.0/24)
            # You can make this configurable, but for now use common ranges
            network_range = "192.168.1.0/24"
            
            print(f"[ARP SCAN] Scanning {network_range}...")
            
            # Create ARP request packet
            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packet and get responses
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            devices_found = 0
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                
                # Process each response (will trigger device discovery)
                with self.lock:
                    is_new = mac not in self.discovered_devices
                    if is_new:
                        devices_found += 1
                        print(f"[ARP SCAN] Found: {ip} ({mac})")
                    
                    self.discovered_devices[mac] = {
                        "ip": ip,
                        "mac": mac,
                        "vendor": self.get_vendor(mac),
                        "status": "online",
                        "last_seen": time.time(),
                        "nmap_info": self.discovered_devices.get(mac, {}).get("nmap_info")
                    }
            
            print(f"[ARP SCAN] Complete. Found {devices_found} new devices, {len(answered_list)} total responses")
            
        except Exception as e:
            print(f"[ARP SCAN] Error: {e}")

    def sniff_network(self):
        try:
            # Filter for ARP packets
            scapy.sniff(filter="arp", prn=self.process_packet, store=False)
        except Exception as e:
            print(f"Sniffer Error: {e}")

    def process_packet(self, packet):
        if packet.haslayer(ARP):
            src_mac = packet[ARP].hwsrc
            src_ip = packet[ARP].psrc
            
            with self.lock:
                # Check for ARP poisoning BEFORE updating device info
                self.detect_arp_poisoning(src_ip, src_mac)
                
                # Update Discovery
                is_new_device = src_mac not in self.discovered_devices
                if is_new_device:
                    print(f"[NEW] Device Discovered: {src_ip} ({src_mac})")
                    
                self.discovered_devices[src_mac] = {
                    "ip": src_ip,
                    "mac": src_mac,
                    "vendor": self.get_vendor(src_mac),
                    "status": "online",
                    "last_seen": time.time(),
                    "nmap_info": self.discovered_devices.get(src_mac, {}).get("nmap_info")  # Preserve existing nmap data
                }
                
                # NO automatic nmap scan - user can trigger manually for speed
                
                # Autonomous Miro Update
                # We do this async or periodically to avoid slowing down packet processing
                # For demo, we'll do it here but wrapped in try/except
                threading.Thread(target=self.update_miro_shape, args=(src_mac, "online")).start()

    def get_vendor(self, mac):
        mac_prefix = mac[:8].upper()
        vendors = {
            "BC:D0:74": "Apple",
            "F6:06:16": "Apple (Personal Hotspot)",
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:15:5D": "Microsoft-Hyper-V",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
        }
        return vendors.get(mac_prefix, "Unknown Device")
    
    def nmap_scan_device(self, ip):
        """
        Use nmap to get detailed device information
        Returns dict with: os, hostname, open_ports, device_type
        """
        try:
            # Run nmap with OS detection, version detection, and faster timing
            # -O: OS detection
            # -sV: Version detection
            # -T4: Faster timing
            # --host-timeout: Don't wait too long per host
            cmd = ['nmap', '-O', '-sV', '-T4', '--host-timeout', '30s', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
            output = result.stdout
            
            info = {
                'os': 'Unknown',
                'hostname': None,
                'open_ports': [],
                'device_type': 'Unknown Device',
                'mac_vendor': None
            }
            
            # Parse hostname
            hostname_match = re.search(r'Nmap scan report for (.+?) \(', output)
            if hostname_match:
                info['hostname'] = hostname_match.group(1)
            
            # Parse MAC vendor
            mac_vendor_match = re.search(r'MAC Address: .+ \((.+?)\)', output)
            if mac_vendor_match:
                info['mac_vendor'] = mac_vendor_match.group(1)
            
            # Parse OS
            os_matches = re.findall(r'OS details: (.+)', output)
            if os_matches:
                info['os'] = os_matches[0]
            else:
                # Try alternative OS detection
                os_cpe = re.search(r'Running: (.+)', output)
                if os_cpe:
                    info['os'] = os_cpe.group(1)
            
            # Parse open ports and services
            port_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)'
            for match in re.finditer(port_pattern, output):
                port_num = match.group(1)
                service = match.group(2)
                version = match.group(3).strip()
                info['open_ports'].append({
                    'port': port_num,
                    'service': service,
                    'version': version
                })
            
            # Infer device type from OS and services
            info['device_type'] = self.infer_device_type(info)
            
            return info
            
        except subprocess.TimeoutExpired:
            print(f"Nmap scan timeout for {ip}")
            return None
        except FileNotFoundError:
            print("Nmap not installed. Install with: sudo apt install nmap")
            return None
        except Exception as e:
            print(f"Nmap scan error for {ip}: {e}")
            return None
    
    def infer_device_type(self, nmap_info):
        """Infer device type from nmap scan results"""
        os_lower = nmap_info['os'].lower()
        services = [p['service'] for p in nmap_info['open_ports']]
        mac_vendor = (nmap_info['mac_vendor'] or '').lower()
        
        # Check OS patterns
        if 'ios' in os_lower or 'iphone' in os_lower:
            return 'iPhone/iOS Device'
        elif 'android' in os_lower:
            return 'Android Device'
        elif 'apple' in os_lower or 'mac os' in os_lower or 'darwin' in os_lower:
            return 'Mac/Apple Device'
        elif 'windows' in os_lower:
            return 'Windows PC'
        elif 'linux' in os_lower:
            # Further classify Linux devices
            if 'raspberry' in os_lower or 'raspberry' in mac_vendor:
                return 'Raspberry Pi'
            elif any(s in services for s in ['http', 'https', 'ssh']):
                return 'Linux Server'
            return 'Linux Device'
        
        # Check MAC vendor
        if 'apple' in mac_vendor:
            return 'Apple Device'
        elif 'raspberry' in mac_vendor:
            return 'Raspberry Pi'
        elif 'samsung' in mac_vendor:
            return 'Samsung Device'
        elif 'tp-link' in mac_vendor or 'netgear' in mac_vendor or 'cisco' in mac_vendor:
            return 'Network Device (Router/Switch)'
        
        # Check services
        if 'http' in services or 'https' in services:
            if 'printer' in services or 'ipp' in services:
                return 'Network Printer'
            return 'Web Server/IoT Device'
        elif 'ssh' in services:
            return 'Server/Linux Device'
        elif 'microsoft-ds' in services or 'netbios-ssn' in services:
            return 'Windows Device'
        
        # Use MAC vendor as fallback
        if nmap_info['mac_vendor']:
            return nmap_info['mac_vendor']
        
        return 'Unknown Device'
    
    def scan_and_update_device(self, mac, ip):
        """Perform nmap scan and update device information"""
        print(f"[NMAP] Scanning {ip} for detailed info...")
        nmap_info = self.nmap_scan_device(ip)
        
        if nmap_info:
            with self.lock:
                if mac in self.discovered_devices:
                    self.discovered_devices[mac]['nmap_info'] = nmap_info
                    # Update vendor with more specific device type
                    self.discovered_devices[mac]['vendor'] = nmap_info['device_type']
                    if nmap_info['hostname']:
                        self.discovered_devices[mac]['hostname'] = nmap_info['hostname']
                    
                    print(f"[NMAP] {ip} identified as: {nmap_info['device_type']}")
                    if nmap_info['os'] != 'Unknown':
                        print(f"       OS: {nmap_info['os']}")
                    if nmap_info['hostname']:
                        print(f"       Hostname: {nmap_info['hostname']}")
                    if nmap_info['open_ports']:
                        ports_str = ', '.join([f"{p['port']}/{p['service']}" for p in nmap_info['open_ports'][:5]])
                        print(f"       Open Ports: {ports_str}")
    
    def detect_arp_poisoning(self, ip, mac):
        """
        Detect ARP poisoning by tracking IP-to-MAC mappings.
        Alerts when multiple MACs claim the same IP.
        """
        current_time = time.time()
        
        # Record this IP-MAC mapping
        self.ip_to_mac_history[ip].append((mac, current_time))
        
        # Clean old entries (keep last 5 minutes)
        self.ip_to_mac_history[ip] = [
            (m, t) for m, t in self.ip_to_mac_history[ip] 
            if current_time - t < 300
        ]
        
        # Get unique MACs for this IP in recent history
        recent_macs = set(m for m, t in self.ip_to_mac_history[ip])
        
        # Alert if multiple MACs claim the same IP
        if len(recent_macs) > 1:
            # Check if we already alerted for this conflict recently
            alert_key = f"arp_conflict_{ip}"
            recent_alerts = [
                a for a in self.security_alerts 
                if a.get('alert_key') == alert_key and current_time - a['timestamp'] < 300
            ]
            
            if not recent_alerts:
                alert = {
                    'id': f"alert_{int(current_time)}_{ip}",
                    'alert_key': alert_key,
                    'type': 'arp_poisoning',
                    'severity': 'critical',
                    'message': f'ARP Poisoning Detected: Multiple MACs claiming IP {ip}',
                    'timestamp': current_time,
                    'details': {
                        'ip': ip,
                        'conflicting_macs': list(recent_macs),
                        'current_mac': mac,
                        'vendors': [self.get_vendor(m) for m in recent_macs]
                    }
                }
                self.security_alerts.append(alert)
                print(f"\n⚠️  [SECURITY ALERT] {alert['message']}")
                print(f"    Conflicting MACs: {', '.join(recent_macs)}")
                print(f"    Vendors: {', '.join(alert['details']['vendors'])}\n")
                
                # Create alert sticky note on Miro board
                threading.Thread(target=self.create_alert_sticky, args=(alert,)).start()
    
    def create_alert_sticky(self, alert):
        """Create a sticky note on Miro board for security alerts"""
        if not (MIRO_BOARD_ID and MIRO_ACCESS_TOKEN):
            return
        
        url = f"https://api.miro.com/v2/boards/{MIRO_BOARD_ID}/sticky_notes"
        headers = {
            "Authorization": f"Bearer {MIRO_ACCESS_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Color based on severity
        color = "#ff6b6b" if alert['severity'] == 'critical' else "#ffd93d"
        
        # Format alert content
        details = alert['details']
        content = f"🚨 {alert['message']}\n\n"
        content += f"IP: {details['ip']}\n"
        content += f"MACs: {', '.join(details['conflicting_macs'][:3])}\n"
        content += f"Time: {time.strftime('%H:%M:%S', time.localtime(alert['timestamp']))}"
        
        # Place alerts at y=500 (alerts area)
        # Spread them horizontally based on alert count
        alert_count = len([a for a in self.security_alerts if a.get('id') in self.alert_shape_map])
        x_pos = alert_count * 250
        
        payload = {
            "data": {
                "content": content,
                "shape": "square"
            },
            "style": {
                "fillColor": color
            },
            "position": {
                "x": x_pos,
                "y": 500  # Alerts area
            }
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 201:
                sticky_data = response.json()
                self.alert_shape_map[alert['id']] = sticky_data['id']
                print(f"✅ Created alert sticky note on Miro board")
            else:
                print(f"Failed to create sticky note: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error creating alert sticky: {e}")



    def update_miro_shape(self, mac, status):
        if not (MIRO_BOARD_ID and MIRO_ACCESS_TOKEN):
            return

        # Poll Miro board for shapes where metadata.miromap_device_id == mac
        url = f"https://api.miro.com/v2/boards/{MIRO_BOARD_ID}/items"
        headers = {
            "Authorization": f"Bearer {MIRO_ACCESS_TOKEN}",
            "Accept": "application/json"
        }
        
        try:
            # Fetch generic items. In a real scenario, we might want to limit limit=50 or use cursor.
            response = requests.get(url, headers=headers) 
            if response.status_code == 200:
                items = response.json().get('data', [])
                for item in items:
                    # Check if item has metadata
                    # Note: We need to inspect the 'metadata' field if it exists
                    # This depends on how the metadata was set.
                    # If set via SDK item.setMetadata('key', 'value'), it might be in detailed item view.
                    # But for now, let's assume we can see it or we iterate.
                    
                    # Actually, fetching all items doesn't return custom metadata in the summary.
                    # We would need to fetch specific items by ID.
                    # This approach is flawed for "Push" without a known ID.
                    # BUT, for the demo, we rely on the BACKEND knowing the ID? 
                    # No, the frontend sets it.
                    # So maybe we should just store the ID in the backend when the frontend links it.
                    # Let's add a /register_link endpoint to the backend so the frontend can tell us!
                    pass
                    
        except Exception as e:
            print(f"Error updating Miro shape: {e}")

    def set_device_link(self, mac, shape_id):
        # Store the mapping locally so we don't have to poll Miro
        self.device_shape_map = getattr(self, 'device_shape_map', {})
        self.device_shape_map[mac] = shape_id
        print(f"Linked MAC {mac} to Shape {shape_id}")
        
    def update_known_shape(self, mac, status):
        shape_id = getattr(self, 'device_shape_map', {}).get(mac)
        if shape_id:
            url = f"https://api.miro.com/v2/boards/{MIRO_BOARD_ID}/shapes/{shape_id}"
            color = "#00ff00" if status == "online" else "#cccccc"
            payload = {
                "style": {
                    "fillColor": color
                }
            }
            headers = {
                "Authorization": f"Bearer {MIRO_ACCESS_TOKEN}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            try:
                requests.patch(url, json=payload, headers=headers)
                print(f"Updated Shape {shape_id} color to {color}")
            except Exception as e:
                print(f"Failed to update shape color: {e}")

# Flask API for Frontend
app = Flask(__name__)
CORS(app)
scanner = NetworkScanner()

@app.route('/devices', methods=['GET'])
def get_devices():
    with scanner.lock:
        devices = list(scanner.discovered_devices.values())
    return jsonify(devices)

@app.route('/link_device', methods=['POST'])
def link_device():
    # Frontend sends {shapeId: "...", mac: "..."}
    data = request.json
    shape_id = data.get('shapeId')
    mac = data.get('mac')
    
    if shape_id and mac:
        scanner.set_device_link(mac, shape_id)
        # Immediately turn it green if online
        scanner.update_known_shape(mac, "online")
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Missing shapeId or mac"}), 400

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Return security alerts"""
    with scanner.lock:
        # Return most recent 50 alerts
        alerts = sorted(scanner.security_alerts, key=lambda x: x['timestamp'], reverse=True)[:50]
    return jsonify(alerts)

@app.route('/clear_alert', methods=['POST'])
def clear_alert():
    """Clear/acknowledge an alert"""
    data = request.json
    alert_id = data.get('alertId')
    
    if alert_id:
        with scanner.lock:
            scanner.security_alerts = [a for a in scanner.security_alerts if a['id'] != alert_id]
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Missing alertId"}), 400

@app.route('/scan_device', methods=['POST'])
def scan_device():
    """Manually trigger nmap scan for a specific device"""
    data = request.json
    mac = data.get('mac')
    
    if not mac:
        return jsonify({"status": "error", "message": "Missing mac"}), 400
    
    with scanner.lock:
        if mac not in scanner.discovered_devices:
            return jsonify({"status": "error", "message": "Device not found"}), 404
        
        device = scanner.discovered_devices[mac]
        ip = device['ip']
    
    # Trigger nmap scan in background
    threading.Thread(target=scanner.scan_and_update_device, args=(mac, ip)).start()
    
    return jsonify({"status": "success", "message": f"Scanning {ip}..."})

@app.route('/scan_network', methods=['POST'])
def scan_network():
    """Manually trigger network-wide ARP scan"""
    threading.Thread(target=scanner.perform_arp_scan).start()
    return jsonify({"status": "success", "message": "Network scan started"})

if __name__ == "__main__":
    scanner.start()
    app.run(host='0.0.0.0', port=5000)
