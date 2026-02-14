import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import threading
import time
import requests
import json
import os
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
        self.lock = threading.Lock()
        self.running = True
        
        # Security Monitoring
        self.arp_packet_counts = defaultdict(int)
        self.arp_mac_ip_map = defaultdict(set) # {mac: {ip1, ip2}}
        self.last_reset_time = time.time()
        
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
        while self.running:
            # Active scan logic could go here
            # For now, we rely on passive sniffing and maybe a broadcast ping if needed
            time.sleep(60)

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
                # Update Discovery
                if src_mac not in self.discovered_devices:
                    print(f"[NEW] Device Discovered: {src_ip} ({src_mac})")
                    
                self.discovered_devices[src_mac] = {
                    "ip": src_ip,
                    "mac": src_mac,
                    "vendor": self.get_vendor(src_mac),
                    "status": "online",
                    "last_seen": time.time()
                }
                
                # Security: ARP Flood Detection
                current_time = time.time()
                if current_time - self.last_reset_time > 1.0:
                    self.arp_packet_counts.clear()
                    self.last_reset_time = current_time
                    
                self.arp_packet_counts[src_mac] += 1
                if self.arp_packet_counts[src_mac] > 10:
                    print(f"[SECURITY] ARP Flood detected from {src_mac} ({self.arp_packet_counts[src_mac]} pkts/sec)")
                    self.trigger_security_alert("ARP_FLOOD", src_mac, src_ip)

                # Security: ARP Spoofing (Duplicate MAC)
                self.arp_mac_ip_map[src_mac].add(src_ip)
                if len(self.arp_mac_ip_map[src_mac]) > 1:
                    print(f"[SECURITY] ARP Spoofing detected! MAC {src_mac} claims IPs: {self.arp_mac_ip_map[src_mac]}")
                    self.trigger_security_alert("ARP_SPOOFING", src_mac, list(self.arp_mac_ip_map[src_mac]))
                
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

    def trigger_security_alert(self, alert_type, mac, details):
        print(f"Triggering Miro Alert: {alert_type} - {mac}")
        url = f"https://api.miro.com/v2/boards/{MIRO_BOARD_ID}/sticky_notes"
        payload = {
            "data": {
                "content": f"<b>SECURITY ALERT</b><br>{alert_type}<br>MAC: {mac}<br>Details: {details}",
                "shape": "square"
            },
            "style": {
                "fillColor": "red"
            },
            "position": {
                "x": 0,
                "y": 0
            }
        }
        headers = {
            "Authorization": f"Bearer {MIRO_ACCESS_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if MIRO_BOARD_ID and MIRO_ACCESS_TOKEN:
            try:
                requests.post(url, json=payload, headers=headers)
            except Exception as e:
                print(f"Failed to post alert to Miro: {e}")

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

if __name__ == "__main__":
    scanner.start()
    app.run(host='0.0.0.0', port=5000)
