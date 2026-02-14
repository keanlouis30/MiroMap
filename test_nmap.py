#!/usr/bin/env python3
"""
Quick test script to scan unknown devices using nmap
"""
import subprocess
import re

def nmap_scan_device(ip):
    """Use nmap to get detailed device information"""
    print(f"\n{'='*60}")
    print(f"Scanning {ip}...")
    print('='*60)
    
    try:
        # Run nmap with OS detection, version detection
        # Note: OS detection (-O) requires root privileges
        cmd = ['sudo', 'nmap', '-O', '-sV', '-T4', '--host-timeout', '30s', ip]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
        output = result.stdout
        
        print(output)  # Print full output for debugging
        
        info = {
            'os': 'Unknown',
            'hostname': None,
            'open_ports': [],
            'mac_vendor': None
        }
        
        # Parse hostname
        hostname_match = re.search(r'Nmap scan report for (.+?) \(', output)
        if not hostname_match:
            hostname_match = re.search(r'Nmap scan report for (.+)', output)
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
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"SUMMARY for {ip}:")
        print('='*60)
        if info['hostname']:
            print(f"Hostname: {info['hostname']}")
        if info['mac_vendor']:
            print(f"Vendor: {info['mac_vendor']}")
        if info['os'] != 'Unknown':
            print(f"OS: {info['os']}")
        if info['open_ports']:
            print(f"Open Ports:")
            for p in info['open_ports']:
                print(f"  - {p['port']}/{p['service']} {p['version']}")
        else:
            print("No open ports detected (might be filtered)")
        
        return info
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  Scan timeout for {ip}")
        return None
    except FileNotFoundError:
        print("❌ Nmap not installed. Install with: sudo apt install nmap")
        return None
    except Exception as e:
        print(f"❌ Scan error for {ip}: {e}")
        return None

if __name__ == "__main__":
    # Your unknown devices
    devices = [
        "192.168.1.105",
        "192.168.1.29",
        "192.168.1.200",
        "192.168.1.1",
        "192.168.1.28",
        "192.168.1.8",
        "192.168.1.62",
        "192.168.1.168"
    ]
    
    print("Starting nmap scan of unknown devices...")
    print("Note: This requires sudo privileges for OS detection")
    
    results = {}
    for ip in devices:
        results[ip] = nmap_scan_device(ip)
    
    print("\n" + "="*60)
    print("FINAL SUMMARY")
    print("="*60)
    for ip, info in results.items():
        if info:
            device_type = info.get('mac_vendor') or info.get('hostname') or 'Unknown'
            print(f"{ip} - {device_type}")
        else:
            print(f"{ip} - Scan failed")
