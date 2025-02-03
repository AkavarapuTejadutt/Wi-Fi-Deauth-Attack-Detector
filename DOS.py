#!/usr/bin/env python3

# Wi-Fi Deauthentication Attack Detector - Version 2.0
# Developed by Akavarapu Teja Dutt

from scapy.all import sniff
from scapy.layers.dot11 import Dot11
import datetime

# Prompt user to enter their Wi-Fi network interface
interface = input("Enter your Wi-Fi Interface (e.g., wlan0) > ").strip()

# Counter to track detected deauthentication packets
packet_counter = 1

# Log file to store attack records
log_file = "deauth_attack_log.txt"

def log_attack(packet_count):
    """Records detected deauthentication attacks in a log file with a timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] ALERT: Deauthentication Attack Detected! Count: {packet_count}\n")

def detect_deauth(packet):
    """Analyzes packets and detects deauthentication frames in Wi-Fi traffic."""
    global packet_counter
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:  # Checking for deauth frames
        print(f"[⚠] ALERT: Deauthentication Packet Detected! Count: {packet_counter}")
        log_attack(packet_counter)
        packet_counter += 1

try:
    print("[*] Monitoring Wi-Fi network for Deauthentication attacks... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=detect_deauth, store=False)  # Start sniffing Wi-Fi packets
except KeyboardInterrupt:
    print("\n[!] Stopping attack detector. Exiting...")
except Exception as e:
    print(f"[Error] {e}")
