import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import json

# Baca konfigurasi dari file config.json
with open('../config/config.json', 'r') as f:
    config = json.load(f)

# Kamus untuk menyimpan alamat IP dan jumlah paketnya
ip_packet_count = defaultdict(int)
failed_login_attempts = defaultdict(int)

# Nilai ambang batas dari konfigurasi
UDP_FLOOD_THRESHOLD = config['UDP_FLOOD_THRESHOLD']
TCP_SYN_FLOOD_THRESHOLD = config['TCP_SYN_FLOOD_THRESHOLD']
ICMP_FLOOD_THRESHOLD = config['ICMP_FLOOD_THRESHOLD']
BRUTE_FORCE_THRESHOLD = config['BRUTE_FORCE_THRESHOLD']

# Daftar untuk menyimpan serangan yang terdeteksi
detected_attacks = []

# Variabel untuk menyimpan jenis serangan terakhir yang terdeteksi
last_detected_attack = None

# Fungsi untuk mendeteksi serangan DDoS (UDP Flood, TCP SYN Flood, ICMP Flood)
def detect_ddos(packet):
    global last_detected_attack

    if IP in packet:
        src_ip = packet[IP].src
        ip_packet_count[src_ip] += 1

        # Memeriksa UDP Flood
        if UDP in packet and ip_packet_count[src_ip] > UDP_FLOOD_THRESHOLD:
            log_attack("UDP Flood", src_ip, ip_packet_count[src_ip])

        # Memeriksa TCP SYN Flood
        if TCP in packet and packet[TCP].flags & 0x02 and ip_packet_count[src_ip] > TCP_SYN_FLOOD_THRESHOLD:
            log_attack("TCP SYN Flood", src_ip, ip_packet_count[src_ip])

        # Memeriksa ICMP Flood
        if ICMP in packet and ip_packet_count[src_ip] > ICMP_FLOOD_THRESHOLD:
            log_attack("ICMP Flood", src_ip, ip_packet_count[src_ip])

# Fungsi untuk mendeteksi serangan brute force (upaya login gagal berulang kali)
def detect_brute_force(packet):
    global last_detected_attack

    if TCP in packet and packet[TCP].dport == 22:  # Misal port SSH
        src_ip = packet[IP].src

        # Memeriksa SYN (inisiasi koneksi) atau RST (reset koneksi, menunjukkan kegagalan)
        if packet[TCP].flags & 0x02 or packet[TCP].flags & 0x04:
            failed_login_attempts[src_ip] += 1

        # Memeriksa jika ambang batas terlampaui
        if failed_login_attempts[src_ip] > BRUTE_FORCE_THRESHOLD:
            log_attack("Brute Force", src_ip, failed_login_attempts[src_ip])

# Fungsi untuk mencatat serangan ke log file
def log_attack(attack_type, src_ip, detail):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "Timestamp": timestamp,
        "Attack Type": attack_type,
        "Source IP": src_ip,
        "Detail": detail
    }
    detected_attacks.append(log_entry)
    with open('../logs/log.txt', 'a') as log_file:
        log_file.write(json.dumps(log_entry) + '\n')
    print(f"Warning!!! Detected {attack_type} Attack from IP: {src_ip}")

# Fungsi sniff untuk menangkap dan menganalisis paket
def start_sniffing(interface):
    print(f"Starting packet capture on interface {interface}...")
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

def packet_callback(packet):
    detect_ddos(packet)
    detect_brute_force(packet)
