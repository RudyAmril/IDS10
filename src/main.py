import threading
import time
from detection import start_sniffing
from telegram_notifier.py import notify_attacks

# Fungsi untuk mencetak serangan yang terdeteksi dalam format tabel setiap 10 detik
def print_detected_attacks():
    while True:
        if detected_attacks:
            headers = ["Timestamp", "Attack Type", "Source IP", "Details"]
            attack_details = []

            for attack in detected_attacks:
                if attack["Attack Type"] == "Brute Force":
                    details = f"Failed Attempts: {attack['Detail']}"
                else:
                    details = f"Packets Count: {attack['Detail']}"

                attack_details.append([attack["Timestamp"], attack["Attack Type"], attack["Source IP"], details])

            print("\nDetected Attacks:")
            print(tabulate.tabulate(attack_details, headers=headers, tablefmt="grid"))
            print()

            # Mengosongkan daftar serangan yang terdeteksi
            detected_attacks.clear()

        time.sleep(10)  # Cetak setiap 10 detik

# Fungsi untuk mencetak pesan "No attacks detected" setiap 15 detik jika tidak ada serangan terdeteksi
def print_no_attacks():
    while True:
        if not detected_attacks:
            print("No attacks detected.")
        time.sleep(15)  # Cetak setiap 15 detik

# Fungsi untuk mengirim notifikasi serangan ke Telegram setiap 60 detik
def notify_attacks_periodically():
    while True:
        notify_attacks()
        time.sleep(60)

# Ganti 'eth0' dengan antarmuka jaringan Anda
network_interface = config['network_interface']

# Mulai mencetak serangan yang terdeteksi dalam thread terpisah
print_thread = threading.Thread(target=print_detected_attacks)
print_thread.start()

# Mulai mencetak pesan "No attacks detected" dalam thread terpisah
no_attack_thread = threading.Thread(target=print_no_attacks)
no_attack_thread.start()

# Mulai mengirim notifikasi serangan ke Telegram dalam thread terpisah
notify_thread = threading.Thread(target=notify_attacks_periodically)
notify_thread.start()

# Mulai mengendus paket
start_sniffing(network_interface)
