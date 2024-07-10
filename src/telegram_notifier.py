import requests
import json

# Baca konfigurasi dari file config.json
with open('../config/config.json', 'r') as f:
    config = json.load(f)

CHAT_ID = config['telegram_chat_id']
BOT_TOKEN = config['telegram_bot_token']
LOG_FILE_PATH = '../logs/log.txt'

def send_message_to_telegram(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': CHAT_ID,
        'text': message
    }
    response = requests.post(url, json=payload)
    return response.json()

def notify_attacks():
    with open(LOG_FILE_PATH, 'r') as log_file:
        log_lines = log_file.readlines()
    
    for line in log_lines:
        attack = json.loads(line)
        message = (f"Timestamp: {attack['Timestamp']}\n"
                   f"Attack Type: {attack['Attack Type']}\n"
                   f"Source IP: {attack['Source IP']}\n"
                   f"Detail: {attack['Detail']}")
        send_message_to_telegram(message)

    # Clear log file after sending messages
    with open(LOG_FILE_PATH, 'w') as log_file:
        log_file.write('')
