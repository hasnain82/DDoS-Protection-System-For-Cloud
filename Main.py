import time
import logging
import smtplib
from email.mime.text import MIMEText
from scapy.all import IP, rdpcap
from collections import defaultdict
import subprocess
import configparser
import os
from datetime import datetime

# Load configuration
config = configparser.ConfigParser()
config_file = 'config.ini'

if not os.path.exists(config_file):
    config['MONITOR'] = {
        'monitor_duration': '60',
        'packet_threshold': '100',
        'suspicious_ip_threshold': '100',
        'target_ip': '172.31.85.165'
    }
    config['LOGGING'] = {
        'log_file': 'ddos_monitor.log',
        'log_level': 'INFO'
    }
    config['ALERT'] = {
        'enable_email_alert': 'False',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': '587',
        'smtp_username': 'hasnainallwebfor@gmail.com',
        'smtp_password': 'gskhhxgmpsdcsbbt',
        'recipient_email': '229219@theemcoe.org'
    }
    config['BLOCKING'] = {
        'enable_blocking': 'False'
    }
    with open(config_file, 'w') as f:
        config.write(f)
    print(f"Default configuration created at {config_file}. Please update it.")
    exit(0)
else:
    config.read(config_file)

# Config values
MONITOR_DURATION = int(config['MONITOR']['monitor_duration'])
PACKET_THRESHOLD = int(config['MONITOR']['packet_threshold'])
SUSPICIOUS_IP_THRESHOLD = int(config['MONITOR']['suspicious_ip_threshold'])
TARGET_IP = config['MONITOR']['target_ip']

LOG_FILE = config['LOGGING']['log_file']
LOG_LEVEL = config['LOGGING']['log_level'].upper()
ENABLE_EMAIL_ALERT = config.getboolean('ALERT', 'enable_email_alert')
SMTP_SERVER = config['ALERT']['smtp_server']
SMTP_PORT = config.getint('ALERT', 'smtp_port')
SMTP_USERNAME = config['ALERT']['smtp_username']
SMTP_PASSWORD = config['ALERT']['smtp_password']
RECIPIENT_EMAIL = config['ALERT']['recipient_email']
ENABLE_BLOCKING = config.getboolean('BLOCKING', 'enable_blocking')

logging.basicConfig(
    filename=LOG_FILE,
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s'
)

packet_count = 0
ip_counter = defaultdict(int)
start_time = time.time()

def send_email_alert(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USERNAME
    msg['To'] = RECIPIENT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        logging.info("Email alert sent.")
    except Exception as e:
        logging.error(f"Email failed: {e}")

def block_ip(ip_address):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
        logging.info(f"Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Block failed for IP {ip_address}: {e}")

def analyze_packet(packet):
    global packet_count
    if IP in packet:
        ip_layer = packet[IP]
        if ip_layer.dst == TARGET_IP:
            packet_count += 1
            src_ip = ip_layer.src
            ip_counter[src_ip] += 1

def capture_packets_with_tshark(output_file="capture.pcap"):
    try:
        logging.info("Starting TShark packet capture...")
        cmd = [
            'tshark',
            '-i', 'enX0',
            '-f', f"dst host {TARGET_IP}",
            '-a', f"duration:{MONITOR_DURATION}",
            '-w', output_file
        ]
        subprocess.run(cmd, check=True)
        logging.info("Packet capture complete.")
    except subprocess.CalledProcessError as e:
        logging.error(f"TShark error: {e}")
        print("TShark capture failed.")

def monitor():
    global packet_count, ip_counter
    capture_file = "capture.pcap"

    logging.info(f"Monitoring traffic to {TARGET_IP} for {MONITOR_DURATION} seconds...")
    print(f"Monitoring traffic to {TARGET_IP} for {MONITOR_DURATION} seconds...")

    capture_packets_with_tshark(capture_file)

    try:
        packets = rdpcap(capture_file)
    except Exception as e:
        logging.error(f"Failed to read pcap: {e}")
        print("Failed to read capture file.")
        return

    for packet in packets:
        analyze_packet(packet)

    duration = time.time() - start_time
    logging.info(f"Monitoring done. Duration: {duration:.2f}s | Packets: {packet_count}")
    print(f"\nMonitoring complete. Duration: {duration:.2f}s | Total Packets: {packet_count}")

    if packet_count > PACKET_THRESHOLD:
        alert_msg = f"ALERT: High traffic volume detected! {packet_count} packets."
        logging.warning(alert_msg)
        print(alert_msg)
        if ENABLE_EMAIL_ALERT:
            send_email_alert("DDoS Alert: High Traffic", alert_msg)

    suspicious_ips = {ip: count for ip, count in ip_counter.items() if count > SUSPICIOUS_IP_THRESHOLD}
    if suspicious_ips:
        logging.warning("Suspicious IPs detected:")
        print("\nSuspicious IPs detected:")
        for ip, count in suspicious_ips.items():
            msg = f" - {ip}: {count} packets"
            logging.warning(msg)
            print(msg)
            if ENABLE_BLOCKING:
                block_ip(ip)
            if ENABLE_EMAIL_ALERT:
                send_email_alert("DDoS Alert: Suspicious IP", msg)
    else:
        print("\nNo suspicious IPs detected.")
        logging.info("No suspicious IPs detected.")

    generate_report(duration)

def generate_report(duration):
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = (
        f"\n----- DDoS Monitoring Report -----\n"
        f"Time: {report_time}\n"
        f"Duration: {duration:.2f} seconds\n"
        f"Target IP: {TARGET_IP}\n"
        f"Packets Captured: {packet_count}\n"
    )

    if packet_count > PACKET_THRESHOLD:
        report += f"⚠️ High traffic detected: {packet_count} packets (threshold: {PACKET_THRESHOLD})\n"
    else:
        report += f"Traffic normal: {packet_count} packets.\n"

    if ip_counter:
        report += "Top 10 IPs:\n"
        sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips[:10]:
            report += f" - {ip}: {count} packets\n"
    else:
        report += "No IPs recorded.\n"

    report += "----- End of Report -----\n"
    report_file = f"ddos_report_{int(time.time())}.txt"
    try:
        with open(report_file, 'w') as f:
            f.write(report)
        logging.info(f"Report saved: {report_file}")
        print(f"Report saved: {report_file}")
    except Exception as e:
        logging.error(f"Report write failed: {e}")
        print(f"Report failed to save: {e}")

if __name__ == "__main__":
    monitor()