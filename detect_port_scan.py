import smtplib
from email.mime.text import MIMEText

def send_alert(email_content):
    msg = MIMEText(email_content)
    msg['Subject'] = 'Intrusion Alert'
    msg['From'] = 'your-email@example.com'
    msg['To'] = 'admin@example.com'

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('your-email@example.com', 'your-password')
        server.sendmail('your-email@example.com', 'admin@example.com', msg.as_string())

def detect_port_scan(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # SYN flag for TCP
        ip_counts[packet[IP].src] += 1
        if ip_counts[packet[IP].src] > 10:  # Threshold value
            alert_content = f"Port scan detected from {packet[IP].src}"
            print(alert_content)
            send_alert(alert_content)
