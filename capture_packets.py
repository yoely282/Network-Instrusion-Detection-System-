import smtplib
from email.mime.text import MIMEText
from google.oauth2 import service_account
from scapy.all import sniff, TCP, IP
from collections import defaultdict
                                                                                                                                     
# Global dictionary to keep track of IP counts
ip_counts = defaultdict(int)
                                                                                                                 
def send_alert(email_content):
    msg = MIMEText(email_content)
    msg['Subject'] = 'Intrusion Alert'
    msg['From'] = 'gmail.com'  # Replace with your Gmail address
    msg['To'] = 'gmail.com'  # Replace with the recipient's email address
                       
    # Path to your OAuth credentials JSON file
    credentials_file = '/ path of the file '

    # Create credentials object from JSON file
    credentials = service_account.Credentials.from_service_account_file(credentials_file,
                                                                        scopes=['https://mail.google.com/'])

    try:
        # Create SMTP connection with SSL
        smtp_conn = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp_conn.login('email enga kutu ', 'inna pas waga ')  # Replace with your Gmail address and password or app password

        smtp_conn.sendmail('email ekkena ', 'email abarma ', msg.as_string())
        print("Email sent successfully!")
        smtp_conn.quit()
    except Exception as e:
        print(f"Error sending email: {e}")

def detect_port_scan(packet):
    global ip_counts
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == 'S':
        # Check if the packet source has an IPv4 address
        if packet[IP].src:
            ip_counts[packet[IP].src] += 1
            if ip_counts[packet[IP].src] > 10:  # Adjust threshold as needed
                alert_content = f"Potential port scan detected from {packet[IP].src}"
                print(alert_content)
                send_alert(alert_content)

# Capture 1000 packets on interface en0 to increase chances of detecting port scans
try:
    sniff(iface='en0', prn=detect_port_scan, count=1000)
except Exception as e:
    print(f"Error sniffing packets: {e}")
