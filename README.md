# Network Instrusion Detection System 
 Build an IDS using Python to monitor network traffic and detect suspicious activities.

## Overview
This project is a simple Network Intrusion Detection System (NIDS) using Python and Scapy. It is designed to capture network packets and detect potential threats like port scans. The system can be useful for network administrators and cybersecurity enthusiasts who want to monitor network traffic and identify suspicious activities.

## Features
- **Packet Capturing**: Capture IP packets on the network to analyze the traffic.
- **Port Scan Detection**: Detect SYN flood attacks and port scanning activities, which are common security threats.
- **Alert System**: Print alerts to the console when potential threats are detected.

## Prerequisites
Before you can run this project, you'll need to install Python and Scapy. This project is developed using Python 3.8 or higher.

### Installing Python
Download and install Python from [python.org](https://www.python.org/downloads/).

### Installing Scapy
Install Scapy using pip:
```bash
pip install scapy
