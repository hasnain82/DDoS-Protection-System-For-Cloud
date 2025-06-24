# DDoS-Protection-System-For-Cloud

This project is a custom-designed DDoS Protection System built to secure cloud-hosted web applications from Distributed Denial-of-Service (DDoS) attacks. It includes intelligent detection, automated mitigation, and recovery tools to maintain high availability and minimal downtime — even during active attacks.

The system simulates real-world attack scenarios using a testbed with EC2 instances, enabling realistic evaluation of defense mechanisms. Inspired by services like AWS Shield, this project demonstrates how to build a flexible and robust protection framework without relying on third-party tools.

🔐 Key Features

- Real-Time Traffic Monitoring using TShark and Scapy
- Anomaly Detection based on packet rates, IP behavior, and flooding patterns
- Top Attacker IP Reporting for visibility and analysis
- Mitigation Engine that blocks or rate-limits malicious IPs
- Auto-Recovery Tools to restore normal traffic after an attack subsides
- Traffic Simulation using controlled EC2-based flooding to test resilience
- Modular Design for easy integration with custom cloud setups


🛠️ Technologies Used

- Python (for detection and mitigation scripts)
- TShark & Scapy (for packet capture and analysis)
- Apache2 / EC2 Instances (for hosting and attack simulation)
- Bash Scripts (for automation and control)


📊 Architecture Overview

1. Traffic Capture → Real-time monitoring of incoming packets
2. Detection Engine → Identifies abnormal traffic patterns
3. IP Blacklist Generator → Dynamically blocks attackers
4. Mitigation Pipeline → Routes or drops suspicious traffic
5. Recovery & Reporting → Logs attack details and restores normal operation

 -- **Working**
 
![image](https://github.com/user-attachments/assets/f09df8a6-17d2-44b5-ac51-b95aec83640e)


Instance 1: Web Server (Victim)

 ![image](https://github.com/user-attachments/assets/b1cbe1a4-7abb-46d6-9859-74e3f2e3fe99)

In this web server we are hosting a website of Simple online Book Store. 

![image](https://github.com/user-attachments/assets/003cc889-6037-4fdf-a5c8-78fd7351eae6)


 
Instance 2: Attack Machine
 
![image](https://github.com/user-attachments/assets/2084911e-4a42-454d-9821-9e13fedc16cd)

Sending Flood Using ApacheBenchmark (ab) Tool

 ![image](https://github.com/user-attachments/assets/767fc815-f797-455b-b021-6db5e7d6f028)




Detection and Mitigation

 ![image](https://github.com/user-attachments/assets/fbc7f729-29b1-494a-8a70-3f868b9b344b)

