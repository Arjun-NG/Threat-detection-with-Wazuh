# 🛡️ Threat Detection & Response Lab using Wazuh, Suricata, Syslog & Malware Detection

This project demonstrates a complete setup of a Threat Detection and Response System using open-source tools including **Wazuh**, **Suricata**, and **Syslog**. The goal is to detect malicious behavior and generate alerts using IDS, endpoint monitoring, and centralized log analysis.

---

**Short Description:**
A practical Threat Detection & Response lab using Wazuh, Suricata, and Syslog for centralized log analysis, network-based threat detection, and malware simulation. Ideal for blue team training, SIEM exploration, and incident response practice.

---

## 📌 Objectives

* Deploy Wazuh SIEM for centralized security monitoring
* Integrate Suricata IDS for network threat detection
* Ingest logs from virtual machines (Linux/Windows) using Syslog
* Simulate malware/attack scenarios and detect them in real-time
* Visualize alerts and investigate security incidents

## 🧰 Tools Used

| Tool                            | Purpose                                                                           |
| ------------------------------- | --------------------------------------------------------------------------------- |
| Wazuh                           | SIEM platform for threat detection, log analysis, file integrity monitoring, etc. |
| Suricata                        | Network Intrusion Detection and Prevention System (IDS/IPS)                       |
| Filebeat / Syslog               | Log forwarding from VMs to Wazuh                                                  |
| VirtualBox / VMware             | VM environment for endpoint simulation                                            |
| Kali Linux / Metasploit / EICAR | Malware simulation and testing                                                    |

## 🏗️ Architecture

```
+------------+       +-----------+       +-------------+
|  Windows VM| ----> |  Syslog   | --->  |             |
|  / Linux VM|       | Forwarder |       |             |
+------------+       +-----------+       |             |
                                          |             |
                      +-----------+       |   Wazuh     |
                      | Suricata  | ----> |   Manager   |
                      +-----------+       |             |
                                          |             |
                                          +-------------+
                                                 |
                                                 v
                                          Kibana Dashboard
```

## 🚀 Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/yourusername/threat-detection-lab.git
cd threat-detection-lab
```

### 2. Prerequisites

* 16+ GB RAM (minimum recommended)
* VirtualBox or VMware
* Internet access
* ISO/OVA for:

  * Wazuh OVA ([https://wazuh.com/](https://wazuh.com/))
  * Suricata (or use agent)
  * Ubuntu Server (agent/log forwarder)
  * Windows VM (malware testing)

## ⚙️ Setup Instructions

### 🧠 Wazuh Manager

* Import Wazuh OVA into VirtualBox
* Access it via SSH or GUI
* Setup Wazuh Web UI using browser on host

### 🌐 Suricata IDS

* Install on a separate Ubuntu VM or same agent VM
* Configure `suricata.yaml` to monitor correct interface
* Forward logs to Wazuh using Filebeat or Syslog

### 📦 Log Forwarding from VMs

* **Linux:**

  * Install `rsyslog` or `Filebeat`
  * Configure to send logs to Wazuh Manager

* **Windows:**

  * Use Wazuh agent or `NXLog` for forwarding Event Logs

### 🧪 Malware Simulation

* Use EICAR file, Metasploit, or Atomic Red Team to simulate attacks
* Observe detections in Wazuh (Sysmon logs, Suricata alerts, etc.)

## 📊 Dashboards & Detection

* Login to **Kibana** via `https://<wazuh-ip>`
* Navigate to:

  * Security Events
  * Suricata Alerts
  * MITRE ATT\&CK Mappings
  * FIM (File Integrity Monitoring)

## 🧠 Sample Detections

* ✅ Suricata detects port scans, brute-force, exploit attempts
* ✅ Wazuh detects unauthorized file changes, suspicious processes
* ✅ Syslog captures logs from Linux services (e.g. SSH brute-force)
* ✅ Windows agent detects malware or PowerShell abuse

## 💣 Common Attack Scenarios

### 🛜 Networking Attacks (Detectable by Suricata)

| Attack Type               | Description                                                          |
| ------------------------- | -------------------------------------------------------------------- |
| **Port Scanning**         | Attackers scan ports to find open services (e.g., `nmap`, `masscan`) |
| **Brute Force (SSH/FTP)** | Repeated login attempts using guessable credentials                  |
| **DDoS (DoS)**            | Flooding systems with traffic using tools like `hping3`, `slowloris` |
| **ARP Spoofing**          | Spoof ARP messages to intercept traffic                              |
| **DNS Spoofing**          | Faking DNS responses to redirect victims                             |
| **MITM Attacks**          | Intercepting/modifying traffic between endpoints                     |
| **Ping of Death**         | Sending malformed/oversized packets                                  |
| **SMB Exploits**          | Using EternalBlue or SMB-based exploits                              |

### 🌐 Web Application Attacks (Detectable via Logs & WAF Rules)

| Attack Type                    | Description                                                       |
| ------------------------------ | ----------------------------------------------------------------- |
| **SQL Injection (SQLi)**       | Injecting malicious SQL via input fields                          |
| **Cross-Site Scripting (XSS)** | Injecting scripts into web pages to steal data or hijack sessions |
| **Command Injection**          | Injecting OS commands through input                               |
| **Directory Traversal**        | Accessing restricted directories via `../` payloads               |
| **File Upload Bypass**         | Uploading malicious files via vulnerable endpoints                |
| **Local File Inclusion (LFI)** | Including local files from the server                             |
| **Brute Force Login**          | Repeated login attempts to web forms                              |

## 📂 Project Structure

```
.
├── docs/
│   └── architecture.png
├── configs/
│   ├── suricata.yaml
│   ├── filebeat.yml
│   └── syslog.conf
├── scripts/
│   └── attack-simulation.sh
├── reports/
│   └── threat-analysis.md
└── README.md
```

## 📚 References

* [Wazuh Documentation](https://documentation.wazuh.com/)
* [Suricata Official Site](https://suricata.io/)
* [Syslog Basics](https://linux.die.net/man/5/syslog.conf)
* [EICAR Test File](https://www.eicar.org/?page_id=3950)

## 🤖 Future Enhancements

* 🔗 Integration with MISP for threat intelligence
* ♻️ Automated Incident Response with TheHive or Shuffle
* 📦 Docker Compose setup for automated deployment
* 📊 Elastic Stack tuning and custom dashboards

 ## Output 

## 🤝 Contributing

Contributions are welcome! Please open issues and pull requests for new ideas, bug fixes, or improvements.

## 🛡️ License

This project is licensed under the MIT License. See `LICENSE` for details.

## 🔍 Contact

Maintained by [Your Name](https://github.com/yourusername)
📧 [your.email@example.com](mailto:your.email@example.com)
🔗 LinkedIn | GitHub | Twitter
