# 🛡️ T-SCAN (Terminal Version) ![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)

T-SCAN is a terminal-based cybersecurity tool that scans URLs, file hashes, IP addresses, and email addresses using the VirusTotal API. It provides a lightweight and effective solution for threat intelligence analysis, displaying scan results with an easy-to-read pie chart directly in the terminal.

---

## 🚀 Features

- 🧠 Supports scanning **file hashes** (MD5, SHA1, SHA256)
- 🌐 Accepts **URLs** and checks for malicious activity
- 🖥️ Analyzes **IP addresses** for any signs of malicious activities
- 📧 Detects suspicious **email addresses** based on known patterns and free email services
- 🔍 Displays results with a **text-based pie chart** in the terminal
- 📝 Automatically generates and saves a scan report to a text file
- 📈 Built with **Python** and integrates with the **VirusTotal Public API**

---

## 📦 Requirements

- Python 3.x
- `requests` library
- `colorama` library

To install the dependencies, run the following:

```bash
pip install requests colorama

🚀 Installation
Example :- git clone https://github.com/opac-sec/T-SCAN.git
           cd T-SCAN
           pip install -r requirements.txt


🖥️ Usage
python tscan.py
 Example: 🔗 T-SCAN > Enter target (or type 'exit' to quit): 192.168.1.1


Example Output:
Scan input: 192.168.1.1
Malicious: 0
Harmless: 3
Suspicious: 0
Total Engines: 3
Malicious %: 0.0%
----------------------------------------

📈 Example Output in Terminal:
████████╗     ███████╗ ██████╗  █████╗ ███╗   ██╗
╚══██╔══╝     ██╔════╝██╔════╝ ██╔══██╗████╗  ██║
   ██║█████╗  ███████╗██║  ███╗███████║██╔██╗ ██║
   ██║╚════╝  ╚════██║██║   ██║██╔══██║██║╚██╗██║
   ██║        ███████║╚██████╔╝██║  ██║██║ ╚████║
   ╚═╝        ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

  🔍 Lightweight Threat Intelligence Scanner
  👨‍💻 Developed by: Abhay Patel
  📁 Output saved to: output_report.txt
----------------------------------------

Scan input: 192.168.1.1
Malicious: 0
Harmless: 3
Suspicious: 0
Total Engines: 3
Malicious %: 0.0%

Malicious: ██████████████ 0.0%
Harmless: ██████████████████████████ 100.0%
Suspicious: ██████ 0.0%
----------------------------------------

