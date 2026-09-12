<div align="center">
  <h1>🛡️ SOC IP Threat Analyzer & Abuse Reporter</h1>
  <p><i>A lightweight, API-free CLI tool for Blue Team analysts to automate Threat Intelligence and Abuse Reporting.</i></p>
  
  ![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
  ![License](https://img.shields.io/badge/License-MIT-green.svg)
  ![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)
</div>

---

**SOC IP Threat Analyzer** is a Python-based command-line utility designed specifically for Security Operations Center (SOC) environments. It streamlines the daily workflow of investigating malicious IP addresses and extracting crucial reporting data directly from the terminal. 

Instead of jumping between multiple browser tabs, this tool instantly pulls ASN details, Geolocation, Abuse Emails, and Blacklist status in a unified, hacker-friendly console interface—**without relying on any paid API subscriptions.**

## ✨ Key Features

* **Zero API Keys Required:** Utilizes public DNS Blacklists (DNSBL), open RDAP protocols, and public endpoints to gather intel.
* **Live Blacklist Checking:** Queries major DNSBL databases (Spamhaus, Spamcop, Barracuda) to determine the malicious footprint of an IP in real-time.
* **Smart Email Extraction:** Intelligently parses RDAP responses using regex to isolate the exact target email for generating abuse reports.
* **Interactive Terminal UI:** Built with the `rich` library to provide a clean, color-coded, and highly readable output.
* **Continuous Execution:** Runs in an interactive loop, allowing analysts to query multiple IPs sequentially without restarting the script.

## 🚀 Installation

1. Clone the repository to your local machine:
```bash
git clone https://github.com/Amirho3einAF/Abuse-Report.git
cd YOUR-REPO-NAME

2. Install the required Python dependencies:

```bash
pip install requests rich

```

## 💻 Usage

Launch the tool using Python. The program will prompt you to enter a target IP address.

```bash
python report_tool.py

```

**Example Output Flow:**

```text
=== SOC IP Abuse Report Tool ===
Enter Target IP: 8.8.8.8
[*] Analyzing Target IP: 8.8.8.8...
...

```

*(Type `exit`, `quit`, or `q` to safely close the interactive session).*

## 📸 Terminal Preview

*(📌 Note: Upload a screenshot of your terminal running the code and replace this image link!)*


## 🛠️ Under the Hood

* **Language:** Python 3
* **UI Formatting:** [Rich Library](https://rich.readthedocs.io/en/stable/)
* **Threat Intel Sources:** `ipinfo.io`, `rdap.org`, `DNSBL (socket)`

---
