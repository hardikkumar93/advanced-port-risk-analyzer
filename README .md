# Advanced Port Risk Analyzer 🔐

Advanced Port Risk Analyzer is a Python-based cybersecurity tool that scans open ports of a target IP address or website within a specified range. It not only detects open ports but also performs detailed security analysis, risk classification, and generates professional reports for better understanding of network security.

---

## 🚀 Features

### 🔍 Port Scanning
- Scans open ports of a target IP/website within a custom range  
- Uses socket programming for fast and efficient scanning  

### 🧠 Service Detection
- Identifies services running on open ports (HTTP, SSH, FTP, DNS, databases, etc.)

### ⚠️ Risk Analysis
- Classifies each open port into Low / Medium / High risk levels  
- Provides detailed explanations for why a service is risky  

### 🛡️ Security Recommendations
- Suggests secure alternative services (e.g., FTP → SFTP, Telnet → SSH, HTTP → HTTPS)  
- Provides improvement suggestions for better security  

### 📊 Reporting System
- Generates structured TXT reports  
- Generates professional PDF reports using ReportLab  
- Displays scan results in real-time  

### ⚙️ Utility Features
- Input validation for website/IP address  
- Port range validation  
- Scan time measurement  
- Handles unknown services gracefully  

---

## 🛠️ Technologies Used
- Python  
- Socket Programming  
- Time Module  
- ReportLab (PDF generation)

---

## ▶️ How to Run

```bash
python main.py
