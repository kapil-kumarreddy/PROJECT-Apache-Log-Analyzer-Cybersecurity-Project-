# 🔍 Apache Log Analyzer (Cybersecurity Project)

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)  
[![Cybersecurity](https://img.shields.io/badge/Field-Cybersecurity-red)]()  
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  
[![Status](https://img.shields.io/badge/Project-Active-brightgreen)]()  

---

## 📌 Project Overview

The **Apache Log Analyzer** is a cybersecurity project that parses and analyzes **Apache web server logs** to detect suspicious activities.  
It helps in identifying:
- 🚨 DoS/Brute Force attempts  
- 🕵️ Malicious User-Agents (bots/crawlers)  
- 🌍 Attack origins using GeoIP lookup  
- ⚠️ Error anomalies (404 floods, server misconfigurations)  
- 📑 Session tracking for suspicious IPs  

The tool also generates a **professional PDF report** with summarized findings.

---

## 🚀 Features
- ✅ Log parsing into structured format (IP, time, method, URL, status, etc.)  
- ✅ Detects **suspicious IPs** exceeding request thresholds  
- ✅ Finds **malicious URLs** (e.g., `/admin`, `/wp-login.php`)  
- ✅ Tracks **user-agents** for bot detection  
- ✅ Performs **GeoIP analysis** for country-based attacks  
- ✅ Exports results to **CSV and PDF report**  
- ✅ Visualizations using Matplotlib  

---

## 📊 Example Outputs

**Suspicious IPs (High Requests):**
