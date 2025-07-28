
# 🔎 Network Packet Sniffer & Live Analysis Dashboard

## 📌 Project Overview
This project is a **Python-based network packet analyser** with a built-in **real-time dashboard** built using **Flask** and **Scapy**. It captures, analyzes, and visualizes live network traffic on a local machine, helping users monitor IP packets, protocols, and suspicious patterns in real time.

## 🎯 Key Features
- **📡 Real-Time Packet Sniffing**  
  Captures packets using the `scapy` library and displays key metadata (timestamp, source IP, destination IP, protocol).

- **🖥️ Web-Based Dashboard**  
  Built with Flask and HTML/CSS, the dashboard dynamically updates every 2 seconds to show the latest traffic.

- **⚙️ Modular Design**  
  Uses a clean project structure with reusable components (`utils/parser.py`) for extracting and processing packet data.

- **🧩 Extensible**  
  Built with scalability in mind – easily extend to support filtering, saving PCAP files, protocol graphs, or basic intrusion detection.

## 🛠️ Technologies Used
- Python 3
- Flask (for the web server)
- Scapy (for packet sniffing)
- HTML/CSS (dashboard interface)
- JavaScript (for live updates)

## 📂 Project Structure
```
network_analyser_dashboard/
├── app.py                  # Main Flask application
├── templates/
│   └── index.html          # Web dashboard UI
├── utils/
│   └── parser.py           # Packet parsing and extraction logic
```

## 🚀 Getting Started

### 1. Install Dependencies
```bash
pip install flask scapy
```

### 2. Run the App
```bash
python app.py
```

### 3. View Dashboard
Open your browser and go to: [http://127.0.0.1:5000](http://127.0.0.1:5000)

## 📌 Use Case Scenarios
- Educational tool for learning how packet sniffing works.
- Lightweight internal tool for basic network monitoring.
- Foundation for building a custom intrusion detection or SIEM solution.

## 📈 Future Improvements
- Protocol filtering (TCP/UDP/ICMP)
- Alert system for suspicious IPs or behavior
- Export to CSV/PCAP
- Graphs and traffic trends (Matplotlib or Chart.js)
- Authentication for dashboard access
