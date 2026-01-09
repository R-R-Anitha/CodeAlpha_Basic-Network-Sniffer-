# 🛡️ Network Packet Sniffer using Python & Scapy

This project is a **basic network packet sniffer** built using **Python** and the **Scapy** library.
It captures live network traffic and analyzes packets to display useful information such as **IP addresses, protocols, ports, and payload data**.

This project helps in understanding **how data flows through a network** and the **structure of different network protocols**.

---

## 📌 Features

* Captures live network packets
* Identifies **IP packets**
* Detects and analyzes:

  * TCP packets
  * UDP packets
  * ICMP packets
* Displays:

  * Source IP address
  * Destination IP address
  * Protocol type
  * Source and destination ports
  * Payload data (if available)
* Real-time packet analysis

---

## 🛠️ Technologies Used

* **Python 3**
* **Scapy** (for packet sniffing and analysis)
* **Networking Protocols**

  * IP
  * TCP
  * UDP
  * ICMP

---

## 📂 Project Structure

```
network-sniffer/
│
├── sniffer.py        # Main Python file
├── README.md         # Project documentation
```

---

## 🚀 How the Program Works

1. The program starts sniffing network packets using Scapy’s `sniff()` function.
2. Each captured packet is passed to the `analyze_packet()` function.
3. The function:

   * Checks whether the packet contains an **IP layer**
   * Extracts source and destination IP addresses
   * Identifies the protocol (TCP / UDP / ICMP)
   * Displays port numbers and payload data (if present)
4. The packet details are printed in a readable format on the terminal.

---

## ▶️ How to Run the Program

### Step 1: Install Scapy

```bash
pip install scapy
```

### Step 2: Run the Script (Administrator / Root required)

**Windows (Run CMD as Administrator):**

```bash
python sniffer.py
```

**Linux / macOS:**

```bash
sudo python3 sniffer.py
```

---

## 🧪 Sample Output

```
==============================
📦 Packet Captured
==============================
Source IP      : 192.168.1.5
Destination IP : 142.250.183.14
Protocol       : TCP
Source Port    : 51523
Dest Port      : 443
Payload        : b'...'
```

---

## ⚠️ Important Notes

* This program must be run with **administrator/root privileges**.
* Packet sniffing should be done **only on networks you own or have permission to monitor**.
* This project is intended for **educational purposes only**.

---

## 🎯 Learning Outcomes

* Understanding packet structure
* Learning how TCP, UDP, and ICMP work
* Practical exposure to network monitoring
* Hands-on experience with Scapy

---

## 📜 License

This project is open-source and free to use for learning and educational purposes.

---

## 🙌 Author

**Anitha Ramaraj**
Computer Science / Cybersecurity Enthusiast
 
