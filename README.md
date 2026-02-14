# MiroMap 🗺️🔒

**Real-time Network Security Monitoring & Visualization on Miro Boards**

MiroMap transforms invisible network security into a collaborative visual experience. Automatically discover devices, detect threats, and visualize your network topology—all in real-time on Miro.

![MiroMap Demo](https://img.shields.io/badge/Status-Active-success) ![Python](https://img.shields.io/badge/Python-3.8+-blue) ![React](https://img.shields.io/badge/React-18+-61dafb)

---

## 🎯 What is MiroMap?

MiroMap is a **visual network security monitoring tool** that bridges the gap between traditional CLI-based network tools and modern collaborative workspaces. It automatically discovers devices on your network, performs deep security analysis, and creates real-time visual representations on Miro boards.

### Key Features

- 🔍 **Instant Device Discovery** - Active ARP scanning finds all network devices in seconds
- 🎯 **Deep Device Fingerprinting** - Optional nmap scans reveal OS, services, and open ports
- 🚨 **Security Threat Detection** - Real-time ARP poisoning/spoofing detection
- 📊 **Visual Network Mapping** - Automatic device shapes on Miro boards
- 🔄 **Live Synchronization** - Network state updates reflected instantly
- 🎨 **Separated Alert Areas** - Security alerts displayed separately from devices
- 👥 **Collaborative Security** - Teams can annotate and discuss threats together

---

## 💡 Unique Value Propositions

### 1. **Visual-First Security**
Unlike traditional CLI tools (Wireshark, tcpdump, nmap), MiroMap makes network security **visual and accessible**. Non-technical stakeholders can understand network topology at a glance.

### 2. **Zero-Configuration Discovery**
- No agents to install on devices
- No manual network mapping required
- Works immediately on any network you're connected to
- Passive + active scanning discovers everything automatically

### 3. **Security + Documentation in One**
Most tools either monitor OR document. MiroMap does both:
- **Monitoring**: Real-time device status, security alerts, threat detection
- **Documentation**: Auto-generated network diagrams, always up-to-date

### 4. **Collaborative Network Operations**
- Security teams can annotate threats directly on Miro boards
- Network diagrams stay automatically synchronized
- Perfect for remote teams managing distributed networks
- Discuss incidents in context using Miro's collaboration features

### 5. **Speed Optimized**
- **Instant discovery**: Devices appear in 2-3 seconds via ARP
- **Optional deep scanning**: Click "Deep Scan" only when you need details
- **No waiting**: Removed automatic nmap delays for better UX

---

## 🚀 Why MiroMap is Useful

### For IT & Security Teams
✅ **"What's on my network?"** - Instant visibility into all connected devices  
✅ **"Is this a security threat?"** - Real-time ARP poisoning detection  
✅ **"How do I explain this to management?"** - Visual, collaborative diagrams  
✅ **"Is my documentation current?"** - Always up-to-date, automatically  

### For Small Businesses
✅ **"Is someone unauthorized on my WiFi?"** - See every device instantly  
✅ **"What devices are connected?"** - Complete network inventory  
✅ **"How do I detect attacks?"** - Free, automatic threat detection  

### For Developers & DevOps
✅ **"What services are running?"** - Port scanning and service detection  
✅ **"How's my local network configured?"** - Visual topology mapping  
✅ **"Can I extend this?"** - Open architecture, API-first design  

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Miro Board                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Device     │  │   Device     │  │   Device     │  │
│  │  (y=-500)    │  │  (y=-500)    │  │  (y=-500)    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐                     │
│  │ 🚨 Alert     │  │ 🚨 Alert     │  (y=500)            │
│  └──────────────┘  └──────────────┘                     │
└─────────────────────────────────────────────────────────┘
                           ▲
                           │ Miro SDK
                           │
┌──────────────────────────┴──────────────────────────────┐
│                  MiroMap Backend (Python)                │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│  │ ARP Scan   │  │ Security   │  │ Nmap Scan  │        │
│  │ (Active)   │  │ Detection  │  │ (Optional) │        │
│  └────────────┘  └────────────┘  └────────────┘        │
└─────────────────────────────────────────────────────────┘
                           ▲
                           │ Network Traffic
                           │
                    ┌──────┴──────┐
                    │   Network   │
                    │   Devices   │
                    └─────────────┘
```

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- Miro account with API access
- Linux/macOS (for network scanning)

### Backend Setup

```bash
# Clone repository
git clone https://github.com/keanlouis30/MiroMap.git
cd MiroMap

# Create virtual environment
python3 -m venv .miromap-venv
source .miromap-venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Miro credentials
```

### Frontend Setup

```bash
cd miromap
npm install
npm run build
```

### Environment Variables

Create a `.env` file:
```env
MIRO_ACCESS_TOKEN=your_miro_access_token
MIRO_BOARD_ID=your_miro_board_id
```

---

## 🎮 Usage

### 1. Start the Scanner

```bash
sudo python scanner.py
```

You'll see:
```
[SCANNER] Starting active ARP scan...
[ARP SCAN] Scanning 192.168.1.0/24...
[ARP SCAN] Found: 192.168.1.105 (9c:53:22:40:c0:91)
[ARP SCAN] Complete. Found 8 new devices, 8 total responses
```

### 2. Open Miro App

- Open your Miro board
- Install the MiroMap app
- Click "🔍 Scan Network" for instant discovery
- Click "Sync to Board" to create device shapes

### 3. Deep Scan Devices

- Click "🔍 Deep Scan" on any device
- Wait ~5 seconds for nmap results
- View OS, hostname, ports, and services

### 4. Monitor Security

- ARP poisoning attacks trigger automatic alerts
- Red sticky notes appear at y=500
- Frontend shows alert details with conflicting MACs

---

## 🔒 Security Features

### ARP Poisoning Detection

MiroMap detects when multiple MAC addresses claim the same IP:

```
⚠️  [SECURITY ALERT] ARP Poisoning Detected: Multiple MACs claiming IP 192.168.1.1
    Conflicting MACs: aa:bb:cc:dd:ee:ff, 00:11:22:33:44:55
    Vendors: Unknown Device, Apple
```

**Alerts appear in:**
- Console output
- Frontend UI (red border)
- Miro board (red sticky notes)

### Testing Security Detection

```bash
# Simulate ARP poisoning attack
sudo python3 test_arp_poisoning.py 192.168.1.1 aa:bb:cc:dd:ee:ff 00:11:22:33:44:55
```

---

## 🛠️ API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/devices` | GET | Get all discovered devices |
| `/alerts` | GET | Get security alerts |
| `/scan_network` | POST | Trigger network-wide ARP scan |
| `/scan_device` | POST | Trigger nmap scan for specific device |
| `/link_device` | POST | Link device to Miro shape |
| `/clear_alert` | POST | Acknowledge/clear security alert |

---

## 🎯 Use Cases

### Network Security Monitoring
- Detect unauthorized devices
- Identify ARP spoofing attacks
- Monitor device connections/disconnections
- Track network changes over time

### IT Documentation
- Auto-generate network topology diagrams
- Maintain up-to-date device inventory
- Document network architecture visually
- Collaborate on network planning

### Penetration Testing
- Discover attack surface
- Identify vulnerable services
- Test ARP poisoning detection
- Demonstrate security concepts

### Education
- Learn network protocols (ARP, TCP/IP)
- Understand security threats visually
- Practice network scanning techniques
- Teach collaborative security practices

---

## 🚧 Roadmap

- [ ] Multi-network support
- [ ] Historical device tracking
- [ ] Traffic flow visualization
- [ ] Integration with SIEM systems
- [ ] Mobile app with AR overlay
- [ ] AI-powered anomaly detection
- [ ] Compliance reporting
- [ ] Webhook notifications

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

MIT License - see LICENSE file for details

---

## 🙏 Acknowledgments

- Built with [Scapy](https://scapy.net/) for packet manipulation
- [Nmap](https://nmap.org/) for device fingerprinting
- [Miro SDK](https://developers.miro.com/) for visual collaboration
- [Flask](https://flask.palletsprojects.com/) for backend API
- [React](https://react.dev/) for frontend UI

---

## 📧 Contact

Created by [@keanlouis30](https://github.com/keanlouis30)

**MiroMap** - Making network security visual, collaborative, and accessible.
