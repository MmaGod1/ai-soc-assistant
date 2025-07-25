# AI SOC Assistant - PCAP Threat Analyzer

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)

A powerful AI-driven Security Operations Center (SOC) assistant that analyzes PCAP files to detect malicious network activity, lateral movement, and indicators of compromise. This tool leverages advanced AI analysis to provide professional-grade threat reports suitable for enterprise security teams.

## 🚀 Features

- **Intelligent PCAP Analysis**: Deep packet inspection with protocol-aware parsing
- **AI-Powered Threat Detection**: Uses advanced language models for threat analysis
- **Real-time DNS Monitoring**: Tracks DNS queries and responses with suspicious domain detection
- **Lateral Movement Detection**: Identifies DCSync attacks, LDAP reconnaissance, and Kerberos anomalies
- **Professional Reporting**: Generates structured IOC reports with actionable recommendations
- **Interactive Web Interface**: Clean Streamlit-based UI for easy file uploads and analysis
- **Comprehensive Protocol Support**: Handles TCP, UDP, DNS, LDAP, Kerberos, TLS, and more

## 📋 Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Features Overview](#features-overview)
- [File Structure](#file-structure)
- [Supported Protocols](#supported-protocols)
- [AI Analysis Capabilities](#ai-analysis-capabilities)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🛠 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3-pip python3-venv tshark wireshark-common
```

**CentOS/RHEL:**
```bash
sudo yum install python3-pip wireshark wireshark-cli
```

**macOS:**
```bash
brew install python3 wireshark
```

**Windows:**
- Install [Python 3.8+](https://python.org/downloads/)
- Install [Wireshark](https://www.wireshark.org/download.html)
- Add Wireshark to system PATH

### Python Environment Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MmaGod1/ai-soc-assistant.git
   cd ai-soc-assistant
   ```

2. **Create virtual environment:**
   ```bash
   python3 -m venv myenv
   source myenv/bin/activate  # On Windows: myenv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Requirements.txt

Create a `requirements.txt` file with the following contents:

```txt
streamlit==1.28.1
pyshark==0.6
openai==1.3.5
python-dotenv==1.0.0
pandas==2.1.3
numpy==1.24.3
requests==2.31.0
```

```bash
# Code formatting
black *.py
flake8 *.py
```
## ⚙️ Configuration

### 1. API Key Setup

Create a `.env` file in the project root directory:

```env
# OpenRouter API Configuration
DEEPSEEK_API_KEY=your_api_key_here

# Optional: Custom API endpoints
API_BASE_URL=https://openrouter.ai/api/v1
API_MODEL=deepseek/deepseek-r1-0528:free
```

**Getting an API Key:**
1. Visit [OpenRouter.ai](https://openrouter.ai/)
2. Create an account and navigate to the API section
3. Generate a new API key
4. Copy the key to your `.env` file
✅ Note: I used the DeepSeek R1 Free model on OpenRouter.ai.

### 2. File Structure

Ensure your project structure looks like this:

```
ai-soc-assistant/
├── main.py              # Streamlit main application
├── analyzer.py          # PCAP processing and DNS extraction
├── prompt_engine.py     # AI prompt building and API calls
├── requirements.txt     # Python dependencies
├── .env                # API keys and configuration
├── README.md           # This file
└── .gitignore          # Tgnores my API key and __pycachea__
```

## 🚀 Usage

### 1. Start the Application

```bash
# Activate virtual environment
source myenv/bin/activate  # On Windows: myenv\Scripts\activate

# Launch Streamlit application
streamlit run main.py
```

### 2. Access the Web Interface

Open your browser and navigate to:
- **Local access**: `http://localhost:8501`

### 3. Analyzing PCAP Files

1. **Upload PCAP File**: Click "Browse files" and select your `.pcap` or `.pcapng` file
2. **Wait for Analysis**: The system will process over  35,000 packets
3. **Review Results**: Get a comprehensive threat analysis report


## 🔍 Features Overview

### DNS Analysis
- **Query Tracking**: Monitors all DNS queries with deduplication
- **Response Mapping**: Maps domains to resolved IP addresses
- **Suspicious Domain Detection**: Identifies typo-squatting and malicious domains
- **Real-time Alerts**: Flags suspicious domains (e.g., `authenticatoor.org`)

### Protocol Analysis
- **Multi-Protocol Support**: TCP, UDP, DNS, LDAP, Kerberos, TLS, HTTP, DHCP
- **Malformed Packet Detection**: Identifies protocol anomalies and exploit attempts
- **Session Reconstruction**: Builds complete communication flows

### AI Threat Analysis
- **Professional Reporting**: Structured IOC analysis with MITRE ATT&CK mapping
- **Lateral Movement Detection**: DCSync, Golden Ticket, and credential theft identification
- **Actionable Recommendations**: Specific mitigation steps and forensic actions
- **Threat Severity Assessment**: Risk-based prioritization

### Debug Output
```
================================================================================
TYPE       | DOMAIN/RESULT                                    | IP             
================================================================================
QUERY      | mobile.events.data.microsoft.com
RESPONSE   | www.tm.ak.prd.aadg.akadns.net                    → 20.190.157.13
🚨 ALERT   | authenticatoor.org                               → 62.210.123.45
================================================================================
SUMMARY    | Unique DNS queries: 112
SUMMARY    | Unique DNS responses: 139
SUMMARY    | Total sessions extracted: 35000
================================================================================
```

## 📁 File Structure Details

### main.py
- Streamlit web interface
- File upload handling
- Progress indicators
- Results display

### analyzer.py
- PCAP file processing with pyshark
- DNS query/response extraction
- Protocol detection and parsing
- Session data structuring

### prompt_engine.py
- AI prompt construction
- OpenRouter API integration
- Response processing
- Error handling

## 🌐 Supported Protocols

| Protocol | Detection | Analysis Level |
|----------|-----------|----------------|
| DNS | ✅ Full | Query/Response mapping, suspicious domains |
| LDAP | ✅ Full | Malformed packets, reconnaissance detection |
| Kerberos | ✅ Full | Ticket requests, Golden Ticket detection |
| TLS/SSL | ✅ Partial | SNI extraction, certificate analysis |
| HTTP | ✅ Partial | Host/URI extraction, suspicious requests |
| TCP | ✅ Basic | Connection tracking, port analysis |
| UDP | ✅ Basic | Service identification, anomaly detection |
| DHCP | ✅ Basic | Host identification, network mapping |

## 🤖 AI Analysis Capabilities

### Threat Detection
- **Malware Communication**: C2 traffic, beaconing patterns
- **Lateral Movement**: DCSync, DRSUAPI, credential theft
- **Reconnaissance**: Network scanning, service enumeration
- **Data Exfiltration**: Unusual traffic patterns, large transfers

### Report Structure
1. **Executive Summary**: High-level findings and risk assessment
2. **IOCs**: Specific indicators with confidence levels
3. **Threat Assessment**: Detailed analysis with MITRE ATT&CK mapping
4. **Recommendations**: Immediate actions and long-term hardening

### Supported AI Models
- DeepSeek R1 (default)
- GPT-4 (via OpenRouter)
- Claude 3 (via OpenRouter)
- Custom models (configurable)

## 🔧 Troubleshooting

### Common Issues

**1. Import Error: No module named 'pyshark'**
```bash
# Ensure tshark is installed and in PATH
which tshark
# Reinstall pyshark
pip uninstall pyshark
pip install pyshark==0.6
```

**2. Permission Denied Errors**
```bash
# Linux/macOS: Fix wireshark permissions
sudo usermod -a -G wireshark $USER
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

**3. API Key Errors**
```bash
# Verify .env file exists and contains valid key
cat .env
# Test API connectivity
curl -H "Authorization: Bearer $DEEPSEEK_API_KEY" https://openrouter.ai/api/v1/models
```

**4. Large PCAP Files**
- I've only tested with a little over 35,000 packets
- Ypu can modify in `analyzer.py`: `if i >= 35000:`
- Consider splitting large files

**5. Memory Issues**
```bash
# Increase system limits
ulimit -v 8388608  # 8GB virtual memory
# Or reduce packet limit in analyzer.py
```

### Debug Mode

Enable verbose debugging:

```python
# In analyzer.py, add after imports:
import logging
logging.basicConfig(level=logging.DEBUG)
```

```
# Skip certain protocols
IGNORE_PROTOCOLS = {"ARP", "SSDP", "ICMP", "NBNS", "MDNS", "DHCP"}
```

## 🙏 Acknowledgments

- **Wireshark Team**: For the excellent packet analysis foundation
- **Streamlit**: For the intuitive web framework
- **OpenRouter**: For AI model access
- **Python Community**: For the amazing ecosystem

---

**⚠️ Security Notice**: This tool is designed for authorized security testing only. Always ensure you have proper authorization before analyzing network traffic.

**🔒 Privacy**: PCAP files may contain sensitive information. Ensure compliance with data protection regulations when using this tool.
