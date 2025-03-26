# SecureFlow Local Network Quick Start

## 1. Prerequisites
- Linux host (Ubuntu 22.04/CentOS 8)
- 4+ CPU cores, 8GB+ RAM
- 50GB+ disk space

##  Setup
# Clone repo
- git clone https://github.com/yourorg/SecureFlow-AI-Cybersecurity.git
- cd SecureFlow-AI-Cybersecurity/Setup

# Make scripts executable
chmod +x *.sh

# Run setup (as root)
- sudo ./setup.sh


# Start Services

# Start all components
- ./run.sh

# Verify system
- ./TEST_SYSTEM.SH

# Access Interfaces
Service	URL
- Dashboard	https://<local-ip>:3000
- API Docs	https://<local-ip>:8000/docs
- Splunk SIEM	https://<local-ip>:8008
# Test Detection
# Simulate phishing attempt
curl -k -X POST https://localhost:8000/api/threats/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"http://malicious.site"}'

  # Troubleshooting
- Port Conflicts: Update ports in docker-compose.yml
- Reset System: docker-compose down -v
- Logs: Check /var/secureflow/logs


---

**Usage Workflow:**  
1. **Initialize**: `sudo ./setup.sh`  
2. **Launch**: `./run.sh`  
3. **Verify**: `./TEST_SYSTEM.SH`  
4. **Access**: Open `https://[local-ip]:3000`  

This setup enables local network deployment with production-grade security configurations while maintaining developer accessibility.
