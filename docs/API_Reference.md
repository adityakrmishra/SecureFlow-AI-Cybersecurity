# SecureFlow API Reference

## Overview
The SecureFlow API provides endpoints for threat detection, network analysis, and incident response automation.

---

## Authentication
```http
POST /api/auth/token
{
  "username": "your_username",
  "password": "your_password"
}
```
Response:\
```
{
  "access_token": "eyJhbGciOi...",
  "token_type": "bearer"
}
```
Include token in headers:
- Authorization: Bearer <access_token>

## Threat Detection Endpoints
### Analyze Network Traffic
```
POST /api/threats/analyze
```
Request Body:
```
{
  "packet_data": "base64_encoded_pcap",
  "source_ip": "192.168.1.100",
  "timestamp": "2023-08-20T14:30:00Z"
}
```
Response:
```
{
  "threat_level": "high",
  "indicators": ["CobaltStrike_Beacon"],
  "recommended_actions": ["isolate_host", "block_domain"]
}
```
### Check File Hash
- GET /api/threats/hash/{file_hash}
  Response:
  ```
  {
  "hash": "a5c0a0e465a52034682d8e70b3d793fc",
  "threat_type": "ransomware",
  "confidence": 0.98
}

### Network Analysis Endpoints
 Get Traffic Statistics
 ```
GET /api/network/stats?hours=24
```
Response:
```
{
  "total_packets": 150000,
  "suspicious_ips": ["94.130.14.15"],
  "protocol_distribution": {"TCP": 65, "UDP": 30, "ICMP": 5}
}
```
### Packet Capture Analysis
- POST /api/network/pcap
  Request Body: Raw PCAP file
  Response:
  ```
  {
  "detected_threats": 3,
  "malicious_patterns": ["Mimikatz", "CobaltStrike"],
  "risk_score": 92.5
}
### Incident Response Endpoints
Execute Playbook
- POST /api/response/execute
  ```
  {
  "playbook_id": "ransomware-001",
  "parameters": {
    "infected_host": "192.168.1.100",
    "iocs": ["94.130.14.15", "malicious-domain.xyz"]
  }
}
Response:
```
{
  "status": "contained",
  "actions_taken": ["host_isolated", "firewall_updated"],
  "timestamp": "2023-08-20T14:35:00Z"
}
```
## Error Codes
Code	Message	Description
401	Unauthorized	Missing/invalid credentials
429	Rate Limit Exceeded	Too many requests (100/min)
500	Internal Server Error	Server-side processing error
```

**2. `docs/architecture_diagram.pdf` Description**  
*(Text description since PDF can't be generated here)*

**SecureFlow Architecture Overview**
```
```
                      +---------------------+
                      |   Frontend Dashboard |
                      | (React/Tailwind CSS) |
                      +----------+----------+
                                 |
                                 | REST API
                                 v

+----------------+ +---------+---------+
| SIEM Tools +<------->| SecureFlow API |
| (Splunk/ELK) | | (Python/FastAPI) |
+----------------+ +---------+---------+
^
|
+--------------+--------------+
| |
+-----+-----+ +-------+-------+
| ML Models | | Threat Intel |
| (PyTorch) +<------------->| (VirusTotal) |
+-----------+ +---------------+
^
|
+----------------+ | +-----------------+
| Network Sensors+----+-------->| PostgreSQL DB |
| (PacketBeats) | | (Threat Storage) |
+----------------+ +-----------------+
```

**Key Components:**  
1. **Data Ingestion Layer**: Network sensors collect raw traffic data  
2. **Processing Layer**: FastAPI service handles data normalization  
3. **AI Layer**: PyTorch models for anomaly detection  
4. **Storage Layer**: PostgreSQL for threat intelligence  
5. **Integration Layer**: SIEM tools and external threat feeds  
6. **Presentation Layer**: React dashboard for visualization  

**Data Flow:**  
`Sensors → API → ML Models → Threat Intel DB → SIEM/Dashboard`  

**Security Features:**  
- JWT Authentication  
- Rate Limiting  
- Input Validation  
- Encrypted Communications (HTTPS)  
- Automated Playbook Execution  

This architecture supports real-time threat detection and response at scale.
