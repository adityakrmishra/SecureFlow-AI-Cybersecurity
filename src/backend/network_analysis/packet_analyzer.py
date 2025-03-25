"""
Real-time Network Packet Analyzer with Threat Detection
"""


import dpkt
import socket
import logging
from collections import defaultdict
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class PacketAnalyzer:
    """Network traffic analysis and anomaly detection"""
    
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'suspicious_ips': defaultdict(int),
            'port_scan_attempts': 0
        }
        self.threat_signatures = {
            'ransomware_ports': [3389, 445, 1433],
            'malicious_ips': self._load_threat_intel()
        }

    def analyze_pcap(self, file_path: str) -> Dict:
        """Analyze pcap file for network threats"""
        try:
            with open(file_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    self._process_packet(buf)
            return self.stats
        except Exception as e:
            logger.error(f"PCAP analysis failed: {str(e)}")
            raise

    def live_capture(self, interface: str = 'eth0', count: int = 100):
        """Capture live network traffic"""
        import pcap
        pc = pcap.pcap(interface)
        pc.setfilter('tcp')
        logger.info(f"Starting live capture on {interface}")
        
        for _ in range(count):
            ts, buf = pc.next()
            self._process_packet(buf)

    def _process_packet(self, packet: bytes):
        """Process individual network packet"""
        self.stats['total_packets'] += 1
        
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            tcp = ip.data
            
            # Protocol analysis
            self.stats['protocols'][ip.p] += 1
            
            # Threat detection
            self._detect_port_scan(ip, tcp)
            self._check_malicious_ip(ip.src)
            self._check_ransomware_ports(tcp.dport)
            
        except Exception as e:
            logger.debug(f"Packet processing error: {str(e)}")

    def _detect_port_scan(self, ip, tcp):
        """Detect port scanning patterns"""
        if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
            self.stats['port_scan_attempts'] += 1
            logger.warning(f"Potential port scan detected from {socket.inet_ntoa(ip.src)}")

    def _check_malicious_ip(self, ip: bytes):
        """Check IP against threat intelligence"""
        ip_str = socket.inet_ntoa(ip)
        if ip_str in self.threat_signatures['malicious_ips']:
            self.stats['suspicious_ips'][ip_str] += 1
            logger.critical(f"Malicious IP detected: {ip_str}")

    def _load_threat_intel(self) -> List[str]:
        """Load known malicious IPs"""
        # Implement threat intel feed integration
        return ['94.130.14.15', '192.42.116.41']

if __name__ == "__main__":
    analyzer = PacketAnalyzer()
    analyzer.live_capture(count=50)
