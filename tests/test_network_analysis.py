import dpkt
import pytest
from src.backend.network_analysis.packet_analyzer import PacketAnalyzer

@pytest.fixture
def sample_pcap():
    eth = dpkt.ethernet.Ethernet()
    eth.data = dpkt.ip.IP(
        src=b'\xc0\xa8\x01\x01',
        dst=b'\xc0\xa8\x01\x02',
        data=dpkt.tcp.TCP(dport=80)
    )
    return eth.pack()

def test_packet_processing():
    analyzer = PacketAnalyzer()
    stats = analyzer.analyze_pcap("tests/data/sample.pcap")
    assert stats['total_packets'] > 0
    assert 'TCP' in stats['protocols']

def test_port_scan_detection():
    analyzer = PacketAnalyzer()
    for _ in range(100):
        analyzer._process_packet(sample_pcap())
    assert analyzer.stats['port_scan_attempts'] > 50

def test_malicious_ip_blocking():
    analyzer = PacketAnalyzer()
    analyzer._check_malicious_ip("94.130.14.15")
    assert "94.130.14.15" in analyzer.stats['suspicious_ips']

def test_threshold_alerting():
    analyzer = PacketAnalyzer()
    analyzer.metadata['threshold'] = 0.7
    assert analyzer._trigger_alert({'score': 0.8}) is True
    assert analyzer._trigger_alert({'score': 0.6}) is False
