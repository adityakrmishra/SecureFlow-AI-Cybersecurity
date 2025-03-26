import pytest
import pandas as pd
from src.backend.scripts.data_ingestion import DataIngestor

@pytest.fixture
def ingestor():
    return DataIngestor(config_path="tests/data/ingestion_config.json")

def test_pcap_processing(ingestor, tmp_path):
    output = tmp_path / "output.parquet"
    ingestor.process_file("tests/data/sample.pcap", output)
    df = pd.read_parquet(output)
    assert not df.empty
    assert "threat_type" in df.columns

def test_csv_enrichment(ingestor):
    test_data = [{"src_ip": "8.8.8.8", "protocol": 6}]
    enriched = ingestor.enrich_ioc(test_data[0])
    assert "confidence" in enriched
    assert 0 <= enriched["confidence"] <= 1

def test_encryption(ingestor):
    test_data = {"src_ip": "192.168.1.1"}
    encrypted = ingestor._encrypt_sensitive(test_data)
    assert encrypted["src_ip"] != test_data["src_ip"]

def test_corrupt_file(ingestor, caplog):
    with pytest.raises(ValueError):
        ingestor.process_file("tests/data/corrupt.pcap", "dummy.parquet")
    assert "Processing failed" in caplog.text
