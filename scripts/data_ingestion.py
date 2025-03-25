#!/usr/bin/env python3
"""
SecureFlow Data Ingestion Pipeline
Handles 100k+ records with threat intel enrichment
"""

import os
import re
import sys
import json
import gzip
import time
import logging
import argparse
from datetime import datetime, timedelta
from typing import Generator, Dict, List, Union

import pandas as pd
import numpy as np
import dpkt
import requests
from tqdm import tqdm
from pydantic import BaseModel, ValidationError
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('data_ingestion.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SecureFlowDataIngest')

class DataValidator(BaseModel):
    """Pydantic model for data validation"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: int
    length: int
    threat_type: Union[str, None] = None
    confidence: Union[float, None] = None

class DataIngestor:
    """Main data ingestion class with threat intel enrichment"""
    
    def __init__(self, config_path: str = 'config/ingestion_config.json'):
        self.config = self._load_config(config_path)
        self.fernet = Fernet(os.getenv('ENCRYPTION_KEY'))
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecureFlow/1.0 DataIngestor',
            'Authorization': f'Bearer {os.getenv("THREAT_INTEL_API_KEY")}'
        })
        
    def _load_config(self, path: str) -> Dict:
        """Load ingestion configuration"""
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Config load failed: {str(e)}")
            raise

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) is not None

    def _enrich_threat_intel(self, record: Dict) -> Dict:
        """Enrich data with threat intelligence"""
        try:
            response = self.session.post(
                self.config['threat_intel_url'],
                json={'indicators': [record['src_ip'], record['dst_ip']},
                timeout=5
            )
            if response.status_code == 200:
                threats = response.json().get('results', [])
                record['threat_type'] = threats[0]['type'] if threats else None
                record['confidence'] = threats[0]['confidence'] if threats else None
        except Exception as e:
            logger.warning(f"Threat intel failed: {str(e)}")
        return record

    def _process_pcap(self, file_path: str) -> Generator[Dict, None, None]:
        """Process PCAP files with dpkt"""
        logger.info(f"Processing PCAP: {file_path}")
        with open(file_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    yield {
                        'timestamp': datetime.utcfromtimestamp(ts),
                        'src_ip': socket.inet_ntoa(ip.src),
                        'dst_ip': socket.inet_ntoa(ip.dst),
                        'protocol': ip.p,
                        'length': len(ip)
                    }
                except Exception as e:
                    logger.debug(f"Packet error: {str(e)}")

    def _process_csv(self, file_path: str) -> pd.DataFrame:
        """Process CSV files with pandas"""
        logger.info(f"Processing CSV: {file_path}")
        return pd.read_csv(
            file_path,
            parse_dates=['timestamp'],
            dtype={
                'src_ip': 'category',
                'dst_ip': 'category',
                'protocol': 'uint8'
            }
        )

    def _encrypt_sensitive(self, data: Dict) -> Dict:
        """Encrypt sensitive fields"""
        if self.config.get('encrypt_fields'):
            for field in self.config['encrypt_fields']:
                if field in data:
                    data[field] = self.fernet.encrypt(
                        data[field].encode()
                    ).decode()
        return data

    def _save_data(self, data: List[Dict], output_path: str):
        """Save processed data with compression"""
        df = pd.DataFrame(data)
        
        if output_path.endswith('.parquet'):
            df.to_parquet(output_path, compression='snappy')
        elif output_path.endswith('.csv.gz'):
            df.to_csv(output_path, index=False, compression='gzip')
        else:
            df.to_json(output_path, orient='records', lines=True)
        
        logger.info(f"Saved {len(df)} records to {output_path}")

    def process_file(self, input_path: str, output_path: str):
        """Main processing pipeline"""
        records = []
        start_time = time.time()
        
        try:
            # Handle different file formats
            if input_path.endswith('.pcap'):
                data_gen = self._process_pcap(input_path)
            elif input_path.endswith('.csv'):
                data_gen = self._process_csv(input_path).to_dict('records')
            else:
                raise ValueError("Unsupported file format")

            # Processing loop with progress bar
            with tqdm(total=os.path.getsize(input_path)) as pbar:
                for record in data_gen:
                    # Validate and enrich
                    try:
                        validated = DataValidator(**record).dict()
                        enriched = self._enrich_threat_intel(validated)
                        encrypted = self._encrypt_sensitive(enriched)
                        records.append(encrypted)
                    except ValidationError as e:
                        logger.warning(f"Validation failed: {str(e)}")
                    
                    # Batch saving
                    if len(records) >= self.config['batch_size']:
                        self._save_data(records, output_path)
                        records = []
                    
                    pbar.update(len(record.get('packet', '')))

            # Save remaining records
            if records:
                self._save_data(records, output_path)

            logger.info(f"Ingestion completed in {time.time() - start_time:.2f}s")

        except Exception as e:
            logger.error(f"Processing failed: {str(e)}")
            raise

    def real_time_ingest(self, kafka_topic: str):
        """Real-time ingestion from Kafka"""
        from kafka import KafkaConsumer
        
        consumer = KafkaConsumer(
            kafka_topic,
            bootstrap_servers=os.getenv('KAFKA_BROKERS'),
            security_protocol='SSL',
            ssl_cafile='certs/ca.pem',
            ssl_certfile='certs/service.cert',
            ssl_keyfile='certs/service.key'
        )
        
        logger.info(f"Listening to Kafka topic: {kafka_topic}")
        for msg in consumer:
            try:
                record = json.loads(msg.value.decode())
                validated = DataValidator(**record).dict()
                enriched = self._enrich_threat_intel(validated)
                self._send_to_siem(enriched)
            except Exception as e:
                logger.error(f"Kafka error: {str(e)}")

    def _send_to_siem(self, record: Dict):
        """Send enriched data to SIEM"""
        try:
            self.session.post(
                self.config['siem_url'],
                json=record,
                timeout=3
            )
        except Exception as e:
            logger.warning(f"SIEM forward failed: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SecureFlow Data Ingestion')
    parser.add_argument('-i', '--input', required=True, help='Input file path')
    parser.add_argument('-o', '--output', required=True, help='Output file path')
    parser.add_argument('--realtime', action='store_true', 
                       help='Enable real-time Kafka ingestion')
    
    args = parser.parse_args()
    
    ingestor = DataIngestor()
    
    if args.realtime:
        ingestor.real_time_ingest('network-telemetry')
    else:
        ingestor.process_file(args.input, args.output)
