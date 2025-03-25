import json
import logging
import requests
import time
from typing import Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, ValidationError
from dotenv import load_dotenv
import os

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

load_dotenv()

class SplunkEvent(BaseModel):
    event: dict
    sourcetype: str = "secflow:log"
    source: str
    index: Optional[str] = "threat_detection"
    time: Optional[float] = datetime.now().timestamp()

class SplunkConnector:
    """Splunk integration handler for security event collection and querying"""
    
    def __init__(self):
        self.hec_url = os.getenv("SPLUNK_HEC_URL")
        self.hec_token = os.getenv("SPLUNK_HEC_TOKEN")
        self.api_url = os.getenv("SPLUNK_API_URL")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json"
        })
        self.verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "true").lower() == "true"
        
    def send_security_event(self, event: Dict, source: str) -> bool:
        """Send security event to Splunk HEC"""
        try:
            splunk_event = SplunkEvent(event=event, source=source)
            response = self.session.post(
                self.hec_url,
                data=json.dumps(splunk_event.dict()),
                verify=self.verify_ssl,
                timeout=5
            )
            response.raise_for_status()
            logger.info(f"Event sent to Splunk: {event.get('event_id')}")
            return True
        except ValidationError as e:
            logger.error(f"Invalid event format: {str(e)}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Splunk HEC error: {str(e)}")
            return False

    def search_threats(self, query: str, timeframe: str = "24h") -> List[Dict]:
        """Execute Splunk search for threat detection"""
        try:
            search_job = self.session.post(
                f"{self.api_url}/services/search/jobs",
                data={
                    "search": f"search {query} earliest=-{timeframe}",
                    "output_mode": "json"
                },
                verify=self.verify_ssl
            )
            search_job.raise_for_status()
            sid = search_job.json()['sid']
            
            # Wait for search completion
            status = ""
            while not status == "DONE":
                time.sleep(1)
                status_check = self.session.get(
                    f"{self.api_url}/services/search/jobs/{sid}",
                    verify=self.verify_ssl
                )
                status = status_check.json()['entry'][0]['content']['dispatchState']
            
            # Retrieve results
            results = self.session.get(
                f"{self.api_url}/services/search/jobs/{sid}/results",
                params={'output_mode': 'json'},
                verify=self.verify_ssl
            )
            return results.json()['results']
        except Exception as e:
            logger.error(f"Splunk search failed: {str(e)}")
            return []

    def check_connectivity(self) -> bool:
        """Check HEC and API connectivity"""
        try:
            hec_response = self.session.head(self.hec_url, verify=self.verify_ssl)
            api_response = self.session.head(
                f"{self.api_url}/services",
                verify=self.verify_ssl
            )
            return hec_response.ok and api_response.ok
        except Exception:
            return False

# Example usage
if __name__ == "__main__":
    splunk = SplunkConnector()
    event = {
        "event_id": "phish-123",
        "threat_type": "phishing",
        "severity": "high",
        "source_ip": "192.168.1.100"
    }
    splunk.send_security_event(event, "secureflow")
    threats = splunk.search_threats("tag=ransomware")
