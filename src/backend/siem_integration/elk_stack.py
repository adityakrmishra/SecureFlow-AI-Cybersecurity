from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ElasticsearchException
from typing import List, Dict, Optional
import logging
import os
from dotenv import load_dotenv
from datetime import datetime

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

load_dotenv()

class ELKConnector:
    """ELK Stack integration for security analytics and logging"""
    
    def __init__(self):
        self.es = Elasticsearch(
            [os.getenv("ELASTICSEARCH_URL")],
            http_auth=(
                os.getenv("ELASTIC_USER"),
                os.getenv("ELASTIC_PASSWORD")
            ),
            scheme="https",
            verify_certs=os.getenv("ELK_VERIFY_SSL", "true") == "true",
            timeout=30
        )
        self.default_index = os.getenv("ELASTIC_INDEX", "secflow-threats")
        self._ensure_index_template()
    
    def _ensure_index_template(self):
        """Create index template with security mapping"""
        template = {
            "index_patterns": ["secflow-*"],
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "threat_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "event_data": {"type": "object", "enabled": False}
                }
            }
        }
        try:
            self.es.indices.put_template(
                name="secflow_template",
                body=template
            )
        except ElasticsearchException as e:
            logger.error(f"Template creation failed: {str(e)}")

    def send_log(self, log_data: Dict, index: Optional[str] = None) -> bool:
        """Send security log to Elasticsearch"""
        index = index or self.default_index
        document = {
            "@timestamp": datetime.utcnow().isoformat(),
            **log_data
        }
        try:
            response = self.es.index(
                index=index,
                document=document,
                refresh=True
            )
            logger.info(f"Log sent to ELK: {response['_id']}")
            return True
        except ElasticsearchException as e:
            logger.error(f"ELK insertion error: {str(e)}")
            return False

    def bulk_send_logs(self, logs: List[Dict], index: Optional[str] = None) -> bool:
        """Bulk insert security logs"""
        index = index or self.default_index
        actions = [
            {
                "_index": index,
                "_source": {
                    "@timestamp": datetime.utcnow().isoformat(),
                    **log
                }
            }
            for log in logs
        ]
        try:
            helpers.bulk(self.es, actions)
            logger.info(f"Bulk inserted {len(logs)} logs")
            return True
        except ElasticsearchException as e:
            logger.error(f"ELK bulk error: {str(e)}")
            return False

    def search_threats(self, query: Dict, index: str = "*") -> List[Dict]:
        """Search threats using Elasticsearch DSL"""
        try:
            result = self.es.search(
                index=index,
                body=query
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except ElasticsearchException as e:
            logger.error(f"ELK search error: {str(e)}")
            return []

    def create_alert(self, alert_body: Dict) -> Optional[str]:
        """Create alert in Elasticsearch Watcher"""
        try:
            response = self.es.watcher.put_watch(
                id=alert_body["id"],
                body=alert_body
            )
            return response["_id"]
        except ElasticsearchException as e:
            logger.error(f"Alert creation failed: {str(e)}")
            return None

    def check_connectivity(self) -> bool:
        """Check cluster health status"""
        try:
            return self.es.ping()
        except ElasticsearchException:
            return False

# Example usage
if __name__ == "__main__":
    elk = ELKConnector()
    elk.send_log({
        "threat_type": "ransomware",
        "severity": "critical",
        "source_ip": "10.0.0.42",
        "event_data": {"files_encrypted": 150}
    })
    query = {
        "query": {
            "term": {"severity.keyword": "critical"}
        }
    }
    critical_threats = elk.search_threats(query)
