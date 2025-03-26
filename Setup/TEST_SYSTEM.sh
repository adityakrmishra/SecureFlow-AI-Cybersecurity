#!/bin/bash
# Local Network Validation Script

# Test Docker services
docker ps | grep -E "postgres|redis|splunk|api" || {
  echo "❌ Docker services not running"
  exit 1
}

# Test API health
API_STATUS=$(curl -sk https://localhost:8000/api/health)
if [[ "$API_STATUS" != *"OK"* ]]; then
  echo "❌ API health check failed"
  exit 1
fi

# Test threat detection
TEST_PHISH=$(curl -sk -X POST https://localhost:8000/api/threats/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"http://phish.example.com"}')

if [[ "$TEST_PHISH" != *"phishing"* ]]; then
  echo "❌ Phishing detection failed"
  exit 1
fi

echo "✅ All systems operational"
