#!/bin/bash
# Start SecureFlow Services

# Start core services
docker-compose -f ../docker-compose.yml up -d \
  postgres \
  redis \
  splunk \
  api

# Wait for DB initialization
sleep 15

# Apply migrations
docker exec secureflow-api \
  python manage.py migrate

# Start frontend
cd ../frontend
npm run build
serve -s build -l 3000 &

echo "🌐 Access dashboard: https://$(hostname -I | awk '{print $1}'):3000"
