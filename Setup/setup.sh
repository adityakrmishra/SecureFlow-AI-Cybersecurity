#!/bin/bash
# Automated Local Network Setup Script

# Check root privileges
if [ "$EUID" -ne 0 ]; then
  echo "🔒 Run as root: sudo ./setup.sh"
  exit 1
fi

# Install dependencies
apt-get update && apt-get install -y \
  docker.io \
  docker-compose \
  python3.10 \
  python3-pip \
  libpcap-dev \
  nginx

# Configure Docker
systemctl enable docker
systemctl start docker
usermod -aG docker $USER

# Create virtual environment
python3 -m venv /opt/secureflow-venv
source /opt/secureflow-venv/bin/activate
pip install -r ../requirements.txt

# Initialize directories
mkdir -p \
  /var/secureflow/data \
  /var/secureflow/logs \
  /etc/secureflow/certs

# Generate self-signed certs
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout /etc/secureflow/certs/nginx.key \
  -out /etc/secureflow/certs/nginx.crt \
  -subj "/CN=secureflow.local"

# Build Docker images
docker-compose -f ../docker-compose.yml build

echo "✅ Setup complete. Run './run.sh' to start services"
