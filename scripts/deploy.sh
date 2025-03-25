#!/usr/bin/env bash
# SecureFlow Deployment Script
# Usage: ./deploy.sh [--env staging|prod] [--migrate] [--rollback]

set -eo pipefail

# Configuration
APP_NAME="secureflow"
VENV_DIR="venv"
REQUIREMENTS="requirements.txt"
CONFIG_DIR="config"
BACKUP_DIR="/var/backups/${APP_NAME}"
DEPLOY_LOG="/var/log/${APP_NAME}/deploy.log"
GUNICORN_WORKERS=4
GUNICORN_PORT=8000

# Initialize colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Error handling
trap 'echo -e "${RED}Deployment failed! Check ${DEPLOY_LOG}${NC}"' ERR

log() {
  echo -e "$(date +"%Y-%m-%d %T") - $1" | tee -a ${DEPLOY_LOG}
}

validate_environment() {
  log "${YELLOW}Validating deployment environment...${NC}"
  
  # Check required files
  [[ ! -f "${CONFIG_DIR}/env.prod" ]] && { 
    log "${RED}Missing production environment file${NC}"
    exit 1
  }
  
  # Validate system dependencies
  declare -A deps=(
    ["python3"]="3.8"
    ["npm"]="7.0"
    ["gunicorn"]="20.0"
  )
  
  for dep in "${!deps[@]}"; do
    if ! command -v ${dep} &> /dev/null; then
      log "${RED}Missing dependency: ${dep}${NC}"
      exit 1
    fi
  done
}

setup_venv() {
  log "${YELLOW}Setting up Python virtual environment...${NC}"
  python3 -m venv ${VENV_DIR}
  source ${VENV_DIR}/bin/activate
  pip install --upgrade pip wheel | tee -a ${DEPLOY_LOG}
  pip install -r ${REQUIREMENTS} | tee -a ${DEPLOY_LOG}
}

db_migrations() {
  log "${YELLOW}Running database migrations...${NC}"
  alembic upgrade head | tee -a ${DEPLOY_LOG}
}

build_frontend() {
  log "${YELLOW}Building frontend assets...${NC}"
  cd frontend
  npm ci --production | tee -a ${DEPLOY_LOG}
  npm run build | tee -a ${DEPLOY_LOG}
  cd ..
}

configure_firewall() {
  log "${YELLOW}Configuring application firewall...${NC}"
  ufw allow ${GUNICORN_PORT}/tcp | tee -a ${DEPLOY_LOG}
  ufw reload | tee -a ${DEPLOY_LOG}
}

start_services() {
  log "${YELLOW}Starting application services...${NC}"
  systemctl daemon-reload
  systemctl restart ${APP_NAME}.service | tee -a ${DEPLOY_LOG}
  systemctl enable ${APP_NAME}.service | tee -a ${DEPLOY_LOG}
}

security_hardening() {
  log "${YELLOW}Applying security hardening...${NC}"
  
  # Set proper permissions
  find . -type d -exec chmod 750 {} \;
  find . -type f -exec chmod 640 {} \;
  chmod 700 ${VENV_DIR}/bin/*
  
  # Secure sensitive files
  chmod 600 ${CONFIG_DIR}/env.prod
  chown -R www-data:www-data .
}

rollback() {
  log "${RED}Initiating rollback...${NC}"
  systemctl stop ${APP_NAME}.service | tee -a ${DEPLOY_LOG}
  git reset --hard HEAD@{1} | tee -a ${DEPLOY_LOG}
  systemctl start ${APP_NAME}.service | tee -a ${DEPLOY_LOG}
}

main() {
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case $1 in
      --env)
        DEPLOY_ENV="$2"
        shift
        ;;
      --migrate)
        RUN_MIGRATIONS=true
        ;;
      --rollback)
        rollback
        exit 0
        ;;
      *)
        log "${RED}Invalid option: $1${NC}"
        exit 1
        ;;
    esac
    shift
  done

  [[ -z ${DEPLOY_ENV} ]] && DEPLOY_ENV="prod"
  
  # Execution flow
  validate_environment
  setup_venv
  build_frontend
  
  [[ ${RUN_MIGRATIONS} ]] && db_migrations
  
  security_hardening
  configure_firewall
  start_services

  log "${GREEN}Deployment to ${DEPLOY_ENV} completed successfully!${NC}"
}

main "$@"
