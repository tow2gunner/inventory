#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"
APP_DIR_DEFAULT="./app"
DATA_DIR_DEFAULT="./data"
SECRETS_DIR_DEFAULT="./secrets"

say() { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

prompt_default() {
  local prompt="$1" default="$2" reply
  read -r -p "$prompt [$default]: " reply
  printf '%s' "${reply:-$default}"
}

prompt_required() {
  local prompt="$1" reply
  while :; do
    read -r -p "$prompt: " reply
    [[ -n "$reply" ]] && { printf '%s' "$reply"; return; }
    say "Value is required."
  done
}

normalize_url() {
  local value="$1"
  case "$value" in
    http://*|https://*) printf '%s' "$value" ;;
    *) printf 'https://%s' "$value" ;;
  esac
}

write_env() {
  cat > "$ENV_FILE" <<EOF_ENV
COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME
CONTAINER_NAME=$CONTAINER_NAME
INVENTORY_PORT=$INVENTORY_PORT
APP_DIR=$APP_DIR
DATA_DIR=$DATA_DIR
SECRETS_DIR=$SECRETS_DIR

FORTIGATE_URL=$FORTIGATE_URL
UNIFI_URL=$UNIFI_URL
UNIFI_SITE_ID=$UNIFI_SITE_ID
DHCP_SERVER_ID=$DHCP_SERVER_ID
VERIFY_TLS=$VERIFY_TLS

FORTI_TOKEN_FILE=fortitoken.key
FORTIPASS_FILE=fortipass.key
UNIFI_API_KEY_FILE=unifi-api.key
LIN_USERS_FILE=lin-users.key
LIN_PASSWORDS_FILE=lin-passwords.key
WIN_USERS_FILE=win-users.key
WIN_PASSWORDS_FILE=win-passwords.key

DB_FILENAME=inventory.db
CHANGE_FILENAME=fortigate-changes.cli

SSH_PORT=22
SSH_TIMEOUT=6
WINRM_HTTP_PORT=5985
WINRM_HTTPS_PORT=5986
WINRM_TIMEOUT=20
WINRM_VERIFY_TLS=false
EOF_ENV
  chmod 600 "$ENV_FILE"
}

create_secret_if_missing() {
  local path="$1" sample="$2"
  if [[ ! -e "$path" ]]; then
    printf '%s\n' "$sample" > "$path"
    chmod 600 "$path"
    say "Created: ${path#$PROJECT_ROOT/}"
  fi
}

need_cmd docker
docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is not available."

cd "$PROJECT_ROOT"

say "Inventory setup"
say "Project root: $PROJECT_ROOT"
say ""

if [[ -f "$ENV_FILE" ]]; then
  read -r -p ".env already exists. Overwrite it? [y/N]: " overwrite
  case "$overwrite" in
    y|Y|yes|YES) ;;
    *) say "Keeping existing .env"; exit 0 ;;
  esac
fi

COMPOSE_PROJECT_NAME="$(prompt_default "Compose project name" "inventory")"
CONTAINER_NAME="$(prompt_default "Container name" "inventory")"
INVENTORY_PORT="$(prompt_default "Web port" "8088")"
APP_DIR="$(prompt_default "Application directory" "$APP_DIR_DEFAULT")"
DATA_DIR="$(prompt_default "Data directory" "$DATA_DIR_DEFAULT")"
SECRETS_DIR="$(prompt_default "Secrets directory" "$SECRETS_DIR_DEFAULT")"

FORTIGATE_INPUT="$(prompt_required "FortiGate IP or URL")"
UNIFI_INPUT="$(prompt_required "UniFi IP or URL")"
FORTIGATE_URL="$(normalize_url "$FORTIGATE_INPUT")"
UNIFI_URL="$(normalize_url "$UNIFI_INPUT")"
UNIFI_SITE_ID="$(prompt_default "UniFi site ID (blank for auto/default)" "")"
DHCP_SERVER_ID="$(prompt_default "FortiGate DHCP server ID" "3")"
VERIFY_TLS="$(prompt_default "Verify FortiGate/UniFi TLS certificates (true/false)" "false")"

[[ -d "$PROJECT_ROOT/${APP_DIR#./}" ]] || fail "Application directory does not exist: $APP_DIR"
[[ -f "$PROJECT_ROOT/${APP_DIR#./}/Dockerfile" ]] || fail "Dockerfile not found under: $APP_DIR"
[[ -f "$PROJECT_ROOT/${APP_DIR#./}/app.py" ]] || fail "app.py not found under: $APP_DIR"
[[ -f "$PROJECT_ROOT/docker-compose.yml" ]] || fail "docker-compose.yml not found in project root"

mkdir -p "$PROJECT_ROOT/${DATA_DIR#./}" "$PROJECT_ROOT/${SECRETS_DIR#./}"
chmod 700 "$PROJECT_ROOT/${SECRETS_DIR#./}"

write_env

SECRETS_PATH="$PROJECT_ROOT/${SECRETS_DIR#./}"
create_secret_if_missing "$SECRETS_PATH/fortitoken.key" "REPLACE_WITH_FORTIGATE_API_TOKEN"
create_secret_if_missing "$SECRETS_PATH/fortipass.key" "REPLACE_WITH_FORTIGATE_PASSWORD"
create_secret_if_missing "$SECRETS_PATH/unifi-api.key" "REPLACE_WITH_UNIFI_API_KEY"
create_secret_if_missing "$SECRETS_PATH/lin-users.key" "u1=root"
create_secret_if_missing "$SECRETS_PATH/lin-passwords.key" "p1=REPLACE_WITH_LINUX_PASSWORD"
create_secret_if_missing "$SECRETS_PATH/win-users.key" "u1=Administrator"
create_secret_if_missing "$SECRETS_PATH/win-passwords.key" "p1=REPLACE_WITH_WINDOWS_PASSWORD"

say ""
say "Validating Compose configuration..."
docker compose config >/dev/null
say "Compose configuration is valid."

say ""
say "Setup complete."
say "Edit the files under ${SECRETS_DIR#./}/ before starting the container."

read -r -p "Build and start Inventory now? [y/N]: " start_now
case "$start_now" in
  y|Y|yes|YES)
    docker compose up -d --build
    say "Inventory started on port $INVENTORY_PORT."
    ;;
  *)
    say "Start later with: docker compose up -d --build"
    ;;
esac