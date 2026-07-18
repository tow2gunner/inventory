# inventory
Fortigate and Ubiquiti AND ssh for local inventory

# Network Inventory and Systems Scanner

A Docker-based inventory application that combines data from a FortiGate firewall, a UniFi controller, and SSH-accessible Linux systems.

The application is intended to provide a single inventory view for:

- Network devices and clients
- DHCP reservations
- Physical and logical devices
- Linux host details
- Network interfaces
- Disks and filesystems
- Docker containers
- Device categorization, naming, location, and notes

## Current Application Views

### Inventory

The Inventory view is the raw network and interface discovery layer.

It combines information from FortiGate and UniFi, including:

- Current IP address
- IP source
- Reserved IP address
- MAC address
- Hostname
- UniFi device/client name
- Connection type
- Uplink
- UniFi model, firmware, and state
- Vendor
- Device type/family
- OS and software information when available
- Logical name
- Category
- Location
- Notes
- Proposed IP
- Reservation description

Current Inventory functions include:

- Column sorting
- Natural numeric IP sorting
- Blank values sorted last
- Global and per-column filtering
- Bulk updates
- CSV export
- FortiGate reservation-add CLI generation
- FortiGate reservation-removal CLI generation
- Conservative category auto-detection
- Linking multiple MAC records to one device

### Devices

The Devices view represents one physical or logical device.

A device may have multiple interfaces, MAC addresses, and IP addresses.

The stable parent key is `device_id`, implemented as a UUID. The UUID remains stable even when:

- An IP address changes
- A NIC is replaced
- A device has wired and wireless interfaces
- Multiple MAC records are merged into one device

Device-level data includes:

- Logical name
- Category
- Location
- Notes
- Associated interfaces and MAC addresses

### Systems

The Systems view contains SSH-derived host information.

Current SSH collection includes:

- Hostname
- OS and version
- Kernel
- CPU model and core/thread information
- Memory
- Uptime
- Physical interfaces
- IP addressing mode when detectable
- Physical disks, partitions, filesystems, capacity, and free space
- Docker container summary

Systems are stored by `device_id`, not by IP address.

## Prerequisites

### Docker Host

The Inventory application requires:

- Docker Engine
- Docker Compose plugin
- Network access to the FortiGate
- Network access to the UniFi controller
- TCP/22 access to Linux systems that will be scanned
- Persistent storage for the SQLite database

Verify Docker:

```bash
docker --version
docker compose version
```

### FortiGate

Required:

- FortiGate management URL or IP address
- Dedicated FortiGate REST API administrator
- REST API token

Optional:

- FortiGate SSH administrator password, when generated CLI files will be applied manually with `sshpass`
- SNMP configuration for separate Prometheus/Grafana monitoring

The application uses the FortiGate API to retrieve:

- DHCP server configuration
- DHCP reservations
- FortiGate-discovered devices
- Lease/device information exposed by the FortiGate API

#### Creating the FortiGate API Administrator

Create a dedicated REST API administrator in FortiGate.

Recommended configuration:

- Use a dedicated account only for Inventory
- Use a read-only administrator profile where possible
- Restrict trusted hosts to the Inventory server IP
- Save the generated token immediately; FortiGate normally displays it only once

The API token is stored in:

```text
secrets/fortitoken.txt
```

#### FortiGate DHCP Server ID

The current application uses a FortiGate DHCP server ID when generating reservation CLI.

The intended setup workflow is:

1. Query the FortiGate API.
2. Retrieve configured DHCP servers.
3. Select the appropriate LAN/internal DHCP server.
4. Write the discovered server ID into `.env`.

If exactly one DHCP server is present, setup can select it automatically.

If several DHCP servers exist, setup should list them and require selection.

#### FortiGate SNMP

SNMP is not required for the Inventory application itself, but it is useful for Prometheus/Grafana monitoring.

A FortiGate SNMP prerequisite section should include:

- SNMP enabled
- Read-only community
- Inventory/monitoring server listed as an allowed manager
- SNMP enabled on the required FortiGate interface
- Firewall policy permitting the monitoring host where required

Exact commands depend on FortiOS version and should be documented separately for the target release.

### UniFi

Required:

- UniFi controller URL or IP address
- UniFi API key

The application uses UniFi to retrieve:

- Managed devices
- Clients
- Uplinks
- Connection type
- Models
- Firmware
- Device state

The API key is stored in:

```text
secrets/unifi-api.key
```

#### UniFi Site ID

The Site ID should not need to be entered manually.

The intended setup workflow is:

1. Read the UniFi URL.
2. Read the API key from `secrets/unifi-api.key`.
3. Query UniFi for available sites.
4. Automatically select the site if only one exists.
5. Prompt for selection if several sites exist.
6. Write the selected Site ID into `.env`.

## Required Secret Files

Create the following files:

```text
secrets/
├── fortitoken.txt
├── unifi-api.key
├── fortipass.key
├── users.key
└── passwords.key
```

### `fortitoken.txt`

Purpose:

- FortiGate REST API authentication

Contents:

```text
<PUT FORTIGATE API TOKEN HERE>
```

### `unifi-api.key`

Purpose:

- UniFi API authentication

Contents:

```text
<PUT UNIFI API KEY HERE>
```

### `fortipass.key`

Purpose:

- Optional FortiGate SSH password for manually applying generated CLI

Contents:

```text
<PUT FORTIGATE SSH PASSWORD HERE>
```

### `users.key`

Purpose:

- Indexed SSH usernames used by the Systems scanner

Format:

```text
u1=root
u2=admin
u3=mks
u4=ubuntu
```

Rules:

- One entry per line
- No spaces around `=`
- IDs must be unique
- Blank lines may be ignored
- Lines beginning with `#` may be ignored

### `passwords.key`

Purpose:

- Indexed SSH passwords used by the Systems scanner

Format:

```text
p1=<PUT PASSWORD HERE>
p2=<PUT PASSWORD HERE>
p3=<PUT PASSWORD HERE>
```

Rules:

- One entry per line
- No spaces around `=`
- IDs must be unique
- Parse only on the first `=`
- Passwords may contain additional `=` characters

Recommended permissions:

```bash
chmod 0400 secrets/*
```

The files must be mounted read-only into the Inventory container.

## Environment Configuration

Site-specific, non-secret values belong in `.env`.

Example:

```text
INVENTORY_PORT=8088
FORTIGATE_URL=https://192.168.2.1
UNIFI_URL=https://192.168.2.3
UNIFI_SITE_ID=<AUTO-DISCOVERED>
DHCP_SERVER_ID=<AUTO-DISCOVERED>
VERIFY_TLS=false
SSH_TIMEOUT=6
```

The setup process should be able to create or update `.env` without rewriting `docker-compose.yml`.

### Values Kept in Docker Compose

Fixed container paths should remain in Compose:

```yaml
environment:
  TOKEN_FILE: /run/secrets/fortitoken
  UNIFI_API_KEY_FILE: /run/secrets/unifi-api.key
  DB_PATH: /data/inventory.db
  CHANGE_FILE: /data/fortigate-changes.cli
  USERS_FILE: /run/secrets/users.key
  PASSWORDS_FILE: /run/secrets/passwords.key
```

Example secret mounts:

```yaml
volumes:
  - ./data:/data
  - ./secrets/fortitoken.txt:/run/secrets/fortitoken:ro
  - ./secrets/unifi-api.key:/run/secrets/unifi-api.key:ro
  - ./secrets/fortipass.key:/run/secrets/fortipass.key:ro
  - ./secrets/users.key:/run/secrets/users.key:ro
  - ./secrets/passwords.key:/run/secrets/passwords.key:ro
```

Example port mapping:

```yaml
ports:
  - "${INVENTORY_PORT:-8088}:8000"
```

## SSH Scanning

The scanner:

1. Checks whether TCP/22 is reachable.
2. Tries the previously successful credential indexes first.
3. Tries remaining username/password combinations.
4. Saves only the successful `u#` and `p#` references.
5. Collects Linux system data.
6. Stores host details using `device_id`.

The database does not need to store plaintext usernames or passwords.

Current Scan All categories:

- Server
- Desktop
- Laptop
- VM
- Printer
- Unknown

Excluded by default:

- Switch
- Access Point
- Camera
- Firewall
- IoT
- Appliance
- Meshtastic

Changing a device category changes its scan eligibility on the next scan.

## Interface Display

The compact Systems interface display uses two lines per interface.

Example:

```text
enp3s0    UP    MTU 1500
f4:4d:30:6b:ab:c1    192.168.2.101/24 [STATIC]
```

```text
wlp2s0    UP    MTU 1500
30:e3:7a:f6:02:d4    192.168.2.163/24 [DHCP]
```

Display rules:

- Hide loopback by default
- Hide Docker bridge and veth interfaces from the host-interface list
- Keep Docker network information under Docker
- Preserve raw JSON under collapsed diagnostic sections

## Disk Display

Loop, snap, and squashfs devices are hidden by default.

Example:

```text
sda    Samsung SSD 850    466 GB
Serial: S2RANB0J621868L

sda2    /    ext4
Capacity: 465 GB    Free: 411 GB
```

Display fields:

- Device
- Model
- Serial
- Mount point
- Filesystem
- Capacity
- Free space

## Docker Display

Docker is shown as a compact host summary.

Example:

```text
Containers: 12 total | 11 running | 1 stopped
```

Per container:

```text
grafana    RUNNING    172.18.0.5
Ports: 3000:3000    Size: 420 MB
```

For host networking:

```text
prometheus    RUNNING    HOST-IP
Ports: 9090:9090
```

## FortiGate Reservation Workflow

The application currently generates CLI files for:

- Adding or changing reservations
- Removing reservations

Generated CLI is reviewed and applied manually.

Example manual execution:

```bash
sshpass -f ./secrets/fortipass.key \
ssh -T \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  admin@192.168.2.1 < fortigate-changes.cli
```

After applying changes, refresh Inventory so current FortiGate reservations are reloaded.

## Persistent Data

The SQLite database is stored at:

```text
/data/inventory.db
```

The host directory should be mounted persistently:

```yaml
- ./data:/data
```

Do not delete the database when upgrading unless a migration specifically requires it.

## Repository Safety

Never commit:

- `secrets/`
- `.env`
- SQLite databases
- generated FortiGate CLI files
- logs

Recommended `.gitignore` entries:

```text
secrets/
.env
data/
*.db
*.sqlite
*.sqlite3
*.cli
*.log
__pycache__/
*.pyc
```

## Planned Setup Script

A future setup script should:

1. Verify Docker and Docker Compose.
2. Create missing secret files with placeholder text.
3. Prompt for the FortiGate URL.
4. Prompt for the UniFi URL.
5. Read the FortiGate API token.
6. Read the UniFi API key.
7. Query UniFi and discover the Site ID.
8. Query FortiGate and discover the DHCP server ID.
9. Create or update `.env`.
10. Validate API access before starting the container.
11. Build and start the application.

The script should not overwrite existing secret files or unrelated `.env` entries.

## Current Limitations

- Generated FortiGate CLI is applied manually.
- Windows collection is not implemented.
- VM/Proxmox collection is not yet implemented.
- SNMP is not currently used by the Inventory application.
- Exact FortiGate setup commands depend on FortiOS version.
- UniFi Site ID and FortiGate DHCP server ID auto-discovery are planned setup functions.
