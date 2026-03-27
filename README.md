# 🔴 RedInfra

Automated red team infrastructure deployment and management.  
Provisions AWS instances via Terraform, configures DNS (Cloudflare), mail (SendGrid), O365 tenants, VPN routing, and runs Ansible playbooks — all driven by YAML mission files.

---

## Features

- **Terraform** — provision/destroy AWS EC2 instances per mission node
- **Cloudflare** — sync A records, proxied records, MX, TXT entries from mission config
- **SendGrid** — manage authenticated domains and verified senders
- **O365** — manage Azure AD domains, licenses, and mailboxes via Graph API
- **Ansible** — run playbooks on nodes over VPN (Mythic, GoPhish, Postfix, WebDAV, Responder, RedELK…)
- **Routing** — configure iptables rules on the router to redirect ports from AWS nodes to C2
- **VPN** — OpenVPN tap-based mesh between the router and all AWS nodes
- **CLI** — subcommands for each service (`aws`, `cloudflare`, `sendgrid`, `o365`, `local`, `auto`)
- **Web UI** — optional Flask dashboard (`dashboard/app.py`) for managing missions without touching YAML

---

## Requirements

### System

- Ubuntu/Debian (tested)
- Python 3.8+
- Ansible
- Terraform
- OpenVPN

### Python dependencies

```
boto3
pyroute2
sendgrid
ansible-runner
python-terraform
msal
colorama
```

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/hegusung/redinfra.git -b automation /opt/redinfra
cd /opt/redinfra
```

### 2. Run the install script (Ubuntu/Debian)

```bash
sudo bash install.sh
```

This installs: Ansible, Terraform, OpenVPN, Python deps.

### 3. Install Python requirements

```bash
pip3 install -r requirements.txt
```

---

## Configuration

### `config/main.yml`

Global credentials and network settings. Copy from the sample:

```bash
cp config/main.yml.sample config/main.yml
```

```yaml
api:
  aws_key: AWS_KEY
  aws_secret: AWS_SECRET
  cloudflare_key: CLOUDFLARE_API_KEY
  sendgrid_api: SENDGRID_API_KEY
  o365:
    - tenant_id: TENANT_ID
      client_id: CLIENT_ID
      client_secret: CLIENT_SECRET

tags:
  Team: RedTeam
  Owner: operator

routing:
  vpn_interface: tap0
  iptables_chain: redinfra
  vpn_range: 192.168.40.0/24
  rule_start_table: 10
  rule_priority: 30000

vpn:
  region: eu-west-1
  instance_type: t2.micro
```

### `config/<mission>.yml`

One file per mission. Copy from the sample:

```bash
cp config/mission.yml.sample config/my-mission.yml
```

```yaml
mission: operation-nightfall
enabled: true

c2:
  region: eu-west-1
  instance_type: t3.medium
  local_ip: 192.168.56.110
  ports: [80, 443]
  dns_A:
    - c2.redteamdomain.com
  dns_proxy: []
  ansible:
    - playbook: install_mythic.yml
      args:
        mythic_password: Passw0rd!
        github_extensions:
          - https://github.com/MythicC2Profiles/httpx

phishing:
  region: eu-west-2
  instance_type: t2.small
  local_ip: 192.168.56.100
  ports: [25, 80, 443, 587]
  dns_A:
    - mx.redteamdomain.com
  dns_proxy:
    - phish.redteamdomain.com
  dns:
    MX:
      - key: redteamdomain.com
        value: mx.redteamdomain.com
  mail:
    - mail: john.doe@redteamdomain.com
      name: John Doe
  ansible:
    - playbook: install_mail.yml
      args:
        domains:
          - domain: redteamdomain.com
            users:
              - name: John Doe
                mail: john.doe
                password: changeme
        sendgrid_password: SENDGRID_API_KEY
    - playbook: install_gophish.yml
      args:
        mails: [john.doe@redteamdomain.com]
        web_domains: [phish.redteamdomain.com]
        gophish_rid: token
        gophish_track_uri: /track
        gophish_uris: [/login]

payloads:
  region: eu-west-3
  instance_type: t2.micro
  local_ip: 192.168.56.101
  ports: [80, 443]
  dns_proxy:
    - payloads.redteamdomain.com
  ansible:
    - playbook: install_web.yml
      args:
        web_domains:
          - payloads.redteamdomain.com

responder:
  region: eu-north-1
  instance_type: t3.micro
  local_ip: 192.168.56.102
  ports: [80, 445]
  dns_A:
    - smb.redteamdomain.com
  ansible:
    - playbook: install_responder.yml
```

Only **enabled** missions (`enabled: true`) are processed during deployment.

---

## Usage

### Automation (`auto`)

Deploy everything for all enabled missions:
```bash
python3 redinfra.py auto --apply
```

Destroy all resources:
```bash
python3 redinfra.py auto --destroy
```

Run individual steps:
```bash
python3 redinfra.py auto --apply-terraform    # provision EC2 instances
python3 redinfra.py auto --apply-cloudflare   # sync DNS records
python3 redinfra.py auto --apply-sendgrid     # configure mail domains/senders
python3 redinfra.py auto --apply-o365         # configure Azure AD
python3 redinfra.py auto --apply-routing      # apply iptables routing rules
python3 redinfra.py auto --apply-ansible      # run all Ansible playbooks
```

Run playbooks for a specific mission/node:
```bash
python3 redinfra.py auto --playbooks <mission> <server>
# e.g.:
python3 redinfra.py auto --playbooks operation-nightfall phishing
```

Install system dependencies:
```bash
python3 redinfra.py auto --install
```

---

### AWS (`aws`)

```bash
# List all instances across configured regions
python3 redinfra.py aws --list

# Start / stop an instance
python3 redinfra.py aws --start <instance-id>
python3 redinfra.py aws --stop  <instance-id>

# Elastic IPs
python3 redinfra.py aws --list-ips
python3 redinfra.py aws --new-ip <region>
python3 redinfra.py aws --remove-ip <ip>
python3 redinfra.py aws --renew-ip <ip>
python3 redinfra.py aws --associate-ip <ip> <instance-id>
python3 redinfra.py aws --dissociate-ip <ip>
```

---

### Cloudflare (`cloudflare`)

```bash
python3 redinfra.py cloudflare --list
python3 redinfra.py cloudflare --new <dns> <value> [--dns-type A]
python3 redinfra.py cloudflare --new-proxy <dns> <value>
python3 redinfra.py cloudflare --remove-dns <dns> <value>
```

---

### SendGrid (`sendgrid`)

```bash
python3 redinfra.py sendgrid --list-domains
python3 redinfra.py sendgrid --new-domain <domain>
python3 redinfra.py sendgrid --delete-domain <domain>

python3 redinfra.py sendgrid --list-senders
python3 redinfra.py sendgrid --new-sender <name> <email>
python3 redinfra.py sendgrid --delete-sender <email>
```

---

### O365 (`o365`)

```bash
python3 redinfra.py o365 --list-domains
python3 redinfra.py o365 --list-emails
```

Credentials are read from `main.yml` (`api.o365`). Domain/email data is merged from mission YAMLs (node `o365:` block).

---

### Local routing & VPN (`local`)

```bash
# Show full current config (AWS + routing)
python3 redinfra.py local --show-config

# VPN IP management
python3 redinfra.py local --set-vpn-ip <instance> <vpn-ip>
python3 redinfra.py local --list-vpn-ip
python3 redinfra.py local --remove-vpn-ip <instance>

# Routing rules
python3 redinfra.py local --set-routing <instance> <local-ip> <ports>
python3 redinfra.py local --list-routing
python3 redinfra.py local --remove-routing <instance>
python3 redinfra.py local --apply      # apply iptables rules
python3 redinfra.py local --clear-config
```

---

## Ansible Playbooks

Playbooks are in `ansible/` and run automatically during `--apply-ansible` or `--playbooks`.

| Playbook | Description |
|---|---|
| `install_mythic.yml` | Mythic C2 framework + optional GitHub extensions |
| `install_mail.yml` | Postfix / Dovecot / Roundcube mail stack |
| `install_gophish.yml` | GoPhish phishing framework |
| `install_web.yml` | Nginx with geo/ASN filtering |
| `install_webdav.yml` | Nginx WebDAV server |
| `install_responder.yml` | Responder (LLMNR/NBT-NS poisoner) |
| `install_vpn.yml` | OpenVPN node setup |
| `install_node.yml` | Base node bootstrap (firewall, VPN client) |
| `install_redelk_c2.yml` | RedELK on C2 server |
| `install_redelk_redirectors.yml` | RedELK on redirectors |
| `install_router.yml` | Router setup |

Playbooks are invoked via `ansible-runner` over the VPN using `local_ip` from the mission YAML.  
Custom playbooks can be added directly to the `ansible:` list of any node — they are executed like built-in ones.

---

## Project Layout

```
redinfra/
├── redinfra.py              # CLI entry point
├── install.sh               # System dependencies installer
├── requirements.txt         # Python dependencies
├── config/
│   ├── aws.yml              # AMI map per region (do not edit)
│   ├── main.yml.sample      # Global config template
│   └── mission.yml.sample   # Mission config template
├── lib/
│   ├── automation.py        # Orchestration (apply/destroy/playbooks)
│   ├── aws.py               # EC2 + Elastic IP management
│   ├── cloudflare.py        # DNS management
│   ├── sendgridclient.py    # SendGrid domains/senders
│   ├── o365.py              # Azure AD / Graph API
│   ├── routing.py           # iptables routing + VPN IP
│   ├── terraform.py         # Terraform wrapper
│   ├── config.py            # YAML config loader
│   └── color.py             # Terminal colors
├── ansible/
│   ├── install_*.yml        # Top-level playbooks
│   └── roles/               # Ansible roles (mail, mythic, web, …)
├── templates/
│   ├── default.tf.j2        # Terraform VPN node template
│   ├── node.tf.j2           # Terraform mission node template
│   └── vpn.tf.j2            # Terraform VPN instance template
└── dashboard/
    ├── app.py               # Optional Flask web UI
    └── nginx.conf           # nginx reverse proxy for the dashboard
```

---

## Notes

- Missions are loaded at runtime — only `enabled: true` missions are processed.
- `config/aws.yml` maps regions to AMI IDs — update it if AMIs are outdated in your target region.
- Routing uses `pyroute2` and iptables — must be run as root on the router.
- Ansible connects to nodes via their `local_ip` (VPN address) — nodes must be reachable over VPN before running playbooks.
- Duplicate keys in YAML configs raise an error (strict loader).

---

## License

For authorized red team use only.
