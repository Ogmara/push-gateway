# Building the Ogmara Push Gateway

## Prerequisites

### System packages (Debian/Ubuntu)

```bash
sudo apt install -y build-essential pkg-config libssl-dev git
```

### Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

## Build

```bash
git clone https://github.com/Ogmara/push-gateway.git
cd push-gateway
cargo build --release
```

Binary: `target/release/ogmara-push-gateway`

### Install

```bash
sudo cp target/release/ogmara-push-gateway /usr/local/bin/
sudo chmod +x /usr/local/bin/ogmara-push-gateway
```

## Configuration

Generate a default config:

```bash
ogmara-push-gateway init
```

Or copy the example:

```bash
sudo mkdir -p /var/lib/ogmara/push-gateway
sudo cp push-gateway.example.toml /var/lib/ogmara/push-gateway/push-gateway.toml
```

The gateway looks for `push-gateway.toml` in its working directory.

### Required settings

**Shared secret** (must match L2 node `[push_gateway].auth_token`):
```toml
[gateway]
push_secret = "your-shared-secret-here"
```

**VAPID key for Web Push** — must be a valid P-256 private key (raw 32 bytes,
base64url-encoded):

```bash
python3 -c "
from cryptography.hazmat.primitives.asymmetric import ec
import base64
key = ec.generate_private_key(ec.SECP256R1())
raw = key.private_numbers().private_value.to_bytes(32, 'big')
print(base64.urlsafe_b64encode(raw).rstrip(b'=').decode())
"
```

```toml
[webpush]
enabled = true
vapid_private_key = "your-base64url-key"
vapid_subject = "mailto:admin@yourdomain.org"
```

### L2 node connection

```toml
[ogmara]
node_urls = ["ws://127.0.0.1:41721/api/v1/ws/public"]
```

### L2 node config

Enable push in the L2 node's `ogmara.toml`:

```toml
[push_gateway]
enabled = true
url = "http://127.0.0.1:41722"
auth_token = "same-shared-secret"
```

## Deployment

### Systemd service

```ini
# /etc/systemd/system/ogmara-push-gateway.service
[Unit]
Description=Ogmara Push Notification Gateway
After=network-online.target ogmara-node.service
Wants=network-online.target

[Service]
Type=simple
User=ogmara
Group=ogmara
ExecStart=/usr/local/bin/ogmara-push-gateway run
WorkingDirectory=/var/lib/ogmara/push-gateway
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ogmara/push-gateway
PrivateTmp=true
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### Reverse proxy

Add to your Apache/Nginx config:

```apache
ProxyPass /push/ http://127.0.0.1:41722/
ProxyPassReverse /push/ http://127.0.0.1:41722/
```

### Verify

```bash
curl -s http://127.0.0.1:41722/health | jq .
curl -s http://127.0.0.1:41722/vapid-key
```

## VAPID key notes

- The VAPID private key must be a raw 32-byte P-256 scalar, **not** PKCS#8 DER
- The gateway uses `SigningKey::from_bytes()` for VAPID (raw), and
  `SigningKey::from_pkcs8_der()` for APNs (.p8 files)
- If you see "ES256 key parse error: PKCS#8 ASN.1 error", the key format is wrong
