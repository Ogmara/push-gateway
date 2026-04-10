# Ogmara Push Gateway

[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-ogmara%2Fogmara-blue)](https://hub.docker.com/r/ogmara/ogmara)

Push notification bridge for the [Ogmara](https://ogmara.org) decentralized platform. Connects to L2 nodes via WebSocket and delivers mention/DM notifications to mobile and web clients via FCM, APNs, and Web Push.

## Architecture

```
┌──────────────┐    WebSocket     ┌─────────────────────┐
│  L2 Node(s)  │◄───────────────►│  Push Notification  │
│              │                 │     Gateway          │
└──────────────┘                 └──────────┬───────────┘
                                            │
                          ┌─────────────────┼─────────────────┐
                          │                 │                 │
                   ┌──────▼─────┐  ┌────────▼───────┐  ┌─────▼──────┐
                   │   FCM      │  │    APNs        │  │  Web Push  │
                   │ (Android)  │  │   (iOS)        │  │ (Browsers) │
                   └────────────┘  └────────────────┘  └────────────┘
```

## Quick Start

### Docker (recommended)

```bash
docker pull ogmara/ogmara:push-gateway-latest

# Create and edit config
mkdir -p ~/ogmara-push-gateway
docker run --rm ogmara/ogmara:push-gateway-latest init \
  --output /dev/stdout > ~/ogmara-push-gateway/push-gateway.toml
# Edit ~/ogmara-push-gateway/push-gateway.toml:
#   - Set listen_addr = "0.0.0.0"
#   - Set node_urls to your L2 node address
#   - Configure webpush/fcm/apns as needed

# Run
docker run -d \
  --name ogmara-push-gateway \
  --restart unless-stopped \
  -v ~/ogmara-push-gateway/push-gateway.toml:/etc/ogmara/push-gateway.toml:ro \
  -v push-gw-data:/data \
  -p 41722:41722 \
  -e OGMARA_PUSH_SECRET="your-shared-secret" \
  ogmara/ogmara:push-gateway-latest
```

Images are tagged by version (e.g., `ogmara/ogmara:push-gateway-0.4.0`) and
`push-gateway-latest` for the most recent. See all tags on
[Docker Hub](https://hub.docker.com/r/ogmara/ogmara/tags?name=push-gateway).

### From source

```bash
cargo build --release
ogmara-push-gateway init        # generate push-gateway.toml
# edit push-gateway.toml
ogmara-push-gateway run
```

See [BUILDING.md](BUILDING.md) for full build, configuration, and deployment instructions.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET | /stats | Registration statistics |
| POST | /register | Register a device for push notifications |
| POST | /unregister | Remove a device registration |
| POST | /push | Receive notification trigger from L2 node |

## Configuration

See [push-gateway.example.toml](push-gateway.example.toml) for all options and
[BUILDING.md](BUILDING.md) for detailed setup instructions.

| Deployment | Config file location |
|------------|---------------------|
| **Docker** | `~/ogmara-push-gateway/push-gateway.toml` on host, mounted to `/etc/ogmara/push-gateway.toml` |
| **Systemd** | `/var/lib/ogmara/push-gateway/push-gateway.toml` |
| **From source** | `push-gateway.toml` in working directory |

**Secrets** should be passed via environment variables in production:

| Variable | Purpose |
|----------|---------|
| `OGMARA_PUSH_SECRET` | Shared secret for L2 node authentication (must match L2 node `[push_gateway].auth_token`) |
| `OGMARA_VAPID_PRIVATE_KEY` | VAPID private key for Web Push (base64url, 32 bytes) |
| `OGMARA_FCM_SERVICE_ACCOUNT_KEY` | Firebase service account credentials |
| `OGMARA_APNS_KEY_PATH` | Path to APNs auth key (.p8 file) |

## Building

See [BUILDING.md](BUILDING.md) for prerequisites, build steps, Docker, and systemd deployment.

## Privacy

- Notification content is minimal ("New mention in #general")
- No message content in push payloads
- DM notifications never include encrypted content
- Anyone can run their own push gateway
- Users choose which gateway to use (or disable push entirely)

## License

MIT
