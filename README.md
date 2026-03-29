# Ogmara Push Gateway

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

```bash
# Generate default config
ogmara-push-gateway init

# Edit push-gateway.toml with your L2 node URLs and push credentials

# Start the gateway
ogmara-push-gateway run
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET | /stats | Registration statistics |
| POST | /register | Register a device for push notifications |
| POST | /unregister | Remove a device registration |
| POST | /push | Receive notification trigger from L2 node |

## Configuration

See [push-gateway.example.toml](push-gateway.example.toml) for all options.

**All secrets (API keys, credential files) must be loaded from environment variables in production.**

## Building

```bash
cargo build --release
```

## Privacy

- Notification content is minimal ("New mention in #general")
- No message content in push payloads
- DM notifications never include encrypted content
- Anyone can run their own push gateway
- Users choose which gateway to use (or disable push entirely)

## License

MIT
