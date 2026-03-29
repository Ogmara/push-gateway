# Changelog

All notable changes to the Ogmara Push Gateway will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-29

### Added
- Device registration API (POST /register, POST /unregister)
  - Multi-device support per address
  - Platform-specific tokens (FCM, APNs, Web Push)
  - Channel subscription filtering
- Push notification trigger API (POST /push)
  - Mention notifications with channel context
  - DM notifications (no content — privacy preserving)
  - Dispatches to all registered devices for the target address
- WebSocket listener for L2 node connections
  - Auto-reconnect with 5-second backoff
  - Monitors public channel messages for mentions
- Push providers (placeholder — ready for credential integration)
  - FCM (Firebase Cloud Messaging) for Android
  - APNs (Apple Push Notification Service) for iOS
  - Web Push with VAPID for browsers
- Configuration via TOML with safe defaults (localhost-only)
- CLI with run and init subcommands
- Health check and stats endpoints
