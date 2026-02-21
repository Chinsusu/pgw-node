# pgw-node

Lightweight sync daemon for distributed PGW proxy nodes.

Runs on remote VPS instances to sync proxy assignments from the master [proxy-server-local](https://github.com/Chinsusu/proxy-server-local) server.

## How it works

1. Generates an Ed25519 keypair (`pgw-node init`)
2. Public key is registered with the master server
3. Every 15s (configurable): polls `/v1/nodes/{id}/assignments` for proxy rules
4. Applies rules locally via `pgw-agent`
5. Reports status back via `/v1/nodes/{id}/heartbeat`

## Install

```bash
curl -fsSL https://github.com/Chinsusu/pgw-node/releases/latest/download/install.sh | bash
```

Or download binary directly:
```bash
curl -fsSL https://github.com/Chinsusu/pgw-node/releases/latest/download/pgw-node-linux-amd64 -o /usr/local/bin/pgw-node
chmod +x /usr/local/bin/pgw-node
```

## Setup

```bash
# 1. Initialize keypair
pgw-node init

# 2. Edit config
nano /etc/pgw-node/pgw-node.env

# 3. Register public key with master
pgw-node pubkey  # copy output -> PUT /v1/nodes/{id} public_key

# 4. Start service
systemctl enable --now pgw-node
```

## Configuration

| Env Var | Default | Description |
|---|---|---|
| `PGW_SERVER` | `http://127.0.0.1:8080` | Master server URL |
| `PGW_NODE_ID` | — | Node ID (from master) |
| `PGW_KEY_PATH` | `/etc/pgw-node/node.key` | Private key file |
| `PGW_POLL_INTERVAL` | `15s` | Sync poll interval |
| `PGW_AGENT_URL` | `http://127.0.0.1:9090` | Local pgw-agent URL |

## Build

```bash
make build           # linux/amd64
make build-all       # linux/amd64 + arm64
```

## Authentication

All requests to master are signed with Ed25519 using headers:
- `X-Node-ID`: node identifier
- `X-Node-TS`: unix timestamp (replay protection ±60s)
- `X-Node-Sig`: hex-encoded Ed25519 signature of `{node-id}:{timestamp}`
