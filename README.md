# P0 SSH Agent

A comprehensive SSH access management tool for on-premises nodes that connects to P0 backend infrastructure via WebSocket, executes provisioning scripts, and provides secure authentication using JWT tokens with ECDSA P-384 keys.

## Features

- **JWT Authentication**: ES384 algorithm with ECDSA P-384 private keys
- **WebSocket Communication**: Secure WebSocket connections with JSON-RPC 2.0 protocol
- **SSH Provisioning**: Automated user, SSH key, and sudo access management
- **Dry-Run Mode**: Safe testing without making actual system changes
- **Command Testing**: Direct script execution for validation
- **Automatic Reconnection**: Exponential backoff retry mechanism for connection failures
- **Enhanced Debugging**: Detailed HTTP status code logging for WebSocket connection issues
- **Secure Key Management**: Separate key generation with protection against accidental recreation

## Quick Start (On-Premises Setup)

### Manual Setup Process

The setup process for P0 SSH Agent:

```bash
# 1. Download the binary
wget https://releases.p0.com/p0-ssh-agent/latest/p0-ssh-agent-linux-amd64
chmod +x p0-ssh-agent-linux-amd64
mv p0-ssh-agent-linux-amd64 p0-ssh-agent

# 2. Generate JWT keys
./p0-ssh-agent keygen

# 3. Create configuration file (see Configuration File Format section)
# Edit config.yaml with your organization settings

# 4. Start the agent
./p0-ssh-agent start --config config.yaml
```

### Method 2: Manual Build and Setup

If you need to build from source:

```bash
# Build the single binary with all subcommands
make build
```

The binary will be created as `dist/p0-ssh-agent`.

### Manual Configuration Steps

#### 1. Generate JWT Keys

**⚠️ Important**: Only run this once per client. Regenerating keys will break existing registrations.

```bash
# Generate keys in current directory
p0-ssh-agent keygen

# Or specify a custom path
p0-ssh-agent keygen --key-path ~/.p0/keys
```

The keygen command will:

- Generate ECDSA P-384 private/public keypair
- Save `jwk.private.json` and `jwk.public.json`
- Display the public key for backend registration
- Protect against accidental overwriting (use `--force` to override)

#### 2. Create Configuration

Create a configuration file `config.yaml`:

```yaml
version: "1.0"
orgId: "my-company" # Replace with your organization ID
hostId: "hostname-goes-here" # Replace with unique host identifier
hostname: "custom-hostname" # Optional: override system hostname
tunnelHost: "wss://api.p0.app" # P0 backend URL
keyPath: "/etc/p0-ssh-agent/keys" # JWT key storage directory
labels:
  - "environment=production" # Machine labels for identification
  - "team=infrastructure"
  - "region=us-west-2"
environmentId: "production" # Environment identifier
```

#### 3. Register with Backend

Generate a registration request:

```bash
p0-ssh-agent register --config config.yaml
```

#### 4. Start the Agent

```bash
# Using configuration file
p0-ssh-agent start --config config.yaml

# Or with command line flags
p0-ssh-agent start \
  --org-id my-company \
  --host-id hostname-goes-here \
  --tunnel-host wss://p0.example.com/websocket \
  --key-path ~/.p0/keys
```

## On-Premises Node Configuration Requirements

### Required Configuration Fields

For on-premises nodes, these fields are **mandatory**:

- `orgId`: Your P0 organization identifier
- `hostId`: Unique identifier for this machine/node
- `tunnelHost`: WebSocket URL to your P0 backend (must be accessible from the node)

### Network Requirements

- **Outbound HTTPS/WSS**: The node must be able to reach your P0 backend on port 443
- **No Inbound Connections**: The agent initiates all connections outbound
- **WebSocket Support**: Ensure firewalls/proxies support WebSocket upgrades

### Security Considerations

- **JWT Keys**: Stored locally on the node, never transmitted
- **Secure Transport**: Always use `wss://` (secure WebSocket) for production
- **File Permissions**: Key files automatically set to 600/700 permissions

## Available Commands

All commands support these global flags:
| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config` | Path to configuration file | - |
| `-v, --verbose` | Enable verbose logging | `false` |

### `start` - Start the SSH Agent

Start the WebSocket proxy agent that connects to P0 backend.

| Flag               | Description                               | Default |
| ------------------ | ----------------------------------------- | ------- |
| `--org-id`         | Organization identifier                   | -       |
| `--host-id`        | Host identifier                           | -       |
| `--tunnel-host`    | WebSocket URL (e.g., ws://localhost:8079) | -       |
| `--key-path`       | Path to store JWT key files               | -       |
| `--labels`         | Machine labels for registration           | -       |
| `--environment`    | Environment ID for registration           | -       |
| `--tunnel-timeout` | Tunnel timeout in milliseconds            | -       |
| `--dry-run`        | Log commands but don't execute them       | `false` |

### `keygen` - Generate JWT Keys

Generate ECDSA P-384 keypair for JWT authentication.

| Flag         | Description                  | Default |
| ------------ | ---------------------------- | ------- |
| `--key-path` | Directory to store key files | `.`     |
| `--force`    | Overwrite existing keys      | `false` |

### `register` - Generate Registration Request

Generate machine registration request for P0 backend.

| Flag       | Description                  | Default |
| ---------- | ---------------------------- | ------- |
| `--output` | Output format (json or yaml) | `json`  |

### `status` - Check Installation Status

Comprehensive health check of your P0 SSH Agent installation.

**Usage:**

```bash
p0-ssh-agent status
```

**Validates:**

- Configuration file validity
- JWT key presence and validity
- Directory permissions and ownership

### `command` - Execute Provisioning Scripts

Execute provisioning scripts directly for testing and validation.

| Flag           | Description                           | Default        |
| -------------- | ------------------------------------- | -------------- |
| `--command`    | Command to execute (required)         | -              |
| `--username`   | Username for the operation (required) | -              |
| `--action`     | Action to perform (grant or revoke)   | `grant`        |
| `--request-id` | Request ID for tracking               | auto-generated |
| `--public-key` | SSH public key for authorized keys    | -              |
| `--sudo`       | Grant sudo access                     | `false`        |
| `--dry-run`    | Log commands but don't execute them   | `false`        |

#### Available Commands for `command`:

- `provisionUser` - Create/remove user accounts
- `provisionAuthorizedKeys` - Manage SSH authorized keys
- `provisionSudo` - Grant/revoke sudo access

## Usage Examples

### On-Premises Node Setup

**Manual setup (recommended):**

```bash
# 1. Generate JWT keys
p0-ssh-agent keygen --key-path ~/.p0/keys

# 2. Create configuration file
cat > config.yaml << EOF
version: "1.0"
orgId: "my-company"
hostId: "$(hostname)"
tunnelHost: "wss://p0.example.com/websocket"
keyPath: "/etc/p0-ssh-agent/keys"
environmentId: "production"
tunnelTimeoutMs: 30000
EOF

# 3. Generate registration request
p0-ssh-agent register --config config.yaml

# 4. Start the agent
p0-ssh-agent start --config config.yaml --verbose
```

### Command Line Usage

```bash
# Start with individual flags
p0-ssh-agent start \
  --org-id my-company \
  --host-id hostname-goes-here \
  --tunnel-host wss://p0.example.com/websocket \
  --key-path ~/.p0/keys \
  --verbose

# Start with dry-run mode (safe testing)
p0-ssh-agent start --config config.yaml --dry-run

# Force regenerate keys (dangerous!)
p0-ssh-agent keygen --key-path ~/.p0/keys --force

# Check configuration validity
p0-ssh-agent --help
```

### Testing and Validation

```bash
# Test user provisioning
p0-ssh-agent command \
  --command provisionUser \
  --username testuser \
  --dry-run

# Test SSH key provisioning
p0-ssh-agent command \
  --command provisionAuthorizedKeys \
  --username testuser \
  --public-key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7..." \
  --dry-run

# Test sudo access
p0-ssh-agent command \
  --command provisionSudo \
  --username testuser \
  --sudo \
  --action grant \
  --dry-run

# Test revoke operations
p0-ssh-agent command \
  --command provisionUser \
  --username testuser \
  --action revoke \
  --dry-run
```

### Production On-Premises Deployment

**Manual setup approach:**

```bash
# 1. Generate JWT keys
p0-ssh-agent keygen --key-path ~/.p0/keys

# 2. Create configuration file
vi config.yaml

# 3. Generate registration request
p0-ssh-agent register --config config.yaml

# 4. Start the agent
p0-ssh-agent start --config config.yaml
```

### Help and Documentation

```bash
# Show help for main command
p0-ssh-agent --help

# Show help for specific subcommands
p0-ssh-agent start --help
p0-ssh-agent keygen --help
p0-ssh-agent register --help
```

## Architecture

### Authentication Flow

1. Agent loads ECDSA P-384 private key from `jwk.private.json`
2. Creates JWT token with ES384 algorithm and client ID
3. Establishes WebSocket connection with `Authorization: Bearer <token>` header
4. Sends `setClientId` RPC call to register with backend

### Request Handling

- Receives `call` method requests via JSON-RPC 2.0
- Extracts commands from request.Data["command"]
- Executes appropriate provisioning scripts (user, SSH keys, sudo)
- Supports dry-run mode for safe testing
- Logs request details and execution results
- Filters sensitive headers from logs (e.g., authorization)

### Connection Management

- Automatic reconnection with exponential backoff (1s to 30s)
- Graceful shutdown on SIGINT/SIGTERM
- Connection status monitoring and detailed error reporting

## Command Reference

The p0-ssh-agent binary includes multiple subcommands:

### Available Commands

- `start` - Start the WebSocket proxy agent
- `keygen` - Generate JWT keypair for authentication
- `register` - Generate machine registration request
- `status` - Check installation health and status
- `command` - Execute provisioning scripts directly
- `help` - Show help information

### Build Options

The included Makefile provides several build targets:

```bash
make build     # Build p0-ssh-agent binary with subcommands (default)
make deps      # Install Go dependencies
make test      # Run tests
make clean     # Remove build artifacts
make install   # Install to /usr/local/bin (requires sudo)
make dev       # Development build without optimization
make help      # Show all available targets
```

## Troubleshooting

### Common Issues

**WebSocket connection fails with "bad handshake":**

- Check authentication with `--verbose` flag
- Verify client ID is registered in backend
- Ensure JWT keys exist and are readable
- Test endpoint with: `npx wscat -c ws://localhost:8079/socket`

**"Failed to load JWT key" error:**

```bash
# Generate keys first
p0-ssh-agent keygen --key-path ~/.p0/keys

# Then run agent
p0-ssh-agent start --org-id my-org --host-id my-host --key-path ~/.p0/keys
```

**Permission denied errors:**

```bash
# Create secure key directory
mkdir -p ~/.p0/keys
chmod 700 ~/.p0/keys

# Generate keys there
p0-ssh-agent keygen --key-path ~/.p0/keys
```

### Debug Logging

Enable verbose logging to see detailed connection information:

```bash
p0-ssh-agent start --config config.yaml --verbose
```

This shows:

- WebSocket connection attempts with URLs
- HTTP status codes for failed handshakes
- JWT token creation (redacted for security)
- RPC message handling details

## Deployment

### Production Installation

```bash
# Build and install system-wide
make install

# Run from anywhere
p0-ssh-agent start --config /etc/p0-ssh-agent/config.yaml
```

### Systemd Service (Manual)

For manual systemd service setup, create your own service file based on your system requirements and configuration.

## Security Notes

- **Private Keys**: Stored locally and never transmitted over the network
- **JWT Tokens**: Short-lived and created per connection attempt
- **Log Filtering**: Authorization headers and sensitive data filtered from logs
- **File Permissions**: Key files should have restrictive permissions (600/700)
- **Transport Security**: Use `wss://` (secure WebSocket) for production deployments
- **Dry-Run Mode**: Test commands safely without making system changes
- **Provisioning Safety**: All script operations are logged and can be tested in dry-run mode

## Configuration File Format

The configuration file uses YAML format with the following structure:

```yaml
# Required fields
version: "1.0"
orgId: "organization-name" # Your organization identifier
hostId: "machine-hostname" # Unique host identifier
tunnelHost: "wss://api.p0.app" # WebSocket URL (ws:// or wss://)

# Optional fields
hostname: "custom-hostname" # Override system hostname (optional)
keyPath: "/path/to/keys" # JWT key storage directory
environmentId: "production" # Environment identifier
heartbeatIntervalSeconds: 60 # Heartbeat interval in seconds (default: 60)
dryRun: false # Enable dry-run mode globally

# Machine labels (optional)
labels:
  - "type=production"
  - "region=us-west-2"
  - "team=infrastructure"
```
