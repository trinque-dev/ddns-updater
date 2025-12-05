# ddns-updater

A secure, multi-backend dynamic DNS updater written in POSIX C.

## Features

- **Secure by design**: HTTPS-only, input validation, secure memory handling
- **Multi-backend architecture**: Easily extensible to support different DNS providers
- **IPv4 and IPv6 support**: Automatic detection or explicit selection
- **Dry-run mode**: See what would change without making modifications
- **Minimal dependencies**: Only requires libcurl

## Supported Backends

| Backend | Environment Variable | Documentation |
|---------|---------------------|---------------|
| Namesilo | `NAMESILO_API_KEY` | [API Reference](https://www.namesilo.com/api-reference) |

## Building

### Prerequisites

- C11-compatible compiler (gcc, clang)
- libcurl development headers
- POSIX-compliant system

#### macOS

```sh
# Install libcurl (usually pre-installed, or via Homebrew)
brew install curl
```

#### Debian/Ubuntu

```sh
apt-get install build-essential libcurl4-openssl-dev
```

#### Fedora/RHEL

```sh
dnf install gcc libcurl-devel
```

### Compile

```sh
make
```

The binary will be created at `bin/ddns-updater`.

### Build Options

```sh
make debug    # Debug build with symbols
make asan     # AddressSanitizer build (for testing)
make ubsan    # UndefinedBehaviorSanitizer build
make analyze  # Run static analysis
```

### Install

```sh
sudo make install          # Install to /usr/local/bin
make PREFIX=~/.local install  # Install to user directory
```

## Usage

```
Usage: ddns-updater -b <backend> -d <domain> -i <ip> [options]

Required arguments:
  -b, --backend <name>    DNS backend to use (e.g., namesilo)
  -d, --domain <fqdn>     Fully qualified domain name to update
  -i, --ip <address>      IP address to set (IPv4 or IPv6)

Optional arguments:
  -4, --ipv4              Force IPv4 (A record) update
  -6, --ipv6              Force IPv6 (AAAA record) update
  -c, --current           Show current IP for domain and exit
  -n, --dry-run           Show what would be done without making changes
  -q, --quiet             Suppress non-error output
  -v, --verbose           Enable verbose output
  -l, --list-backends     List available backends and exit
  -h, --help              Show this help message and exit
  -V, --version           Show version information and exit
```

## Examples

### Update an A record

```sh
export NAMESILO_API_KEY="your-api-key-here"
ddns-updater -b namesilo -d home.example.com -i 203.0.113.42
```

### Update an AAAA record

```sh
ddns-updater -b namesilo -d home.example.com -i 2001:db8::1 -6
```

### Check current IP

```sh
ddns-updater -b namesilo -d home.example.com -c
```

### Dry run

```sh
ddns-updater -b namesilo -d home.example.com -i 203.0.113.42 -n
```

### Verbose output

```sh
ddns-updater -b namesilo -d home.example.com -i 203.0.113.42 -v
```

## Automation

### Cron example

Update DNS every 5 minutes:

```cron
*/5 * * * * NAMESILO_API_KEY=your-key /usr/local/bin/ddns-updater -b namesilo -d home.example.com -i $(curl -s https://api.ipify.org) -q
```

### systemd timer example

Create `/etc/systemd/system/ddns-updater.service`:

```ini
[Unit]
Description=Dynamic DNS Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment="NAMESILO_API_KEY=your-api-key"
ExecStart=/usr/local/bin/ddns-updater -b namesilo -d home.example.com -i %I
```

Create `/etc/systemd/system/ddns-updater.timer`:

```ini
[Unit]
Description=Run DDNS updater every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

Enable with:

```sh
systemctl enable --now ddns-updater.timer
```

## Security Considerations

- **API keys**: Stored in environment variables, never logged or written to disk
- **HTTPS only**: All API requests use TLS with certificate verification
- **Input validation**: Strict validation of domains, IPs, and API keys
- **Memory safety**: Secure zeroing of sensitive data, bounds checking
- **No shell execution**: All operations performed via C library calls

## Adding a New Backend

1. Create a new file `src/backend_<name>.c`
2. Implement the `ddns_backend_ops_t` interface
3. Register the backend in `src/backend.c`
4. Update the README with the new backend information

See `src/backend_namesilo.c` as a reference implementation.

## License

MIT License. See source files for details.
