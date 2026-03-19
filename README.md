# PivotGoblin

> **Modular, operator-focused SSH pivoting framework for red teamers and penetration testers**

---

## Overview

```
 ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗
 ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝
 ██████╔╝██║██║   ██║██║   ██║   ██║   
 ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║   
 ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║   
 ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   
  ██████╗  ██████╗ ██████╗ ██╗     ██╗███╗   ██╗
 ██╔════╝ ██╔═══██╗██╔══██╗██║     ██║████╗  ██║
 ██║  ███╗██║   ██║██████╔╝██║     ██║██╔██╗ ██║
 ██║   ██║██║   ██║██╔══██╗██║     ██║██║╚██╗██║
 ╚██████╔╝╚██████╔╝██████╔╝███████╗██║██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝

  "I am not here to save you. I am here to slay networks."
  hxhBrofessor  //  Cyber Warfare  //  Pivot Goblin
```

**PivotGoblin** is a lightweight, operator-friendly framework for managing SSH-based pivots during red team engagements and penetration tests.

It simplifies:

* SOCKS proxying
* SSH tunneling (local & remote)
* Multi-hop pivoting
* Transparent routing with `sshuttle`
* Automatic network discovery
* Session tracking & cleanup

Built for **real-world operations**, not just lab demos.

---

## Features

### Core Capabilities

* SOCKS proxy pivoting (`ssh -D`)
* Transparent pivoting (`sshuttle`)
* Local port forwarding (`ssh -L`)
* Remote port forwarding (`ssh -R`)
* Multi-hop chaining (`ProxyJump`)
* Session tracking & lifecycle management
* Clean teardown (no orphaned processes)

---

### Smart Auto-Discovery

When using `sshuttle auto`, the tool automatically discovers pivotable networks in this order:

1. **Remote routing table** (`ip route`)
2. **Directly connected interfaces** (`ip addr`)
3. **Fallback /24 inference** from target IP (RFC1918 only)

The pivot host itself is **automatically excluded** from tunnel routes to prevent sshuttle from intercepting its own SSH connection — this is handled transparently and requires no operator input.

Example:

```bash
./pivotGoblin.sh sshuttle kali 10.42.87.14 auto --dns
```

Output:

```
[*] Auto discovery: checking remote routes
[✔] Found routed subnet: 10.42.87.0/24
[✔] Found routed subnet: 192.168.45.0/24
[✔] Found routed subnet: 172.16.33.0/24

[*] Auto discovery: checking interface addresses
[✔] Derived directly connected subnet: 10.42.87.0/24
[✔] Derived directly connected subnet: 192.168.45.0/24

[*] Auto discovery: checking target-IP fallback
[⚠] Inferred fallback subnet: 10.42.87.0/24

[*] Auto-excluding pivot host 10.42.87.14/32 from tunnel routes
[*] Starting sshuttle for: 10.42.87.0/24 192.168.45.0/24 172.16.33.0/24 (method=auto)
[✔] sshuttle running (PID 9200, method=auto)
```

---

### Security

* Safer SSH defaults (`StrictHostKeyChecking=accept-new`)
* Dedicated `~/.pivot/known_hosts` file (isolated from system known_hosts)
* Optional `--insecure` mode (lab only — disables host key checking entirely)
* No unsafe sourcing
* Controlled process cleanup

---

### Operator UX Improvements

* Timestamped logging to `~/.pivot/logs/pivot.log`
* Session reuse (no duplicate tunnels)
* Automatic port conflict resolution
* Cleaner output & status visibility
* Multi-target awareness
* Control socket multiplexing (discovery reuses authenticated session — no repeated prompts)

---

## Installation

```bash
git clone https://github.com/hxhBrofessor/PivotGoblin.git
cd PivotGoblin
chmod +x pivotGoblin.sh
```

Optional (add to PATH):

```bash
sudo ln -s $(pwd)/pivotGoblin.sh /usr/local/bin/pivot
```

---

## Reducing Password Prompts (Recommended)

Pivot-MERP uses SSH ControlMaster multiplexing to reuse connections across discovery calls — but sshuttle spawns its own independent SSH subprocess that cannot share the control socket. This means you will see **two password prompts** on a password-auth target: one for the control session and one for sshuttle itself.

**The cleanest solution is key-based auth with ssh-agent:**

```bash
# Load your key once before starting
ssh-add /path/to/your/private_key

# Verify it's loaded
ssh-add -l

# Now run pivot — zero password prompts
./pivotGoblin.sh sshuttle kali 10.42.87.14 auto --dns
```

With `ssh-agent` loaded, both the control session and sshuttle's subprocess will authenticate silently via the agent. This is the recommended approach for real engagements.

---

## Usage

```bash
./pivotGoblin.sh [--insecure] <mode> <user> <target> [options]
```

> **Do not run the entire script as root.** sshuttle requires elevated privileges for firewall rules — the script handles this automatically via an internal `sudo` call. Running as root will break path handling.

---

## Target Format

Supports **multi-hop pivoting** using comma-separated chains. The last entry is always the final target; everything before it is treated as a ProxyJump chain.

```bash
jump1,jump2,target
```

Example:

```bash
./pivotGoblin.sh socks kali jump1,jump2,internal-host 1080
```

---

## Modes

---

### SOCKS Proxy

```bash
./pivotGoblin.sh socks <user> <target> [port]
```

* Default port: `1080`
* Auto-reuses existing sessions — safe to call multiple times
* Auto-selects a free port if the requested one is in use

---

### Transparent Pivot (sshuttle)

```bash
./pivotGoblin.sh sshuttle <user> <target> [auto|cidr] [--dns] [--auto-nets]
```

Examples:

```bash
# Auto-discovery (recommended)
./pivotGoblin.sh sshuttle kali 10.42.87.14 auto --dns

# Manual subnet
./pivotGoblin.sh sshuttle kali 10.42.87.14 172.16.0.0/12 --dns
```

**Notes:**
* The script handles `sudo` internally — do not prefix the command with `sudo`
* The pivot host IP is automatically excluded from routes (prevents self-interception)
* sshuttle tries `auto` then `nat` methods by default — override with `SSHUTTLE_FALLBACK_METHODS`
* On modern systems using nftables instead of iptables, set `SSHUTTLE_FALLBACK_METHODS="nft"` if the default methods fail

---

### Local Port Forward

```bash
./pivotGoblin.sh local <user> <target> <lport> <rhost> <rport> [lbind]
```

Forwards `lbind:lport` on your local machine to `rhost:rport` through the tunnel.

Example — access an internal web server on port 80:

```bash
./pivotGoblin.sh local kali 10.42.87.14 8080 192.168.45.22 80
# Then browse to http://127.0.0.1:8080
```

Default `lbind` is `127.0.0.1`. Pass a different bind address to expose the forward to other hosts on your network.

---

### Remote Port Forward

```bash
./pivotGoblin.sh remote <user> <target> <rport> <lhost> <lport> [rbind]
```

Binds `rbind:rport` on the remote target back to `lhost:lport` on your machine.

Example — expose your local listener to the pivot host:

```bash
./pivotGoblin.sh remote kali 10.42.87.14 4444 127.0.0.1 4444
# Target can now reach your listener at 127.0.0.1:4444 via its own port 4444
```

Default `rbind` is `127.0.0.1`. Note that remote bind addresses other than `127.0.0.1` require `GatewayPorts yes` in the target's `sshd_config`.

---

## Session Management

---

### Status

```bash
./pivotGoblin.sh status
```

Displays all tracked sessions including mode, target chain, ports/routes, and live health check (UP/DOWN).

---

### Stop a Specific Session

```bash
./pivotGoblin.sh stop <user> <target>
```

---

### Stop All Sessions

```bash
./pivotGoblin.sh stop all
```

Cleanly tears down all managed pivots and removes stale sockets and metadata.

---

## Environment Variables

These variables can be set before running the script to modify behavior without editing the source.

| Variable | Default | Description |
|---|---|---|
| `SSHUTTLE_DEBUG` | `0` | Set to `1` to run sshuttle in foreground — shows full output for troubleshooting |
| `SSHUTTLE_FALLBACK_METHODS` | `auto nat` | Space-separated list of sshuttle firewall methods to try in order. Use `nft` on modern nftables systems |
| `AUTO_INCLUDE_CONNECTED` | `1` | Set to `0` to skip directly-connected interface subnets during auto-discovery |
| `AUTO_INCLUDE_GUESSES` | `1` | Set to `0` to skip /24 fallback inference from target IP |
| `PIVOT_VERIFY_HOST` | _(unset)_ | Host to TCP-probe after sshuttle starts — used to validate traffic is actually flowing |
| `PIVOT_VERIFY_PORT` | _(unset)_ | Port to probe on `PIVOT_VERIFY_HOST` for traffic validation |
| `PIVOT_INSECURE` | `0` | Set to `1` to disable host key checking (equivalent to `--insecure` flag) |
| `SSH_LOG_LEVEL` | `ERROR` | SSH verbosity level. Set to `DEBUG` or `VERBOSE` for deep SSH troubleshooting |

**Examples:**

```bash
# Debug a failing sshuttle tunnel
SSHUTTLE_DEBUG=1 ./pivotGoblin.sh sshuttle kali 10.42.87.14 auto --dns

# Use nftables instead of iptables (modern Debian/Ubuntu/Fedora)
SSHUTTLE_FALLBACK_METHODS="nft" ./pivotGoblin.sh sshuttle kali 10.42.87.14 auto --dns

# Validate traffic reaches an internal host after tunnel starts
PIVOT_VERIFY_HOST=192.168.45.1 PIVOT_VERIFY_PORT=80 ./pivotGoblin.sh sshuttle kali 10.42.87.14 auto --dns

# Skip the /24 fallback guess (stricter auto-discovery)
AUTO_INCLUDE_GUESSES=0 ./pivotGoblin.sh sshuttle kali 10.42.87.14 auto --dns
```

---

## Tool Integration

---

### Proxychains

```
# /etc/proxychains.conf
dynamic_chain
socks5 127.0.0.1 1080
```

```bash
proxychains nmap -sT -Pn target.internal
proxychains firefox
```

---

### Burp Suite

Set upstream proxy to:
* SOCKS Host: `127.0.0.1`
* SOCKS Port: `1080`

---

## Example Workflow

```bash
# 0. Pre-load your SSH key (eliminates password prompts)
ssh-add ~/.ssh/id_rsa

# 1. Start transparent pivot with auto-discovery
./pivotGoblin.sh sshuttle kali 10.42.87.14 auto --dns

# 2. Verify tunnel is healthy
./pivotGoblin.sh status

# 3. Use tools directly — no proxychains needed with sshuttle
nmap -Pn -sT 192.168.45.0/24
curl http://172.16.33.9/

# 4. Add a SOCKS proxy on top for tools that need it
./pivotGoblin.sh socks kali 10.42.87.14 1080
proxychains firefox

# 5. Expose a specific internal port locally
./pivotGoblin.sh local kali 10.42.87.14 8080 192.168.45.22 80

# 6. Cleanup everything
./pivotGoblin.sh stop all
```

---

## Troubleshooting

---

### sshuttle Tunnel Dies Immediately

Enable debug mode to see the full output:

```bash
SSHUTTLE_DEBUG=1 ./pivotGoblin.sh sshuttle kali <target> auto --dns
```

Common causes:
* **No python3 on remote host** — sshuttle bootstraps a Python helper remotely; if Python is missing or in a non-standard path, the connection resets immediately
* **Firewall method mismatch** — try `SSHUTTLE_FALLBACK_METHODS="nft"` on nftables systems
* **Self-interception** — automatically handled by pivot host exclusion, but if you are specifying a manual CIDR that contains your pivot host, add `-x <pivot_ip>/32` manually

---

### DNS Issues

Pass `--dns` to route DNS through the tunnel:

```bash
./pivotGoblin.sh sshuttle kali <target> auto --dns
```

---

### Port Already in Use

Handled automatically — the tool selects the next available port and logs a warning.

---

### Double Password Prompts

Expected behavior when using password auth. See the [Reducing Password Prompts](#reducing-password-prompts-recommended) section above — `ssh-agent` + `ssh-add` eliminates both prompts entirely.

---

### sshuttle on Modern Systems (nftables)

If sshuttle fails with iptables errors on Debian 12+, Ubuntu 22.04+, or Fedora:

```bash
SSHUTTLE_FALLBACK_METHODS="nft" ./pivotGoblin.sh sshuttle kali <target> auto --dns
```

---

## Roadmap

* [ ] `-A` agent forwarding as a dedicated mode — currently absent from the framework; relevant for lateral movement scenarios and also directly addresses the double-password-prompt UX issue when key auth is in use via `ssh-agent`
* [ ] `pivot web` (auto SOCKS + proxychains + Burp)
* [ ] Reverse pivoting
* [ ] JSON session tracking
* [ ] Plugin architecture
* [ ] Auto tool launching
* [ ] Traffic shaping / OPSEC modes
* [ ] `ssh-agent` detection warning at startup when no keys are loaded

---

## Disclaimer

This tool is intended for:

* Authorized penetration testing
* Red team engagements
* Lab environments

**Do not use without proper authorization.**

---

## Author

**hxhBrofessor**
Cyber Warfare | Red Team | Pivot Goblin 👺

---

## References

* [An Excruciatingly Detailed Guide To SSH — Graham Helton](https://grahamhelton.com/blog/ssh-cheatsheet) — primary reference for tunnel mechanics
* [SSH Tunneling Explained — iximiuz](https://iximiuz.com/en/posts/ssh-tunnels/)
* [Red Team Village SSH Tunnels — cwolff411](https://github.com/cwolff411/redteamvillage-sshtunnels)
