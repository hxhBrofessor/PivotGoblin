# Pivot-MERP

> **Modular, operator-focused SSH pivoting framework for red teamers and penetration testers**

---

## Overview

**Pivot-MERP** is a lightweight, operator-friendly framework for managing SSH-based pivots during red team engagements and penetration tests.

It simplifies:

* SOCKS proxying
* SSH tunneling (local & remote)
* Multi-hop pivoting
* Transparent routing with `sshuttle`
* **Automatic network discovery (NEW)**
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

When using `sshuttle auto`, the tool will automatically discover pivotable networks:

1. **Remote routing table**
2. **Directly connected interfaces**
3. **Fallback /24 inference from target IP**

Example:

```bash
./pivot.sh sshuttle kali target auto --dns
```

Output:

```
[*] Auto discovery: checking remote routes
[✔] Found routed subnet: 10.117.100.0/24
[✔] Found routed subnet: 172.16.110.0/24

[*] Auto discovery: checking interface addresses
[✔] Derived directly connected subnet: 172.16.110.0/24

[*] Auto discovery: checking target-IP fallback
[⚠] Inferred fallback subnet: 10.117.100.0/24
```

---

### Security 

* Safer SSH defaults (`accept-new`)
* Dedicated `known_hosts` file
* Optional `--insecure` mode (lab only)
* No unsafe sourcing
* Controlled process cleanup

---

### Operator UX Improvements

* Timestamped logging
* Session reuse (no duplicate tunnels)
* Automatic port conflict resolution
* Cleaner output & status visibility
* Multi-target awareness

---

## Installation

```bash
git clone https://github.com/hxhBrofessor/Pivot-merp.git
cd Pivot-merp
chmod +x pivot.sh
```

Optional:

```bash
sudo ln -s $(pwd)/pivot.sh /usr/local/bin/pivot
```

---

## Usage

```bash
./pivot.sh [--insecure] <mode> <user> <target> [options]
```

---

## Target Format

Supports **multi-hop pivoting**:

```bash
jump1,jump2,target
```

Example:

```bash
./pivot.sh socks kali jump1,jump2,internal-host 1080
```

---

## Modes

---

### SOCKS Proxy

```bash
./pivot.sh socks <user> <target> <port>
```

* Auto-reuses existing sessions
* Auto-selects free port if needed

---

### Transparent Pivot (sshuttle)

```bash
./pivot.sh sshuttle <user> <target> <subnet|auto> [options]
```

Examples:

```bash
# Manual subnet
./pivot.sh sshuttle kali target 172.16.0.0/12 --dns

# Auto-discovery (recommended)
./pivot.sh sshuttle kali target auto --dns
```

---

### Local Port Forward

```bash
./pivot.sh local <user> <target> <lport> <rhost> <rport>
```

---

### Remote Port Forward

```bash
./pivot.sh remote <user> <target> <rport> <lhost> <lport>
```

---

## Session Management

---

### Status

```bash
./pivot.sh status
```

Displays:

* Mode
* Target chain
* Ports / routes
* Health status (UP/DOWN)

---

### Stop Session

```bash
./pivot.sh stop <user> <target>
```

---

### Stop Everything

```bash
./pivot.sh stop all
```

---

## Tool Integration

---

### Proxychains

Instead of modifying system configs, use:

```bash
dynamic_chain
socks5 127.0.0.1 1080
```

Run:

```bash
proxychains nmap -sT target.internal
proxychains firefox
```

---

### Burp Suite

Set:

* SOCKS Host: `127.0.0.1`
* SOCKS Port: `1080`

---

## Example Workflow

```bash
# 1. Start SOCKS pivot
./pivot.sh socks kali jump,target 1080

# 2. Use tools
proxychains nmap -Pn target.internal

# 3. Full network pivot (AUTO )
./pivot.sh sshuttle kali jump,target auto --dns

# 4. Check sessions
./pivot.sh status

# 5. Cleanup
./pivot.sh stop all
```

---

## Troubleshooting

---

### DNS Issues

```bash
--dns
```

---

### Port Already in Use

Handled automatically — tool selects next available port.

---

### sshuttle Requires Root

```bash
sudo ./pivot.sh sshuttle ...
```

---

## Roadmap

* [ ] `pivot web` (auto SOCKS + proxychains + Burp)
* [ ] Reverse pivoting
* [ ] JSON session tracking
* [ ] Plugin architecture
* [ ] Auto tool launching
* [ ] Traffic shaping / OPSEC modes

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
Cyber Warfare | Red Team | Pivot Goblin
