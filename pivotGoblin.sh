#!/usr/bin/env bash
set -euo pipefail

CONTROL_DIR="${HOME}/.pivot"
LOG_DIR="${CONTROL_DIR}/logs"
KNOWN_HOSTS_FILE="${CONTROL_DIR}/known_hosts"

mkdir -p "${CONTROL_DIR}" "${LOG_DIR}"
touch "${KNOWN_HOSTS_FILE}"
chmod 700 "${CONTROL_DIR}" "${LOG_DIR}"
chmod 600 "${KNOWN_HOSTS_FILE}"

GREEN="✔"
RED="✖"
YELLOW="⚠"

DEFAULT_SOCKS_PORT=1080
DEFAULT_CONTROL_PERSIST="10m"
DEFAULT_LPORT_BIND="127.0.0.1"
DEFAULT_RPORT_BIND="127.0.0.1"
SSH_LOG_LEVEL="${SSH_LOG_LEVEL:-ERROR}"
PIVOT_INSECURE="${PIVOT_INSECURE:-0}"
AUTO_INCLUDE_CONNECTED="${AUTO_INCLUDE_CONNECTED:-1}"
AUTO_INCLUDE_GUESSES="${AUTO_INCLUDE_GUESSES:-1}"
SSHUTTLE_DEBUG="${SSHUTTLE_DEBUG:-0}"
SSHUTTLE_FALLBACK_METHODS="${SSHUTTLE_FALLBACK_METHODS:-auto nat}"
PIVOT_VERIFY_HOST="${PIVOT_VERIFY_HOST:-}"
PIVOT_VERIFY_PORT="${PIVOT_VERIFY_PORT:-}"

LOGFILE="${LOG_DIR}/pivot.log"

########################################
# TIMESTAMP HELPER
########################################

ts() {
  date +"%Y-%m-%d %H:%M:%S"
}

########################################
# LOGGING
########################################

log() {
  local level="$1"; shift
  echo -e "[$(ts)] [$level] $*" | tee -a "$LOGFILE" >&2
}

log_info() { log "*" "$@"; }
log_ok()   { log "✔" "$@"; }
log_warn() { log "⚠" "$@"; }
log_fail() { log "✖" "$@"; exit 1; }

########################################
# CLEANUP TRAP
########################################

cleanup() {
  log_warn "Interrupt received - cleaning up managed pivots..."
  stop_all || true
}
trap cleanup INT TERM

########################################
# HELPERS
########################################

need_bin() {
  command -v "$1" >/dev/null 2>&1 || log_fail "Missing binary: $1"
}

sanitize_name() {
  tr ',:@/' '____' <<< "$1"
}

session_id() {
  local user="$1"
  local chain="$2"
  printf '%s@%s' "$user" "$(sanitize_name "$chain")"
}

sock_path() {
  printf '%s/%s.ctl\n' "$CONTROL_DIR" "$(session_id "$1" "$2")"
}

meta_path() {
  printf '%s/%s.meta\n' "$CONTROL_DIR" "$(session_id "$1" "$2")"
}

pid_path() {
  printf '%s/%s.pid\n' "$CONTROL_DIR" "$(session_id "$1" "$2")"
}

final_target() {
  awk -F',' '{print $NF}' <<< "$1"
}

jump_chain() {
  local chain="$1"
  awk -F',' 'NF>1 {for(i=1;i<NF;i++) printf "%s%s", $i, (i<NF-1 ? "," : "")}' <<< "$chain"
}

safe_meta_get() {
  local key="$1"
  local file="$2"
  awk -F= -v k="$key" '$1==k {sub(/^[^=]*=/, ""); print; exit}' "$file" 2>/dev/null || true
}

write_meta() {
  local file="$1"
  shift
  : > "$file"
  while (($#)); do
    printf '%s\n' "$1" >> "$file"
    shift
  done
}

is_rfc1918_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^10\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || \
  [[ "$cidr" =~ ^192\.168\.[0-9]+\.[0-9]+/[0-9]+$ ]] || \
  [[ "$cidr" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+/[0-9]+$ ]]
}

is_noise_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^127\. ]] || \
  [[ "$cidr" =~ ^169\.254\. ]] || \
  [[ "$cidr" =~ ^172\.17\.0\.0/16$ ]] || \
  [[ "$cidr" =~ ^172\.18\.0\.0/16$ ]] || \
  [[ "$cidr" =~ ^172\.19\.0\.0/16$ ]] || \
  [[ "$cidr" =~ ^172\.20\.0\.0/14$ ]]
}

########################################
# PYTHON NET HELPERS
########################################

network_from_ip_cidr() {
  local value="$1"
  python3 - "$value" <<'PY'
import ipaddress, sys
try:
    iface = ipaddress.ip_interface(sys.argv[1])
    print(iface.network)
except Exception:
    pass
PY
}

infer_24_from_ip() {
  local ip="$1"
  python3 - "$ip" <<'PY'
import ipaddress, sys
try:
    addr = ipaddress.ip_address(sys.argv[1])
    if addr.is_private:
        if addr.version == 4:
            print(ipaddress.ip_network(f"{addr}/24", strict=False))
except Exception:
    pass
PY
}

########################################
# SSH OPTION BUILDERS
########################################

ssh_security_opts() {
  if [[ "$PIVOT_INSECURE" == "1" ]]; then
    cat <<EOF2
-o StrictHostKeyChecking=no
-o UserKnownHostsFile=/dev/null
EOF2
  else
    cat <<EOF2
-o StrictHostKeyChecking=accept-new
-o UserKnownHostsFile=${KNOWN_HOSTS_FILE}
EOF2
  fi
}

ssh_base_opts() {
  cat <<EOF2
-o ExitOnForwardFailure=yes
-o ServerAliveInterval=60
-o ServerAliveCountMax=2
-o TCPKeepAlive=no
-o ControlMaster=auto
-o ControlPersist=${DEFAULT_CONTROL_PERSIST}
-o LogLevel=${SSH_LOG_LEVEL}
-o PreferredAuthentications=publickey,password,keyboard-interactive
-o Compression=yes
$(ssh_security_opts)
EOF2
}

build_ssh_opts_array() {
  local -n _out_ref=$1
  local jumps="$2"
  mapfile -t _out_ref < <(awk 'NF{print}' <<< "$(ssh_base_opts)")
  if [[ -n "$jumps" ]]; then
    _out_ref+=("-J" "$jumps")
  fi
}

ssh_cmd_string_for_sshuttle() {
  local user="$1"
  local chain="$2"

  local jumps
  jumps="$(jump_chain "$chain")"

  local parts=(ssh)
  parts+=(
    "-o" "ControlMaster=no"
    "-o" "ExitOnForwardFailure=yes"
    "-o" "ServerAliveInterval=60"
    "-o" "ServerAliveCountMax=2"
    "-o" "TCPKeepAlive=no"
    "-o" "LogLevel=${SSH_LOG_LEVEL}"
    "-o" "PreferredAuthentications=publickey,password,keyboard-interactive"
    "-o" "Compression=yes"
  )

  if [[ "$PIVOT_INSECURE" == "1" ]]; then
    parts+=("-o" "StrictHostKeyChecking=no" "-o" "UserKnownHostsFile=/dev/null")
  else
    parts+=("-o" "StrictHostKeyChecking=accept-new" "-o" "UserKnownHostsFile=${KNOWN_HOSTS_FILE}")
  fi

  if [[ -n "$jumps" ]]; then
    parts+=("-J" "$jumps")
  fi

  # Use %s not %q — sshuttle passes this to Python shlex.split(), not bash.
  # %q produces backslash-escaped commas (publickey\,password) which shlex
  # does not strip, causing SSH to receive a malformed PreferredAuthentications value.
  printf '%s ' "${parts[@]}"
}

########################################
# PORT HANDLING
########################################

find_free_port() {
  local port="$1"
  while ss -ltn | awk '{print $4}' | grep -qE "[:.]${port}$"; do
    port=$((port+1))
  done
  echo "$port"
}

check_port_available() {
  local requested="$1"
  local chosen
  chosen="$(find_free_port "$requested")"

  if [[ "$chosen" != "$requested" ]]; then
    log_warn "Port ${requested} in use -> using ${chosen}" >&2
  else
    log_ok "Port ${chosen} available" >&2
  fi

  echo "$chosen"
}

########################################
# CONTROL SESSION MANAGEMENT
########################################

control_alive() {
  local user="$1" chain="$2"
  local ctl target jumps
  ctl="$(sock_path "$user" "$chain")"
  target="$(final_target "$chain")"
  jumps="$(jump_chain "$chain")"

  [[ -S "$ctl" ]] || return 1

  local opts=()
  build_ssh_opts_array opts "$jumps"
  ssh "${opts[@]}" -S "$ctl" -O check "${user}@${target}" >/dev/null 2>&1
}

init_control() {
  local user="$1" chain="$2"
  local ctl target jumps meta
  ctl="$(sock_path "$user" "$chain")"
  target="$(final_target "$chain")"
  jumps="$(jump_chain "$chain")"
  meta="$(meta_path "$user" "$chain")"

  if control_alive "$user" "$chain"; then
    log_ok "Reusing existing SSH control session for ${user}@${target}"
    return
  fi

  rm -f "$ctl"

  local opts=()
  build_ssh_opts_array opts "$jumps"

  log_info "Establishing control session to ${user}@${target}${jumps:+ via ${jumps}}"
  ssh "${opts[@]}" -M -S "$ctl" -N -f "${user}@${target}" || log_fail "SSH control session failed"

  if control_alive "$user" "$chain"; then
    write_meta "$meta" \
      "MODE=CONTROL" \
      "USER=${user}" \
      "CHAIN=${chain}" \
      "TARGET=${target}" \
      "JUMPS=${jumps}" \
      "CREATED=$(date -Is)" \
      "UPDATED=$(date -Is)"
    log_ok "Control session established"
  else
    log_fail "Control session did not come up cleanly"
  fi
}

close_control() {
  local user="$1" chain="$2"
  local ctl target jumps
  ctl="$(sock_path "$user" "$chain")"
  target="$(final_target "$chain")"
  jumps="$(jump_chain "$chain")"

  [[ -S "$ctl" ]] || return 0

  local opts=()
  build_ssh_opts_array opts "$jumps"

  if ssh "${opts[@]}" -S "$ctl" -O exit "${user}@${target}" >/dev/null 2>&1; then
    log_ok "Closed SSH control session for ${user}@${target}"
  else
    log_warn "Failed graceful SSH control close for ${user}@${target}; removing stale socket"
  fi
  rm -f "$ctl"
}

########################################
# SMART AUTO DISCOVERY
########################################

run_remote_cmd() {
  local user="$1" chain="$2" remote_cmd="$3"
  local target jumps
  target="$(final_target "$chain")"
  jumps="$(jump_chain "$chain")"

  local ssh_opts=()
  local ctl
  ctl="$(sock_path "$user" "$chain")"

  # Reuse the existing control socket if alive — avoids a fresh SSH auth
  # for every discovery call (route, iface, etc.)
  if [[ -S "$ctl" ]] && ssh -S "$ctl" -O check "${user}@${target}" >/dev/null 2>&1; then
    ssh_opts+=("-S" "$ctl" "-o" "ControlMaster=no")
  else
    build_ssh_opts_array ssh_opts "$jumps"
  fi

  ssh "${ssh_opts[@]}" "${user}@${target}" "$remote_cmd" 2>/dev/null || true
}

discover_route_cidrs() {
  local user="$1" chain="$2"
  run_remote_cmd "$user" "$chain" "ip -4 route show 2>/dev/null || ip route 2>/dev/null" | awk '
    {
      cidr=$1
      if (cidr ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) print cidr
    }
  '
}

discover_iface_cidrs() {
  local user="$1" chain="$2"
  run_remote_cmd "$user" "$chain" "ip -o -4 addr show up scope global 2>/dev/null" | while read -r _ _ _ addr _; do
    [[ -n "${addr:-}" ]] || continue
    network_from_ip_cidr "$addr"
  done
}

infer_target_subnet() {
  local chain="$1"
  local target
  target="$(final_target "$chain")"
  if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    infer_24_from_ip "$target"
  fi
}

filter_cidrs() {
  local include_connected="$1"
  local source="$2"
  while read -r cidr; do
    [[ -n "$cidr" ]] || continue
    is_rfc1918_cidr "$cidr" || continue
    is_noise_cidr "$cidr" && continue
    local prefix="${cidr#*/}"
    [[ "$prefix" =~ ^[0-9]+$ ]] || continue
    if [[ "$source" == "route" ]]; then
      (( prefix <= 30 )) || continue
    elif [[ "$source" == "iface" ]]; then
      (( include_connected == 1 )) || continue
      (( prefix <= 30 )) || continue
    elif [[ "$source" == "guess" ]]; then
      (( prefix <= 30 )) || continue
    fi
    echo "$cidr"
  done
}

discover_smart_cidrs() {
  local user="$1" chain="$2"
  local route_tmp iface_tmp guess_tmp merged_tmp
  route_tmp="$(mktemp)"
  iface_tmp="$(mktemp)"
  guess_tmp="$(mktemp)"
  merged_tmp="$(mktemp)"

  log_info "Auto discovery: checking remote routes"
  discover_route_cidrs "$user" "$chain" | filter_cidrs 1 route | sort -u > "$route_tmp"
  if [[ -s "$route_tmp" ]]; then
    while read -r cidr; do
      log_ok "Found routed subnet: ${cidr}"
    done < "$route_tmp"
  else
    log_warn "No routed private CIDRs found"
  fi

  log_info "Auto discovery: checking interface addresses"
  discover_iface_cidrs "$user" "$chain" | filter_cidrs "$AUTO_INCLUDE_CONNECTED" iface | sort -u > "$iface_tmp"
  if [[ -s "$iface_tmp" ]]; then
    while read -r cidr; do
      log_ok "Derived directly connected subnet: ${cidr}"
    done < "$iface_tmp"
  else
    log_warn "No usable interface-derived subnets found"
  fi

  if [[ "$AUTO_INCLUDE_GUESSES" == "1" ]]; then
    log_info "Auto discovery: checking target-IP fallback"
    infer_target_subnet "$chain" | filter_cidrs 1 guess | sort -u > "$guess_tmp"
    if [[ -s "$guess_tmp" ]]; then
      while read -r cidr; do
        log_warn "Inferred fallback subnet: ${cidr}"
      done < "$guess_tmp"
    else
      log_warn "No target-IP fallback available"
    fi
  else
    : > "$guess_tmp"
  fi

  cat "$route_tmp" "$iface_tmp" "$guess_tmp" | awk 'NF' | sort -u > "$merged_tmp"
  cat "$merged_tmp"

  rm -f "$route_tmp" "$iface_tmp" "$guess_tmp" "$merged_tmp"
}

sshuttle_session_prefix() {
  local user="$1" chain="$2"
  printf '%s/%s__sshuttle' "$CONTROL_DIR" "$(session_id "$user" "$chain")"
}

new_sshuttle_sid() {
  local user="$1" chain="$2"
  printf '%s__%s' "$(session_id "$user" "$chain")" "$(date +%Y%m%d%H%M%S)"
}

validate_sshuttle_traffic() {
  local cidrs_csv="$1"
  local verify_host="$PIVOT_VERIFY_HOST"
  local verify_port="$PIVOT_VERIFY_PORT"

  if [[ -n "$verify_host" && -n "$verify_port" ]]; then
    timeout 3 bash -lc "</dev/tcp/${verify_host}/${verify_port}" >/dev/null 2>&1
    return $?
  fi

  return 0
}

wait_for_sshuttle() {
  local user="$1" target="$2" tries="${3:-8}"
  local i
  for ((i=0;i<tries;i++)); do
    if pgrep -f "sshuttle.*${user}@${target}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

cleanup_dead_sshuttle() {
  local user="$1" target="$2"
  pgrep -f "sshuttle.*${user}@${target}" | xargs -r kill >/dev/null 2>&1 || true
  sleep 1
  pgrep -f "sshuttle.*${user}@${target}" | xargs -r kill -9 >/dev/null 2>&1 || true
}

launch_sshuttle_attempt() {
  local user="$1" target="$2" ssh_cmd="$3" method="$4"
  shift 4
  local args=("$@")

  if [[ "$SSHUTTLE_DEBUG" == "1" ]]; then
    log_warn "SSHUTTLE_DEBUG=1 set - running sshuttle in foreground"
    sshuttle --method "$method" --ssh-cmd "$ssh_cmd" -r "${user}@${target}" "${args[@]}"
  else
    sshuttle --daemon --method "$method" --ssh-cmd "$ssh_cmd" -r "${user}@${target}" "${args[@]}"
  fi
}

########################################
# SESSION REGISTRY
########################################

update_meta_value() {
  local key="$1" value="$2" file="$3"
  if [[ ! -f "$file" ]]; then
    printf '%s=%s\n' "$key" "$value" > "$file"
    return
  fi

  if grep -q "^${key}=" "$file"; then
    awk -F= -v k="$key" -v v="$value" 'BEGIN{OFS="="} $1==k {$0=k OFS v} {print}' "$file" > "${file}.tmp"
    mv "${file}.tmp" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

register_session() {
  local user="$1" chain="$2" mode="$3" port="$4" bind="$5" dest="$6"
  local meta target jumps
  meta="$(meta_path "$user" "$chain")"
  target="$(final_target "$chain")"
  jumps="$(jump_chain "$chain")"

  if [[ ! -f "$meta" ]]; then
    write_meta "$meta" \
      "USER=${user}" \
      "CHAIN=${chain}" \
      "TARGET=${target}" \
      "JUMPS=${jumps}" \
      "CREATED=$(date -Is)"
  fi

  update_meta_value "MODE" "$mode" "$meta"
  update_meta_value "PORT" "$port" "$meta"
  update_meta_value "BIND" "$bind" "$meta"
  update_meta_value "DEST" "$dest" "$meta"
  update_meta_value "UPDATED" "$(date -Is)" "$meta"
}

########################################
# MODES
########################################

start_socks() {
  local user="$1" chain="$2" requested_port="${3:-$DEFAULT_SOCKS_PORT}"
  local ctl target meta port
  ctl="$(sock_path "$user" "$chain")"
  meta="$(meta_path "$user" "$chain")"
  target="$(final_target "$chain")"

  need_bin ssh
  need_bin ss

  if [[ -f "$meta" ]]; then
    local mode old_port
    mode="$(safe_meta_get MODE "$meta")"
    old_port="$(safe_meta_get PORT "$meta")"
    if [[ "$mode" == "SOCKS" && -n "$old_port" ]] && control_alive "$user" "$chain"; then
      log_ok "Reusing SOCKS on port ${old_port}"
      log_info "proxychains: socks5 127.0.0.1 ${old_port}"
      return
    fi
  fi

  port="$(check_port_available "$requested_port")"
  init_control "$user" "$chain"

  log_info "Starting SOCKS proxy to ${user}@${target}"
  ssh -S "$ctl" -D "127.0.0.1:${port}" -N -f "${user}@${target}"
  register_session "$user" "$chain" "SOCKS" "$port" "127.0.0.1" "dynamic"

  log_ok "SOCKS -> 127.0.0.1:${port}"
}

start_local_forward() {
  local user="$1" chain="$2" lport="$3" rhost="$4" rport="$5" lbind="${6:-$DEFAULT_LPORT_BIND}"
  local ctl target port
  ctl="$(sock_path "$user" "$chain")"
  target="$(final_target "$chain")"

  need_bin ssh
  need_bin ss

  [[ -n "$lport" && -n "$rhost" && -n "$rport" ]] || log_fail "Usage: local <user> <chain> <lport> <rhost> <rport> [lbind]"

  port="$(check_port_available "$lport")"
  init_control "$user" "$chain"

  log_info "Creating local forward ${lbind}:${port} -> ${rhost}:${rport} via ${user}@${target}"
  ssh -S "$ctl" -L "${lbind}:${port}:${rhost}:${rport}" -N -f "${user}@${target}"
  register_session "$user" "$chain" "LOCAL" "$port" "$lbind" "${rhost}:${rport}"

  log_ok "LOCAL -> ${lbind}:${port} => ${rhost}:${rport}"
}

start_remote_forward() {
  local user="$1" chain="$2" rport="$3" lhost="$4" lport="$5" rbind="${6:-$DEFAULT_RPORT_BIND}"
  local ctl target
  ctl="$(sock_path "$user" "$chain")"
  target="$(final_target "$chain")"

  need_bin ssh

  [[ -n "$rport" && -n "$lhost" && -n "$lport" ]] || log_fail "Usage: remote <user> <chain> <rport> <lhost> <lport> [rbind]"

  init_control "$user" "$chain"

  log_info "Creating remote forward ${rbind}:${rport} -> ${lhost}:${lport} on ${user}@${target}"
  ssh -S "$ctl" -R "${rbind}:${rport}:${lhost}:${lport}" -N -f "${user}@${target}"
  register_session "$user" "$chain" "REMOTE" "$rport" "$rbind" "${lhost}:${lport}"

  log_ok "REMOTE -> ${rbind}:${rport} => ${lhost}:${lport}"
}

start_sshuttle() {
  local user="$1" chain="$2" cidrs_arg="${3:-auto}"
  shift 3 || true
  local extra_args=("$@")

  local target jumps ssh_cmd
  target="$(final_target "$chain")"
  jumps="$(jump_chain "$chain")"

  need_bin sshuttle
  need_bin ssh
  need_bin sudo
  need_bin python3
  need_bin timeout

  log_info "Requesting sudo privileges..."
  sudo -v || log_fail "sudo authentication failed"

  # Init control session BEFORE discovery so run_remote_cmd reuses it (avoids 3x password prompts)
  if ! control_alive "$user" "$chain"; then
    init_control "$user" "$chain"
    sleep 1
  fi

  local cidr_list=()
  if [[ "$cidrs_arg" == "auto" ]]; then
    mapfile -t cidr_list < <(discover_smart_cidrs "$user" "$chain")
    if (( ${#cidr_list[@]} == 0 )); then
      log_fail "No routes discovered and no safe fallback could be inferred"
    fi
  else
    cidr_list=("$cidrs_arg")
  fi

  # Auto-exclude the pivot host itself to prevent sshuttle intercepting its own SSH tunnel
  local exclude_args=()
  if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    exclude_args+=("-x" "${target}/32")
    log_info "Auto-excluding pivot host ${target}/32 from tunnel routes"
  fi

  ssh_cmd="$(ssh_cmd_string_for_sshuttle "$user" "$chain")"

  local method sid pidfile meta pid
  for method in $SSHUTTLE_FALLBACK_METHODS; do
    log_info "Starting sshuttle for: ${cidr_list[*]} (method=${method})"
    cleanup_dead_sshuttle "$user" "$target"

    if ! launch_sshuttle_attempt "$user" "$target" "$ssh_cmd" "$method" "${exclude_args[@]}" "${extra_args[@]}" "${cidr_list[@]}"; then
      log_warn "sshuttle exited during launch (method=${method})"
      continue
    fi

    if [[ "$SSHUTTLE_DEBUG" == "1" ]]; then
      return 0
    fi

    if ! wait_for_sshuttle "$user" "$target" 8; then
      log_warn "sshuttle did not stay alive (method=${method})"
      continue
    fi

    pid="$(pgrep -f "sshuttle.*${user}@${target}" | head -n1 || true)"
    if [[ -z "$pid" ]]; then
      log_warn "sshuttle process disappeared after launch (method=${method})"
      continue
    fi

    if ! validate_sshuttle_traffic "${cidr_list[*]}"; then
      log_warn "Traffic validation failed (method=${method})"
      cleanup_dead_sshuttle "$user" "$target"
      continue
    fi

    sid="$(new_sshuttle_sid "$user" "$chain")"
    pidfile="${CONTROL_DIR}/${sid}.pid"
    meta="${CONTROL_DIR}/${sid}.meta"
    echo "$pid" > "$pidfile"
    write_meta "$meta"       "MODE=SSHUTTLE"       "SID=${sid}"       "USER=${user}"       "CHAIN=${chain}"       "TARGET=${target}"       "JUMPS=${jumps}"       "CIDRS=${cidr_list[*]}"       "METHOD=${method}"       "PID=${pid}"       "CREATED=$(date -Is)"       "UPDATED=$(date -Is)"       "VALIDATED=1"
    log_ok "sshuttle running (PID ${pid}, method=${method})"
    return 0
  done

  log_fail "sshuttle failed across all fallback methods: ${SSHUTTLE_FALLBACK_METHODS}"
}

########################################
# STATUS / HEALTH
########################################

show_status() {
  local found=0
  shopt -s nullglob

  log_info "Pivot sessions:"
  for f in "${CONTROL_DIR}"/*.meta; do
    found=1
    echo "--- $(basename "$f" .meta) ---"
    cat "$f"

    local mode user chain pid port ctl
    mode="$(safe_meta_get MODE "$f")"
    user="$(safe_meta_get USER "$f")"
    chain="$(safe_meta_get CHAIN "$f")"
    pid="$(safe_meta_get PID "$f")"
    port="$(safe_meta_get PORT "$f")"
    ctl="$(sock_path "$user" "$chain")"

    local target
    target="$(final_target "$chain")"

    case "$mode" in
      SSHUTTLE)
        if pgrep -f "sshuttle.*${user}@${target}" >/dev/null 2>&1; then
          if [[ "$(safe_meta_get VALIDATED "$f")" == "1" ]]; then
            echo "HEALTH=UP"
          else
            echo "HEALTH=UNVERIFIED"
          fi
        else
          echo "HEALTH=DOWN"
        fi
        ;;
      SOCKS|LOCAL|REMOTE|CONTROL)
        if [[ -S "$ctl" ]] && control_alive "$user" "$chain"; then
          echo "CONTROL=UP"
        else
          echo "CONTROL=DOWN"
        fi
        if [[ -n "$port" ]] && ss -ltn | awk '{print $4}' | grep -qE "[:.]${port}$"; then
          echo "LISTENER=UP"
        fi
        ;;
    esac
  done

  shopt -u nullglob

  if [[ "$found" == "0" ]]; then
    log_warn "No managed pivot metadata found"
  fi
}

########################################
# STOP FUNCTIONS
########################################

stop_target() {
  local user="$1" chain="$2"
  local stopped=0
  shopt -s nullglob

  for meta in "${CONTROL_DIR}"/*.meta; do
    local m_user m_chain pidfile pid base
    m_user="$(safe_meta_get USER "$meta")"
    m_chain="$(safe_meta_get CHAIN "$meta")"
    [[ "$m_user" == "$user" && "$m_chain" == "$chain" ]] || continue

    base="$(basename "$meta" .meta)"
    pidfile="${CONTROL_DIR}/${base}.pid"
    if [[ -f "$pidfile" ]]; then
      pid="$(cat "$pidfile")"
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" >/dev/null 2>&1 || true
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
          kill -9 "$pid" >/dev/null 2>&1 || true
        fi
        log_ok "Stopped process ${pid} for ${user}@${chain}"
      fi
    fi

    close_control "$user" "$chain"
    rm -f "$meta" "$pidfile"
    stopped=1
  done

  shopt -u nullglob
  if [[ "$stopped" == "1" ]]; then
    log_ok "Stopped pivot for ${user}@${chain}"
  else
    log_warn "No managed pivot found for ${user}@${chain}"
  fi
}

stop_all() {
  local stopped=0
  shopt -s nullglob

  for meta in "${CONTROL_DIR}"/*.meta; do
    local base user chain
    base="$(basename "$meta" .meta)"
    user="$(safe_meta_get USER "$meta")"
    chain="$(safe_meta_get CHAIN "$meta")"

    if [[ -n "$user" && -n "$chain" ]]; then
      stop_target "$user" "$chain"
      stopped=1
    else
      rm -f "$meta"
      rm -f "${CONTROL_DIR}/${base}.ctl" "${CONTROL_DIR}/${base}.pid"
    fi
  done

  shopt -u nullglob

  if [[ "$stopped" == "1" ]]; then
    log_ok "All managed pivots stopped"
  else
    log_warn "No managed pivots to stop"
  fi
}

########################################
# HELP / PARSING
########################################

usage() {
  cat <<EOF2
Usage:
  $0 [--insecure] socks <user> <host[,jump1,...]> [local_socks_port]
  $0 [--insecure] local <user> <host[,jump1,...]> <lport> <rhost> <rport> [lbind]
  $0 [--insecure] remote <user> <host[,jump1,...]> <rport> <lhost> <lport> [rbind]
  $0 [--insecure] sshuttle <user> <host[,jump1,...]> [auto|cidr ...] [--dns] [--auto-nets]
  $0 status
  $0 stop <user> <host[,jump1,...]>
  $0 stop all

Smart auto-discovery order:
  1. Routed private CIDRs from remote 'ip route'
  2. Directly connected private subnets from remote interface addresses
  3. /24 fallback inferred from the target IP when it is RFC1918

Notes:
  - Multi-hop chains are comma-separated and interpreted as jump hosts ending with the final target.
    Example: kali dmz-jump,core-jump,target.internal 1080
  - Default security uses StrictHostKeyChecking=accept-new and a dedicated known_hosts file.
  - Use --insecure only for throwaway lab situations.
  - SSHUTTLE_DEBUG=1 runs sshuttle in foreground for troubleshooting.
  - SSHUTTLE_FALLBACK_METHODS controls retry order (default: "auto nat").
EOF2
}

########################################
# BANNER
########################################

print_banner() {
  cat <<'BANNER'

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
  ─────────────────────────────────────────────────────────────────
BANNER
}

parse_global_flags() {
  while (($#)); do
    case "$1" in
      --insecure)
        PIVOT_INSECURE=1
        shift
        ;;
      *)
        break
        ;;
    esac
  done
  REMAINING_ARGS=("$@")
}

main() {
  print_banner
  need_bin ssh
  need_bin ss

  parse_global_flags "$@"
  set -- "${REMAINING_ARGS[@]}"

  case "${1:-}" in
    socks)
      start_socks "${2:-}" "${3:-}" "${4:-}"
      ;;
    local)
      start_local_forward "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}"
      ;;
    remote|reverse)
      start_remote_forward "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}"
      ;;
    sshuttle)
      start_sshuttle "${2:-}" "${3:-}" "${4:-auto}" "${@:5}"
      ;;
    status)
      show_status
      ;;
    stop)
      if [[ "${2:-}" == "all" ]]; then
        stop_all
      else
        stop_target "${2:-}" "${3:-}"
      fi
      ;;
    help|-h|--help|"")
      usage
      ;;
    *)
      usage
      log_fail "Unknown command: ${1}"
      ;;
  esac
}

main "$@"
