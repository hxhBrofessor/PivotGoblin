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

LOGFILE="${LOG_DIR}/pivot.log"

########################################
# LOGGING
########################################

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_ok()   { echo -e "[$(ts)] [${GREEN}] $1" | tee -a "$LOGFILE"; }
log_fail() { echo -e "[$(ts)] [${RED}] $1" | tee -a "$LOGFILE" >&2; exit 1; }
log_warn() { echo -e "[$(ts)] [${YELLOW}] $1" | tee -a "$LOGFILE"; }
log_info() { echo -e "[$(ts)] [*] $1" | tee -a "$LOGFILE"; }

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
# ROUTE DISCOVERY
########################################

discover_networks() {
  local user="$1" chain="$2"
  local ctl target jumps
  ctl="$(sock_path "$user" "$chain")"
  target="$(final_target "$chain")"
  jumps="$(jump_chain "$chain")"

  local opts=()
  build_ssh_opts_array opts "$jumps"

  ssh "${opts[@]}" -S "$ctl" "${user}@${target}" \
    "ip route | grep -E '(^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.)'" \
    2>/dev/null || true
}

extract_private_cidrs() {
  local user="$1" chain="$2"
  discover_networks "$user" "$chain" | awk '$1 ~ /\// {print $1}' | sort -u
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
  local user="$1" chain="$2" cidrs="$3" dns="${4:-}" auto_nets="${5:-}"
  local pidfile meta target jumps ssh_cmd
  pidfile="$(pid_path "$user" "$chain")"
  meta="$(meta_path "$user" "$chain")"
  target="$(final_target "$chain")"
  jumps="$(jump_chain "$chain")"

  need_bin sshuttle
  need_bin ssh

  if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    log_warn "sshuttle already running for ${user}@${chain}"
    return
  fi

  local ssh_cmd_parts=(ssh)
  if [[ "$PIVOT_INSECURE" == "1" ]]; then
    ssh_cmd_parts+=("-o" "StrictHostKeyChecking=no" "-o" "UserKnownHostsFile=/dev/null")
  else
    ssh_cmd_parts+=("-o" "StrictHostKeyChecking=accept-new" "-o" "UserKnownHostsFile=${KNOWN_HOSTS_FILE}")
  fi
  ssh_cmd_parts+=("-o" "ServerAliveInterval=60" "-o" "ServerAliveCountMax=2" "-o" "TCPKeepAlive=no")
  if [[ -n "$jumps" ]]; then
    ssh_cmd_parts+=("-J" "$jumps")
  fi
  printf -v ssh_cmd '%q ' "${ssh_cmd_parts[@]}"

  log_info "Starting sshuttle for ${cidrs} to ${user}@${target}${jumps:+ via ${jumps}}"
  # shellcheck disable=SC2086
  sshuttle ${dns:-} ${auto_nets:-} --ssh-cmd "$ssh_cmd" -r "${user}@${target}" "${cidrs}" >/dev/null 2>&1 &
  echo "$!" > "$pidfile"
  sleep 2

  if kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    write_meta "$meta" \
      "MODE=SSHUTTLE" \
      "USER=${user}" \
      "CHAIN=${chain}" \
      "TARGET=${target}" \
      "JUMPS=${jumps}" \
      "CIDRS=${cidrs}" \
      "DNS=${dns}" \
      "AUTO_NETS=${auto_nets}" \
      "PID=$(cat "$pidfile")" \
      "CREATED=$(date -Is)" \
      "UPDATED=$(date -Is)"
      log_ok "sshuttle started"
  else
    rm -f "$pidfile"
    log_fail "sshuttle failed"
  fi
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

    case "$mode" in
      SSHUTTLE)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
          echo "HEALTH=UP"
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
  local meta pidfile pid
  meta="$(meta_path "$user" "$chain")"
  pidfile="$(pid_path "$user" "$chain")"

  if [[ -f "$pidfile" ]]; then
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
      log_ok "Stopped sshuttle process ${pid} for ${user}@${chain}"
    fi
  fi

  close_control "$user" "$chain"
  rm -f "$meta" "$pidfile"
  log_ok "Stopped pivot for ${user}@${chain}"
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
  $0 [--insecure] sshuttle <user> <host[,jump1,...]> <cidrs> [--dns] [--auto-nets]
  $0 status
  $0 stop <user> <host[,jump1,...]>
  $0 stop all

Notes:
  - Multi-hop chains are comma-separated and interpreted as jump hosts ending with the final target.
    Example: kali dmz-jump,core-jump,target.internal 1080
  - Default security uses StrictHostKeyChecking=accept-new and a dedicated known_hosts file.
  - Use --insecure only for throwaway lab situations.
EOF2
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
      local dns_flag="" auto_nets_flag=""
      [[ "${5:-}" == "--dns" || "${6:-}" == "--dns" ]] && dns_flag="--dns"
      [[ "${5:-}" == "--auto-nets" || "${6:-}" == "--auto-nets" || "${7:-}" == "--auto-nets" ]] && auto_nets_flag="--auto-nets"
      start_sshuttle "${2:-}" "${3:-}" "${4:-}" "$dns_flag" "$auto_nets_flag"
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
