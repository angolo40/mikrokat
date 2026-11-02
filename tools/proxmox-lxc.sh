#!/usr/bin/env bash
# Mikrokat on Proxmox: makes an LXC container, installs Docker and Mikrokat in it, and starts it.
# Run it as root on the Proxmox host:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/angolo40/mikrokat/main/tools/proxmox-lxc.sh)"
#
# Every question has a variable. With the variable set the script does not ask, and with no terminal it
# uses the defaults, so it can run unattended:
#
#   var_ctid=120 var_ip=192.0.2.20/24 var_gateway=192.0.2.1 bash -c "$(curl -fsSL <the address above>)"
#
# Update an install made by this script, keeping .env, rules and data:
#
#   bash -c "$(curl -fsSL <the address above>)" _ update <ctid>
#
# Variables: var_ctid var_hostname var_cpu var_ram var_disk var_storage var_bridge var_ip var_gateway
# var_router_ip var_https. For tests of a change that is not published: var_repo (a Git URL, or a Git
# bundle file on this host) and var_ref (a tag or branch). The script never touches the router and
# never destroys anything.
# The var_ variables are set by ask, by name.
# shellcheck disable=SC2154
set -euo pipefail

PUBLIC_REPO="https://github.com/angolo40/mikrokat.git"
SCRIPT_URL="https://raw.githubusercontent.com/angolo40/mikrokat/main/tools/proxmox-lxc.sh"
RELEASE_API="https://api.github.com/repos/angolo40/mikrokat/releases/latest"
ROUTER_DOC="https://github.com/angolo40/mikrokat#router-setup"
INSTALL_DOC="https://github.com/angolo40/mikrokat#on-proxmox-with-one-command"
DIR=/root/mikrokat

STEP="starting"
CTID=""
LOG=""
KEEP_NOTE=""

say() { printf '%s\n' "$*"; }
step() { STEP=$1; say "==> $1"; }
die() {
  say "ERROR: $*" >&2
  exit 1
}

on_exit() {
  local code=$?
  if [ "$code" -ne 0 ]; then
    say "" >&2
    say "FAILED while: $STEP" >&2
    [ -z "$LOG" ] || say "The log is $LOG" >&2
    [ -z "$KEEP_NOTE" ] || say "$KEEP_NOTE" >&2
  fi
}
trap on_exit EXIT

# ask <name> <question> <default>: sets var_<name> from the variable, the terminal, or the default.
ask() {
  local name="var_$1" question=$2 default=$3 answer=""
  if [ -n "${!name+x}" ]; then
    return 0
  fi
  if [ -t 0 ] && [ -t 1 ]; then
    read -r -p "$question [$default]: " answer || answer=""
  fi
  printf -v "$name" '%s' "${answer:-$default}"
}

usage() {
  say "Mikrokat on Proxmox. Run with no argument to make a container and install Mikrokat in it,"
  say "or with: update <ctid>. The variables that answer the questions are in $INSTALL_DOC"
}

# yes_no <value> <what>: sets ANSWER to yes or no, and stops on anything else.
yes_no() {
  case "$1" in
    yes | y | true | 1) ANSWER=yes ;;
    no | n | false | 0 | "") ANSWER=no ;;
    *) die "$2 must be yes or no. It is: $1" ;;
  esac
}

# --- Checks -----------------------------------------------------------------------------------

check_host() {
  step "Checking this host"
  [ "$(id -u)" -eq 0 ] || die "Run this script as root, on the Proxmox host."
  command -v pveversion >/dev/null 2>&1 || die "pveversion was not found. This script runs on a Proxmox VE host."
  local cmd
  for cmd in pct pveam pvesh pvesm; do
    command -v "$cmd" >/dev/null 2>&1 || die "$cmd was not found. This script runs on a Proxmox VE host."
  done
  local version major minor
  version=$(pveversion | sed -n 's|^pve-manager/\([0-9]*\)\.\([0-9]*\).*|\1 \2|p')
  read -r major minor <<<"$version"
  if [ -z "${major:-}" ] || [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "${minor:-0}" -lt 1 ]; }; then
    die "Proxmox VE 8.1 or newer is needed to pass /dev/net/tun to a container. This is: $(pveversion)"
  fi
  [ -c /dev/net/tun ] || die "/dev/net/tun is missing on this host. Run: modprobe tun"
}

check_storage() {
  step "Checking storage"
  local free_kib need_kib
  pvesm status --storage "$var_storage" >/dev/null 2>&1 || die "Storage $var_storage does not exist."
  pvesm status --content rootdir 2>/dev/null | awk 'NR > 1 && $3 == "active" {print $1}' | grep -qx "$var_storage" ||
    die "Storage $var_storage cannot hold container disks, or is not active."
  free_kib=$(pvesm status --storage "$var_storage" | awk 'NR == 2 {print $6}')
  need_kib=$((var_disk * 1024 * 1024))
  if [ -n "$free_kib" ] && [ "$free_kib" -lt "$need_kib" ]; then
    die "Storage $var_storage has $((free_kib / 1024 / 1024)) GB free, and the container needs $var_disk GB."
  fi
}

# --- Questions --------------------------------------------------------------------------------

number_ok() { [[ ${2:-} =~ ^[0-9]+$ ]] && [ "$2" -ge "$3" ] || die "$1 must be a number, at least $3. It is: ${2:-}"; }

collect() {
  step "Reading the answers"
  local first_storage next_id
  next_id=$(pvesh get /cluster/nextid 2>/dev/null || echo 100)
  first_storage=$(pvesm status --content rootdir 2>/dev/null | awk 'NR > 1 && $3 == "active" {print $1; exit}')
  ask ctid "Container ID" "$next_id"
  ask hostname "Hostname" "mikrokat"
  ask cpu "CPU cores" "2"
  ask ram "RAM in MB" "2048"
  ask disk "Disk in GB" "16"
  ask storage "Storage for the disk" "${first_storage:-local-lvm}"
  ask bridge "Network bridge" "vmbr0"
  ask ip "IP address: dhcp, or an address with its prefix such as 192.0.2.20/24" "dhcp"
  if [ "$var_ip" != dhcp ]; then
    [[ $var_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || die "var_ip must be dhcp or an address with its prefix, such as 192.0.2.20/24. It is: $var_ip"
    ask gateway "Gateway" ""
    [ -n "$var_gateway" ] || die "A fixed address needs var_gateway."
  fi
  ask router_ip "Address of the MikroTik router, to accept TZSP only from it (empty for any)" ""
  ask https "Enable the HTTPS inspection beta? (yes/no)" "no"

  number_ok var_ctid "$var_ctid" 100
  number_ok var_cpu "$var_cpu" 1
  number_ok var_ram "$var_ram" 1024
  number_ok var_disk "$var_disk" 8
  [[ $var_hostname =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || die "var_hostname is not a valid host name: $var_hostname"
  [[ -z $var_router_ip || $var_router_ip =~ ^[0-9a-fA-F:.]+$ ]] || die "var_router_ip must be an address. It is: $var_router_ip"
  yes_no "$var_https" var_https
  var_https=$ANSWER
  ! pct status "$var_ctid" >/dev/null 2>&1 || die "Container $var_ctid already exists. Choose another var_ctid. Nothing was changed."
  ! [ -e "/etc/pve/qemu-server/$var_ctid.conf" ] || die "ID $var_ctid is used by a virtual machine. Choose another var_ctid."
}

# --- The part inside the container ------------------------------------------------------------

# Written to the container and run there. It never prints the password.
inner_script() {
  cat <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
DIR=/root/mikrokat
export DEBIAN_FRONTEND=noninteractive
say() { printf '==> %s\n' "$*"; }

# Prints the tag of the latest release, or nothing.
latest_tag() {
  curl -fsSL --max-time 20 "$RELEASE_API" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1
}

# Makes the checkout at DIR match the wanted version: REF, else the latest release, else the newest
# tag if GitHub did not answer, else main. An update must not land on main because of a rate limit.
checkout() {
  local source=${REPO_FILE:-} tag
  if [ -n "$source" ]; then
    git -C "$DIR" fetch -q --force --tags "$source" '+refs/heads/*:refs/remotes/origin/*'
  else
    git -C "$DIR" fetch -q --force --tags "${REPO:-origin}" '+refs/heads/*:refs/remotes/origin/*'
  fi
  tag=${REF:-}
  [ -n "$tag" ] || tag=$(latest_tag || true)
  [ -n "$tag" ] || tag=$(git -C "$DIR" tag --list 'v*' --sort=-v:refname | head -n 1 || true)
  if [ -n "$tag" ] && git -C "$DIR" rev-parse -q --verify "refs/tags/$tag^{commit}" >/dev/null; then
    git -C "$DIR" checkout -q --detach "refs/tags/$tag"
  elif [ -n "$tag" ] && git -C "$DIR" rev-parse -q --verify "refs/remotes/origin/$tag^{commit}" >/dev/null; then
    git -C "$DIR" checkout -q --detach "refs/remotes/origin/$tag"
  elif [ -n "${REF:-}" ]; then
    echo "The version $REF does not exist in the repository." >&2
    exit 1
  else
    say "No release found, using main"
    git -C "$DIR" checkout -q --detach refs/remotes/origin/main
  fi
  say "Version: $(git -C "$DIR" describe --tags --always)"
}

set_env() { # set_env <name> <value>
  if grep -q "^$1=" "$DIR/.env"; then
    sed -i "s|^$1=.*|$1=$2|" "$DIR/.env"
  else
    printf '%s=%s\n' "$1" "$2" >>"$DIR/.env"
  fi
}

case "$1" in
  install)
    say "Installing packages"
    apt-get update -q
    apt-get install -y -q ca-certificates curl git gnupg python3
    say "Installing Docker from Docker's repository"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    . /etc/os-release
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian %s stable\n' \
      "$(dpkg --print-architecture)" "$VERSION_CODENAME" >/etc/apt/sources.list.d/docker.list
    apt-get update -q
    apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    say "Getting Mikrokat"
    git clone -q "${REPO_FILE:-$REPO}" "$DIR"
    git -C "$DIR" remote set-url origin "$PUBLIC_REPO"
    checkout
    say "Writing .env"
    cp "$DIR/.env.example" "$DIR/.env"
    chmod 600 "$DIR/.env"
    password=$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)))')
    set_env WEB_PASSWORD "$password"
    unset password
    [ -z "${ROUTER_HOST:-}" ] || set_env ROUTER_HOST "$ROUTER_HOST"
    [ "${HTTPS:-no}" != yes ] || set_env COMPOSE_PROFILES https
    cd "$DIR"
    say "Downloading the rules"
    docker compose run -T --rm --no-deps suricata suricata-update --no-reload </dev/null
    say "Building and starting Mikrokat. This takes a few minutes"
    docker compose up -d
    ;;
  update)
    [ -d "$DIR/.git" ] || { echo "$DIR is not a Mikrokat install" >&2; exit 1; }
    cd "$DIR"
    if ! git diff --quiet HEAD -- 2>/dev/null; then
      echo "Files in $DIR were changed by hand, so the update stops. .env, rules and data are not affected by it." >&2
      exit 1
    fi
    checkout
    if [ -n "${HTTPS:-}" ]; then
      if [ "$HTTPS" = yes ]; then set_env COMPOSE_PROFILES https; else set_env COMPOSE_PROFILES ""; fi
    fi
    say "Building and starting Mikrokat"
    docker compose up -d --build --remove-orphans
    # Compose leaves a running container alone when its profile goes.
    if ! grep -qE '^COMPOSE_PROFILES=.*https' .env; then
      docker compose --profile https rm -sf tlsproxy
    fi
    ;;
  *)
    echo "usage: install|update" >&2
    exit 2
    ;;
esac
INNER
}

# in_ct <command...>: runs a command in the container.
in_ct() { pct exec "$CTID" -- "$@"; }

# Pushes the repository file, if var_repo is a file on this host, and sets REPO_FILE.
repo_args() {
  local -n out=$1
  out=("RELEASE_API=$RELEASE_API" "PUBLIC_REPO=$PUBLIC_REPO")
  if [ -n "${var_repo:-}" ] && [ -f "$var_repo" ]; then
    pct push "$CTID" "$var_repo" /root/mikrokat-source.bundle
    out+=("REPO_FILE=/root/mikrokat-source.bundle")
  else
    out+=("REPO=${var_repo:-$PUBLIC_REPO}")
  fi
  [ -z "${var_ref:-}" ] || out+=("REF=$var_ref")
}

run_inner() { # run_inner <mode> [env...]
  local mode=$1
  shift
  local tmp
  tmp=$(mktemp)
  inner_script >"$tmp"
  pct push "$CTID" "$tmp" /root/mikrokat-setup.sh --perms 0700
  rm -f "$tmp"
  # Only progress lines reach the terminal. The whole output goes to the log, and it holds no password.
  in_ct env "$@" bash /root/mikrokat-setup.sh "$mode" 2>&1 | tee -a "$LOG" | sed -n 's/^==> /    /p'
}

wait_web() {
  step "Waiting for the web page"
  local tries=120
  until in_ct curl -s -o /dev/null --max-time 3 http://127.0.0.1:8088/login; do
    tries=$((tries - 1))
    [ "$tries" -gt 0 ] || die "The web page did not answer on port 8088 within 10 minutes. See: pct exec $CTID -- docker compose -f $DIR/docker-compose.yml ps -a"
    sleep 5
  done
}

container_ip() {
  in_ct hostname -I 2>/dev/null | awk '{print $1}'
}

# --- Install ----------------------------------------------------------------------------------

template_store() {
  pvesm status --content vztmpl 2>/dev/null | awk 'NR > 1 && $3 == "active" {print $1; exit}'
}

make_container() {
  local store template args
  store=$(template_store)
  [ -n "$store" ] || die "No active storage holds container templates. Enable the content type Container template on a storage."
  step "Getting the Debian 13 template"
  pveam update >>"$LOG" 2>&1 || say "    pveam update failed, using the list it has"
  template=$(pveam available --section system | awk '$2 ~ /^debian-13-standard/ {print $2}' | sort -V | tail -n 1)
  [ -n "$template" ] || die "pveam does not list a Debian 13 standard template."
  if ! pveam list "$store" | awk '{print $1}' | grep -qx "$store:vztmpl/$template"; then
    pveam download "$store" "$template" >>"$LOG" 2>&1 || die "Could not download $template."
  fi

  step "Creating container $var_ctid"
  local net="name=eth0,bridge=$var_bridge"
  if [ "$var_ip" = dhcp ]; then net+=",ip=dhcp"; else net+=",ip=$var_ip,gw=$var_gateway"; fi
  local features="nesting=1,keyctl=1" tun="/dev/net/tun,mode=0666"
  args=(--hostname "$var_hostname" --cores "$var_cpu" --memory "$var_ram" --swap 512 --rootfs "$var_storage:$var_disk"
    --net0 "$net" --unprivileged 1 --features "$features" --dev0 "$tun" --onboot 1 --ostype debian
    --description "Mikrokat, made by tools/proxmox-lxc.sh")
  pct create "$var_ctid" "$store:vztmpl/$template" "${args[@]}" >>"$LOG" 2>&1 ||
    die "pct create failed. See $LOG"
  CTID=$var_ctid
  KEEP_NOTE="Container $CTID was left as it is for you to inspect. Remove it with: pct stop $CTID; pct destroy $CTID --purge"
}

start_container() {
  step "Starting the container"
  pct start "$CTID" >>"$LOG" 2>&1 || die "pct start failed. See $LOG"
  local tries=60
  until in_ct sh -c 'getent hosts deb.debian.org >/dev/null' >/dev/null 2>&1; do
    tries=$((tries - 1))
    [ "$tries" -gt 0 ] || die "The container has no network after 2 minutes. Check the bridge $var_bridge, the address and the gateway."
    sleep 2
  done
}

install() {
  check_host
  collect
  check_storage
  LOG="/var/log/mikrokat-lxc-$var_ctid.log"
  : >"$LOG"
  chmod 600 "$LOG"
  say "Log: $LOG"
  make_container
  start_container
  step "Installing Docker and Mikrokat in the container"
  local env=()
  repo_args env
  env+=("ROUTER_HOST=$var_router_ip" "HTTPS=$var_https")
  run_inner install "${env[@]}"
  wait_web
  local ip password
  ip=$(container_ip)
  # Read from the container and shown only here: nothing writes it to a log.
  password=$(in_ct sed -n 's/^WEB_PASSWORD=//p' "$DIR/.env")
  KEEP_NOTE=""
  say ""
  say "Mikrokat is running."
  say "  Address:   http://${ip:-<container address>}:8088"
  say "  User:      admin"
  say "  Password:  $password"
  say ""
  say "Next, point the MikroTik at it: send TZSP to ${ip:-the container address} port 37008 with the mangle rules"
  say "in the section Router setup of the README: $ROUTER_DOC"
  if [ "$var_https" = yes ]; then
    say "HTTPS inspection (beta) is enabled. Turn it on for your own devices under Settings, HTTPS inspection."
  fi
  say "To update later, on this host:"
  say "  bash -c \"\$(curl -fsSL $SCRIPT_URL)\" _ update $CTID"
}

# --- Update -----------------------------------------------------------------------------------

update() {
  check_host
  CTID=${1:-}
  [[ $CTID =~ ^[0-9]+$ ]] || die "Usage: proxmox-lxc.sh update <ctid>"
  pct status "$CTID" >/dev/null 2>&1 || die "Container $CTID does not exist."
  [ "$(pct status "$CTID")" = "status: running" ] || die "Container $CTID is not running. Start it with: pct start $CTID"
  in_ct test -d "$DIR/.git" || die "Container $CTID has no Mikrokat install at $DIR."
  LOG="/var/log/mikrokat-lxc-$CTID.log"
  : >>"$LOG"
  chmod 600 "$LOG"
  step "Updating Mikrokat in container $CTID, keeping .env, rules and data"
  local env=()
  repo_args env
  if [ -n "${var_https:-}" ]; then
    yes_no "$var_https" var_https
    env+=("HTTPS=$ANSWER")
  fi
  run_inner update "${env[@]}"
  wait_web
  say ""
  say "Updated to $(in_ct git -C "$DIR" describe --tags --always)."
}

case "${1:-install}" in
  install) install ;;
  update)
    shift
    update "${1:-}"
    ;;
  -h | --help | help) usage ;;
  *) die "Unknown command: $1. Use no argument to install, or: update <ctid>" ;;
esac
