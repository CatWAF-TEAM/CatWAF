#!/usr/bin/env bash
#
# CatWAF installer — installs or updates CatWAF Lite or CatWAF Full.
#
#   CatWAF Lite   Caddy + Coraza + the OWASP CRS, the `catwaf` CLI and the
#                 SQLite event store. No dashboard, no HTTP API, no CatAI,
#                 no frontend dependencies.
#   CatWAF Full   Everything in Lite plus the HTTP API, the built React
#                 dashboard (including the Attack Map) and optional CatAI.
#
# Recommended use — download, read, then run:
#
#   curl -fsSLo setup.sh https://raw.githubusercontent.com/CatWAF-TEAM/CatWAF/release-1.0.1/setup.sh
#   less setup.sh
#   sudo bash setup.sh --lite
#
# Piping straight into a root shell means trusting the server, the TLS chain and
# every future change to the file, sight unseen. See SECURITY.md.
#
# Re-running is safe: an existing installation is detected and updated in place.
# Your .env, database, Caddyfile, rules and admin accounts are preserved.

set -euo pipefail

readonly REPO_URL="https://github.com/CatWAF-TEAM/CatWAF"
readonly MIN_NODE_MAJOR=22
readonly DEFAULT_DIR="/opt/catwaf"
readonly SERVICE_USER="catwaf"

EDITION=""
INSTALL_DIR="$DEFAULT_DIR"
DOMAIN=""
ADMIN_USER=""
ASSUME_YES=0
WITH_AI=""
WITH_CLAMAV=""
TMP_DIR=""

# ── output ───────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
fi

info()  { printf '%s\n' "  $*"; }
step()  { printf '%s\n' "${C_CYAN}==>${C_RESET} ${C_BOLD}$*${C_RESET}"; }
ok()    { printf '%s\n' "  ${C_GREEN}✓${C_RESET} $*"; }
warn()  { printf '%s\n' "  ${C_YELLOW}!${C_RESET} $*" >&2; }
die()   { printf '%s\n' "  ${C_RED}✗${C_RESET} $*" >&2; exit 1; }

cleanup() {
  local code=$?
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf -- "$TMP_DIR"
  fi
  return $code
}
trap cleanup EXIT
trap 'die "Interrupted."' INT TERM

usage() {
  cat <<'EOF'
CatWAF installer

Usage: sudo bash setup.sh [options]

Editions
  --lite              WAF + CLI only. No dashboard, no API server, no CatAI,
                      and no frontend dependencies are installed.
  --full              Everything: WAF, CLI, HTTP API, dashboard, CatAI.
  (neither)           Interactive menu.

Options
  --dir <path>        Install directory (default: /opt/catwaf)
  --domain <domain>   Base domain, e.g. example.com. Omit to run locally.
  --admin-user <name> Admin account to create.
  --with-ai           Install Ollama for CatAI (Full only).
  --no-ai             Skip CatAI even in Full.
  --with-clamav       Install ClamAV for upload malware scanning. Optional;
                      the feature stays off until enabled in Settings.
  --no-clamav         Skip ClamAV (the default).
  --yes               Never prompt. Fails instead of asking.
                      Suppresses prompts only; all validation still runs.
  -h, --help          Show this message.

Environment
  CATWAF_ADMIN_PASSWORD   Admin password for non-interactive installs.
                          Preferred over any flag: a flag would land in your
                          shell history and in the process list.

Examples
  sudo bash setup.sh --lite
  sudo bash setup.sh --full --domain example.com --admin-user admin
  CATWAF_ADMIN_PASSWORD='...' sudo -E bash setup.sh --lite --yes \
      --domain example.com --admin-user admin
EOF
}

# ── argument parsing ─────────────────────────────────────────────────────
# Every value is validated below. Nothing parsed here is ever passed to a
# shell for interpretation.
require_value() {
  local flag="$1" value="${2-}"
  # Catches both "--dir" as the final argument (no value at all) and
  # "--dir --yes" (the next flag mistaken for a value).
  [ -n "$value" ] || die "Option $flag requires a value."
  case "$value" in
    -*) die "Option $flag requires a value (got the flag '$value')." ;;
  esac
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --lite)
        [ -z "$EDITION" ] || [ "$EDITION" = "lite" ] || die "Pass either --lite or --full, not both."
        EDITION="lite"; shift ;;
      --full)
        [ -z "$EDITION" ] || [ "$EDITION" = "full" ] || die "Pass either --lite or --full, not both."
        EDITION="full"; shift ;;
      --dir)          require_value "$1" "${2:-}"; INSTALL_DIR="$2"; shift 2 ;;
      --domain)       require_value "$1" "${2:-}"; DOMAIN="$2"; shift 2 ;;
      --admin-user)   require_value "$1" "${2:-}"; ADMIN_USER="$2"; shift 2 ;;
      --with-ai) WITH_AI="yes"; shift ;;
      --no-ai)   WITH_AI="no"; shift ;;
      --with-clamav) WITH_CLAMAV="yes"; shift ;;
      --no-clamav)   WITH_CLAMAV="no"; shift ;;
      --yes|-y)  ASSUME_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "Unknown option: $1" ;;
    esac
  done
}

# ── validation ───────────────────────────────────────────────────────────
# Applied whether or not --yes was passed. --yes removes prompts, never checks.
validate_inputs() {
  if [ -n "$DOMAIN" ]; then
    if ! printf '%s' "$DOMAIN" \
      | grep -Eq '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
      die "Invalid domain: '$DOMAIN'"
    fi
    [ "${#DOMAIN}" -le 253 ] || die "Domain is too long."
  fi

  if [ -n "$ADMIN_USER" ]; then
    printf '%s' "$ADMIN_USER" | grep -Eq '^[a-zA-Z0-9._-]{2,32}$' \
      || die "Invalid admin username: '$ADMIN_USER' (2-32 chars: letters, digits, . _ -)"
  fi

  case "$INSTALL_DIR" in
    /*) ;;
    *)  die "--dir must be an absolute path (got '$INSTALL_DIR')." ;;
  esac
  case "$INSTALL_DIR" in
    *..*) die "--dir must not contain '..'." ;;
  esac

  if [ -n "${CATWAF_ADMIN_PASSWORD:-}" ] && [ "${#CATWAF_ADMIN_PASSWORD}" -lt 8 ]; then
    die "CATWAF_ADMIN_PASSWORD must be at least 8 characters."
  fi

  if [ "$EDITION" = "lite" ] && [ "$WITH_AI" = "yes" ]; then
    die "--with-ai requires --full: CatAI is not part of CatWAF Lite."
  fi
}

# ── platform detection ───────────────────────────────────────────────────
OS_ID=""; OS_LIKE=""; PKG=""

detect_platform() {
  [ "$(uname -s)" = "Linux" ] || die "This installer supports Linux only (found $(uname -s)).
  On macOS, install manually: git clone $REPO_URL && npm install && catwaf setup"

  [ -r /etc/os-release ] || die "Cannot read /etc/os-release — unsupported distribution."
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"

  case "$OS_ID" in
    debian|ubuntu|raspbian|linuxmint|pop) PKG="apt" ;;
    fedora)                               PKG="dnf" ;;
    rhel|centos|rocky|almalinux)          PKG="dnf" ;;
    alpine)                               PKG="apk" ;;
    *)
      case "$OS_LIKE" in
        *debian*)         PKG="apt" ;;
        *rhel*|*fedora*)  PKG="dnf" ;;
        *alpine*)         PKG="apk" ;;
        *)
          die "Unsupported distribution: ${PRETTY_NAME:-$OS_ID}
  Supported: Debian, Ubuntu, Fedora, RHEL/Rocky/AlmaLinux, Alpine.
  Install manually instead:
    git clone $REPO_URL && cd catwaf && npm install && catwaf setup"
          ;;
      esac
      ;;
  esac
  ok "Platform: ${PRETTY_NAME:-$OS_ID} (package manager: $PKG)"
}

has_systemd() { [ -d /run/systemd/system ]; }

pkg_install() {
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -- "$@" >/dev/null ;;
    dnf) if command -v dnf >/dev/null 2>&1; then dnf install -y -- "$@" >/dev/null
         else yum install -y -- "$@" >/dev/null; fi ;;
    apk) apk add --no-cache -- "$@" >/dev/null ;;
  esac
}

pkg_refresh() {
  case "$PKG" in
    apt) apt-get update -qq >/dev/null ;;
    apk) apk update >/dev/null 2>&1 || true ;;
    dnf) : ;;
  esac
}

# ── prerequisites ────────────────────────────────────────────────────────
ensure_base_tools() {
  local missing=()
  for tool in curl tar git; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done

  # pgrep comes from procps, whose package name is not "pgrep" — and which a
  # minimal Debian/Ubuntu install (and every Docker base image) omits. Without
  # it CatWAF's "is Caddy/nginx/Apache already running here" detection silently
  # answers "nothing is running".
  if ! command -v pgrep >/dev/null 2>&1; then
    case "$PKG" in
      dnf|yum) missing+=(procps-ng) ;;
      *)       missing+=(procps) ;;
    esac
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    step "Installing base tools: ${missing[*]}"
    pkg_refresh
    pkg_install "${missing[@]}" ca-certificates
    ok "Base tools installed"
  fi
}

node_major() {
  command -v node >/dev/null 2>&1 || { echo 0; return; }
  node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0
}

ensure_node() {
  local major
  major="$(node_major)"
  if [ "$major" -ge "$MIN_NODE_MAJOR" ]; then
    ok "Node.js $(node -v) (>= $MIN_NODE_MAJOR required)"
    return
  fi

  if [ "$major" -gt 0 ]; then
    warn "Node.js $(node -v) is too old — CatWAF needs $MIN_NODE_MAJOR+ (it uses node:sqlite)."
  fi
  step "Installing Node.js ${MIN_NODE_MAJOR}"

  case "$PKG" in
    apt)
      # NodeSource's setup script is fetched to a file and executed explicitly.
      # It is never piped into a shell, so it can be inspected on failure, and
      # it is never `eval`ed. The Node packages themselves are installed from
      # the NodeSource apt/rpm repository, whose metadata is GPG-signed — the
      # distro package manager verifies those signatures on every install, so
      # the actual Node binary is verified by the strongest mechanism upstream
      # offers. Only this one-time bootstrap script rides on TLS trust alone.
      local script="$TMP_DIR/nodesource_setup.sh"
      curl -fsSL --proto '=https' --tlsv1.2 \
        "https://deb.nodesource.com/setup_${MIN_NODE_MAJOR}.x" -o "$script" \
        || die "Could not download the NodeSource setup script."
      [ -s "$script" ] || die "Downloaded NodeSource script is empty."
      bash "$script" >/dev/null 2>&1 || die "NodeSource setup failed."
      pkg_install nodejs
      ;;
    dnf)
      local script="$TMP_DIR/nodesource_setup.sh"
      curl -fsSL --proto '=https' --tlsv1.2 \
        "https://rpm.nodesource.com/setup_${MIN_NODE_MAJOR}.x" -o "$script" \
        || die "Could not download the NodeSource setup script."
      [ -s "$script" ] || die "Downloaded NodeSource script is empty."
      bash "$script" >/dev/null 2>&1 || die "NodeSource setup failed."
      pkg_install nodejs
      ;;
    apk)
      pkg_refresh
      pkg_install nodejs npm
      ;;
  esac

  major="$(node_major)"
  [ "$major" -ge "$MIN_NODE_MAJOR" ] \
    || die "Node.js $MIN_NODE_MAJOR+ is still not available after installation.
  Install it manually (https://nodejs.org) and re-run this script."
  ok "Node.js $(node -v) installed"
}

ensure_npm() {
  command -v npm >/dev/null 2>&1 || die "npm is missing even though Node is installed. Install npm and re-run."
  ok "npm $(npm -v)"
}

# ── source ───────────────────────────────────────────────────────────────
fetch_source() {
  if [ -d "$INSTALL_DIR/.git" ]; then
    step "Updating existing installation at $INSTALL_DIR"
    # A checkout does not necessarily have an 'origin' remote — it may have been
    # created from a release tarball with `git init`, copied from another
    # machine, or had its remote renamed. `set -e` turned the resulting
    # "No such remote" (exit 2) into a silent abort of the whole installer with
    # no message at all, so add the remote when it is missing and never let
    # this step be fatal.
    if git -C "$INSTALL_DIR" remote get-url origin >/dev/null 2>&1; then
      git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL" \
        || warn "Could not update the 'origin' remote. Keeping the current one."
    else
      git -C "$INSTALL_DIR" remote add origin "$REPO_URL" \
        || warn "Could not add an 'origin' remote. Continuing with the local checkout."
    fi
    if ! git -C "$INSTALL_DIR" pull --ff-only >/dev/null 2>&1; then
      warn "Could not fast-forward (local changes?). Keeping the current checkout."
    else
      ok "Source updated"
    fi
    return
  fi

  if [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null || true)" ]; then
    # Never clobber a non-empty directory that is not a CatWAF checkout.
    die "$INSTALL_DIR exists and is not a CatWAF git checkout.
  Refusing to overwrite it. Choose another location with --dir, or remove it yourself."
  fi

  step "Installing CatWAF into $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" >/dev/null 2>&1 \
    || die "Could not clone $REPO_URL"
  ok "Source installed"
}

# ── service account ──────────────────────────────────────────────────────
ensure_service_user() {
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    ok "Service account '$SERVICE_USER' exists"
    return
  fi
  step "Creating service account '$SERVICE_USER'"
  # A dedicated, non-login, no-home system account: CatWAF must not run as root.
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
      || useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
  elif command -v adduser >/dev/null 2>&1; then
    adduser -S -D -H -s /sbin/nologin "$SERVICE_USER"
  else
    die "No useradd/adduser available to create the service account."
  fi
  ok "Service account created"
}

# ── dependencies + build ─────────────────────────────────────────────────
install_dependencies() {
  step "Installing dependencies (edition: $EDITION)"
  # postinstall reads CATWAF_EDITION and installs frontend dependencies only
  # for Full. This is what keeps a Lite install free of the React toolchain.
  ( cd "$INSTALL_DIR" && CATWAF_EDITION="$EDITION" npm ci --omit=dev --no-audit --no-fund ) \
    || die "npm ci failed."
  ok "Dependencies installed"

  if [ "$EDITION" = "full" ]; then
    step "Building the dashboard"
    ( cd "$INSTALL_DIR" && npm run build ) >/dev/null 2>&1 \
      || die "Dashboard build failed. The WAF and CLI are installed; re-run 'npm run build' in $INSTALL_DIR to retry."
    [ -f "$INSTALL_DIR/frontend/dist/index.html" ] \
      || die "Dashboard build reported success but produced no index.html."
    ok "Dashboard built"
  else
    ok "Dashboard skipped (Lite installs no frontend dependencies)"
  fi
}

# ── configuration ────────────────────────────────────────────────────────
write_env() {
  local env_file="$INSTALL_DIR/.env"
  step "Writing configuration"

  # Secrets are written with a restrictive umask so the file is never briefly
  # world-readable between creation and chmod.
  local old_umask; old_umask="$(umask)"
  umask 077

  if [ ! -f "$env_file" ]; then
    : > "$env_file"
  fi

  set_env_var "$env_file" "CATWAF_EDITION" "$EDITION"
  [ -n "$DOMAIN" ] && set_env_var "$env_file" "DOMAIN" "$DOMAIN"

  if ! grep -q '^JWT_SECRET=' "$env_file" 2>/dev/null; then
    local secret
    secret="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')"
    set_env_var "$env_file" "JWT_SECRET" "$secret"
    unset secret
  fi

  umask "$old_umask"

  chown "$SERVICE_USER":"$SERVICE_USER" "$env_file" 2>/dev/null || true
  chmod 600 "$env_file"
  ok "Configuration written ($env_file, mode 600)"
}

# Idempotent key=value upsert. Values are written through a temp file in the
# same directory and moved into place, so a failure never leaves a truncated
# .env behind.
set_env_var() {
  local file="$1" key="$2" value="$3"
  local tmp; tmp="$(mktemp "${file}.XXXXXX")"
  chmod 600 "$tmp"
  if [ -f "$file" ]; then
    grep -v "^${key}=" "$file" > "$tmp" 2>/dev/null || true
  fi
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  mv -- "$tmp" "$file"
}

# ── CLI on PATH ──────────────────────────────────────────────────────────
link_cli() {
  step "Installing the 'catwaf' command"
  local target="/usr/local/bin/catwaf"
  chmod +x "$INSTALL_DIR/bin/catwaf.js"
  ln -sfn "$INSTALL_DIR/bin/catwaf.js" "$target"
  ok "catwaf → $target"
}

# ── ownership ────────────────────────────────────────────────────────────
set_permissions() {
  step "Setting ownership and permissions"
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
  # The tree is not world-writable, and the data directory (database, logs,
  # pid file) is readable only by the service account.
  chmod 755 "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR/data"
  chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/data"
  chmod 750 "$INSTALL_DIR/data"
  [ -f "$INSTALL_DIR/.env" ] && chmod 600 "$INSTALL_DIR/.env"
  ok "Permissions set (owner: $SERVICE_USER)"
}

# ── systemd ──────────────────────────────────────────────────────────────
install_systemd_unit() {
  if ! has_systemd; then
    warn "systemd is not running here — skipping service installation."
    info "Start CatWAF manually with: catwaf start"
    return
  fi

  # Lite has no HTTP API, so it gets no catwaf.service. Its WAF is Caddy,
  # supervised by Caddy's own unit. Writing a unit that starts a server Lite
  # does not install would be a unit that fails on every boot.
  if [ "$EDITION" = "lite" ]; then
    if [ -f /etc/systemd/system/catwaf.service ]; then
      step "Removing the API service (not used by Lite)"
      systemctl disable --now catwaf.service >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/catwaf.service
      systemctl daemon-reload
      ok "catwaf.service removed"
    fi
    ok "No API service in Lite — the WAF runs as Caddy"
    return
  fi

  step "Installing the catwaf systemd service"
  local node_bin; node_bin="$(command -v node)"
  cat > /etc/systemd/system/catwaf.service <<EOF
[Unit]
Description=CatWAF API and dashboard
Documentation=$REPO_URL
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$node_bin --experimental-sqlite $INSTALL_DIR/backend/server.js
Restart=on-failure
RestartSec=5

# Hardening: CatWAF needs to read its own tree, write its data directory and
# reload Caddy. It needs nothing else.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 /etc/systemd/system/catwaf.service
  systemctl daemon-reload
  systemctl enable catwaf.service >/dev/null 2>&1 || warn "Could not enable catwaf.service"
  ok "catwaf.service installed and enabled"
}

# ── CatAI (Full, optional) ───────────────────────────────────────────────
maybe_install_ai() {
  [ "$EDITION" = "full" ] || return 0
  [ "$WITH_AI" = "yes" ] || { info "CatAI skipped (optional — Full works without it)"; return 0; }

  step "Installing Ollama for CatAI"
  if command -v ollama >/dev/null 2>&1; then
    ok "Ollama already installed"
    return
  fi
  local script="$TMP_DIR/ollama_install.sh"
  if ! curl -fsSL --proto '=https' --tlsv1.2 https://ollama.com/install.sh -o "$script"; then
    warn "Could not download the Ollama installer — skipping CatAI."
    info "CatWAF Full runs fine without it. Install later: https://ollama.com/download"
    return
  fi
  # Supply-chain: Ollama publishes no signed checksum for its install script.
  # If the operator supplies CATWAF_OLLAMA_INSTALL_SHA256 (e.g. recorded from
  # a previous reviewed install, trust-on-first-use), enforce it. Either way
  # the script is saved to disk first — never piped into a shell — and runs
  # with output VISIBLE so what it does is on the record.
  if [ -n "${CATWAF_OLLAMA_INSTALL_SHA256:-}" ]; then
    local actual; actual="$(sha256sum "$script" | awk '{print $1}')"
    if [ "$actual" != "$CATWAF_OLLAMA_INSTALL_SHA256" ]; then
      warn "Ollama installer hash mismatch (expected $CATWAF_OLLAMA_INSTALL_SHA256, got $actual) — skipping CatAI."
      info "Review $script manually or update CATWAF_OLLAMA_INSTALL_SHA256."
      return
    fi
    ok "Ollama installer hash matches the recorded pin"
  fi
  if ! sh "$script"; then
    warn "Ollama installation failed — skipping CatAI. CatWAF Full still works."
    return
  fi
  ok "Ollama installed"
}

# ── optional: ClamAV for upload scanning ─────────────────────────────────
#
# Off unless asked for. CatWAF never bundles an AV engine, and an install that
# does not accept file uploads has no reason to carry a signature database —
# so a missing clamd makes the feature report itself unavailable rather than
# failing anything.
maybe_install_clamav() {
  [ "$WITH_CLAMAV" = "yes" ] || { info "Upload malware scanning skipped (optional — enable later with --with-clamav)"; return 0; }

  step "Installing ClamAV for upload scanning"
  if command -v clamd >/dev/null 2>&1 || command -v clamdscan >/dev/null 2>&1; then
    ok "ClamAV already installed"
  else
    pkg_refresh
    case "$PKG" in
      apt) pkg_install clamav clamav-daemon || { warn "Could not install ClamAV — upload scanning will report itself unavailable."; return 0; } ;;
      dnf) pkg_install clamav clamd clamav-update || { warn "Could not install ClamAV — upload scanning will report itself unavailable."; return 0; } ;;
      apk) pkg_install clamav clamav-daemon || { warn "Could not install ClamAV — upload scanning will report itself unavailable."; return 0; } ;;
    esac
    ok "ClamAV installed"
  fi

  # Without a signature database clamd refuses to start, and freshclam is the
  # only thing that puts one there. A failure is not fatal: the daemon can be
  # updated and started by hand later.
  step "Fetching ClamAV signatures (this can take a few minutes)"
  if command -v freshclam >/dev/null 2>&1; then
    freshclam >/dev/null 2>&1 || warn "freshclam did not complete — run it manually before enabling upload scanning."
  fi

  if has_systemd; then
    local unit=""
    for candidate in clamav-daemon clamd@scan clamd; do
      if systemctl list-unit-files 2>/dev/null | grep -q "^${candidate}\."; then unit="$candidate"; break; fi
    done
    if [ -n "$unit" ]; then
      systemctl enable --now "$unit" >/dev/null 2>&1 \
        && ok "clamd running ($unit)" \
        || warn "Could not start $unit — start it manually, then enable upload scanning in Settings."
    else
      warn "No clamd service unit found — start the daemon manually before enabling upload scanning."
    fi
  fi

  info "Enable it in Settings → Upload malware scanning (off by default)."
}

# ── CatWAF's own setup wizard ────────────────────────────────────────────
run_catwaf_setup() {
  step "Running CatWAF setup"
  local args=("setup" "--$EDITION")
  [ -n "$DOMAIN" ]     && args+=("--domain" "$DOMAIN")
  [ -n "$ADMIN_USER" ] && args+=("--admin-user" "$ADMIN_USER")
  [ "$ASSUME_YES" -eq 1 ] && args+=("--yes")
  [ "$WITH_AI" = "no" ]   && args+=("--no-ai")

  # Argument array, no shell interpretation, run as the service account so
  # every file it creates is owned correctly from the start.
  #
  # This script already runs as root, so `sudo` buys nothing — and a minimal
  # Debian/Ubuntu install (and every Docker base image) does not ship it, which
  # made this final step fail with "sudo: command not found" on an otherwise
  # complete installation. `runuser` (util-linux) and `su` are part of the base
  # system everywhere the installer supports, so prefer those and keep sudo
  # only as a last resort.
  local -a drop_priv
  if command -v runuser >/dev/null 2>&1; then
    drop_priv=(runuser -u "$SERVICE_USER" --)
  elif command -v setpriv >/dev/null 2>&1 && id -u "$SERVICE_USER" >/dev/null 2>&1; then
    drop_priv=(setpriv --reuid "$SERVICE_USER" --regid "$SERVICE_USER" --init-groups --)
  elif command -v sudo >/dev/null 2>&1; then
    drop_priv=(sudo -u "$SERVICE_USER" -H)
  else
    warn "No way to drop privileges (runuser, setpriv and sudo are all missing)."
    info "Finish it yourself with: su -s /bin/sh -c 'catwaf setup --$EDITION' $SERVICE_USER"
    return 1
  fi

  if ! "${drop_priv[@]}" \
        env CATWAF_EDITION="$EDITION" \
            CATWAF_ADMIN_PASSWORD="${CATWAF_ADMIN_PASSWORD:-}" \
            node "$INSTALL_DIR/bin/catwaf.js" "${args[@]}"; then
    warn "CatWAF setup did not complete."
    info "Finish it yourself with: runuser -u $SERVICE_USER -- catwaf setup --$EDITION"
    return 1
  fi
  ok "CatWAF setup complete"
}

# ── interactive edition choice ───────────────────────────────────────────
choose_edition() {
  [ -n "$EDITION" ] && return 0

  if [ "$ASSUME_YES" -eq 1 ] || [ ! -t 0 ]; then
    die "No edition selected and this is a non-interactive run.
  Pass --lite or --full."
  fi

  printf '\n%s\n\n' "${C_BOLD}Which edition of CatWAF do you want?${C_RESET}"
  printf '  %s CatWAF Lite%s\n' "${C_BOLD}1)${C_RESET} ${C_CYAN}" "${C_RESET}"
  printf '     Caddy + Coraza + CRS, the catwaf CLI, event database.\n'
  printf '     %sNo dashboard, no API server, no CatAI, no frontend deps.%s\n\n' "$C_DIM" "$C_RESET"
  printf '  %s CatWAF Full%s\n' "${C_BOLD}2)${C_RESET} ${C_CYAN}" "${C_RESET}"
  printf '     Everything in Lite plus the HTTP API, the web dashboard,\n'
  printf '     the Attack Map and optional CatAI.\n'
  printf '     %sNeeds Node build tooling and roughly 500 MB more disk.%s\n\n' "$C_DIM" "$C_RESET"

  local choice
  while :; do
    printf '%s' "Enter 1 or 2 [1]: "
    read -r choice </dev/tty || die "Could not read from the terminal. Pass --lite or --full."
    case "${choice:-1}" in
      1|lite|Lite|LITE) EDITION="lite"; break ;;
      2|full|Full|FULL) EDITION="full"; break ;;
      *) printf '%s\n' "  Please enter 1 or 2." ;;
    esac
  done
  printf '\n'
}

detect_existing() {
  [ -f "$INSTALL_DIR/.env" ] || return 0
  local existing
  existing="$(grep -m1 '^CATWAF_EDITION=' "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2- || true)"
  [ -n "$existing" ] || return 0

  info "Found an existing CatWAF ${C_BOLD}${existing}${C_RESET} installation at $INSTALL_DIR"
  if [ -z "$EDITION" ]; then
    EDITION="$existing"
    info "Keeping edition '$existing'. Pass --lite or --full to change it."
  elif [ "$EDITION" != "$existing" ]; then
    info "Converting: ${existing} → ${EDITION}"
    info "Your configuration, database, rules and accounts are preserved."
  fi
}

summary() {
  printf '\n%s\n' "${C_GREEN}${C_BOLD}CatWAF ${EDITION} is installed.${C_RESET}"
  printf '%s\n\n' "${C_DIM}$INSTALL_DIR${C_RESET}"

  printf '%s\n' "  ${C_BOLD}Next steps${C_RESET}"
  printf '%s\n' "    catwaf status              version, edition and component health"
  printf '%s\n' "    catwaf doctor              verify this environment"
  if [ "$EDITION" = "full" ]; then
    # Only advise systemctl when a unit was actually installed — telling a
    # container or an init-less host to run `systemctl start catwaf` sends
    # people to a command that cannot work.
    if has_systemd; then
      printf '%s\n' "    systemctl start catwaf     start the API and dashboard"
    else
      printf '%s\n' "    catwaf start               start the API and dashboard"
    fi
    if [ -n "$DOMAIN" ]; then
      printf '%s\n' "    https://catwaf.$DOMAIN     your dashboard"
      printf '\n%s\n' "  ${C_BOLD}DNS${C_RESET}  point these at this server:"
      printf '%s\n' "    catwaf.$DOMAIN       and       api.catwaf.$DOMAIN"
    else
      printf '%s\n' "    http://localhost:8000      your dashboard"
    fi
  else
    printf '%s\n' "    catwaf start               start the WAF"
    printf '%s\n' "    catwaf audit               traffic and attack summary"
    printf '%s\n' "    catwaf explain --last      why the last request was blocked"
    printf '\n%s\n' "  ${C_DIM}Lite has no web dashboard. Add it later: catwaf setup --full${C_RESET}"
  fi
  printf '\n'
}

# ── main ─────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  validate_inputs

  [ "$(id -u)" -eq 0 ] || die "This installer must run as root (it writes to $INSTALL_DIR,
  /usr/local/bin and /etc/systemd/system).
  Re-run with: sudo bash setup.sh $*"

  TMP_DIR="$(mktemp -d)"
  chmod 700 "$TMP_DIR"

  printf '\n%s\n' "${C_BOLD}${C_CYAN}CatWAF installer${C_RESET}"
  printf '%s\n\n' "${C_DIM}A web application firewall built on Caddy + Coraza + OWASP CRS${C_RESET}"

  detect_platform
  detect_existing
  choose_edition
  validate_inputs

  ensure_base_tools
  ensure_node
  ensure_npm
  ensure_service_user
  fetch_source
  install_dependencies
  write_env
  link_cli
  maybe_install_ai
  maybe_install_clamav
  set_permissions
  install_systemd_unit
  run_catwaf_setup || true
  set_permissions

  summary
}

main "$@"
