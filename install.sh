#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="recon-orchestrator"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=11
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
  BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; NC=""
fi

info()  { printf '%s[*]%s %s\n' "$BLUE"   "$NC" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$GREEN"  "$NC" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*"; }
err()   { printf '%s[-]%s %s\n' "$RED"    "$NC" "$*" >&2; }
title() { printf '\n%s%s%s\n' "$BOLD$CYAN" "$*" "$NC"; }

detect_platform() {
  if [[ -n "${PREFIX:-}" && "$PREFIX" == *"com.termux"* ]]; then
    echo "termux"
  elif [[ -f /etc/os-release ]] && grep -qi '^ID=kali' /etc/os-release 2>/dev/null; then
    echo "kali"
  elif [[ -f /etc/debian_version ]]; then
    echo "debian"
  else
    echo "unknown"
  fi
}

check_python() {
  if ! command -v python3 &>/dev/null; then
    err "python3 not found in PATH"; return 1
  fi
  local ver major minor
  ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || {
    err "python3 is broken"; return 1
  }
  major=${ver%%.*}; minor=${ver##*.}
  if (( major < PYTHON_MIN_MAJOR )) || \
     (( major == PYTHON_MIN_MAJOR && minor < PYTHON_MIN_MINOR )); then
    err "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ required; found ${ver}"; return 1
  fi
  ok "Python ${ver} ($(command -v python3))"
}

check_tools() {
  local required=(nmap curl git)
  local optional=(nuclei searchsploit arp-scan masscan sqlite3 go)
  local missing=0
  info "Required tools:"
  for t in "${required[@]}"; do
    if command -v "$t" &>/dev/null; then ok "  $t -> $(command -v "$t")"
    else err "  $t -> MISSING"; missing=$((missing+1)); fi
  done
  info "Optional tools:"
  for t in "${optional[@]}"; do
    if command -v "$t" &>/dev/null; then ok "  $t -> $(command -v "$t")"
    else warn "  $t -> not installed"; fi
  done
  return "$missing"
}

create_structure() {
  local dirs=(config core phases integrations ui ui/screens ui/widgets
              reports reports/templates reports/output data logs tools tools/bin tests)
  for d in "${dirs[@]}"; do mkdir -p "$d"; done
  ok "Directory structure ready (${#dirs[@]} dirs)"
}

ensure_config_files() {
  if [[ ! -f config/scope.txt ]]; then
    cat > config/scope.txt <<'EOF'
# Authorized scope — ONLY these targets may be scanned.
# One entry per line. Lines starting with '#' are ignored.
127.0.0.1
::1
EOF
    ok "Created config/scope.txt (loopback only — edit to add your targets)"
  else warn "config/scope.txt already exists — preserved"; fi

  if [[ ! -f config/tools.yaml ]]; then
    cat > config/tools.yaml <<'EOF'
nmap:
  binary: nmap
  requires_root_for_syn: true
  fallback_connect_scan: "-sT"
  profiles:
    quick:         "-T4 -F"
    comprehensive: "-T4 -p- -A"
    stealth:       "-T2 -sS -Pn"
    udp:           "-sU --top-ports 50"
    nse:           "--script vuln"
nuclei:
  binary: nuclei
  rate_limit: 150
  severity_default: "critical,high"
searchsploit:
  binary: searchsploit
msfconsole:
  binary: msfconsole
EOF
    ok "Created config/tools.yaml"
  fi

  if [[ ! -f config/categories.yaml ]]; then
    cat > config/categories.yaml <<'EOF'
device_types:
  router:  {port_hints: [80, 443, 22, 23]}
  camera:  {port_hints: [554, 80, 8080, 8554]}
  printer: {port_hints: [515, 631, 9100]}
  mobile:  {port_hints: [62078, 5223]}
  iot:     {port_hints: [1883, 8883, 5683]}
severity:
  critical: {cvss_min: 9.0, color: "red"}
  high:     {cvss_min: 7.0, color: "orange"}
  medium:   {cvss_min: 4.0, color: "yellow"}
  low:      {cvss_min: 0.1, color: "blue"}
EOF
    ok "Created config/categories.yaml"
  fi
}

install_system_deps() {
  case "$PLATFORM" in
    termux)
      info "Installing Termux packages..."
      pkg update -y
      pkg install -y python nmap curl git sqlite openssl libffi which
      pkg install -y arp-scan 2>/dev/null || warn "arp-scan unavailable — fallback will be used"
      pkg install -y golang   2>/dev/null || warn "golang unavailable — nuclei install skipped"
      ;;
    kali|debian)
      info "Installing APT packages..."
      sudo apt-get update -y
      sudo apt-get install -y python3 python3-pip python3-venv \
        nmap curl git sqlite3 libffi-dev libssl-dev
      sudo apt-get install -y arp-scan masscan 2>/dev/null || warn "Some optional tools unavailable"
      ;;
    *) warn "Unknown platform '$PLATFORM' — skipping system deps" ;;
  esac
}

install_python_deps() {
  info "Upgrading pip..."
  if [[ "$PLATFORM" != "termux" ]]; then
    python3 -m pip install --upgrade pip --quiet || warn "pip upgrade failed (continuing)"
  else
    warn "pip self-upgrade skipped on Termux (managed by pkg)"
  fi

  info "Installing core Python packages..."
  if [[ "$PLATFORM" == "termux" ]]; then
    export ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-24}"
    info "Android API level: $ANDROID_API_LEVEL"

    if ! python3 -c "import maturin" 2>/dev/null; then
      info "Installing maturin (needed to build pydantic-core)..."
      python3 -m pip install --break-system-packages maturin \
        || { err "maturin install failed"; return 1; }
    fi
    if ! python3 -c "import pydantic_core" 2>/dev/null; then
      info "Building pydantic-core (this may take several minutes)..."
      python3 -m pip install --break-system-packages --no-build-isolation pydantic-core \
        || { err "pydantic-core build failed"; return 1; }
    fi

    local tmpreq="${TMPDIR:-${PREFIX:-/tmp}/tmp}/req-core.txt"
    mkdir -p "$(dirname "$tmpreq")" 2>/dev/null || tmpreq="$PWD/requirements.termux.txt"
    grep -v weasyprint requirements.txt > "$tmpreq"
    python3 -m pip install --break-system-packages -r "$tmpreq" \
      || { err "core package install failed"; return 1; }
    warn "WeasyPrint skipped on Termux — PDF export disabled (HTML only)"
  else
    python3 -m pip install -r requirements.txt
    info "WeasyPrint available — PDF export enabled"
  fi

  if ! python3 -c "import textual, pydantic, httpx, aiosqlite, jinja2, yaml, structlog, rich" 2>/dev/null; then
    err "Post-install verification FAILED — some packages missing"
    return 1
  fi
  ok "Python packages verified"
}


install_nuclei_besteffort() {
  if command -v nuclei &>/dev/null; then
    ok "nuclei already installed: $(command -v nuclei)"; return 0
  fi
  if command -v go &>/dev/null; then
    info "Installing nuclei via 'go install'..."
    GOBIN="$SCRIPT_DIR/tools/bin" \
      go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
      2>&1 | tail -3 || warn "nuclei build failed"
    [[ -x "$SCRIPT_DIR/tools/bin/nuclei" ]] && ok "nuclei installed at tools/bin/nuclei"
  else
    warn "Go not available — nuclei skipped (install manually later)"
  fi
}

show_help() {
  cat <<EOF
${PROJECT_NAME} installer

Usage:
  bash install.sh              Full install
  bash install.sh --check-only Verify environment only
  bash install.sh --help       Show help

Platforms: Termux, Kali Linux, Debian/Ubuntu
EOF
}

check_only() {
  title "=== Environment Check (no changes) ==="
  PLATFORM=$(detect_platform)
  info "Platform: $PLATFORM"
  check_python || exit 1
  if check_tools; then ok "All required tools present"; exit 0
  else err "Some required tools missing — run 'bash install.sh' to install them"; exit 1; fi
}

full_install() {
  title "=== ${PROJECT_NAME} — Full Install ==="
  PLATFORM=$(detect_platform)
  info "Platform: $PLATFORM"
  create_structure
  install_system_deps
  check_python || { err "Python requirement not met"; exit 1; }
  install_python_deps
  install_nuclei_besteffort
  ensure_config_files
  title "=== Install Complete ==="
  ok "Next: bash install.sh --check-only"
}

case "${1:-}" in
  --check-only|check)  check_only ;;
  --help|-h)           show_help ;;
  ""|install)          full_install ;;
  *)                   err "Unknown option: $1"; show_help; exit 1 ;;
esac
