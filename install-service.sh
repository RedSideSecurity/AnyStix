#!/usr/bin/env bash
#
# install-service.sh — install anystix as a systemd service + timer on
# Ubuntu so it harvests malicious ANY.RUN submissions for ONE country on a
# schedule.
#
# Each run writes to a persistent bundle under /var/lib/anystix; the tool
# itself dedups by task UUID, so every run appends ONLY new malicious entries.
#
# Usage:
#   sudo ./install-service.sh install --country armenia [--interval 1h] \
#                                     [--date-range 30] [--push]
#   sudo ./install-service.sh run-now              # trigger one harvest now
#   sudo ./install-service.sh status               # timer state + bundle
#   sudo ./install-service.sh logs                 # recent journal output
#   sudo ./install-service.sh uninstall [--purge]  # remove unit (+ data)
#
set -euo pipefail

APP_DIR=/opt/anystix
DATA_DIR=/var/lib/anystix          # systemd StateDirectory
ENV_FILE=/etc/anystix.env
UNIT=anystix
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INTERVAL=1h
DATE_RANGE=30
COUNTRY=""
PUSH=0
PURGE=0

die() { echo "[!] $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (use sudo)"; }

parse_flags() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --country)    COUNTRY="$2";    shift 2 ;;
      --interval)   INTERVAL="$2";   shift 2 ;;
      --date-range) DATE_RANGE="$2"; shift 2 ;;
      --push)       PUSH=1; shift ;;
      --purge)      PURGE=1; shift ;;
      *) die "unknown option: $1" ;;
    esac
  done
}

cmd_install() {
  need_root
  parse_flags "$@"
  [ -n "$COUNTRY" ] || die "--country is required (e.g. --country armenia)"
  command -v python3 >/dev/null || die "python3 not found"

  echo "[*] Installing app to $APP_DIR"
  install -d "$APP_DIR"
  install -m 0644 "$SRC_DIR/anystix.py" "$SRC_DIR/anyrun_ddp.py" \
                  "$SRC_DIR/requirements.txt" "$APP_DIR/"

  echo "[*] Building virtualenv + dependencies"
  python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
  "$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
  [ "$PUSH" -eq 1 ] && "$APP_DIR/.venv/bin/pip" install --quiet pycti || true
  # World-readable so the systemd DynamicUser can execute it.
  chmod -R a+rX "$APP_DIR"

  # Optional OpenCTI credentials (only used with --push). Never commit this file.
  if [ ! -f "$ENV_FILE" ]; then
    echo "[*] Writing $ENV_FILE template (fill in for --push)"
    cat > "$ENV_FILE" <<EOF
# anystix environment (used only when the service runs with --push)
# OPENCTI_URL=https://127.0.0.1
# OPENCTI_TOKEN=
EOF
    chmod 0600 "$ENV_FILE"
  fi

  local out_file="${DATA_DIR}/$(echo "$COUNTRY" | tr ' ' '_')_anystix.json"
  local extra=""
  [ "$PUSH" -eq 1 ] && extra="--push-opencti"

  echo "[*] Writing systemd units (country=$COUNTRY, interval=$INTERVAL, date-range=$DATE_RANGE, push=$PUSH)"
  cat > "/etc/systemd/system/${UNIT}.service" <<EOF
[Unit]
Description=anystix harvest for ${COUNTRY}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
DynamicUser=yes
StateDirectory=anystix
EnvironmentFile=-${ENV_FILE}
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/anystix.py \\
  --country ${COUNTRY} --date-range ${DATE_RANGE} \\
  --out ${out_file} ${extra}
# hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6
EOF

  cat > "/etc/systemd/system/${UNIT}.timer" <<EOF
[Unit]
Description=Schedule anystix harvest for ${COUNTRY}

[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL}
Persistent=true
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${UNIT}.timer"

  echo "[+] Installed. Harvesting '${COUNTRY}' every ${INTERVAL}."
  echo "    Bundle: ${out_file}"
  echo "    Run now: sudo $0 run-now"
}

cmd_run_now() { need_root; systemctl start "${UNIT}.service"
                echo "[+] Started; see: sudo $0 logs"; }

cmd_status()  { systemctl list-timers "${UNIT}.timer" --all || true
                echo; ls -l "$DATA_DIR" 2>/dev/null || echo "(no data dir yet)"; }

cmd_logs()    { journalctl -u "${UNIT}.service" -n 50 --no-pager; }

cmd_uninstall() {
  need_root; parse_flags "$@"
  echo "[*] Stopping and disabling timer"
  systemctl disable --now "${UNIT}.timer" 2>/dev/null || true
  systemctl stop "${UNIT}.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/${UNIT}.service" "/etc/systemd/system/${UNIT}.timer"
  systemctl daemon-reload
  rm -rf "$APP_DIR"
  if [ "$PURGE" -eq 1 ]; then
    echo "[*] Purging data + env"; rm -rf "$DATA_DIR" "$ENV_FILE"
  else
    echo "[*] Kept data ($DATA_DIR) and env ($ENV_FILE); use --purge to remove."
  fi
  echo "[+] Uninstalled."
}

case "${1:-}" in
  install)   shift; cmd_install   "$@" ;;
  run-now)   shift; cmd_run_now   "$@" ;;
  status)    shift; cmd_status    "$@" ;;
  logs)      shift; cmd_logs      "$@" ;;
  uninstall) shift; cmd_uninstall "$@" ;;
  *) cat >&2 <<EOF
anystix systemd installer (single country)

  sudo $0 install --country armenia [--interval 1h] [--date-range 30] [--push]
  sudo $0 run-now
  sudo $0 status
  sudo $0 logs
  sudo $0 uninstall [--purge]
EOF
     exit 1 ;;
esac
