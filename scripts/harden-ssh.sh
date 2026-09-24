#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${EUID} -ne 0 || $# -ne 1 ]]; then
  echo "usage: sudo harden-ssh.sh ADMIN_USER" >&2
  exit 64
fi
admin_user=$1
if [[ ! $admin_user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "Invalid administrator account name." >&2
  exit 1
fi
if ! id "$admin_user" >/dev/null 2>&1; then
  echo "Administrator account does not exist." >&2
  exit 1
fi
admin_home=$(getent passwd "$admin_user" | cut -d: -f6)
authorized=$admin_home/.ssh/authorized_keys
if [[ ! -s $authorized || -L $authorized ]]; then
  echo "Refusing to disable password SSH: $authorized is absent, empty, or a symlink." >&2
  exit 1
fi
auth_uid=$(stat -c '%u' "$authorized")
admin_uid=$(id -u "$admin_user")
auth_mode=$((8#$(stat -c '%a' "$authorized")))
if [[ $auth_uid -ne $admin_uid && $auth_uid -ne 0 ]] || (( auth_mode & 0022 )); then
  echo "Refusing unsafe authorized_keys ownership or mode." >&2
  exit 1
fi

install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d
temporary=$(mktemp /etc/ssh/sshd_config.d/.60-relayforge.XXXXXX)
trap 'rm -f -- "$temporary"' EXIT
{
  echo '# Managed by RelayForge. Keep the current SSH session open while validating.'
  echo 'PasswordAuthentication no'
  echo 'KbdInteractiveAuthentication no'
  echo 'ChallengeResponseAuthentication no'
  echo 'PermitRootLogin no'
  echo 'PubkeyAuthentication yes'
  echo 'AuthenticationMethods publickey'
  echo "AllowUsers $admin_user"
  echo 'AllowAgentForwarding no'
  echo 'AllowTcpForwarding no'
  echo 'GatewayPorts no'
  echo 'PermitTunnel no'
  echo 'X11Forwarding no'
  echo 'MaxAuthTries 3'
  echo 'LoginGraceTime 30'
} >"$temporary"
chown root:root "$temporary"
chmod 0644 "$temporary"
mv -f -- "$temporary" /etc/ssh/sshd_config.d/60-relayforge-hardening.conf
trap - EXIT
/usr/sbin/sshd -t
systemctl reload ssh.service
if [[ -f /etc/relayforge/install.state && ! -L /etc/relayforge/install.state ]]; then
  sed -i 's/^SSH_DEFERRED=.*/SSH_DEFERRED=0/' /etc/relayforge/install.state
fi
