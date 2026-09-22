#!/bin/bash
# Prepara el host Proxmox para que el Updates-Bot lo actualice, y cierra el SSH.
# Se corre UNA vez, como root, EN EL HOST PROXMOX:
#
#     ANSIBLE_PUBKEY="$(ssh <controller> cat ~/.ssh/id_ed25519_ansible.pub)" \
#       ./setup-proxmox-access.sh
#
# Idempotente: se puede correr de nuevo sin romper nada.
#
#   1. ansible-pct -> updates de los LXC. sudoers fijado al SUBCOMANDO
#                     'pct exec 101 -- *', no al binario.
#   2. ansible     -> updates del SO del hypervisor. NOPASSWD: ALL, que no se
#                     puede acotar (el modulo apt corre un interprete Python
#                     completo, no el binario apt).
#   3. sshd        -> sin password, root solo por key. Y fail2ban.
#
# Por que el sudoers del punto 1 NO puede ser 'NOPASSWD: /usr/sbin/pct' a secas:
# pct expone create, restore, set, mount, push, pull, clone, console y enter.
# 'pct pull <vmid> <origen> <destino>' copia DEL contenedor AL host como root, y
# el contenido del contenedor lo controla quien tenga 'pct exec'. O sea:
#
#   sudo pct exec 101 -- sh -c 'echo "ansible-pct ALL=(ALL) NOPASSWD: ALL" >/tmp/x'
#   sudo pct pull 101 /tmp/x /etc/sudoers.d/pwn
#
# Escritura arbitraria de archivos root-owned en cualquier ruta del hypervisor.
# Con el subcomando fijo el comodin si es seguro: lo que va despues de '--' se
# ejecuta ADENTRO del contenedor y no puede volverse otro subcomando de pct.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "correr como root en el pve"; exit 1; }

PUBKEY="${ANSIBLE_PUBKEY:?exportá ANSIBLE_PUBKEY con la pública de id_ed25519_ansible del controller}"
LXC_VMIDS="101"     # una linea de sudoers por contenedor

# Instala un sudoers validandolo ANTES de ponerlo en su lugar: un error de
# sintaxis en /etc/sudoers.d rompe sudo en todo el host, y validar despues ya es
# tarde.
install_sudoers() {
  local dest="$1" content="$2" tmp
  tmp="$(mktemp)"
  printf '%s\n' "$content" > "$tmp"
  chmod 440 "$tmp"
  visudo -cf "$tmp" >/dev/null
  install -m 440 -o root -g root "$tmp" "$dest"
  rm -f "$tmp"
}

install_key() {
  local user="$1" home="$2"
  install -d -m 700 -o "$user" -g "$user" "$home/.ssh"
  printf '%s\n' "$PUBKEY" > "$home/.ssh/authorized_keys"
  chown "$user:$user" "$home/.ssh/authorized_keys"
  chmod 600 "$home/.ssh/authorized_keys"
}

# ── 1. ansible-pct: solo 'pct exec <vmid> --' ──
getent passwd ansible-pct >/dev/null || \
  useradd -r -m -d /opt/ansible-pct -s /bin/sh -c 'Ansible: pct exec en LXC' ansible-pct
install_key ansible-pct /opt/ansible-pct
RULES=""
for vmid in $LXC_VMIDS; do
  RULES="${RULES}ansible-pct ALL = (root) NOPASSWD: /usr/sbin/pct exec $vmid -- *"$'\n'
done
install_sudoers /etc/sudoers.d/ansible-pct "$RULES"

# ── 2. ansible: updates del host ──
getent passwd ansible >/dev/null || \
  useradd -m -d /home/ansible -s /bin/bash -c 'Ansible: updates del host' ansible
install_key ansible /home/ansible
install_sudoers /etc/sudoers.d/ansible 'ansible ALL = (ALL) NOPASSWD: ALL'

# ── 3. sshd + fail2ban ──
# 'prohibit-password' y no 'no': todavia hay cosas que entran como root con key
# (tu Kali, homelab-backup). Lo que se mata aca es el password, que es lo que se
# fuerza bruta. Pasar a 'no' cuando se verifique que nada mas necesita root.
cat > /etc/ssh/sshd_config.d/60-hardening.conf <<'CONF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
CONF
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd

if ! command -v fail2ban-server >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
fi
cat > /etc/fail2ban/jail.d/sshd.local <<'CONF'
[sshd]
enabled = true
backend = systemd
maxretry = 4
bantime = 1h
findtime = 10m
CONF
systemctl enable --now fail2ban
systemctl restart fail2ban

# ── verificacion ──
echo
echo "OK sudoers de ansible-pct (tiene que decir 'pct exec 101 --', NO el binario pelado):"
sudo -n -u ansible-pct sudo -n -l 2>&1 | grep NOPASSWD || true
echo "OK cuentas sin password utilizable (se espera '!' o '*'):"
awk -F: '$1=="ansible"||$1=="ansible-pct"{print "  "$1": "substr($2,1,1)}' /etc/shadow
echo "OK sshd:"; sshd -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractive)'
echo "OK fail2ban:"; fail2ban-client status sshd 2>&1 | head -4
echo
echo "AHORA, desde otra terminal y SIN cerrar esta, verifica que seguis entrando:"
echo "    ssh root@192.168.1.70 true && echo ok"
