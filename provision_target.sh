#!/bin/bash
# Target VM: a normal Ubuntu host with SSH open, a throwaway weak-password
# account for the demo, and the Event Collector Agent ready to run.
set -e
apt-get update -y
apt-get install -y openssh-server python3 python3-venv

# throwaway account hydra will try to guess — lab only, never do this elsewhere
id -u labuser &>/dev/null || useradd -m -s /bin/bash labuser
echo "labuser:labpass123" | chpasswd

# account the runner SSHes in as, to run iptables/fail2ban
id -u labadmin &>/dev/null || useradd -m -s /bin/bash -G sudo labadmin
echo "labadmin:labadmin123" | chpasswd
echo "labadmin ALL=(ALL) NOPASSWD: /sbin/iptables, /usr/bin/apt-get, /bin/systemctl" \
  > /etc/sudoers.d/labadmin-lab

sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart ssh

python3 -m venv /opt/agent/venv
/opt/agent/venv/bin/pip install -q -r /opt/agent/requirements.txt 2>/dev/null || true

echo "target-01 ready. SSH at 192.168.56.10. Run the agent with:"
echo "  cd /opt/agent && sudo API_URL=http://<backend-ip>:8000/api API_KEY=<key> venv/bin/python3 collector.py"
