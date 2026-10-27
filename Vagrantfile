# Isolated lab: Kali attacker + Ubuntu target on a host-only (private) network.
# Nothing here is bridged to the real network or the internet-facing NIC.
Vagrant.configure("2") do |config|

  config.vm.define "target" do |target|
    target.vm.box = "ubuntu/jammy64"
    target.vm.hostname = "target-01"
    target.vm.network "private_network", ip: "192.168.56.10"
    target.vm.synced_folder "agent", "/opt/agent"
    target.vm.provision "shell", path: "scripts/provision_target.sh"
  end

  config.vm.define "attacker" do |attacker|
    # Official Offensive Security box. If it isn't available on your host,
    # swap for "kalilinux/rolling" or any Debian-based box and `apt install hydra`.
    attacker.vm.box = "kalilinux/rolling"
    attacker.vm.hostname = "attacker-01"
    attacker.vm.network "private_network", ip: "192.168.56.20"
    attacker.vm.synced_folder "runner", "/opt/runner"
    attacker.vm.provision "shell", path: "scripts/provision_attacker.sh"
  end
end
