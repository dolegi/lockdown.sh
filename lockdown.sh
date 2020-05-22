#!/bin/sh

# Update package list
apt update

# Apt upgrade packages
apt upgrade -y

# Apt full upgrade 
apt full-upgrade -y

# iptables
apt install iptables-persistent -y

# Flush existing rules
iptables -F

# Defaults
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Accept loopback input
iptables -A INPUT -i lo -p all -j ACCEPT

# Allow three-way Handshake
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Stop Masked Attackes
iptables -A INPUT -p icmp --icmp-type 13 -j DROP
iptables -A INPUT -p icmp --icmp-type 17 -j DROP
iptables -A INPUT -p icmp --icmp-type 14 -j DROP
iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT

# Discard invalid Packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# Drop Spoofing attacks
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# Drop packets with excessive RST to avoid Masked attacks
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Block ips doing portscan for 24 hours
iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# After 24 hours remove IP from block list
iptables -A INPUT   -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# Allow ssh
iptables -A INPUT -p tcp -m tcp --dport 141 -j ACCEPT

# Allow Ping
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT

# Allow one ssh connection at a time
iptables -A INPUT -p tcp --syn --dport 141 -m connlimit --connlimit-above 2 -j REJECT

iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# Install fail2ban
apt install fail2ban -y

# Configure Kernel
echo "
  net.ipv4.tcp_syncookies: 1
  net.ipv4.conf.all.accept_source_route: 0
  net.ipv6.conf.all.accept_source_route: 0
  net.ipv4.conf.default.accept_source_route: 0
  net.ipv6.conf.default.accept_source_route: 0
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv6.conf.all.accept_redirects: 0
  net.ipv4.conf.default.accept_redirects: 0
  net.ipv6.conf.default.accept_redirects: 0
  net.ipv4.conf.all.secure_redirects: 1
  net.ipv4.conf.default.secure_redirects: 1
  net.ipv4.ip_forward: 0
  net.ipv6.conf.all.forwarding: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.default.send_redirects: 0
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.conf.default.rp_filter: 1
  net.ipv4.icmp_echo_ignore_broadcasts: 1
  net.ipv4.icmp_ignore_bogus_error_responses: 1
  net.ipv4.icmp_echo_ignore_all: 0
  net.ipv4.conf.all.log_martians: 1
  net.ipv4.conf.default.log_martians: 1
  net.ipv4.tcp_rfc1337: 1
  kernel.randomize_va_space: 2
  fs.protected_hardlinks: 1
  fs.protected_symlinks: 1
  kernel.kptr_restrict: 1
  kernel.perf_event_paranoid: 2
" > /etc/sysctl.conf

# Add Daily Update Cron Job
touch job
echo "@daily apt update; apt dist-upgrade -y" >> job
crontab job
rm job

# Enable automatic updates
dpkg-reconfigure -plow unattended-upgrades

# Install auditd
apt install auditd -y
echo "
# First rule - delete all
-D

# Increase the buffers to survive stress events.
# Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 0

## Set failure mode to syslog
-f 1

-a exit,always -S unlink -S rmdir
-a exit,always -S stime.*
-a exit,always -S setrlimit.*
-w /etc/group -p wa
-w /etc/passwd -p wa
-w /etc/shadow -p wa
-w /etc/sudoers -p wa

## Make the configuration immutable - reboot is required to change audit rules
#-e 2
" > /etc/audit/audit.rules
systemctl enable auditd.service
service auditd restart

# Disable core dumps
echo "* hard core 0" >> /etc/security/limits.conf

# Set login.defs
sed -i s/UMASK.*/UMASK\ 027/ /etc/login.defs
sed -i s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 90/ /etc/login.defs
sed -i s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 7/ /etc/login.defs
echo "
SHA_CRYPT_MIN_ROUNDS 1000000
SHA_CRYPT_MAX_ROUNDS 100000000
" >> /etc/login.defs

# Secure ssh
echo "
ClientAliveCountMax 2
Compression no
LogLevel VERBOSE
MaxAuthTries 3
MaxSessions 2
TCPKeepAlive no
AllowAgentForwarding no
Port 141
" >> /etc/ssh/sshd_config
sed -i s/^X11Forwarding.*/X11Forwarding\ no/ /etc/ssh/sshd_config

# Add legal banner
echo "
Unauthorized access to this server is prohibited.
Legal action will be taken. Disconnect now.
" > /etc/issue
echo "
Unauthorized access to this server is prohibited.
Legal action will be taken. Disconnect now.
" > /etc/issue.net

# Install recommended packages
apt install apt-listbugs apt-listchanges needrestart debsecan debsums libpam-cracklib aide rkhunter -y

# Disable unused filesystems, firewire and protocols
echo "install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install squashfs /bin/true" >> /etc/modprobe.d/filesystems.conf
echo "install udf /bin/true
blacklist usb-storage
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2" >> /etc/modprobe.d/blacklist.conf
echo "install sctp /bin/true
install dccp /bin/true
install rds /bin/true
install tipc /bin/true" >> /etc/modprobe.d/protocols.conf

# Change /root permissions
chmod 700 /root
chmod 750 /home/debian

# Purge old/removed packages
apt autoremove -y
apt purge "$(dpkg -l | grep '^rc' | awk '{print $2}')" -y

# Reboot
reboot
