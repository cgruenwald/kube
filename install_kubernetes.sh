#!/bin/bash

set -e
apt update && apt upgrade -y
apt -y install \
    at jq unzip wget socat mtr logrotate apt-transport-https ca-certificates curl gpg

# Install yq
YQ_VERSION=v4.44.6 #https://github.com/mikefarah/yq
YQ_BINARY=yq_linux_${PACKER_ARCH}
wget https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BINARY} -O /usr/bin/yq &&\
chmod +x /usr/bin/yq


echo '--> Starting Logrotate.' 
# Content from: https://github.com/kubernetes/kubernetes/blob/master/cluster/gce/gci/configure-helper.sh#L509

cat > /etc/logrotate.d/allvarlogs <<"EOF"
/var/log/*.log {
    rotate 5
    copytruncate
    missingok
    notifempty
    compress
    maxsize 25M
    daily
    dateext
    dateformat -%Y%m%d-%s
    create 0644 root root
}
EOF

cat > /etc/logrotate.d/allpodlogs <<"EOF"
/var/log/pods/*/*.log {
    rotate 3
    copytruncate
    missingok
    notifempty
    compress
    maxsize 5M
    daily
    dateext
    dateformat -%Y%m%d-%s
    create 0644 root root
}

EOF

# mount bpfs for cilium
cat > /etc/systemd/system/sys-fs-bpf.mount <<EOF
[Unit]
Description=Cilium BPF mounts
Documentation=https://docs.cilium.io/
DefaultDependencies=no
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=bpffs
Where=/sys/fs/bpf
Type=bpf
Options=rw,nosuid,nodev,noexec,relatime,mode=700

[Install]
WantedBy=multi-user.target
EOF

systemctl enable sys-fs-bpf.mount

# Cilium 1.9 Requirements
# Set up required sysctl params, these persist across reboots.
cat > /etc/sysctl.d/99-cilium.conf <<EOF
net.ipv4.conf.lxc*.rp_filter = 0
EOF

# Cilium 1.13 Requirements
# https://docs.cilium.io/en/v1.13/operations/system_requirements/#systemd-based-distributions
cat > /etc/systemd/networkd.conf <<EOF
[Network]
ManageForeignRoutes=no
ManageForeignRoutingPolicyRules=no
EOF


# Prerequisites

swapoff -a
sed -i '/swap/d' /etc/fstab



cat <<'EOF' | tee /etc/modules-load.d/containerd.conf
overlay
br_netfilter
EOF

modprobe overlay
modprobe br_netfilter

# Setting up sysctl properties
echo fs.inotify.max_user_watches=524288 | tee -a /etc/sysctl.conf
echo fs.inotify.max_user_instances=8192 | tee -a /etc/sysctl.conf
echo vm.max_map_count=524288 | tee -a /etc/sysctl.conf

# Set up required sysctl params, these persist across reboots.
cat >/etc/sysctl.d/99-kubernetes-cri.conf <<'EOF'
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

# Required by protectedKernelDefaults=true
cat >/etc/sysctl.d/99-kubelet.conf <<'EOF'
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
EOF

# Create containerd systemd unit
cat >/etc/systemd/system/containerd.service <<'EOF'
# Copyright The containerd Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# https://raw.githubusercontent.com/containerd/containerd/main/containerd.service

[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target local-fs.target dbus.service

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd

Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5

# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNPROC=infinity
LimitCORE=infinity

# Comment TasksMax if your systemd version does not supports it.
# Only systemd 226 and above support this version.
TasksMax=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
EOF

# Apply sysctl params without reboot
sysctl --system

ARCH="$(dpkg --print-architecture)"
CONTAINERD=2.0.1 # https://github.com/containerd/containerd/releases
RUNC=1.2.4 # https://github.com/opencontainers/runc/releases

# Install runc
wget https://github.com/opencontainers/runc/releases/download/v$RUNC/runc.$ARCH
wget https://github.com/opencontainers/runc/releases/download/v$RUNC/runc.sha256sum
sha256sum --check --ignore-missing runc.sha256sum
install runc.$ARCH /usr/local/sbin/runc

# Install containerd
wget https://github.com/containerd/containerd/releases/download/v$CONTAINERD/containerd-$CONTAINERD-linux-$ARCH.tar.gz
wget https://github.com/containerd/containerd/releases/download/v$CONTAINERD/containerd-$CONTAINERD-linux-$ARCH.tar.gz.sha256sum
sha256sum --check containerd-$CONTAINERD-linux-$ARCH.tar.gz.sha256sum
tar -zxf containerd-$CONTAINERD-linux-$ARCH.tar.gz -C /usr/local

# Cleanup
rm -f runc.$ARCH runc.sha256sum
rm -f containerd-$CONTAINERD-linux-$ARCH.tar.gz containerd-$CONTAINERD-linux-$ARCH.tar.gz.sha256sum

mkdir -p /etc/containerd
containerd config default >/etc/containerd/config.toml
sed -i "s/SystemdCgroup = false/SystemdCgroup = true/" /etc/containerd/config.toml

# enable systemd service after next boot
systemctl daemon-reload
systemctl enable containerd
systemctl start containerd


curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update
apt-get install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

systemctl enable --now kubelet

# Install kubeadm
