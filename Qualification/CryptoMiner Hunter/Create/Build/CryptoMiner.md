# CryptoMiner 

## Overview
This document explains how to create the CryptoMiner memory forensics challenge from scratch.

## Prerequisites
- Ubuntu 24.04 Server (kernel 6.8.0-71-generic)
- SSH access to server
- 8GB+ RAM on server
- Root privileges

---

## Step 1: Server Preparation

### Clean Server State
```bash
ssh root@IP

pkill -9 xmrig
rm -rf /opt/miner
rm -rf /tmp/*
rm -f /root/memory*.lime
crontab -r
history -c
cat /dev/null > ~/.bash_history

exit
```

---

## Step 2: Install LiME for Memory Capture

### Install Dependencies
```bash
ssh root@IP

apt update
apt install -y build-essential linux-headers-$(uname -r) git
```

### Build LiME Module
```bash
cd /tmp
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make
```

This creates: `lime-6.8.0-71-generic.ko`

---

## Step 3: Deploy Cryptocurrency Miner

### Download XMRig
```bash
mkdir -p /opt/miner
cd /opt/miner
wget https://github.com/xmrig/xmrig/releases/download/v6.22.0/xmrig-6.22.0-linux-static-x64.tar.gz
tar -xf xmrig-6.22.0-linux-static-x64.tar.gz
mv xmrig-6.22.0/xmrig .
chmod +x xmrig
```

### Create Mining Configuration
```bash
cat > config.json << 'EOF'
{
    "pools": [{
        "url": "pool.hashvault.pro:443",
        "user": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
        "pass": "x"
    }]
}
EOF
```

### Run Miner
```bash
nohup ./xmrig --config=config.json > /dev/null 2>&1 &
sleep 30
ps aux | grep xmrig
```

Verify miner is running with high CPU usage.

---

## Step 4: Capture Memory with LiME

```bash
cd /tmp/LiME/src
sudo insmod lime-$(uname -r).ko "path=/root/memory-lime.lime format=lime"
```

Wait for capture to complete (takes 2-5 minutes for 8GB RAM).

```bash
ls -lh /root/memory-lime.lime
```

Should show ~8GB file.

---

## Step 5: Create Volatility Symbol Table

### Install Go
```bash
apt install -y golang-go
```

### Install Debug Symbols
```bash
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" | tee -a /etc/apt/sources.list.d/ddebs.list
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse" | tee -a /etc/apt/sources.list.d/ddebs.list

apt install ubuntu-dbgsym-keyring
apt update
apt install -y linux-image-$(uname -r)-dbgsym
```

### Build dwarf2json
```bash
cd /tmp
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json
go build
```

### Generate Symbol Table
```bash
sudo ./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) --system-map /boot/System.map-$(uname -r) > /tmp/ubuntu-6.8.0-71-generic.json
```

Verify creation:
```bash
ls -lh /tmp/ubuntu-6.8.0-71-generic.json
```



---

## Step 6: Download Challenge Files

### From Local Machine
```bash
scp root@IP:/root/memory-lime.lime .
scp root@IP:/tmp/ubuntu-6.8.0-71-generic.json .
```

```bash
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -e .

mkdir -p volatility3/symbols/linux/
cp ../ubuntu-6.8.0-71-generic.json volatility3/symbols/linux/
```

Tese
```bash
python3 vol.py -f ../memory-lime.lime linux.pslist.PsList | grep xmrig
```