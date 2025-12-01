# Solution Guide

Password: Q$Ys93h!dd3n

# install 
- Ubuntu 24.04 Server (kernel 6.8.0-71-generic)

```
https://ubuntu.com/download/server
```



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

### From Local Machine
```bash
scp root@IP:/tmp/ubuntu-6.8.0-71-generic.json .
```

```bash
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -e .

mkdir -p volatility3/symbols/linux/
cp ../ubuntu-6.8.0-71-generic.json volatility3/symbols/linux/
```


---

## Q1: PPID
```bash
$ python3 vol.py -f ../memory-lime.lime linux.pslist.PsList | grep xmrig
0x9cdb00a58000.029434   29434   28606 ingxmrig   0       0       0       0       2025-10-11 01:15:14.933669 UTC  Disabled

```
Answer: `28606`

## Q2: Timestamp
```bash
$ python3 vol.py -f ../memory-lime.lime linux.pslist.PsList | grep xmrig
0x9cdb00a58000.029434   29434   28606 ingxmrig   0       0       0       0       2025-10-11 01:15:14.933669 UTC  Disabled

```
Answer: `2025-10-11_01:15:14`

## Q3: Network Connection
```bash
$ python3 vol.py -f ../memory-lime.lime linux.sockstat.Sockstat | grep 29434
$ python3 vol.py -f ../memory-lime.lime linux.bash.Bash | grep pool
4026531840 100.0xmrig   29434   29434   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      iou-sqp-29434   29434   29436   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29437   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29438   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29439   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29440   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29441   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29445   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29446   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29447   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
    "pools": [{
        "url": "pool.hashvault.pro:443",

```
Answer: `46.4.28.18:443`

## Q4: Full Command
```bash
$ python3 vol.py -f ../memory-lime.lime linux.psaux.PsAux | grep xmrig
29434ess286060.0xmrig   ./xmrig --config=config.json

```
Answer: `./xmrig_--config=config.json`

## Q5: Working Directory
```bash
$ python3 vol.py -f ../memory-lime.lime linux.envars.Envars --pid 29434 | grep PWD
29434ess286060.0xmrig   PWD     /opt/miner
29434   28606   xmrig   OLDPWD  /tmp/LiME/src
```
Answer: `/opt/miner`

## Q6: Cryptocurrency
```bash
$ python3 vol.py -f ../memory-lime.lime linux.bash.Bash | grep pool
    "pools": [{
        "url": "pool.hashvault.pro:443",

```
Answer: `Monero`

## Q7: Wallet Address
```bash
$ python3 vol.py -f ../memory-lime.lime linux.bash.Bash            
Volatility 3 Framework 2.27.0
Progress:  100.00               Stacking attempts finished           
PID     Process CommandTime     Command

28606   bash    2025-10-11 01:14:16.000000 UTC  cat /dev/null > ~/.bash_history
28606   bash    2025-10-11 01:14:16.000000 UTC  exit
28606   bash    2025-10-11 01:14:17.000000 UTC  clear
28606   bash    2025-10-11 01:14:18.000000 UTC  l
28606   bash    2025-10-11 01:14:37.000000 UTC  # Install dependencies
28606   bash    2025-10-11 01:14:37.000000 UTC  apt update
28606   bash    2025-10-11 01:14:54.000000 UTC  apt install -y build-essential linux-headers-$(uname -r) git
28606   bash    2025-10-11 01:14:56.000000 UTC  cd /tmp
28606   bash    2025-10-11 01:14:56.000000 UTC  git clone https://github.com/504ensicsLabs/LiME
28606   bash    2025-10-11 01:14:56.000000 UTC  # Install LiME
28606   bash    2025-10-11 01:14:57.000000 UTC  make
28606   bash    2025-10-11 01:14:57.000000 UTC  cd LiME/src
28606   bash    2025-10-11 01:15:14.000000 UTC  wget https://github.com/xmrig/xmrig/releases/download/v6.22.0/xmrig-6.22.0-linux-static-x64.tar.gz
28606   bash    2025-10-11 01:15:14.000000 UTC  # Setup miner
28606   bash    2025-10-11 01:15:14.000000 UTC  tar -xf xmrig-6.22.0-linux-static-x64.tar.gz
28606   bash    2025-10-11 01:15:14.000000 UTC  cd /opt/miner
28606   bash    2025-10-11 01:15:14.000000 UTC  mv xmrig-6.22.0/xmrig .
28606   bash    2025-10-11 01:15:14.000000 UTC  mkdir -p /opt/miner
28606   bash    2025-10-11 01:15:14.000000 UTC  chmod +x xmrig
28606   bash    2025-10-11 01:15:14.000000 UTC  nohup ./xmrig --config=config.json > /dev/null 2>&1 &
28606   bash    2025-10-11 01:15:14.000000 UTC  cat > config.json << 'EOF'
{
    "pools": [{
        "url": "pool.hashvault.pro:443",
        "user": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
        "pass": "x"
    }]
}
EOF

28606   bash    2025-10-11 01:15:14.000000 UTC  # Run miner
28606   bash    2025-10-11 01:15:14.000000 UTC  sleep 30
28606   bash    2025-10-11 01:15:45.000000 UTC  # Capture with LiME
28606   bash    2025-10-11 01:15:45.000000 UTC  sudo insmod lime-$(uname -r).ko "path=/root/memory-lime.lime format=lime"
28606   bash    2025-10-11 01:15:45.000000 UTC  ps aux | grep xmrig
28606   bash    2025-10-11 01:15:45.000000 UTC  cd /tmp/LiME/src

```
Answer: `48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD`

## Q8: Pool Domain
```bash
$ python3 vol.py -f ../memory-lime.lime linux.bash.Bash | grep url
        "url": "pool.hashvault.pro:443",

```
Answer: `pool.hashvault.pro`

## Q9: SSH Source IP
```bash
$ python3 vol.py -f ../memory-lime.lime linux.envars.Envars --pid 29434 | grep SSH_CLIENT
29434ess286060.0xmrig   SSH_CLIENT      104.28.216.42 38854 22

```
Answer: `104.28.216.42`

## Q10: Kernel Module Analysis
```bash
$ python3 vol.py -f ../memory-lime.lime linux.bash.Bash | grep insmod
$ python3 vol.py -f ../memory-lime.lime linux.lsmod.Lsmod | head -20
28606essbash00.02025-10-11 01:15:45.000000 UTCptsudo insmod lime-$(uname -r).ko "path=/root/memory-lime.lime format=lime"
Volatility 3 Framework 2.27.0   Stacking attempts finished           

Offset  Module Name     Code Size       Taints  Load Arguments  File Output

0xffffc0bc7140  lime    0x5000  OOT_MODULE,UNSIGNED_MODULE      compress=None, timeout=None, digest=, localhostonly=None, format=, dio=None, path=      N/A
0xffffc0bc1100  tcp_diag        0x3000                  N/A
0xffffc0bbb0c0  udp_diag        0x3000                  N/A
0xffffc0ba9440  inet_diag       0x7000                  N/A
0xffffc0bae140  ip6t_REJECT     0x3000                  N/A
0xffffc0ba21c0  nf_reject_ipv6  0x6000                  N/A
0xffffc0b9b140  xt_hl   0x3000                  N/A
0xffffc0b931c0  ip6t_rt 0x4000                  N/A
0xffffc0b8b140  ipt_REJECT      0x3000                  N/A
0xffffc0b7e080  nf_reject_ipv4  0x3000                  N/A
0xffffc0b83200  xt_LOG  0x4000                  N/A
0xffffc0b78240  nf_log_syslog   0x5000                  N/A
0xffffc0b6f280  nft_limit       0x4000                  N/A
0xffffc0b69180  xt_limit        0x3000                  N/A
0xffffc0b61540  xt_tcpudp       0x4000                  N/A
0xffffc0b584c0  xt_recent       0x6000          ip_pkt_list_tot=None, ip_list_gid=None, ip_list_uid=None, ip_list_perms=None, ip_list_hash_size=None, ip_list_tot=None  N/A

```
Answer: `lime`


## Q11: PID
```bash
 python3 vol.py -f ../memory-lime.lime linux.pslist.PsList | grep xmrig
0x9cdb00a58000.029434   29434   28606ingxmrig   0       0       0       0       2025-10-11 01:15:14.933669 UTC  Disabled

```
Answer: `29434`

## Q12: Process Tree
```bash
$ python3 vol.py -f ../memory-lime.lime linux.pstree.PsTree | grep -A4 sshd
* 0x9cdb02fe28c00       13939   13939ing1attemptsshd
** 0x9cdb01ff5180       28556   28556   13939   sshd
*** 0x9cdb0d54d180      28606   28606   28556   bash
**** 0x9cdb00a58000     29434   29434   28606   xmrig
**** 0x9cdb109f28c0     29451   29451   28606   sudo
***** 0x9cdb00b35180    29452   29452   29451   sudo
```
Answer: `sshd->bash->xmrig`

---