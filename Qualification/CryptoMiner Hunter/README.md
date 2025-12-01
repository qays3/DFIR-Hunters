# CryptoMiner 

## Scenario
A Linux server (Ubuntu 24.04) was compromised. Security team captured memory during incident response. Analyze the dump to uncover the attack.


## Setup
```bash
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -e .
mkdir -p volatility3/symbols/linux/
cp ../ubuntu-FINAL-6.8.0-71-generic.json volatility3/symbols/linux/
```

## Challenge Questions

### Q1: Process Genealogy
What is the PPID (Parent Process ID) of the malicious cryptocurrency miner?

### Q2: Temporal Analysis
What is the exact UTC timestamp when the malicious process was created?
Format: YYYY-MM-DD_HH:MM:SS

### Q3: Network IOC
What is the destination IP address the miner connected to?
Format: IP:PORT

### Q4: Command Reconstruction
The attacker executed a specific command to run the miner. What is the FULL command line with all arguments?

### Q5: Environmental Forensics
What was the working directory (PWD) when the miner process was launched?

### Q6: Cryptocurrency Intelligence
What cryptocurrency was being mined? Research the pool domain and wallet address format.

### Q7: Wallet Extraction
Extract the attacker's cryptocurrency wallet address from memory.

### Q8: Pool Infrastructure
What is the FQDN of the mining pool server?

### Q9: SSH Forensics
What is the source IP address that established the SSH session used for the attack?

### Q10: Kernel Module Analysis
A kernel module was loaded during the incident. What is the module name visible in the loaded kernel modules?

### Q11: Process ID
What is the PID of the malicious miner process?

### Q12: Process Tree Analysis
What is the complete process execution chain from sshd to the miner? Format: parentname->childname->minername

## Final Flag Format
After answering all questions, combine your answers in this exact order:

```
flag{Q1_Q2_Q3_Q4_Q5_Q6_Q7_Q8_Q9_Q10_Q11_Q12}
```

Replace each Q# with your answer. Use underscores between answers.

**Example Format:**
```
flag{1234_2025-01-01_01:01:01_192.168.1.1:443_command_/path_Bitcoin_wallet123_pool.example.com_10.0.0.1_module_5678_parent->child->process}
```