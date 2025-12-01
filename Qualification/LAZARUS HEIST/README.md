# LAZARUS GROUP BANKING HEIST

## Description

You are a digital forensics investigator tasked with analyzing a sophisticated cyberattack against a major financial institution. The Lazarus Group, a notorious APT organization, has conducted a complex multi-stage attack targeting the bank SWIFT payment gateway system.

## Scenario

On January 15, 2025, FirstBank Corporation detected unusual network activity during routine monitoring. The bank's SWIFT gateway processed an unauthorized $81 million transfer to an unknown North Korean entity. Initial investigation revealed:

* Compromised banking workstation with elevated privileges
* Unknown executable files in system directories
* Suspicious network communications to external domains
* Evidence of credential harvesting and keylogging
* Potential lateral movement to critical financial systems
* Signs of data exfiltration and cryptocurrency mining


# LAZARUS GROUP BANKING HEIST 

## Question 1: XOR Key Recovery Through Cryptanalysis
The malware uses XOR encryption throughout. Recover the encryption key by analyzing the keylogger's known plaintext patterns and the encrypted backdoor. 

## Question 2: PE Configuration Extraction
Extract the malware configuration from the PE binary using the discovered XOR key. Identify all C2 infrastructure and attack parameters. 

Answer Format: C2_PRIMARY_C2_BACKUP_CAMPAIGN_ID

## Question 3: SWIFT Transaction Forensics
Analyze the keylogger data to reconstruct complete SWIFT transaction timeline and calculate total financial exposure.

Answer Format: TOTAL_FRAUD_AMOUNT_USD_SWIFT_OPERATOR_PASSWORD


## Question 4: Network Protocol Analysis and C2 Communication Decoding
Analyze complete C2 communication protocol and decode beacon payloads.

Answer Format: C2_HOST_SESSION_ID_FORMAT

## Question 5: Cryptocurrency Mining Infrastructure Analysis
Extract complete cryptocurrency mining configuration and correlate wallet address with known Lazarus operations.

Answer Format: WALLET_ADDRESS_FIRST_20_CHARS

## Question 6: Multi-Vector Data Exfiltration Analysis
Reconstruct all data exfiltration channels and identify exfiltrated content types.
Answer Format: HTTP_PORT_CHUNK_COUNT



## Question 7: Banking Credential Compromise Assessment
Determine complete scope of credential compromise and calculate potential financial exposure.
Answer Format: TOTAL_SYSTEMS:ADMIN_ACCOUNTS:DB_ADMIN_HASH_FIRST_16


## Question 8: Attack Timeline Reconstruction
Build complete timeline of attack phases by correlating network traffic with malware execution stages.

Answer Format: KEYLOGGER_PORT_MINING_PORT_BACKDOOR_PORT

## Question 9: Advanced Persistence and Anti-Forensics Analysis
Analyze malware persistence mechanisms and anti-forensics capabilities.

Answer Format: Capabilities_Sessionprefix

## Question 10: Attribution and Infrastructure Correlation
Correlate discovered infrastructure with known Lazarus Group operations and identify attribution evidence.

Answer Format: TYPOSQUAT_DOMAIN_CAMPAIGN_ID_SWIFT_TARGETS