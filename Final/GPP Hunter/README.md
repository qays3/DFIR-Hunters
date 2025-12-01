# GPP 

## Description

Your team intercepted network traffic from a corporate domain controller during a security assessment. The SYSVOL share was accessed, and Group Policy Preferences files were transferred. These files may contain sensitive credentials encrypted with a well-known vulnerability. Analyze the packet capture to extract and decrypt any credentials hidden within the traffic.

Hint: 
```
# CVE-2014-1812: Microsoft GPP AES Key (Published by Microsoft on MSDN in 2012)
# This is the publicly known key that Microsoft published for Group Policy Preferences
# Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
```

## Questions

Q1: Domain name (lowercase)

Q2: GPO GUID (uppercase, with braces)

Q3: Username with cpassword (no domain prefix)

Q4: Decrypted password

Q5: Date of Groups.xml modification (YYYY-MM-DD)

