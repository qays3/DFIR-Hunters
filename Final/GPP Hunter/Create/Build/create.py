import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import *
from scapy.layers.smb import *
from scapy.layers.smb2 import *
import random
import string

# CVE-2014-1812: Microsoft GPP AES Key (Published by Microsoft on MSDN in 2012)
# This key was publicly disclosed, making all GPP passwords vulnerable to decryption
# Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
AES_KEY = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xff\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
AES_IV = b'\x00' * 16

def encrypt_password(password):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(password.encode('utf-16-le'), 16)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()

def create_groups_xml(username, encrypted_pass, changed_date, uid):
    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{{3125E937-EB16-4b4c-9934-544FC6D24D26}}">
    <User clsid="{{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}}" name="{username}" image="2" changed="{changed_date}" uid="{uid}">
        <Properties action="U" newName="" fullName="" description="" cpassword="{encrypted_pass}" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="{username}"/>
    </User>
</Groups>'''
    return xml

def create_services_xml(service_name, encrypted_pass, changed_date, uid):
    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<NTServices clsid="{{2CFB484A-4E96-4b5d-A0B6-093D2F91E6AE}}">
    <NTService clsid="{{AB6F0B67-341F-4e51-92F9-005FBFBA1A43}}" name="{service_name}" image="0" changed="{changed_date}" uid="{uid}">
        <Properties startupType="AUTOMATIC" serviceName="{service_name}" timeout="30" accountName="NT AUTHORITY\\LocalService" cpassword="{encrypted_pass}" firstFailure="NO_ACTION" secondFailure="NO_ACTION" thirdFailure="NO_ACTION"/>
    </NTService>
</NTServices>'''
    return xml

def create_scheduled_tasks_xml(task_name, encrypted_pass, changed_date, uid):
    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A71CD118DBCC}}">
    <Task clsid="{{2ABBAD61-f829-4007-A45D-05F7C03D5C1D}}" name="{task_name}" image="0" changed="{changed_date}" uid="{uid}">
        <Properties action="C" name="{task_name}" runAs="CORP\\svc_backup" cpassword="{encrypted_pass}">
            <Task version="1.2">
                <Triggers>
                    <TimeTrigger>
                        <StartBoundary>2024-01-15T02:00:00</StartBoundary>
                    </TimeTrigger>
                </Triggers>
            </Task>
        </Properties>
    </Task>
</ScheduledTasks>'''
    return xml

def create_decoy_xml(xml_type):
    decoys = [
        '2F6B2D9E8C4A1B5F3E7D8A9C0B1F4E6D8A2C5B7F9E1D3A6C8B0F2E5D7A9C1B4F',
        'j1g2KLmvKjI8Mov8v6+WJ9XV8cKygSQn6jWd8rwSM1A=',
        'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcq19ArfM5cVgKmK98M=',
        'kJDo8F3m9Pqw8NbV5xTy2LmZ7RsG4hWq6NeK1CvB8jY='
    ]
    return random.choice(decoys)

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def create_smb_packet(src_ip, dst_ip, src_port, dst_port, smb_data, seq, ack):
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq, ack=ack)
    return ip/tcp/Raw(load=smb_data)

def create_challenge():
    username = "qays3"
    service_account = "svc_deploy"
    task_account = "svc_backup"
    
    real_password = "q4y$!@9393"
    
    encrypted_real = encrypt_password(real_password)
    
    changed_date_groups = "2025-03-15 14:23:11"
    changed_date_services = "2025-02-20 09:15:33"
    changed_date_tasks = "2025-01-15 16:42:07"
    
    uid_groups = "{B5C8D7E9-4F2A-4d3b-9E1C-7A8F6D5E4C3B}"
    uid_services = "{A7D9E2F1-3C4B-4e5d-8F9A-6B7C8D9E0F1A}"
    uid_tasks = "{C3E5F7A9-2D4B-4c6e-9A1B-5C7D8E9F0A1B}"
    
    groups_xml = create_groups_xml(username, encrypted_real, changed_date_groups, uid_groups)
    services_xml = create_services_xml(service_account, create_decoy_xml("services"), changed_date_services, uid_services)
    tasks_xml = create_scheduled_tasks_xml(task_account, create_decoy_xml("tasks"), changed_date_tasks, uid_tasks)
    
    packets = []
    
    client_ip = "192.168.10.50"
    server_ip = "192.168.10.10"
    smb_port = 445
    client_port = 49732
    
    for i in range(50):
        noise_data = generate_random_string(random.randint(100, 500)).encode()
        pkt = create_smb_packet(
            random.choice([client_ip, server_ip]),
            random.choice([client_ip, server_ip]),
            random.randint(49000, 50000),
            random.choice([445, 139, 80, 443]),
            noise_data,
            random.randint(1000000, 9999999),
            random.randint(1000000, 9999999)
        )
        packets.append(pkt)
    
    smb_header = b'\xffSMB'
    
    sysvol_path = b'\\\\CORP-DC01\\SYSVOL\\qayssarayra.fun\\Policies\\'
    
    groups_file_data = smb_header + b'\x2d\x00' + sysvol_path + b'{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\Groups\\Groups.xml' + b'\x00' * 20 + groups_xml.encode()
    pkt1 = create_smb_packet(server_ip, client_ip, smb_port, client_port, groups_file_data, 5234891, 8923441)
    packets.append(pkt1)
    
    for i in range(30):
        noise_data = generate_random_string(random.randint(100, 500)).encode()
        pkt = create_smb_packet(
            random.choice([client_ip, server_ip]),
            random.choice([client_ip, server_ip]),
            random.randint(49000, 50000),
            random.choice([445, 139, 80, 443]),
            noise_data,
            random.randint(1000000, 9999999),
            random.randint(1000000, 9999999)
        )
        packets.append(pkt)
    
    services_file_data = smb_header + b'\x2d\x00' + sysvol_path + b'{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\Services\\Services.xml' + b'\x00' * 20 + services_xml.encode()
    pkt2 = create_smb_packet(server_ip, client_ip, smb_port, client_port + 1, services_file_data, 5334992, 8923552)
    packets.append(pkt2)
    
    for i in range(40):
        noise_data = generate_random_string(random.randint(100, 500)).encode()
        pkt = create_smb_packet(
            random.choice([client_ip, server_ip]),
            random.choice([client_ip, server_ip]),
            random.randint(49000, 50000),
            random.choice([445, 139, 80, 443]),
            noise_data,
            random.randint(1000000, 9999999),
            random.randint(1000000, 9999999)
        )
        packets.append(pkt)
    
    tasks_file_data = smb_header + b'\x2d\x00' + sysvol_path + b'{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml' + b'\x00' * 20 + tasks_xml.encode()
    pkt3 = create_smb_packet(server_ip, client_ip, smb_port, client_port + 2, tasks_file_data, 5435103, 8923663)
    packets.append(pkt3)
    
    for i in range(80):
        noise_data = generate_random_string(random.randint(100, 500)).encode()
        pkt = create_smb_packet(
            random.choice([client_ip, server_ip]),
            random.choice([client_ip, server_ip]),
            random.randint(49000, 50000),
            random.choice([445, 139, 80, 443]),
            noise_data,
            random.randint(1000000, 9999999),
            random.randint(1000000, 9999999)
        )
        packets.append(pkt)
    
    random.shuffle(packets)
    
    wrpcap('challenge.pcap', packets)
    
    print("Challenge created: challenge.pcap")
    print("\n[*] CVE-2014-1812 - Group Policy Preferences Password Vulnerability")
    print("[*] Microsoft published the AES decryption key on MSDN in 2012")
    print("[*] Any domain user can decrypt passwords stored in SYSVOL")
    print("[*] Reference: MS14-025 Security Bulletin (May 2014)")

if __name__ == "__main__":
    create_challenge()