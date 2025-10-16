from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import os
import json
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FLAG = "flag{$93_qays.fun_t3$t_i7_&_t3ll_m3_ur_0p}"

CHALLENGES = {
    'initial_compromise': {
        'name': 'Initial Compromise Analysis',
        'description': 'What is the exact timestamp (UTC) when the initial malicious payload was first downloaded?',
        'difficulty': 'Easy',
        'answer': '2025-09-19_23:28:14'
    },
    'c2_infrastructure': {
        'name': 'C2 Infrastructure Discovery',
        'description': 'How many unique C2 domains were contacted during the attack, and what is the total number of HTTP requests sent to ALL C2 domains combined?',
        'difficulty': 'Medium',
        'answer': '4:10'
    },
    'session_tracking': {
        'name': 'Session Tracking Analysis',
        'description': 'What is the X-Session-ID header value used in the primary C2 communication channel, and how many beacons used this exact session ID?',
        'difficulty': 'Medium',
        'answer': '8887f071f3c3e5a5583e19d737f52f1a:5'
    },
    'credential_harvesting': {
        'name': 'Credential Harvesting Detection',
        'description': 'What are the exact usernames and passwords stolen from the browser credential store? List them in the order they appear in the network traffic.',
        'difficulty': 'Hard',
        'answer': 'shosho.ahmed:Summer2024!_shosho.ahmed:HR_P@ss123_s.ahmed.personal:MyPersonal$2024'
    },
    'dns_tunneling': {
        'name': 'DNS Tunneling Command Extraction',
        'description': 'What are the Base64-encoded commands sent via DNS tunneling, and what do they decode to? List the first 3 commands in chronological order.',
        'difficulty': 'Hard',
        'answer': 'whoami_net_user_ipconfig'
    },
    'lateral_movement': {
        'name': 'Lateral Movement Timeline',
        'description': 'At what exact time (UTC) did the attacker begin network reconnaissance scanning, and which three IP addresses were the primary targets?',
        'difficulty': 'Medium',
        'answer': '2025-09-19_23:28:34_172.25.1.10_172.25.1.11_172.25.1.101'
    },
    'malware_hash': {
        'name': 'Malware Hash Correlation',
        'description': 'What is the MD5 hash value transmitted in the malware_deploy POST request, and what malware family name is associated with it?',
        'difficulty': 'Medium',
        'answer': '04fb0ccf3ef309b1cd587f609ab0e81e_CRACKSHOT'
    },
    'data_exfiltration': {
        'name': 'Data Exfiltration Quantification',
        'description': 'What is the total amount of data exfiltrated via HTTP uploads (in bytes), and through how many different destination ports?',
        'difficulty': 'Medium',
        'answer': '2605:3'
    },
    'incident_response': {
        'name': 'Incident Response Contact Analysis',
        'description': 'What is the exact email address contacted for incident response, and how many bytes of data were transmitted containing this email address?',
        'difficulty': 'Easy',
        'answer': 'info@qayssarayra.com_3437'
    },
    'golden_ticket': {
        'name': 'Golden Ticket Attack Details',
        'description': 'What is the KRBTGT hash used in the Golden Ticket attack, and what is the Domain SID?',
        'difficulty': 'Hard',
        'answer': '502c2ba5c4e1234567890abcdef12345_S-1-5-21-1234567890-1234567890-1234567890'
    },
    'anti_forensics': {
        'name': 'Anti-Forensics Timeline',
        'description': 'At what time did the anti-forensics activities begin, and what specific action was reported to the C2 server?',
        'difficulty': 'Medium',
        'answer': '2025-09-19_19:29:04_cleanup'
    },
    'persistence_mechanism': {
        'name': 'Persistence Mechanism Analysis',
        'description': 'How many different persistence mechanisms were deployed, and what is the total time span (in seconds) between the first and last persistence installation?',
        'difficulty': 'Hard',
        'answer': '2:3'
    },
    'file_server': {
        'name': 'File Server Compromise',
        'description': 'Which classified document was accessed first on the file server, and how many total file access events were logged?',
        'difficulty': 'Medium',
        'answer': 'Employee_Database.xlsx_1'
    },
    'attack_chain': {
        'name': 'Complete Attack Chain Reconstruction',
        'description': '[A] Credential Harvesting, [B] Initial Compromise, [C] Data Exfiltration, [D] Lateral Movement, [E] C2 Establishment, [F] Persistence Installation',
        'difficulty': 'Hard',
        'answer': 'B_E_A_C_D_F'
    }
}

@app.get("/api/challenges")
async def get_challenges():
    challenges_info = {}
    for key, config in CHALLENGES.items():
        challenges_info[key] = {
            'name': config['name'],
            'description': config['description'],
            'difficulty': config['difficulty']
        }
    return JSONResponse(content=challenges_info)

@app.post("/api/analyze")
async def analyze_findings(file: UploadFile = File(...)):
    MAX_FILE_SIZE = 5 * 1024
    
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="File must be a JSON file")
    
    try:
        content = await file.read()
        
        if len(content) == 0:
            raise HTTPException(status_code=400, detail="File is empty")
        
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail=f"File too large. Maximum size is 5KB")
        
        submitted_answers = json.loads(content.decode('utf-8'))
        
        expected_keys = set(CHALLENGES.keys())
        submitted_keys = set(submitted_answers.keys())
        
        if submitted_keys != expected_keys:
            raise HTTPException(
                status_code=400, 
                detail="Invalid JSON structure. Don't modify the keys, only add values to the template."
            )
        
        empty_fields = []
        for key in CHALLENGES.keys():
            value = str(submitted_answers.get(key, '')).strip()
            if not value:
                empty_fields.append(key)
        
        if empty_fields:
            raise HTTPException(
                status_code=400,
                detail=f"All fields must be filled. Empty or whitespace-only values are not allowed. Empty fields: {', '.join(empty_fields)}"
            )
        
        results = {}
        correct_count = 0
        
        for key, config in CHALLENGES.items():
            user_answer = str(submitted_answers.get(key, '')).strip()
            correct_answer = config['answer']
            
            is_correct = user_answer.lower() == correct_answer.lower()
            
            results[key] = {
                'correct': is_correct,
                'submitted': user_answer
            }
            
            if is_correct:
                correct_count += 1
        
        response_data = {
            'success': True,
            'challenges': results,
            'correct': correct_count,
            'total': len(CHALLENGES)
        }
        
        if correct_count == len(CHALLENGES):
            response_data['flag'] = FLAG
            response_data['message'] = "Outstanding work! APT41 attack fully analyzed!"
        
        return JSONResponse(content=response_data)
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.get("/template.json")
async def download_template():
    template_path = "template.json"
    if os.path.exists(template_path):
        return FileResponse(
            template_path,
            media_type="application/json",
            filename="template.json"
        )
    raise HTTPException(status_code=404, detail="Template file not found")

@app.get("/APT41.pcap")
async def download_pcap():
    pcap_path = "APT41.pcap"
    if os.path.exists(pcap_path):
        return FileResponse(
            pcap_path,
            media_type="application/vnd.tcpdump.pcap",
            filename="APT41.pcap"
        )
    raise HTTPException(status_code=404, detail="PCAP file not found")

app.mount("/assets", StaticFiles(directory="assets", html=True), name="assets")

@app.get("/")
async def read_root():
    return FileResponse("index.html")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5007)