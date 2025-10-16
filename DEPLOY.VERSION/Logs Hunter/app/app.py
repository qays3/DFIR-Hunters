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

FLAG = "flag{$93_3fcba33d-4a69-419b-9d97-3bb3024ee179}"

CHALLENGES = {
    'aes_key': {
        'name': 'AES Encryption Key',
        'description': 'Find the AES encryption key used in database query',
        'difficulty': 'Hard',
        'points': 150,
        'answer': '97ec6260-eedd-487b-9d6d-74a6dbccc3a2'
    },
    'xss_payload_hash': {
        'name': 'XSS Payload Hash',
        'description': 'MD5 hash of the complete JavaScript payload',
        'difficulty': 'Hard',
        'points': 150,
        'answer': '15f4b6f00a9cdbaee09916eaf59bd16b'
    },
    'wmi_persistence_hash': {
        'name': 'WMI Persistence Command Hash',
        'description': 'MD5 hash of PowerShell WMI persistence command',
        'difficulty': 'Hard',
        'points': 150,
        'answer': 'efb3b45d66137b7c1cadf37101698f39'
    },
    'dll_hash': {
        'name': 'Malicious DLL Hash',
        'description': 'SHA256 hash of shadowstorm.dll performing injection',
        'difficulty': 'Hard',
        'points': 150,
        'answer': 'E0CA6EE51D17F909BBA2038964169DE69264D0AE009B903AE1512EBC7E388100'
    },
    'tor_bridge': {
        'name': 'Tor Bridge Base64',
        'description': 'Base64-encoded Tor bridge address for C2',
        'difficulty': 'Hard',
        'points': 150,
        'answer': 'MTkyLjE2OC4xLjEwMDo5MDAxIDAxMjM0NTY3ODlBQkNERUYwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc='
    },
    'mimikatz_hash': {
        'name': 'Credential Dumping Hash',
        'description': 'MD5 hash of mimikatz command line',
        'difficulty': 'Hard',
        'points': 150,
        'answer': 'eaf8dac40a0af87a4c827d5a66fbb3fb'
    },
    'backdoor_path': {
        'name': 'Backdoor File Path',
        'description': 'Complete Windows path of persistence backdoor',
        'difficulty': 'Medium',
        'points': 100,
        'answer': 'C:\\temp\\backdoor.exe'
    },
    'sqli_sessions': {
        'name': 'SQL Injection Sessions',
        'description': 'Count of unique session IDs in SQL injection attempts',
        'difficulty': 'Medium',
        'points': 100,
        'answer': '5'
    },
    'failed_ssh': {
        'name': 'Failed SSH Attempts',
        'description': 'Total failed SSH authentication attempts from attacker IP',
        'difficulty': 'Medium',
        'points': 100,
        'answer': '1000'
    },
    'granted_access': {
        'name': 'Process Access Value',
        'description': 'GrantedAccess hex value for lateral movement',
        'difficulty': 'Medium',
        'points': 100,
        'answer': '0x1FFFFF'
    }
}

@app.get("/api/challenges")
async def get_challenges():
    challenges_info = {}
    for key, config in CHALLENGES.items():
        challenges_info[key] = {
            'name': config['name'],
            'description': config['description'],
            'difficulty': config['difficulty'],
            'points': config['points']
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
        total_points = 0
        max_points = sum(c['points'] for c in CHALLENGES.values())
        
        for key, config in CHALLENGES.items():
            user_answer = str(submitted_answers.get(key, '')).strip()
            correct_answer = config['answer']
            
            is_correct = user_answer.lower() == correct_answer.lower()
            
            results[key] = {
                'correct': is_correct,
                'submitted': user_answer,
                'expected': config['answer'],
                'points': config['points'] if is_correct else 0
            }
            
            if is_correct:
                correct_count += 1
                total_points += config['points']
        
        response_data = {
            'success': True,
            'challenges': results,
            'correct': correct_count,
            'total': len(CHALLENGES),
            'points': total_points,
            'maxPoints': max_points
        }
        
        if correct_count == len(CHALLENGES):
            response_data['flag'] = FLAG
            response_data['message'] = "Outstanding work! All IOCs identified correctly!"
        
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

@app.get("/logs.zip")
async def download_logs():
    logs_path = "logs.zip"
    if os.path.exists(logs_path):
        return FileResponse(
            logs_path,
            media_type="application/zip",
            filename="logs.zip"
        )
    raise HTTPException(status_code=404, detail="Logs file not found")

app.mount("/assets", StaticFiles(directory="assets", html=True), name="assets")

@app.get("/")
async def read_root():
    return FileResponse("index.html")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5002)