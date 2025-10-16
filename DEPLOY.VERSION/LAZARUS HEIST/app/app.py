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

FLAG = "flag{$93_no_hun73r_7h!$_71m3_xd}"

CHALLENGES = {
    'xor_key': {
        'name': 'XOR Key Recovery',
        'description': 'Recover encryption key through cryptanalysis',
        'difficulty': 'Hard',
        'answer': 'L4z4ru5Gr0up2024K3yL4z'
    },
    'pe_configuration': {
        'name': 'PE Configuration Extraction',
        'description': 'Extract C2 infrastructure and attack parameters',
        'difficulty': 'Hard',
        'answer': 'update.microsoft-security.org:8443_cdn.adobe-updates.net:8443_SWIFT_HEIST_2024'
    },
    'swift_forensics': {
        'name': 'SWIFT Transaction Forensics',
        'description': 'Reconstruct transaction timeline and financial exposure',
        'difficulty': 'Hard',
        'answer': '96000000_Sw1ft$ecur3!'
    },
    'c2_protocol': {
        'name': 'Network Protocol Analysis',
        'description': 'Analyze C2 communication and decode beacons',
        'difficulty': 'Hard',
        'answer': 'update.microsoft-security.org_LAZARUS-12345_BANK-WORKSTATION-01'
    },
    'crypto_mining': {
        'name': 'Cryptocurrency Mining Analysis',
        'description': 'Extract mining configuration and wallet address',
        'difficulty': 'Hard',
        'answer': '4A7Bb2kHh9Ca8Y4BjP3t'
    },
    'data_exfiltration': {
        'name': 'Data Exfiltration Analysis',
        'description': 'Reconstruct exfiltration channels',
        'difficulty': 'Medium',
        'answer': '8080_4'
    },
    'credential_compromise': {
        'name': 'Banking Credential Assessment',
        'description': 'Determine scope of credential compromise',
        'difficulty': 'Hard',
        'answer': '4:2:e99a18c428cb38d5'
    },
    'attack_timeline': {
        'name': 'Attack Timeline Reconstruction',
        'description': 'Correlate network traffic with malware stages',
        'difficulty': 'Medium',
        'answer': '9999_3333_4444'
    },
    'persistence_analysis': {
        'name': 'Persistence and Anti-Forensics',
        'description': 'Analyze persistence mechanisms and capabilities',
        'difficulty': 'Hard',
        'answer': '4_LAZARUS_PERSIST_UNKNOWN'
    },
    'attribution': {
        'name': 'Attribution and Infrastructure',
        'description': 'Correlate infrastructure with Lazarus operations',
        'difficulty': 'Hard',
        'answer': 'update.microsoft-security.org_LAZARUS_SWIFT_HEIST_FINAL_EXFIL_LAZARUS_FRONT_COMPANY_LIMITED'
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
            response_data['message'] = "Outstanding work! Lazarus Group attack completely analyzed!"
        
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

@app.get("/LAZARUS_HEIST.zip")
async def download_heist():
    heist_path = "LAZARUS_HEIST.zip"
    if os.path.exists(heist_path):
        return FileResponse(
            heist_path,
            media_type="application/zip",
            filename="LAZARUS_HEIST.zip"
        )
    raise HTTPException(status_code=404, detail="LAZARUS_HEIST file not found")

app.mount("/assets", StaticFiles(directory="assets", html=True), name="assets")

@app.get("/")
async def read_root():
    return FileResponse("index.html")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5005)