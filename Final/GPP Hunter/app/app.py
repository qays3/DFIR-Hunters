from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import os
import json
import uvicorn
from typing import Optional

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_config():
    config = {}
    with open('config.cfg', 'r') as f:
        for line in f:
            line = line.strip()
            if line and '=' in line:
                key, value = line.split('=', 1)
                config[key] = value
    return config

CONFIG = load_config()
SECRET = CONFIG['SECRET']
FLAG = CONFIG['FLAG']

CHALLENGES = {
    'domain_name': {
        'name': 'Domain Identification',
        'description': 'Extract the target domain from network traffic\nDomain name (lowercase)',
        'difficulty': 'Easy',
        'answer': CONFIG['domain_name']
    },
    'gpo_guid': {
        'name': 'GPO GUID Extraction',
        'description': 'Identify the Group Policy Object unique identifier\nGPO GUID (uppercase, with braces)',
        'difficulty': 'Medium',
        'answer': CONFIG['gpo_guid']
    },
    'username': {
        'name': 'Username Discovery',
        'description': 'Find the username associated with cpassword\nUsername with cpassword (no domain prefix)',
        'difficulty': 'Easy',
        'answer': CONFIG['username']
    },
    'decrypted_password': {
        'name': 'Password Decryption',
        'description': 'Decrypt the GPP cpassword value\nDecrypted password',
        'difficulty': 'Hard',
        'answer': CONFIG['decrypted_password']
    },
    'modification_date': {
        'name': 'Timeline Analysis',
        'description': 'Determine when Groups.xml was modified\nDate of Groups.xml modification (YYYY-MM-DD)',
        'difficulty': 'Medium',
        'answer': CONFIG['modification_date']
    }
}

def check_access(request: Request, access_token: Optional[str] = Cookie(None)):
    access_param = request.query_params.get('access')
    if access_param == SECRET or access_token == SECRET:
        return True
    return False

@app.get("/")
async def read_root(request: Request, access: str = None):
    if access != SECRET:
        return RedirectResponse(url="https://qayssarayra.com/")
    response = FileResponse("index.html")
    response.set_cookie(key="access_token", value=SECRET, httponly=False, max_age=3600, samesite='lax')
    return response

@app.get("/api/challenges")
async def get_challenges(request: Request, access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    challenges_info = {}
    for key, config in CHALLENGES.items():
        challenges_info[key] = {
            'name': config['name'],
            'description': config['description'],
            'difficulty': config['difficulty']
        }
    return JSONResponse(content=challenges_info)

@app.post("/api/analyze")
async def analyze_findings(request: Request, file: UploadFile = File(...), access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
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
            response_data['message'] = "Outstanding work! GPP vulnerability completely analyzed!"
        
        return JSONResponse(content=response_data)
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.get("/template.json")
async def download_template(request: Request, access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    template_path = "template.json"
    if os.path.exists(template_path):
        return FileResponse(
            template_path,
            media_type="application/json",
            filename="template.json"
        )
    raise HTTPException(status_code=404, detail="Template file not found")

@app.get("/challenge.pcap")
async def download_evidence(request: Request, access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    evidence_path = "challenge.pcap"
    if os.path.exists(evidence_path):
        return FileResponse(
            evidence_path,
            media_type="application/vnd.tcpdump.pcap",
            filename="challenge.pcap"
        )
    raise HTTPException(status_code=404, detail="Challenge file not found")

app.mount("/assets", StaticFiles(directory="assets", html=True), name="assets")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5009)