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
    'xor_key': {
        'name': 'XOR Key Recovery Through Cryptanalysis',
        'description': 'The malware uses XOR encryption throughout. Recover the encryption key by analyzing the keylogger\'s known plaintext patterns and the encrypted backdoor. known_start = b"#!/usr/bin/env python3"',
        'difficulty': 'Hard',
        'answer_format': 'Key string',
        'answer': CONFIG['xor_key']
    },
    'pe_configuration': {
        'name': 'PE Configuration Extraction',
        'description': 'Extract the malware configuration from the PE binary using the discovered XOR key. Identify all C2 infrastructure and attack parameters.',
        'difficulty': 'Hard',
        'answer_format': 'C2_PRIMARY_C2_BACKUP_CAMPAIGN_ID',
        'answer': CONFIG['pe_configuration']
    },
    'swift_forensics': {
        'name': 'SWIFT Transaction Forensics',
        'description': 'Analyze the keylogger data to reconstruct complete SWIFT transaction timeline and calculate total financial exposure.',
        'difficulty': 'Hard',
        'answer_format': 'TOTAL_FRAUD_AMOUNT_USD_SWIFT_OPERATOR_PASSWORD',
        'answer': CONFIG['swift_forensics']
    },
    'c2_protocol': {
        'name': 'Network Protocol Analysis and C2 Communication Decoding',
        'description': 'Analyze complete C2 communication protocol and decode beacon payloads.',
        'difficulty': 'Hard',
        'answer_format': 'C2_HOST_SESSION_ID_FORMAT',
        'answer': CONFIG['c2_protocol']
    },
    'crypto_mining': {
        'name': 'Cryptocurrency Mining Infrastructure Analysis',
        'description': 'Extract complete cryptocurrency mining configuration and correlate wallet address with known Lazarus operations.',
        'difficulty': 'Hard',
        'answer_format': 'WALLET_ADDRESS_FIRST_20_CHARS',
        'answer': CONFIG['crypto_mining']
    },
    'data_exfiltration': {
        'name': 'Multi-Vector Data Exfiltration Analysis',
        'description': 'Reconstruct all data exfiltration channels and identify exfiltrated content types.',
        'difficulty': 'Medium',
        'answer_format': 'HTTP_PORT_CHUNK_COUNT',
        'answer': CONFIG['data_exfiltration']
    },
    'credential_compromise': {
        'name': 'Banking Credential Compromise Assessment',
        'description': 'Determine complete scope of credential compromise and calculate potential financial exposure.',
        'difficulty': 'Hard',
        'answer_format': 'TOTAL_SYSTEMS:ADMIN_ACCOUNTS:DB_ADMIN_HASH_FIRST_16',
        'answer': CONFIG['credential_compromise']
    },
    'attack_timeline': {
        'name': 'Attack Timeline Reconstruction',
        'description': 'Build complete timeline of attack phases by correlating network traffic with malware execution stages.',
        'difficulty': 'Medium',
        'answer_format': 'KEYLOGGER_PORT_MINING_PORT_BACKDOOR_PORT',
        'answer': CONFIG['attack_timeline']
    },
    'persistence_analysis': {
        'name': 'Advanced Persistence and Anti-Forensics Analysis',
        'description': 'Analyze malware persistence mechanisms and anti-forensics capabilities.',
        'difficulty': 'Hard',
        'answer_format': 'Capabilities_Sessionprefix',
        'answer': CONFIG['persistence_analysis']
    },
    'attribution': {
        'name': 'Attribution and Infrastructure Correlation',
        'description': 'Correlate discovered infrastructure with known Lazarus Group operations and identify attribution evidence.',
        'difficulty': 'Hard',
        'answer_format': 'TYPOSQUAT_DOMAIN_CAMPAIGN_ID_SWIFT_TARGETS',
        'answer': CONFIG['attribution']
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
            'difficulty': config['difficulty'],
            'answer_format': config['answer_format']
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
            response_data['message'] = "Outstanding work! Lazarus Group attack completely analyzed!"

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

@app.get("/LAZARUS_HEIST.zip")
async def download_heist(request: Request, access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    heist_path = "LAZARUS_HEIST.zip"
    if os.path.exists(heist_path):
        return FileResponse(
            heist_path,
            media_type="application/zip",
            filename="LAZARUS_HEIST.zip"
        )
    raise HTTPException(status_code=404, detail="LAZARUS_HEIST file not found")

app.mount("/assets", StaticFiles(directory="assets", html=True), name="assets")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5005)