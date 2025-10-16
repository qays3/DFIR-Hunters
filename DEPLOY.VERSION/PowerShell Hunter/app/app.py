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

FLAG = "flag{$93_34c72e1e-826c-47cb-8472-50551e76c2fe}"

CHALLENGES = {
    'suspicious_count': {
        'name': 'VBA Macro Classification',
        'description': 'How many files does mraptor classify as SUSPICIOUS',
        'difficulty': 'Easy',
        'answer': '3'
    },
    'ioc_count': {
        'name': 'IOC Detection Count',
        'description': 'Unique IOCs detected across all three Office files',
        'difficulty': 'Medium',
        'answer': '8'
    },
    'suspicious_keywords': {
        'name': 'Suspicious Keyword Analysis',
        'description': 'Total count of Suspicious keywords detected',
        'difficulty': 'Medium',
        'answer': '47'
    },
    'base64_strings': {
        'name': 'Base64 String Enumeration',
        'description': 'Distinct Base64 encoded strings identified',
        'difficulty': 'Medium',
        'answer': '7'
    },
    'autoexec_triggers': {
        'name': 'AutoExec Detection',
        'description': 'AutoExec triggers in DOCM file (alphabetically)',
        'difficulty': 'Hard',
        'answer': 'AutoExec_Auto_Open_Document_Close_Document_Open'
    },
    'macro_flags': {
        'name': 'Macro Flag Analysis',
        'description': 'Flags assigned to XLSM file by mraptor',
        'difficulty': 'Medium',
        'answer': 'AWX'
    },
    'risk_level': {
        'name': 'File Type Classification',
        'description': 'Risk level assigned to VBA macros',
        'difficulty': 'Easy',
        'answer': 'HIGH'
    },
    'vba_modules': {
        'name': 'Macro Detection Summary',
        'description': 'VBA modules detected in XLSM file',
        'difficulty': 'Easy',
        'answer': '1'
    },
    'createobject_count': {
        'name': 'OLE Object Analysis',
        'description': 'CreateObject function appearances across all files',
        'difficulty': 'Medium',
        'answer': '4'
    },
    'powershell_frequency': {
        'name': 'Keyword Frequency Analysis',
        'description': 'Combined frequency count of powershell',
        'difficulty': 'Medium',
        'answer': '23'
    },
    'malicious_patterns': {
        'name': 'Malicious Pattern Detection',
        'description': 'Unique malicious patterns in DOCM file',
        'difficulty': 'Hard',
        'answer': '3'
    },
    'external_urls': {
        'name': 'External Reference Analysis',
        'description': 'External URLs or domains extracted',
        'difficulty': 'Medium',
        'answer': '1'
    },
    'vba_code_lines': {
        'name': 'VBA Code Metrics',
        'description': 'Pure VBA code line count from DOC file',
        'difficulty': 'Hard',
        'answer': '62'
    },
    'highest_risk_score': {
        'name': 'Threat Detection',
        'description': 'Highest individual risk score by mraptor',
        'difficulty': 'Medium',
        'answer': '20'
    },
    'analysis_entries': {
        'name': 'Comprehensive Analysis',
        'description': 'Total analysis entries in XLSM file',
        'difficulty': 'Hard',
        'answer': '52'
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
            response_data['message'] = "Outstanding work! All malware analysis findings identified correctly!"
        
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

@app.get("/malware.zip")
async def download_malware():
    malware_path = "malware.zip"
    if os.path.exists(malware_path):
        return FileResponse(
            malware_path,
            media_type="application/zip",
            filename="malware.zip"
        )
    raise HTTPException(status_code=404, detail="Malware file not found")

app.mount("/assets", StaticFiles(directory="assets", html=True), name="assets")

@app.get("/")
async def read_root():
    return FileResponse("index.html")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5004)