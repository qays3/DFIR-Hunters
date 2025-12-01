const API_BASE = '/api';

const CHALLENGE_ICONS = {
    'ppid': 'P',
    'timestamp': 'T',
    'network_connection': 'N',
    'command_line': 'C',
    'working_directory': 'W',
    'cryptocurrency': 'K',
    'wallet_address': 'A',
    'pool_domain': 'D',
    'ssh_source_ip': 'S',
    'kernel_module': 'M',
    'process_id': 'I',
    'process_tree': 'R'
};

let challengesInfo = {};
let selectedFile = null;
let successSound = null;

function loadSuccessSound() {
    successSound = new Audio('assets/sounds/correct-356013.mp3');
    successSound.preload = 'auto';
}

async function loadChallenges() {
    try {
        const response = await fetch(`${API_BASE}/challenges`);
        challengesInfo = await response.json();
        renderChallenges();
    } catch (error) {
        showError('Failed to load challenges. Ensure the backend is running.');
    }
}

function renderChallenges() {
    const grid = document.getElementById('challengesGrid');
    grid.innerHTML = '';
    
    Object.entries(challengesInfo).forEach(([key, info]) => {
        const card = document.createElement('div');
        card.className = 'malware-card';
        card.id = `challenge-${key}`;
        card.innerHTML = `
            <div class="malware-status">?</div>
            <div class="malware-icon">${CHALLENGE_ICONS[key]}</div>
            <h3 class="malware-name">${info.name}</h3>
            <div class="malware-type">${info.description}</div>
            <div class="malware-meta">
                <span class="malware-difficulty">${info.difficulty}</span>
            </div>
        `;
        grid.appendChild(card);
    });
}

function setupFileUpload() {
    const fileInput = document.getElementById('yaraFile');
    const fileNameDisplay = document.getElementById('fileName');
    const scanButton = document.getElementById('scanBtn');
    
    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            if (!file.name.endsWith('.json')) {
                showError('Please upload a .json file');
                fileInput.value = '';
                selectedFile = null;
                fileNameDisplay.textContent = '';
                scanButton.disabled = true;
                return;
            }
            selectedFile = file;
            fileNameDisplay.textContent = file.name;
            scanButton.disabled = false;
        } else {
            selectedFile = null;
            fileNameDisplay.textContent = '';
            scanButton.disabled = true;
        }
    });
    
    scanButton.addEventListener('click', analyzeFindings);
}

async function analyzeFindings() {
    if (!selectedFile) return;
    
    const scanButton = document.getElementById('scanBtn');
    const originalHTML = scanButton.innerHTML;
    
    scanButton.disabled = true;
    scanButton.innerHTML = `
        <svg class="scan-icon spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
        </svg>
        Analyzing...
    `;
    
    hideError();
    
    const resultsSection = document.getElementById('resultsSection');
    const flagSection = document.getElementById('flagSection');
    resultsSection.classList.remove('visible');
    flagSection.classList.remove('visible');
    
    const challengeCards = document.querySelectorAll('.malware-card');
    challengeCards.forEach(card => {
        card.classList.remove('detected', 'not-detected');
        const statusIcon = card.querySelector('.malware-status');
        statusIcon.textContent = '?';
    });
    
    const formData = new FormData();
    formData.append('file', selectedFile);
    
    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.detail || 'Analysis failed');
        }
        
        displayResults(data);
        
    } catch (error) {
        showError(error.message);
        scanButton.disabled = false;
        scanButton.innerHTML = originalHTML;
    }
}

function updateChallengeCard(key, correct) {
    const card = document.getElementById(`challenge-${key}`);
    const statusIcon = card.querySelector('.malware-status');
    
    card.classList.remove('detected', 'not-detected');
    
    if (correct) {
        card.classList.add('detected');
        statusIcon.textContent = '✓';
    } else {
        card.classList.add('not-detected');
        statusIcon.textContent = '✗';
    }
}

function displayResults(data) {
    const resultsSection = document.getElementById('resultsSection');
    const detectedCount = document.getElementById('detectedCount');
    const totalCount = document.getElementById('totalCount');
    const resultsGrid = document.getElementById('resultsGrid');
    const scanButton = document.getElementById('scanBtn');
    
    detectedCount.textContent = '0';
    totalCount.textContent = data.total;
    
    resultsGrid.innerHTML = '';
    
    resultsSection.classList.add('visible');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    
    const challengeEntries = Object.entries(data.challenges);
    let currentCorrectCount = 0;
    
    challengeEntries.forEach(([key, result], index) => {
        setTimeout(() => {
            updateChallengeCard(key, result.correct);
            
            if (result.correct) {
                currentCorrectCount++;
                detectedCount.textContent = currentCorrectCount;
            }
            
            const resultItem = document.createElement('div');
            resultItem.className = 'result-item';
            
            const name = challengesInfo[key].name;
            
            let badge = '';
            if (result.correct) {
                badge = '<span class="result-badge detected">✓ CORRECT</span>';
            } else {
                badge = '<span class="result-badge not-detected">✗ INCORRECT</span>';
            }
            
            let submittedValue = result.submitted;
            if (submittedValue === 'Empty' || submittedValue === 'No answer provided') {
                submittedValue = '<span style="color: var(--error-primary);">Empty</span>';
            }
            
            resultItem.innerHTML = `
                <span class="result-name">${CHALLENGE_ICONS[key]} ${name}</span>
                <span class="signature-count">${submittedValue}</span>
                ${badge}
            `;
            
            resultsGrid.appendChild(resultItem);
            
            setTimeout(() => {
                resultItem.classList.add('show');
            }, 50);
            
            if (index === challengeEntries.length - 1) {
                setTimeout(() => {
                    scanButton.disabled = false;
                    scanButton.innerHTML = `
                        <svg class="scan-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"/>
                            <path d="M21 21l-4.35-4.35"/>
                        </svg>
                        Analyze Findings
                    `;
                    
                    if (data.flag) {
                        displayFlag(data.flag);
                    }
                }, 800);
            }
            
        }, index * 400);
    });
}

function displayFlag(flag) {
    const flagSection = document.getElementById('flagSection');
    const flagCode = document.getElementById('flagCode');
    const copyButton = document.getElementById('copyFlag');

    if (successSound) {
        successSound.play().catch(() => {});
    }

    flagCode.textContent = flag;
    flagSection.classList.add('visible');
    flagSection.scrollIntoView({ behavior: 'smooth', block: 'center' });

    copyButton.onclick = () => {
        const textToCopy = flagCode.textContent.trim();

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(textToCopy).then(showCopied).catch(fallbackCopy);
        } else {
            fallbackCopy();
        }

        function fallbackCopy() {
            const tempInput = document.createElement('textarea');
            tempInput.value = textToCopy;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand('copy');
            document.body.removeChild(tempInput);
            showCopied();
        }

        function showCopied() {
            const originalHTML = copyButton.innerHTML;
            copyButton.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"/>
                </svg>
            `;
            setTimeout(() => {
                copyButton.innerHTML = originalHTML;
            }, 2000);
        }
    };
}

function showError(message) {
    const errorElement = document.getElementById('errorMessage');
    errorElement.textContent = message;
    errorElement.classList.add('visible');
    
    setTimeout(() => {
        hideError();
    }, 5000);
}

function hideError() {
    const errorElement = document.getElementById('errorMessage');
    errorElement.classList.remove('visible');
}

loadChallenges();
setupFileUpload();
loadSuccessSound();