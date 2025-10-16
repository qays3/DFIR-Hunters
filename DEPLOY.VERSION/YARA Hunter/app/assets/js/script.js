const API_BASE = '/api';

const MALWARE_ICONS = {
    'wannacry': 'W',
    'emotet': 'E',
    'mirai': 'M',
    'zeus': 'Z',
    'stuxnet': 'S',
    'petya': 'P'
};

let malwareInfo = {};
let selectedFile = null;
let successSound = null;

function loadSuccessSound() {
    successSound = new Audio('assets/sounds/correct-356013.mp3');
    successSound.preload = 'auto';
}

async function loadMalwareInfo() {
    try {
        const response = await fetch(`${API_BASE}/malware-info`);
        malwareInfo = await response.json();
        renderMalwareCards();
    } catch (error) {
        showError('Failed to load malware information. Ensure the backend is running.');
    }
}

function renderMalwareCards() {
    const grid = document.getElementById('malwareGrid');
    grid.innerHTML = '';
    
    Object.entries(malwareInfo).forEach(([key, info]) => {
        const card = document.createElement('div');
        card.className = 'malware-card';
        card.id = `malware-${key}`;
        card.innerHTML = `
            <div class="malware-status">?</div>
            <div class="malware-icon">${MALWARE_ICONS[key]}</div>
            <h3 class="malware-name">${info.name}</h3>
            <div class="malware-type">${info.type}</div>
            <div class="malware-meta">
                <span class="malware-year">${info.year}</span>
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
            if (!file.name.endsWith('.yar')) {
                showError('Please upload a .yar file');
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
    
    scanButton.addEventListener('click', scanMalware);
}

async function scanMalware() {
    if (!selectedFile) return;
    
    const scanButton = document.getElementById('scanBtn');
    const originalHTML = scanButton.innerHTML;
    
    scanButton.disabled = true;
    scanButton.innerHTML = `
        <svg class="scan-icon spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
        </svg>
        Scanning...
    `;
    
    hideError();
    
    const resultsSection = document.getElementById('resultsSection');
    const flagSection = document.getElementById('flagSection');
    resultsSection.classList.remove('visible');
    flagSection.classList.remove('visible');
    
    const malwareCards = document.querySelectorAll('.malware-card');
    malwareCards.forEach(card => {
        card.classList.remove('detected', 'not-detected');
        const statusIcon = card.querySelector('.malware-status');
        statusIcon.textContent = '?';
    });
    
    const formData = new FormData();
    formData.append('file', selectedFile);
    
    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.detail || 'Scan failed');
        }
        
        displayResults(data);
        
    } catch (error) {
        showError(error.message);
        scanButton.disabled = false;
        scanButton.innerHTML = originalHTML;
    }
}

function updateMalwareCard(malware, detected) {
    const card = document.getElementById(`malware-${malware}`);
    const statusIcon = card.querySelector('.malware-status');
    
    card.classList.remove('detected', 'not-detected');
    
    if (detected) {
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
    
    const malwareEntries = Object.entries(data.results);
    let currentDetectedCount = 0;
    
    malwareEntries.forEach(([malware, detected], index) => {
        setTimeout(() => {
            updateMalwareCard(malware, detected);
            
            if (detected) {
                currentDetectedCount++;
                detectedCount.textContent = currentDetectedCount;
            }
            
            const resultItem = document.createElement('div');
            resultItem.className = 'result-item log-entry';
            
            const name = malwareInfo[malware].name;
            const signatureData = data.signature_counts[malware];
            
            const requiredSignatures = {
                'mirai': 1,
                'wannacry': 3,
                'emotet': 3,
                'petya': 3,
                'zeus': 4,
                'stuxnet': 5
            };
            
            let signatureInfo = '';
            let badge = '';
            
            if (signatureData) {
                const matched = signatureData.matched;
                const required = signatureData.required;
                signatureInfo = `<span class="signature-count">[${matched}/${required} signatures]</span>`;
                
                if (detected) {
                    badge = '<span class="result-badge detected">✓ DETECTED</span>';
                } else {
                    badge = '<span class="result-badge not-detected">✗ FAILED</span>';
                }
            } else {
                const required = requiredSignatures[malware] || 0;
                signatureInfo = `<span class="signature-count">[0/${required} signatures]</span>`;
                badge = '<span class="result-badge not-detected">✗ NO RULE</span>';
            }
            
            resultItem.innerHTML = `
                <span class="result-name">${MALWARE_ICONS[malware]} ${name}</span>
                ${signatureInfo}
                ${badge}
            `;
            
            resultsGrid.appendChild(resultItem);
            
            setTimeout(() => {
                resultItem.classList.add('show');
            }, 50);
            
            if (index === malwareEntries.length - 1) {
                setTimeout(() => {
                    scanButton.disabled = false;
                    scanButton.innerHTML = `
                        <svg class="scan-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"/>
                            <path d="M21 21l-4.35-4.35"/>
                        </svg>
                        Scan Malware
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

loadMalwareInfo();
setupFileUpload();
loadSuccessSound();