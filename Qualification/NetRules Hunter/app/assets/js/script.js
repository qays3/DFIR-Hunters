const API_BASE = '/api';

const TRAFFIC_ICONS = {
    'ssh_bruteforce': 'S',
    'sql_injection': 'Q',
    'dns_tunneling': 'D',
    'cobalt_strike': 'C',
    'ransomware_c2': 'R',
    'data_exfiltration': 'E'
};

let trafficInfo = {};
let selectedFile = null;
let successSound = null;

function loadSuccessSound() {
    successSound = new Audio('assets/sounds/correct-356013.mp3');
    successSound.preload = 'auto';
}

async function loadTrafficInfo() {
    try {
        const response = await fetch(`${API_BASE}/traffic-info`);
        trafficInfo = await response.json();
        renderTrafficCards();
    } catch (error) {
        showError('Failed to load traffic information. Ensure the backend is running.');
    }
}

function renderTrafficCards() {
    const grid = document.getElementById('trafficGrid');
    grid.innerHTML = '';
    
    Object.entries(trafficInfo).forEach(([key, info]) => {
        const card = document.createElement('div');
        card.className = 'malware-card';
        card.id = `traffic-${key}`;
        card.innerHTML = `
            <div class="malware-status">?</div>
            <div class="malware-icon">${TRAFFIC_ICONS[key]}</div>
            <h3 class="malware-name">${info.name}</h3>
            <div class="malware-type">${info.type}</div>
            <div class="malware-meta">
                <span class="malware-year">${info.protocol}</span>
                <span class="malware-difficulty">${info.difficulty}</span>
            </div>
        `;
        grid.appendChild(card);
    });
}

function setupFileUpload() {
    const fileInput = document.getElementById('rulesFile');
    const fileNameDisplay = document.getElementById('fileName');
    const scanButton = document.getElementById('scanBtn');
    
    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            if (!file.name.endsWith('.rules')) {
                showError('Please upload a .rules file');
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
    
    scanButton.addEventListener('click', scanTraffic);
}

async function scanTraffic() {
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
    
    const trafficCards = document.querySelectorAll('.malware-card');
    trafficCards.forEach(card => {
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

function updateTrafficCard(traffic, detected) {
    const card = document.getElementById(`traffic-${traffic}`);
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
    
    const trafficEntries = Object.entries(data.results);
    let currentDetectedCount = 0;
    
    trafficEntries.forEach(([traffic, detected], index) => {
        setTimeout(() => {
            updateTrafficCard(traffic, detected);
            
            if (detected) {
                currentDetectedCount++;
                detectedCount.textContent = currentDetectedCount;
            }
            
            const resultItem = document.createElement('div');
            resultItem.className = 'result-item log-entry';
            
            const name = trafficInfo[traffic].name;
            const signatureData = data.signature_counts[traffic];
            
            const requiredSignatures = {
                'ssh_bruteforce': 1,
                'sql_injection': 3,
                'dns_tunneling': 3,
                'cobalt_strike': 4,
                'ransomware_c2': 5,
                'data_exfiltration': 6
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
                const required = requiredSignatures[traffic] || 0;
                signatureInfo = `<span class="signature-count">[0/${required} signatures]</span>`;
                badge = '<span class="result-badge not-detected">✗ NO RULE</span>';
            }
            
            resultItem.innerHTML = `
                <span class="result-name">${TRAFFIC_ICONS[traffic]} ${name}</span>
                ${signatureInfo}
                ${badge}
            `;
            
            resultsGrid.appendChild(resultItem);
            
            setTimeout(() => {
                resultItem.classList.add('show');
            }, 50);
            
            if (index === trafficEntries.length - 1) {
                setTimeout(() => {
                    scanButton.disabled = false;
                    scanButton.innerHTML = `
                        <svg class="scan-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"/>
                            <path d="M21 21l-4.35-4.35"/>
                        </svg>
                        Scan Traffic
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

loadTrafficInfo();
setupFileUpload();
loadSuccessSound();