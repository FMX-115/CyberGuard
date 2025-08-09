/**
 * CyberGuard - JavaScript Module
 * Version: 2.0
 * Author: CyberGuard Team
 * Description: All-in-one security and encryption tools
 */

// ===============================================
// Global Configuration
// ===============================================
const CONFIG = {
    // VirusTotal API Configuration
    VIRUSTOTAL_API_KEY: 'Enter_Your_VirusTotal_API_Here', // Replace with your API key
    
    // Password Generator Settings
    PASSWORD_HISTORY_MAX: 5,
    PASSWORD_MIN_LENGTH: 8,
    PASSWORD_MAX_LENGTH: 32,
    PASSWORD_DEFAULT_LENGTH: 16,
    
    // File Size Limits
    MAX_FILE_SIZE: 32 * 1024 * 1024, // 32MB
    MAX_SCAN_FILE_SIZE: 32 * 1024 * 1024, // 32MB for VirusTotal
    
    // Animation Durations
    ANIMATION_DURATION: 300,
    NOTIFICATION_DURATION: 3000,
};

// ===============================================
// Utility Functions
// ===============================================
const Utils = {
    /**
     * Show notification to user
     */
    showNotification(message, type = 'info') {
        let container = document.getElementById('notificationContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notificationContainer';
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
        
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        container.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideInDown 0.3s ease reverse';
            setTimeout(() => notification.remove(), 300);
        }, CONFIG.NOTIFICATION_DURATION);
    },
    
    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    },
    
    /**
     * Debounce function for performance
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    /**
     * Format file size
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    },
    
    /**
     * Validate URL
     */
    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    },
    
    /**
     * Copy to clipboard
     */
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            // Fallback method
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.left = "-999999px";
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                document.body.removeChild(textArea);
                return true;
            } catch (err) {
                document.body.removeChild(textArea);
                console.error('Failed to copy:', err);
                return false;
            }
        }
    }
};

// ===============================================
// Dark Mode Toggle
// ===============================================
function initDarkMode() {
    const toggle = document.querySelector('.dark-mode-toggle');
    if (!toggle) return;
    
    // Check for saved preference
    const savedMode = localStorage.getItem('darkMode');
    if (savedMode === 'true') {
        document.body.classList.add('dark-mode');
    }
    
    toggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        const isDarkMode = document.body.classList.contains('dark-mode');
        localStorage.setItem('darkMode', isDarkMode);
    });
}

// ===============================================
// Password Generator
// ===============================================
const passwordHistory = [];

function initPasswordGenerator() {
    const generateBtn = document.getElementById('generateBtn');
    const copyBtn = document.getElementById('copyBtn');
    const passwordLength = document.getElementById('passwordLength');
    const lengthValue = document.getElementById('lengthValue');
    
    if (!generateBtn || !copyBtn) return;
    
    // Update length display
    passwordLength.addEventListener('input', () => {
        lengthValue.textContent = `${passwordLength.value} characters`;
    });
    
    // Generate password
    generateBtn.addEventListener('click', generatePassword);
    
    // Copy password
    copyBtn.addEventListener('click', copyPassword);
    
    // Generate initial password
    generatePassword();
}

function generatePassword() {
    const length = parseInt(document.getElementById('passwordLength').value);
    const includeUppercase = document.getElementById('includeUppercase').checked;
    const includeLowercase = document.getElementById('includeLowercase').checked;
    const includeNumbers = document.getElementById('includeNumbers').checked;
    const includeSpecial = document.getElementById('includeSpecial').checked;
    
    if (!includeUppercase && !includeLowercase && !includeNumbers && !includeSpecial) {
        alert('Please select at least one character type');
        return;
    }
    
    const chars = {
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        numbers: '0123456789',
        special: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    };
    
    let validChars = '';
    let password = '';
    
    if (includeUppercase) {
        validChars += chars.uppercase;
        password += chars.uppercase.charAt(Math.floor(Math.random() * chars.uppercase.length));
    }
    if (includeLowercase) {
        validChars += chars.lowercase;
        password += chars.lowercase.charAt(Math.floor(Math.random() * chars.lowercase.length));
    }
    if (includeNumbers) {
        validChars += chars.numbers;
        password += chars.numbers.charAt(Math.floor(Math.random() * chars.numbers.length));
    }
    if (includeSpecial) {
        validChars += chars.special;
        password += chars.special.charAt(Math.floor(Math.random() * chars.special.length));
    }
    
    // Fill the rest randomly
    while (password.length < length) {
        password += validChars.charAt(Math.floor(Math.random() * validChars.length));
    }
    
    // Shuffle the password
    password = password.split('').sort(() => Math.random() - 0.5).join('');
    password = password.substring(0, length);
    
    document.getElementById('generatedPassword').value = password;
    addToHistory(password);
}

function addToHistory(password) {
    passwordHistory.unshift(password);
    if (passwordHistory.length > CONFIG.PASSWORD_HISTORY_MAX) {
        passwordHistory.pop();
    }
    updateHistoryDisplay();
}

function updateHistoryDisplay() {
    const historyContainer = document.getElementById('passwordHistory');
    if (!historyContainer) return;
    
    historyContainer.innerHTML = '';
    passwordHistory.forEach((pass, index) => {
        const item = document.createElement('div');
        item.className = 'history-item';
        item.innerHTML = `
            <span>${pass.replace(/./g, '•')}</span>
            <button class="btn btn-sm" data-index="${index}">Copy</button>
        `;
        const btn = item.querySelector('button');
        btn.addEventListener('click', () => copyHistoryPassword(index));
        historyContainer.appendChild(item);
    });
}

function copyHistoryPassword(index) {
    Utils.copyToClipboard(passwordHistory[index]).then(() => {
        showCopyConfirmation();
    });
}

function copyPassword() {
    const password = document.getElementById('generatedPassword').value;
    if (!password) {
        alert('No password to copy');
        return;
    }
    
    Utils.copyToClipboard(password).then(() => {
        showCopyConfirmation();
    });
}

function showCopyConfirmation() {
    const checkmark = document.querySelector('.checkmark');
    if (checkmark) {
        checkmark.classList.add('show');
        setTimeout(() => checkmark.classList.remove('show'), 2000);
    }
}

// ===============================================
// Password Strength Checker
// ===============================================
function initPasswordAnalyzer() {
    const passwordInput = document.getElementById('passwordInput');
    const togglePassword = document.getElementById('togglePassword');
    
    if (!passwordInput || !togglePassword) return;
    
    passwordInput.addEventListener('input', () => {
        checkPasswordStrength(passwordInput.value);
    });
    
    togglePassword.addEventListener('click', () => {
        const type = passwordInput.type === 'password' ? 'text' : 'password';
        passwordInput.type = type;
        togglePassword.textContent = type === 'password' ? '👁️' : '👁️‍🗨️';
    });
}

function checkPasswordStrength(password) {
    const strengthIndicator = document.getElementById('strengthIndicator');
    const strengthText = document.getElementById('strengthText');
    const entropyText = document.getElementById('entropyText');
    const strengthDetails = document.getElementById('strengthDetails');
    
    if (!strengthIndicator) return;
    
    if (!password) {
        strengthIndicator.style.width = '0%';
        strengthText.textContent = '';
        entropyText.textContent = '';
        strengthDetails.innerHTML = '';
        return;
    }
    
    let strength = 0;
    let details = [];
    
    // Length check
    if (password.length >= 12) {
        strength += 2;
        details.push('✅ Good length (12+ characters)');
    } else if (password.length >= 8) {
        strength += 1;
        details.push('⚠️ Minimum length (8+ characters)');
    } else {
        details.push('❌ Too short (less than 8 characters)');
    }
    
    // Character type checks
    if (/[A-Z]/.test(password)) {
        strength += 1;
        details.push('✅ Contains uppercase letters');
    } else {
        details.push('❌ No uppercase letters');
    }
    
    if (/[a-z]/.test(password)) {
        strength += 1;
        details.push('✅ Contains lowercase letters');
    } else {
        details.push('❌ No lowercase letters');
    }
    
    if (/[0-9]/.test(password)) {
        strength += 1;
        details.push('✅ Contains numbers');
    } else {
        details.push('❌ No numbers');
    }
    
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        strength += 1;
        details.push('✅ Contains special characters');
    } else {
        details.push('❌ No special characters');
    }
    
    // Pattern checks
    if (/(.)\1{2,}/.test(password)) {
        strength -= 1;
        details.push('❌ Contains repeated characters');
    }
    
    if (/^(?:abc|123|password|qwerty)/i.test(password)) {
        strength -= 1;
        details.push('❌ Contains common patterns');
    }
    
    // Calculate entropy
    const entropy = calculateEntropy(password);
    entropyText.textContent = `Entropy: ${entropy.toFixed(2)} bits`;
    
    // Update UI
    const percentage = Math.max(0, Math.min(100, (strength / 6) * 100));
    strengthIndicator.style.width = `${percentage}%`;
    
    if (strength <= 2) {
        strengthIndicator.style.backgroundColor = 'var(--danger-color)';
        strengthText.textContent = 'Weak Password';
    } else if (strength <= 4) {
        strengthIndicator.style.backgroundColor = 'var(--warning-color)';
        strengthText.textContent = 'Medium Password';
    } else {
        strengthIndicator.style.backgroundColor = 'var(--secondary-color)';
        strengthText.textContent = 'Strong Password';
    }
    
    strengthDetails.innerHTML = details.map(detail => `<div>${detail}</div>`).join('');
}

function calculateEntropy(password) {
    let possibleChars = 0;
    if (/[a-z]/.test(password)) possibleChars += 26;
    if (/[A-Z]/.test(password)) possibleChars += 26;
    if (/[0-9]/.test(password)) possibleChars += 10;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) possibleChars += 32;
    
    return Math.log2(Math.pow(possibleChars, password.length));
}

// ===============================================
// Text Encryption
// ===============================================
function initTextEncryption() {
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    
    if (!encryptBtn || !decryptBtn) return;
    
    encryptBtn.addEventListener('click', encryptText);
    decryptBtn.addEventListener('click', decryptText);
}

function encryptText() {
    const text = document.getElementById('encryptInput').value;
    const method = document.getElementById('encryptionMethod').value;
    const key = document.getElementById('encryptKey').value;
    
    if (!text) {
        alert('Please enter text to encrypt');
        return;
    }
    
    try {
        let result;
        if (method === 'aes') {
            if (!key) {
                alert('Please enter an encryption key for AES');
                return;
            }
            result = CryptoJS.AES.encrypt(text, key).toString();
        } else {
            result = btoa(text);
        }
        document.getElementById('encryptOutput').value = result;
    } catch (error) {
        alert('Encryption failed: ' + error.message);
    }
}

function decryptText() {
    const text = document.getElementById('encryptOutput').value || document.getElementById('encryptInput').value;
    const method = document.getElementById('encryptionMethod').value;
    const key = document.getElementById('encryptKey').value;
    
    if (!text) {
        alert('Please enter text to decrypt');
        return;
    }
    
    try {
        let result;
        if (method === 'aes') {
            if (!key) {
                alert('Please enter the decryption key for AES');
                return;
            }
            const bytes = CryptoJS.AES.decrypt(text, key);
            result = bytes.toString(CryptoJS.enc.Utf8);
            if (!result) throw new Error('Invalid key or corrupted data');
        } else {
            result = atob(text);
        }
        document.getElementById('encryptOutput').value = result;
    } catch (error) {
        alert('Decryption failed: ' + error.message);
    }
}

// ===============================================
// Hash Generator
// ===============================================
function initHashGenerator() {
    const computeHashBtn = document.getElementById('computeHashBtn');
    if (!computeHashBtn) return;
    
    computeHashBtn.addEventListener('click', computeHash);
}

function computeHash() {
    const text = document.getElementById('hashInput').value;
    const algorithm = document.getElementById('hashAlgorithm').value;
    
    if (!text) {
        alert('Please enter text to hash');
        return;
    }
    
    try {
        let hash;
        switch (algorithm) {
            case 'SHA-256':
                hash = CryptoJS.SHA256(text);
                break;
            case 'SHA-512':
                hash = CryptoJS.SHA512(text);
                break;
            case 'MD5':
                hash = CryptoJS.MD5(text);
                break;
            case 'SHA-1':
                hash = CryptoJS.SHA1(text);
                break;
            default:
                throw new Error('Unsupported hash algorithm');
        }
        document.getElementById('hashOutput').value = hash.toString();
    } catch (error) {
        alert('Hash generation failed: ' + error.message);
    }
}

// ===============================================
// File Encryption
// ===============================================
function initFileEncryption() {
    const encryptFileBtn = document.getElementById('encryptFileBtn');
    const decryptFileBtn = document.getElementById('decryptFileBtn');
    
    if (!encryptFileBtn || !decryptFileBtn) return;
    
    encryptFileBtn.addEventListener('click', encryptFile);
    decryptFileBtn.addEventListener('click', decryptFile);
}

function showFileStatus(message, isError = false) {
    const status = document.getElementById('fileStatus');
    if (!status) return;
    
    status.textContent = message;
    status.style.display = 'block';
    status.className = `status ${isError ? 'error' : 'success'} fade-in`;
    setTimeout(() => status.style.display = 'none', 5000);
}

function downloadFile(content, fileName, contentType) {
    const a = document.createElement('a');
    const file = new Blob([content], { type: contentType });
    a.href = URL.createObjectURL(file);
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(a.href);
}

function encryptFile() {
    const fileInput = document.getElementById('file');
    const passwordInput = document.getElementById('filePassword');
    
    if (!fileInput.files.length || !passwordInput.value) {
        showFileStatus('Please select a file and enter a password', true);
        return;
    }
    
    const file = fileInput.files[0];
    const reader = new FileReader();
    
    reader.onload = function(e) {
        try {
            const wordArray = CryptoJS.lib.WordArray.create(e.target.result);
            const encrypted = CryptoJS.AES.encrypt(wordArray, passwordInput.value).toString();
            downloadFile(encrypted, file.name + '.encrypted', 'application/octet-stream');
            showFileStatus('File encrypted successfully!');
        } catch (error) {
            showFileStatus('Encryption failed: ' + error.message, true);
        }
    };
    
    reader.readAsArrayBuffer(file);
}

function decryptFile() {
    const fileInput = document.getElementById('file');
    const passwordInput = document.getElementById('filePassword');
    
    if (!fileInput.files.length || !passwordInput.value) {
        showFileStatus('Please select a file and enter a password', true);
        return;
    }
    
    const file = fileInput.files[0];
    const reader = new FileReader();
    
    reader.onload = function(e) {
        try {
            const decrypted = CryptoJS.AES.decrypt(e.target.result, passwordInput.value);
            const typedArray = convertWordArrayToUint8Array(decrypted);
            const fileName = file.name.replace('.encrypted', '');
            downloadFile(typedArray, 'decrypted_' + fileName, 'application/octet-stream');
            showFileStatus('File decrypted successfully!');
        } catch (error) {
            showFileStatus('Decryption failed: Invalid password or corrupted file', true);
        }
    };
    
    reader.readAsText(file);
}

function convertWordArrayToUint8Array(wordArray) {
    const len = wordArray.words.length;
    const u8Array = new Uint8Array(len << 2);
    let offset = 0;
    let word;
    
    for (let i = 0; i < len; i++) {
        word = wordArray.words[i];
        u8Array[offset++] = word >> 24;
        u8Array[offset++] = (word >> 16) & 0xff;
        u8Array[offset++] = (word >> 8) & 0xff;
        u8Array[offset++] = word & 0xff;
    }
    
    return u8Array.slice(0, wordArray.sigBytes);
}

// ===============================================
// File Integrity Checker
// ===============================================
function initFileIntegrityChecker() {
    const computeFileHashBtn = document.getElementById('computeFileHashBtn');
    if (!computeFileHashBtn) return;
    
    computeFileHashBtn.addEventListener('click', computeFileHash);
}

function computeFileHash() {
    const fileInput = document.getElementById('integrityFile');
    const algorithm = document.getElementById('hashAlgorithmSelect').value;
    const outputArea = document.getElementById('integrityOutput');
    
    if (!fileInput.files.length) {
        alert('Please select a file');
        return;
    }
    
    const file = fileInput.files[0];
    const reader = new FileReader();
    
    reader.onload = function(e) {
        try {
            const wordArray = CryptoJS.lib.WordArray.create(e.target.result);
            let hash;
            
            switch (algorithm) {
                case 'MD5':
                    hash = CryptoJS.MD5(wordArray).toString();
                    break;
                case 'SHA-256':
                    hash = CryptoJS.SHA256(wordArray).toString();
                    break;
                case 'SHA-512':
                    hash = CryptoJS.SHA512(wordArray).toString();
                    break;
                default:
                    throw new Error('Unsupported algorithm');
            }
            
            outputArea.value = hash;
        } catch (err) {
            alert('Error computing hash: ' + err.message);
        }
    };
    
    reader.readAsArrayBuffer(file);
}

// ===============================================
// URL and File Scanner
// ===============================================
function initThreatScanner() {
    const tabs = document.querySelectorAll('#threatScannerCard .tab');
    const scanUrlBtn = document.getElementById('scanUrlBtn');
    const scanFileBtn = document.getElementById('scanFileBtn');
    
    if (!tabs.length) return;
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            const urlScan = document.getElementById('urlScan');
            const fileScan = document.getElementById('fileScan');
            
            if (tab.dataset.tab === 'url') {
                urlScan.style.display = 'block';
                fileScan.style.display = 'none';
            } else {
                urlScan.style.display = 'none';
                fileScan.style.display = 'block';
            }
        });
    });
    
    if (scanUrlBtn) scanUrlBtn.addEventListener('click', scanUrl);
    if (scanFileBtn) scanFileBtn.addEventListener('click', scanFile);
}

async function scanUrl() {
    const url = document.getElementById('urlInput').value.trim();
    const loader = document.querySelector('#threatScannerCard .loader');
    const urlError = document.getElementById('urlError');
    
    if (!url) {
        showError(urlError, 'Please enter a URL');
        return;
    }
    
    if (!Utils.isValidUrl(url)) {
        showError(urlError, 'Please enter a valid URL');
        return;
    }
    
    hideError(urlError);
    showLoader(loader);
    
    try {
        const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                'x-apikey': CONFIG.VIRUSTOTAL_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${encodeURIComponent(url)}`
        });
        
        if (!submitResponse.ok) throw new Error(`HTTP error! status: ${submitResponse.status}`);
        
        const submitData = await submitResponse.json();
        const analysisId = submitData.data.id;
        
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { 'x-apikey': CONFIG.VIRUSTOTAL_API_KEY }
        });
        
        if (!analysisResponse.ok) throw new Error(`HTTP error! status: ${analysisResponse.status}`);
        
        const analysisData = await analysisResponse.json();
        const stats = analysisData.data.attributes.stats;
        
        document.getElementById('maliciousCount').textContent = stats.malicious || 0;
        document.getElementById('cleanCount').textContent = stats.harmless || 0;
        document.getElementById('suspiciousCount').textContent = stats.suspicious || 0;
    } catch (error) {
        showError(urlError, `Scan failed: ${error.message}`);
    } finally {
        hideLoader(loader);
    }
}

async function scanFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    const loader = document.querySelector('#threatScannerCard .loader');
    const fileError = document.getElementById('fileError');
    
    if (!file) {
        showError(fileError, 'Please select a file');
        return;
    }
    
    if (file.size > CONFIG.MAX_SCAN_FILE_SIZE) {
        showError(fileError, `File size must be less than ${Utils.formatFileSize(CONFIG.MAX_SCAN_FILE_SIZE)}`);
        return;
    }
    
    hideError(fileError);
    showLoader(loader);
    
    try {
        // Similar implementation to scanUrl but for files
        // Note: VirusTotal file scanning requires API key
        alert('File scanning requires a valid VirusTotal API key');
    } catch (error) {
        showError(fileError, `Scan failed: ${error.message}`);
    } finally {
        hideLoader(loader);
    }
}

function showLoader(loader) {
    if (loader) loader.classList.add('show');
}

function hideLoader(loader) {
    if (loader) loader.classList.remove('show');
}

function showError(element, message) {
    if (element) {
        element.textContent = message;
        element.classList.add('show');
    }
}

function hideError(element) {
    if (element) {
        element.classList.remove('show');
        element.textContent = '';
    }
}

// ===============================================
// Steganography
// ===============================================
let currentStegImage = null;

function initSteganography() {
    const encodeBtn = document.getElementById('encodeBtn');
    const decodeBtn = document.getElementById('decodeBtn');
    
    if (!encodeBtn || !decodeBtn) return;
    
    setupDropZone('stegDropZone', 'stegFileInput', 'stegPreview', 'encodeBtn');
    setupDropZone('decodeDropZone', 'stegDecodeFileInput', 'decodePreview', 'decodeBtn');
    
    encodeBtn.addEventListener('click', encodeMessage);
    decodeBtn.addEventListener('click', decodeMessage);
}

function setupDropZone(dropZoneId, inputId, previewId, btnId) {
    const dropZone = document.getElementById(dropZoneId);
    const input = document.getElementById(inputId);
    const preview = document.getElementById(previewId);
    const btn = document.getElementById(btnId);
    
    if (!dropZone || !input) return;
    
    dropZone.addEventListener('click', () => input.click());
    
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) {
            handleStegImageUpload(file, preview, btn);
        }
    });
    
    input.addEventListener('change', () => {
        if (input.files[0]) {
            handleStegImageUpload(input.files[0], preview, btn);
        }
    });
}

function handleStegImageUpload(file, preview, btn) {
    const reader = new FileReader();
    reader.onload = (e) => {
        if (preview) {
            preview.src = e.target.result;
            preview.style.display = 'block';
        }
        if (btn) btn.disabled = false;
        currentStegImage = e.target.result;
    };
    reader.readAsDataURL(file);
}

function encodeMessage() {
    const message = document.getElementById('stegMessage').value;
    if (!message || !currentStegImage) {
        alert('Please enter a message and select an image');
        return;
    }
    
    const img = new Image();
    img.onload = () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const encodedData = encodeDataInImage(imageData.data, message);
        ctx.putImageData(new ImageData(encodedData, canvas.width, canvas.height), 0, 0);
        
        // Show download button
        const stegDownload = document.getElementById('stegDownload');
        const downloadBtn = document.getElementById('downloadBtn');
        
        if (stegDownload) stegDownload.style.display = 'block';
        if (downloadBtn) {
            downloadBtn.onclick = () => {
                const link = document.createElement('a');
                link.download = 'encoded_image.png';
                link.href = canvas.toDataURL();
                link.click();
            };
        }
    };
    img.src = currentStegImage;
}

function decodeMessage() {
    if (!currentStegImage) {
        alert('Please select an image to decode');
        return;
    }
    
    const img = new Image();
    img.onload = () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const message = decodeDataFromImage(imageData.data);
        
        const decodeResult = document.getElementById('decodeResult');
        const decodedMessage = document.getElementById('decodedMessage');
        
        if (decodeResult) decodeResult.style.display = 'block';
        if (decodedMessage) decodedMessage.value = message;
    };
    img.src = currentStegImage;
}

function encodeDataInImage(imageData, message) {
    const binaryMessage = textToBinary(message + '|END|');
    let binaryIndex = 0;
    
    const newData = new Uint8ClampedArray(imageData);
    for (let i = 0; i < newData.length; i += 4) {
        if (binaryIndex < binaryMessage.length) {
            newData[i] = (newData[i] & 254) | parseInt(binaryMessage[binaryIndex]);
            binaryIndex++;
        }
    }
    
    return newData;
}

function decodeDataFromImage(imageData) {
    let binaryMessage = '';
    for (let i = 0; i < imageData.length; i += 4) {
        binaryMessage += imageData[i] & 1;
    }
    
    const message = binaryToText(binaryMessage);
    const endIndex = message.indexOf('|END|');
    return endIndex !== -1 ? message.substring(0, endIndex) : message;
}

function textToBinary(text) {
    return text.split('').map(char => 
        char.charCodeAt(0).toString(2).padStart(8, '0')
    ).join('');
}

function binaryToText(binary) {
    const bytes = binary.match(/.{1,8}/g) || [];
    return bytes.map(byte => 
        String.fromCharCode(parseInt(byte, 2))
    ).join('');
}

// ===============================================
// QR Code Generator
// ===============================================
function initQRCodeGenerator() {
    const qrEncryptToggle = document.getElementById('qrEncryptToggle');
    const generateQRBtn = document.getElementById('generateQRBtn');
    const qrDownloadBtn = document.getElementById('qrDownloadBtn');
    
    if (!generateQRBtn) return;
    
    if (qrEncryptToggle) {
        qrEncryptToggle.addEventListener('change', function() {
            const qrPasswordInput = document.getElementById('qrPasswordInput');
            if (qrPasswordInput) {
                qrPasswordInput.style.display = this.checked ? 'block' : 'none';
            }
        });
    }
    
    generateQRBtn.addEventListener('click', generateQR);
    if (qrDownloadBtn) qrDownloadBtn.addEventListener('click', downloadQR);
}

function generateQR() {
    const text = document.getElementById('qrText').value;
    const container = document.getElementById('qrcode');
    const downloadBtn = document.getElementById('qrDownloadBtn');
    
    if (!text) {
        alert('Please enter text or URL');
        return;
    }
    
    container.innerHTML = '';
    if (downloadBtn) downloadBtn.style.display = 'none';
    
    let finalContent = text;
    const qrEncryptToggle = document.getElementById('qrEncryptToggle');
    if (qrEncryptToggle && qrEncryptToggle.checked) {
        const password = document.getElementById('qrPassword').value;
        if (!password) {
            alert('Please enter encryption password');
            return;
        }
        finalContent = CryptoJS.AES.encrypt(text, password).toString();
    }
    
    new QRCode(container, {
        text: finalContent,
        width: 200,
        height: 200,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.H
    });
    
    if (downloadBtn) downloadBtn.style.display = 'block';
}

function downloadQR() {
    const canvas = document.querySelector('#qrcode canvas');
    if (!canvas) {
        alert('No QR code to download');
        return;
    }
    
    const url = canvas.toDataURL('image/png');
    const a = document.createElement('a');
    a.download = 'cyberguard-qrcode.png';
    a.href = url;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// ===============================================
// Base Converter
// ===============================================
function initBaseConverter() {
    const convertBaseBtn = document.getElementById('convertBaseBtn');
    if (!convertBaseBtn) return;
    
    convertBaseBtn.addEventListener('click', convertBase);
}

function convertBase() {
    const input = document.getElementById('baseInput').value.trim();
    const direction = document.getElementById('conversionDirection').value;
    const conversionType = document.getElementById('conversionType').value;
    let result = '';
    
    if (!input) {
        alert('Please enter some text or code');
        return;
    }
    
    try {
        if (direction === 'encode') {
            for (let i = 0; i < input.length; i++) {
                const code = input.charCodeAt(i);
                if (conversionType === 'binary') {
                    result += code.toString(2).padStart(8, '0') + ' ';
                } else if (conversionType === 'hex') {
                    result += code.toString(16).padStart(2, '0') + ' ';
                } else if (conversionType === 'decimal') {
                    result += code + ' ';
                }
            }
        } else if (direction === 'decode') {
            const tokens = input.split(/\s+/);
            tokens.forEach(token => {
                if (!token) return;
                let charCode;
                if (conversionType === 'binary') {
                    charCode = parseInt(token, 2);
                } else if (conversionType === 'hex') {
                    charCode = parseInt(token, 16);
                } else if (conversionType === 'decimal') {
                    charCode = parseInt(token, 10);
                }
                if (!isNaN(charCode)) {
                    result += String.fromCharCode(charCode);
                }
            });
        }
        
        document.getElementById('baseOutput').value = result.trim();
    } catch (error) {
        alert('Conversion failed: ' + error.message);
    }
}

// ===============================================
// Text Diff Checker
// ===============================================
function initTextDiffChecker() {
    const compareTextBtn = document.getElementById('compareTextBtn');
    if (!compareTextBtn) return;
    
    compareTextBtn.addEventListener('click', compareText);
}

function compareText() {
    const text1 = document.getElementById('diffInput1').value;
    const text2 = document.getElementById('diffInput2').value;
    
    if (!text1 || !text2) {
        alert('Please enter text in both fields');
        return;
    }
    
    try {
        // Use jsdiff if available, otherwise do simple comparison
        if (typeof Diff !== 'undefined') {
            const diff = Diff.diffWords(text1, text2);
            
            let resultHtml = '';
            diff.forEach(part => {
                if (part.added) {
                    resultHtml += `<span style="background-color: #2ecc71; color: white; padding: 2px 4px; border-radius: 3px;">${Utils.escapeHtml(part.value)}</span>`;
                } else if (part.removed) {
                    resultHtml += `<span style="background-color: #e74c3c; color: white; padding: 2px 4px; border-radius: 3px;">${Utils.escapeHtml(part.value)}</span>`;
                } else {
                    resultHtml += `<span>${Utils.escapeHtml(part.value)}</span>`;
                }
            });
            
            document.getElementById('diffOutput').innerHTML = resultHtml;
        } else {
            // Fallback simple comparison
            document.getElementById('diffOutput').innerHTML = 'Diff library not loaded. Showing simple comparison:<br><br>' +
                '<strong>Text 1:</strong><br>' + Utils.escapeHtml(text1) + '<br><br>' +
                '<strong>Text 2:</strong><br>' + Utils.escapeHtml(text2);
        }
    } catch (error) {
        alert('Comparison failed: ' + error.message);
    }
}

// ===============================================
// Initialize Everything
// ===============================================
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing CyberGuard...');
    
    // Initialize all modules
    initDarkMode();
    initPasswordGenerator();
    initPasswordAnalyzer();
    initTextEncryption();
    initHashGenerator();
    initFileEncryption();
    initFileIntegrityChecker();
    initThreatScanner();
    initSteganography();
    initQRCodeGenerator();
    initBaseConverter();
    initTextDiffChecker();
    
    console.log('CyberGuard initialized successfully!');
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Generate password with Ctrl+G
        if (e.ctrlKey && e.key === 'g') {
            e.preventDefault();
            generatePassword();
        }
        
        // Toggle dark mode with Ctrl+D
        if (e.ctrlKey && e.key === 'd') {
            e.preventDefault();
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        }
        
        // Show help with Ctrl+H
        if (e.ctrlKey && e.key === 'h') {
            e.preventDefault();
            alert(`Keyboard Shortcuts:
• Ctrl+G: Generate new password
• Ctrl+D: Toggle dark mode
• Ctrl+H: Show this help
• Escape: Clear current input`);
        }
        
        // Clear active input with Escape
        if (e.key === 'Escape') {
            const activeElement = document.activeElement;
            if (activeElement && (activeElement.tagName === 'INPUT' || activeElement.tagName === 'TEXTAREA')) {
                activeElement.value = '';
            }
        }
    });
});
