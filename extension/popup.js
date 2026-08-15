document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('current-url');
    const resultCard = document.getElementById('result-card');
    const errorMsg = document.getElementById('error-message');
    const spinner = document.querySelector('.spinner');
    const btnText = document.querySelector('.btn-text');
    const statusBadge = document.getElementById('status-badge');

    let currentTabUrl = "";
    let isManualInput = false;   // 🔑 CORE FIX

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].url) {
            currentTabUrl = tabs[0].url;
            urlInput.value = tabs[0].url;
        } else {
            scanBtn.disabled = true;
        }
    });

    // Detect manual typing or paste
    urlInput.addEventListener('input', () => {
        isManualInput = true;
    });

    scanBtn.addEventListener('click', async () => {
        let urlToScan;

        // ✅ DECISION LOGIC
        if (isManualInput && urlInput.value.trim() !== "") {
            urlToScan = urlInput.value.trim();   // manual URL
        } else {
            urlToScan = currentTabUrl;           // current tab URL
        }

        console.log("Scanning URL:", urlToScan); // DEBUG (keep for now)

        if (!urlToScan || !urlToScan.startsWith('http')) {
            showError("Invalid URL. Only HTTP/HTTPS supported.");
            return;
        }

        resetUI();
        setLoading(true);

        try {
            const apiUrl = `${CONFIG.API_BASE_URL}${CONFIG.ENDPOINTS.SCAN}`;

            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlToScan })
            });

            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }

            const data = await response.json();
            displayResult(data);

        } catch (error) {
            console.error('Scan failed:', error);
            showError("Could not connect to detection server.");
        } finally {
            setLoading(false);
        }
    });

    function setLoading(isLoading) {
        scanBtn.disabled = isLoading;
        spinner.classList.toggle('hidden', !isLoading);
        btnText.textContent = isLoading ? 'Analyzing...' : 'Scan';
    }

    function resetUI() {
        resultCard.classList.add('hidden');
        errorMsg.classList.add('hidden');
        statusBadge.className = 'status-badge neutral';
        statusBadge.textContent = 'Ready';
    }

    function showError(msg) {
        errorMsg.classList.remove('hidden');
        document.getElementById('error-text').textContent = msg;
    }

    function displayResult(data) {
        resultCard.classList.remove('hidden');

        const verdictText = document.getElementById('verdict-text');
        const verdictIcon = document.getElementById('verdict-icon');
        const confidenceScore = document.getElementById('confidence-score');
        const confidenceFill = document.getElementById('confidence-fill');
        const reasonText = document.getElementById('reason-text');

        verdictText.textContent = data.verdict;
        confidenceScore.textContent = `${data.confidence}%`;
        confidenceFill.style.width = `${data.confidence}%`;

        reasonText.innerHTML = data.reasons?.length
            ? data.reasons.map(r => `• ${r}`).join('<br>')
            : "No significant threats detected.";

        statusBadge.className = 'status-badge';

        if (data.verdict === 'Safe') {
            verdictIcon.textContent = '🟢';
            statusBadge.classList.add('safe');
            statusBadge.textContent = 'Safe';
        } else if (data.verdict === 'Suspicious') {
            verdictIcon.textContent = '🟡';
            statusBadge.classList.add('warning');
            statusBadge.textContent = 'Suspicious';
        } else {
            verdictIcon.textContent = '🔴';
            statusBadge.classList.add('danger');
            statusBadge.textContent = 'Phishing';
        }
    }
});