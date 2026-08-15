// config.js
// Central configuration for PhishGuard Chrome Extension

const CONFIG = {
    // Local backend (FastAPI)
    // NOTE: Use 127.0.0.1 for Chrome extensions (more reliable than localhost)
    API_BASE_URL: "http://127.0.0.1:8000",

    ENDPOINTS: {
        SCAN: "/api/v1/scan"
    }
};

// Helper function to build full API URL
function getApiUrl(endpoint) {
    return `${CONFIG.API_BASE_URL}${endpoint}`;
}