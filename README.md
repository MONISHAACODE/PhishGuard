# PhishGuard - Phishing Detection System

## 📌 Project Overview
PhishGuard is a browser-based phishing detection system designed to identify malicious URLs in real-time. It consists of a **Chrome Extension (Manifest V3)** for the frontend and a **Python FastAPI Backend** for the detection logic.

## 📂 Project Structure
```
/
├── backend/                  # Python FastAPI Server
│   ├── app/
│   │   ├── api/              # API Routes
│   │   ├── core/             # Configuration
│   │   ├── engine/           # Detection Logic (Heuristics)
│   │   ├── models/           # Data Models
│   │   └── main.py           # Entry Point
│   ├── requirements.txt      # Dependencies
│   └── Dockerfile            # Deployment Config
│
├── extension/                # Chrome Extension
│   ├── manifest.json         # V3 Configuration
│   ├── popup.html            # UI Layout
│   ├── popup.js              # Client Logic
│   ├── config.js             # API Configuration
│   └── styles.css            # Styling
```

## 🚀 Setup Instructions

### 1. Backend Setup (Python)
The backend performs the actual URL analysis.

1. Navigate to the backend folder:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the server:
   ```bash
  python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
   *Server will run at `http://localhost:8000`*

### 2. Chrome Extension Setup
The extension captures the browser URL and sends it to the backend.

1. Open Google Chrome and go to `chrome://extensions`.
2. Enable **Developer Mode** (toggle in top-right).
3. Click **Load Unpacked**.
4. Select the `/extension` folder from this project.
5. The PhishGuard shield icon will appear in your toolbar.

## 🧪 Testing the System

### Test Cases

| URL Type | Example URL | Expected Verdict |
| :--- | :--- | :--- |
| **Safe** | `https://google.com` | 🟢 Safe |
| **Safe** | `https://github.com/login` | 🟢 Safe (Allowlisted) |
| **Phishing** | `http://192.168.1.5/login` | 🔴 Phishing (IP Usage) |
| **Phishing** | `https://secure-bank-login-update.xyz` | 🔴 Phishing (Keywords + TLD) |
| **Suspicious** | `https://example.com//admin` | 🟡 Suspicious (Double Slash) |
| **Suspicious** | `https://very-long-url...` (>75 chars) | 🟡 Suspicious (Length) |

## 🌍 Deployment Guide

### Backend Deployment (Render/Railway)
1. Push this repository to GitHub.
2. Create a new Web Service on Render/Railway.
3. Point to the `/backend` directory.
4. **Build Command**: `pip install -r requirements.txt`
5. **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
6. Copy the provided URL (e.g., `https://phishguard.onrender.com`).

### Extension Configuration
1. Open `extension/config.js`.
2. Update `API_BASE_URL` with your deployed backend URL.
3. Reload the extension in Chrome.

## 🛡️ Security Features
- **Manifest V3**: Compliant with latest Chrome security standards.
- **Minimal Permissions**: Uses `activeTab` to respect user privacy.
- **Input Validation**: Backend strictly validates URLs before processing.
- **CORS**: Configured to allow extension communication.
