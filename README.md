# AutoRecon — Automated Reconnaissance Platform

A web-based recon tool that orchestrates popular security scanners (subfinder, nmap, gobuster, nuclei, etc.) with a real-time terminal UI and results dashboard.

---

## Architecture

```
Frontend (React + Vite)  ←→  Backend (FastAPI + WebSocket)  ←→  OS recon tools
   :8080                        :8000
```

## Prerequisites

| Requirement | Version |
|---|---|
| **Node.js** | 18+ |
| **Python** | 3.10+ |
| **pip** | latest |

### Recon tools (install whichever you need)

```bash
# Subdomain enumeration
sudo apt install -y subfinder amass

# Port scanning
sudo apt install -y nmap

# Directory brute-forcing
sudo apt install -y gobuster

# Vulnerability scanning
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Tech fingerprinting
sudo apt install -y whatweb

# DNS
GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# HTTP probing
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Screenshots
go install github.com/sensepost/gowitness@latest

# WAF detection
pip install wafw00f

# Email harvesting
pip install theHarvester

# SSL testing
sudo apt install -y testssl.sh
```

> Tools that are not installed will be automatically skipped during scans.

---

## Quick Start

### 1. Clone the repo

```bash
git clone <YOUR_GIT_URL>
cd void-seeker
```

### 2. Start the backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`. Check `http://localhost:8000/docs` for the interactive Swagger UI.

### 3. Start the frontend

```bash
# In a new terminal, from the project root
npm install
npm run dev
```

The UI will be available at `http://localhost:8080`.

### 4. Run a scan

1. Open `http://localhost:8080` in your browser.
2. Enter a target domain (make sure you have authorization).
3. Select the modules you want to run.
4. Check the authorization box and click **Launch Scan**.
5. Watch real-time output in the terminal window.
6. View parsed results in the dashboard tabs once the scan completes.

---

## Project Structure

```
├── backend/
│   ├── main.py            # FastAPI app, REST + WebSocket endpoints
│   ├── scanner.py         # Scan orchestration, spawns OS processes
│   ├── parser.py          # Parses tool output into structured data
│   ├── db.py              # SQLite database (scan history, logs)
│   ├── report.py          # HTML/PDF/JSON/Markdown report generation
│   ├── terminal.py        # Interactive PTY WebSocket
│   └── requirements.txt   # Python dependencies
├── src/
│   ├── components/        # React UI components
│   ├── hooks/             # Custom hooks (useScanEngine, etc.)
│   ├── types/             # TypeScript type definitions
│   ├── config/            # Backend API/WS URL config
│   └── pages/             # Route pages
├── package.json
└── vite.config.ts
```

## Configuration

### Backend URL

Edit `src/config/backend.ts` to change the backend host/port if not using defaults.

### Settings

The settings page lets you configure:
- Default wordlist path
- Thread count
- Discord/Slack webhook URLs for scan notifications

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Failed to connect to backend` | Make sure the backend is running on port 8000 |
| `CORS error` | Backend allows all origins by default — check `main.py` |
| `gobuster exit code 1` | Target may return uniform responses; try a different wordlist |
| Tools showing "Not installed — skipping" | Install the missing tool and ensure it's on your `$PATH` |

---

## Tech Stack

- **Frontend:** React, Vite, TypeScript, Tailwind CSS, shadcn/ui
- **Backend:** Python, FastAPI, WebSocket, asyncio
- **Database:** SQLite (via aiosqlite)
- **Reports:** WeasyPrint (PDF), Jinja2 (HTML)
