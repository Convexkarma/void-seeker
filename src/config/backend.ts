/**
 * Backend configuration.
 * When running locally, set VITE_BACKEND_URL in .env.local to your FastAPI server.
 * Example: VITE_BACKEND_URL=http://localhost:8000
 */
export const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

export const API = {
  startScan: `${BACKEND_URL}/api/scan/start`,
  scanStatus: (id: string) => `${BACKEND_URL}/api/scan/${id}/status`,
  scanResults: (id: string) => `${BACKEND_URL}/api/scan/${id}/results`,
  cancelScan: (id: string) => `${BACKEND_URL}/api/scan/${id}/cancel`,
  history: `${BACKEND_URL}/api/scan/history`,
  deleteScan: (id: string) => `${BACKEND_URL}/api/scan/${id}`,
  toolsCheck: `${BACKEND_URL}/api/tools/check`,
  settings: `${BACKEND_URL}/api/settings`,
  report: `${BACKEND_URL}/api/report/generate`,
} as const;

export const WS = {
  scan: (id: string) => {
    const wsUrl = BACKEND_URL.replace(/^http/, "ws");
    return `${wsUrl}/ws/scan/${id}`;
  },
} as const;
