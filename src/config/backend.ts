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
  health: `${BACKEND_URL}/api/health`,
} as const;

export const WS = {
  scan: (id: string) => {
    const wsUrl = BACKEND_URL.replace(/^http/, "ws");
    return `${wsUrl}/ws/scan/${id}`;
  },
  terminal: (sessionId: string) => {
    const wsUrl = BACKEND_URL.replace(/^http/, "ws");
    return `${wsUrl}/ws/terminal/${sessionId}`;
  },
} as const;

/**
 * Map frontend module IDs (from scanConfig.ts) to backend tool names.
 * The backend expects individual tool names, not grouped module IDs.
 */
export const MODULE_ID_TO_BACKEND: Record<string, string[]> = {
  subdomain:  ["subfinder", "amass"],
  portscan:   ["nmap"],
  techfp:     ["whatweb"],
  dirbrute:   ["gobuster"],
  vulnscan:   ["nuclei"],
  screenshot: ["gowitness"],
  waf:        ["wafw00f"],
  dns:        ["dnsx", "dig", "whois"],
  email:      ["theHarvester"],
  ssl:        ["testssl"],
  // These don't have backend tools yet
  asn:        [],
  github:     [],
  jsanalysis: [],
  cloud:      [],
};

/**
 * Convert frontend module IDs to flat list of backend tool names.
 */
export function mapModulesToBackend(moduleIds: string[]): string[] {
  const tools: string[] = [];
  for (const id of moduleIds) {
    const mapped = MODULE_ID_TO_BACKEND[id];
    if (mapped) {
      tools.push(...mapped);
    }
  }
  // Always include httpx and curl_headers for enrichment
  if (tools.includes("subfinder") || tools.includes("amass")) {
    if (!tools.includes("httpx")) tools.push("httpx");
  }
  if (!tools.includes("curl_headers")) tools.push("curl_headers");
  return tools;
}
