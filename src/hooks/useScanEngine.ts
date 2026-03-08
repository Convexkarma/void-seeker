import { useState, useCallback, useRef } from "react";
import { ScanConfig, ScanStatus, ScanResult } from "@/types/scan";
import { API, WS } from "@/config/backend";

interface TerminalLine {
  module: string;
  color: string;
  text: string;
}

const emptyResult: ScanResult = {
  id: "",
  domain: "",
  status: "idle",
  startedAt: "",
  progress: 0,
  findings: {
    subdomains: [],
    ports: [],
    vulnerabilities: [],
    directories: [],
    technologies: [],
    screenshots: [],
    dns: { a: [], aaaa: [], mx: [], ns: [], txt: [], cname: [], whois: { registrar: "", createdDate: "", expiryDate: "", nameServers: [] }, spf: false, dmarc: false, dkim: false },
    secrets: [],
    logs: [],
  },
};

export function useScanEngine() {
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);
  const [activeModule, setActiveModule] = useState<string>("");
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);
  const [result, setResult] = useState<ScanResult>(emptyResult);
  const [showResults, setShowResults] = useState(false);
  const scanIdRef = useRef<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const cleanup = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const fetchResults = useCallback(async (scanId: string) => {
    try {
      const res = await fetch(API.scanResults(scanId));
      if (res.ok) {
        const data = await res.json();
        // Map backend response to ScanResult shape
        setResult({
          id: data.id || scanId,
          domain: data.domain || "",
          status: data.status || "completed",
          startedAt: data.started_at || data.startedAt || "",
          completedAt: data.completed_at || data.completedAt,
          progress: data.progress || 100,
          findings: data.results || data.findings || emptyResult.findings,
        });
        setShowResults(true);
      }
    } catch (err) {
      console.error("Failed to fetch results:", err);
    }
  }, []);

  const startScan = useCallback((config: ScanConfig) => {
    if (!config.authorized) return;

    setStatus("running");
    setProgress(0);
    setTerminalLines([]);
    setShowResults(false);
    setActiveModule("");

    // Start scan via REST
    fetch(API.startScan, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domain: config.domain,
        modules: config.modules,
        profile: config.profile,
        wordlist: config.wordlist,
        threads: config.threads,
        authorized: config.authorized,
      }),
    })
      .then((res) => res.json())
      .then((data) => {
        const scanId = data.scan_id;
        scanIdRef.current = scanId;

        // Connect WebSocket for live terminal output
        const ws = new WebSocket(WS.scan(scanId));
        wsRef.current = ws;

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            // Skip non-terminal messages (ping, scan_complete, etc.)
            if (msg.type === "ping" || msg.type === "scan_complete") return;
            if (!msg.text) return;
            setTerminalLines((prev) => {
              const next = [...prev, msg];
              // Cap at 1000 lines to prevent memory/render issues
              return next.length > 1000 ? next.slice(-800) : next;
            });
            if (msg.module) {
              setActiveModule(msg.module);
            }
          } catch {
            // non-JSON message, ignore
          }
        };

        ws.onerror = () => {
          console.warn("WebSocket error — falling back to polling");
        };

        // Poll status for progress updates
        pollingRef.current = setInterval(async () => {
          try {
            const res = await fetch(API.scanStatus(scanId));
            if (res.ok) {
              const statusData = await res.json();
              setProgress(statusData.progress || 0);
              if (statusData.active_module) {
                setActiveModule(statusData.active_module);
              }

              if (statusData.status === "completed" || statusData.status === "cancelled" || statusData.status === "failed") {
                setStatus(statusData.status);
                setProgress(100);
                setActiveModule("");
                cleanup();
                await fetchResults(scanId);
              }
            }
          } catch {
            // polling error, will retry
          }
        }, 2000);
      })
      .catch((err) => {
        console.error("Failed to start scan:", err);
        setStatus("failed");
        setTerminalLines((prev) => [
          ...prev,
          { module: "System", color: "terminal-red", text: `[Error] Failed to connect to backend: ${err.message}. Is the backend running?` },
        ]);
      });
  }, [cleanup, fetchResults]);

  const cancelScan = useCallback(async () => {
    const scanId = scanIdRef.current;
    if (scanId) {
      try {
        await fetch(API.cancelScan(scanId), { method: "POST" });
      } catch {
        // best effort
      }
    }
    setStatus("cancelled");
    setActiveModule("");
    cleanup();
  }, [cleanup]);

  return { status, progress, activeModule, terminalLines, result, showResults, startScan, cancelScan, setShowResults };
}
