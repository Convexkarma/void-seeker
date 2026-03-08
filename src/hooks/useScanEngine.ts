import { useState, useCallback, useRef } from "react";
import { ScanConfig, ScanStatus, ScanResult } from "@/types/scan";
import { API, WS, mapModulesToBackend } from "@/config/backend";
import { mapBackendResults, emptyFindings } from "@/lib/resultMapper";

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
  findings: emptyFindings,
};

/** Map backend WS message types to terminal-friendly color/text */
function wsMessageToTerminalLine(msg: any): TerminalLine | null {
  if (msg.type === "ping" || !msg.type) return null;

  switch (msg.type) {
    case "started":
      return { module: "System", color: "terminal-cyan", text: `AutoRecon v2.0 — Target: ${msg.domain} | Modules: ${msg.total_modules}` };
    case "module_start":
      return { module: msg.module || "System", color: "terminal-blue", text: `[${msg.module}] Starting (${msg.index}/${msg.total})...` };
    case "command":
      return { module: msg.module || "System", color: "terminal-blue", text: `[${msg.module}] $ ${msg.command}` };
    case "output":
      return { module: msg.module || "System", color: "terminal-green", text: `[${msg.module}] ${msg.line}` };
    case "module_skip":
      return { module: msg.module || "System", color: "terminal-amber", text: `[${msg.module}] ⚠ Skipped: ${msg.reason}` };
    case "module_complete":
      return { module: msg.module || "System", color: "terminal-green", text: `[${msg.module}] ✓ Complete (${msg.lines || 0} lines)` };
    case "module_error":
      return { module: msg.module || "System", color: "terminal-red", text: `[${msg.module}] ✗ Error: ${msg.error}` };
    case "scan_complete":
      return { module: "System", color: "terminal-cyan", text: `[✓] Scan ${msg.status} in ${msg.duration || 0}s` };
    case "cancelled":
      return { module: "System", color: "terminal-red", text: `[✗] Scan cancelled` };
    default:
      // Fallback: if it has text/line, show it
      if (msg.text) return { module: msg.module || "System", color: msg.color || "terminal-green", text: msg.text };
      if (msg.line) return { module: msg.module || "System", color: "terminal-green", text: `[${msg.module || ""}] ${msg.line}` };
      return null;
  }
}

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
      try { wsRef.current.close(); } catch {}
      wsRef.current = null;
    }
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const addLine = useCallback((line: TerminalLine) => {
    setTerminalLines((prev) => {
      const next = [...prev, line];
      return next.length > 1000 ? next.slice(-800) : next;
    });
  }, []);

  const fetchResults = useCallback(async (scanId: string) => {
    try {
      const res = await fetch(API.scanResults(scanId));
      if (res.ok) {
        const data = await res.json();
        const findings = mapBackendResults(data.results || data.findings);
        setResult({
          id: data.id || scanId,
          domain: data.domain || "",
          status: data.status || "completed",
          startedAt: data.started_at || data.startedAt || data.created_at || "",
          completedAt: data.completed_at || data.completedAt,
          progress: data.progress || 100,
          findings,
        });
        setShowResults(true);
      }
    } catch (err) {
      console.error("Failed to fetch results:", err);
    }
  }, []);

  const startScan = useCallback(async (config: ScanConfig) => {
    if (!config.authorized) return;

    setStatus("running");
    setProgress(0);
    setTerminalLines([]);
    setShowResults(false);
    setActiveModule("");

    // Map frontend module IDs to backend tool names
    const backendModules = mapModulesToBackend(config.modules);

    let scanId: string;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);

      const res = await fetch(API.startScan, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: config.domain,
          modules: backendModules,
          wordlist: config.wordlist,
          threads: config.threads,
        }),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!res.ok) {
        const errText = await res.text().catch(() => "Unknown error");
        throw new Error(`Backend returned ${res.status}: ${errText}`);
      }

      const data = await res.json();
      scanId = data.scan_id;
      if (!scanId) throw new Error("No scan_id in response");
      scanIdRef.current = scanId;
    } catch (err: any) {
      console.error("Failed to start scan:", err);
      setStatus("failed");
      const msg = err.name === "AbortError"
        ? "Connection timed out. Is the backend running?"
        : `Failed to connect to backend: ${err.message}. Is the backend running?`;
      addLine({
        module: "System",
        color: "terminal-red",
        text: `[Error] ${msg}`,
      });
      return;
    }

    // Connect WebSocket for live terminal output
    try {
      const ws = new WebSocket(WS.scan(scanId));
      wsRef.current = ws;

      // Close WS if it doesn't connect within 5s
      const wsTimeout = setTimeout(() => {
        if (ws.readyState !== WebSocket.OPEN) {
          try { ws.close(); } catch {}
          wsRef.current = null;
        }
      }, 5000);

      ws.onopen = () => clearTimeout(wsTimeout);

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          const line = wsMessageToTerminalLine(msg);
          if (line) {
            addLine(line);
            if (msg.module) setActiveModule(msg.module);
          }
        } catch {
          // non-JSON message, ignore
        }
      };

      ws.onerror = () => {
        clearTimeout(wsTimeout);
        console.warn("WebSocket error — falling back to polling only");
      };

      ws.onclose = () => {
        clearTimeout(wsTimeout);
        wsRef.current = null;
      };
    } catch (wsErr) {
      console.warn("WebSocket connection failed:", wsErr);
    }

    // Poll status for progress updates
    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetch(API.scanStatus(scanId));
        if (res.ok) {
          const statusData = await res.json();
          setProgress(statusData.progress || 0);
          const mod = statusData.active_module || statusData.current_module;
          if (mod) setActiveModule(mod);

          if (statusData.status === "completed" || statusData.status === "cancelled" || statusData.status === "failed") {
            setStatus(statusData.status as ScanStatus);
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
  }, [cleanup, fetchResults, addLine]);

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
