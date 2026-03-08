import { useState, useCallback } from "react";
import { ScanConfig, ScanStatus } from "@/types/scan";
import { mockScanResult, mockTerminalLines } from "@/data/mockData";

export function useScanEngine() {
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);
  const [activeModule, setActiveModule] = useState<string>("");
  const [terminalLines, setTerminalLines] = useState<typeof mockTerminalLines>([]);
  const [result, setResult] = useState(mockScanResult);
  const [showResults, setShowResults] = useState(false);

  const startScan = useCallback((config: ScanConfig) => {
    if (!config.authorized) return;
    
    setStatus("running");
    setProgress(0);
    setTerminalLines([]);
    setShowResults(false);

    // Simulate scan with progressive terminal output
    let lineIndex = 0;
    const totalLines = mockTerminalLines.length;

    const interval = setInterval(() => {
      if (lineIndex >= totalLines) {
        clearInterval(interval);
        setStatus("completed");
        setProgress(100);
        setActiveModule("");
        setResult({ ...mockScanResult, domain: config.domain });
        setShowResults(true);
        return;
      }

      const line = mockTerminalLines[lineIndex];
      setTerminalLines(prev => [...prev, line]);
      setProgress(Math.round(((lineIndex + 1) / totalLines) * 100));
      setActiveModule(line.module);
      lineIndex++;
    }, 400);

    return () => clearInterval(interval);
  }, []);

  const cancelScan = useCallback(() => {
    setStatus("cancelled");
    setActiveModule("");
  }, []);

  return { status, progress, activeModule, terminalLines, result, showResults, startScan, cancelScan, setShowResults };
}
