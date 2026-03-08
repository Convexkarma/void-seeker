import { useState } from "react";
import { TopNav } from "@/components/TopNav";
import { ScanSidebar } from "@/components/ScanSidebar";
import { ScanLauncher } from "@/components/ScanLauncher";
import { TerminalWindow } from "@/components/TerminalWindow";
import { ScanProgress } from "@/components/ScanProgress";
import { ResultsDashboard } from "@/components/ResultsDashboard";
import { SCAN_MODULES } from "@/data/scanConfig";
import { ScanModule } from "@/types/scan";
import { useScanEngine } from "@/hooks/useScanEngine";

const Index = () => {
  const [modules, setModules] = useState<ScanModule[]>(SCAN_MODULES);
  const { status, progress, activeModule, terminalLines, result, showResults, startScan, cancelScan } = useScanEngine();

  const toggleModule = (id: string) => {
    setModules(prev => prev.map(m => m.id === id ? { ...m, enabled: !m.enabled } : m));
  };

  const enabledModules = modules.filter(m => m.enabled).map(m => m.id);

  return (
    <div className="flex flex-col h-screen bg-background">
      <TopNav
        activeScans={status === "running" ? 1 : 0}
        onHistoryClick={() => {}}
        onSettingsClick={() => {}}
      />

      <div className="flex flex-1 overflow-hidden">
        <ScanSidebar modules={modules} onToggle={toggleModule} />

        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Scan launcher */}
          <ScanLauncher
            status={status}
            onLaunch={startScan}
            onCancel={cancelScan}
            enabledModules={enabledModules}
          />

          {/* Progress */}
          <ScanProgress status={status} progress={progress} activeModule={activeModule} />

          {/* Terminal */}
          <TerminalWindow lines={terminalLines} isRunning={status === "running"} />

          {/* Results */}
          {showResults && <ResultsDashboard result={result} />}
        </main>
      </div>
    </div>
  );
};

export default Index;
