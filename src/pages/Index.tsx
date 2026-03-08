import { useState, useEffect, useCallback } from "react";
import { TopNav } from "@/components/TopNav";
import { ScanSidebar } from "@/components/ScanSidebar";
import { ScanLauncher } from "@/components/ScanLauncher";
import { TerminalWindow } from "@/components/TerminalWindow";
import { ScanProgress } from "@/components/ScanProgress";
import { ResultsDashboard } from "@/components/ResultsDashboard";
import { SettingsPage } from "@/components/SettingsPage";
import { ScanHistoryPanel } from "@/components/ScanHistoryPanel";
import { SCAN_MODULES } from "@/data/scanConfig";
import { ScanModule } from "@/types/scan";
import { useScanEngine } from "@/hooks/useScanEngine";
import { useIsMobile } from "@/hooks/use-mobile";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";

const Index = () => {
  const [modules, setModules] = useState<ScanModule[]>(SCAN_MODULES);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [view, setView] = useState<"main" | "settings" | "history">("main");
  const [terminalCollapsed, setTerminalCollapsed] = useState(false);
  const { status, progress, activeModule, terminalLines, result, showResults, startScan, cancelScan } = useScanEngine();
  const isMobile = useIsMobile();

  const toggleModule = (id: string) => {
    setModules(prev => prev.map(m => m.id === id ? { ...m, enabled: !m.enabled } : m));
  };

  const enabledModules = modules.filter(m => m.enabled).map(m => m.id);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Don't trigger when typing in inputs
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

      switch (e.key.toLowerCase()) {
        case "t":
          setTerminalCollapsed(prev => !prev);
          break;
        case "h":
          setView(prev => prev === "history" ? "main" : "history");
          break;
        case "escape":
          if (status === "running") cancelScan();
          if (view !== "main") setView("main");
          break;
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [status, cancelScan, view]);

  if (view === "settings") {
    return <SettingsPage onBack={() => setView("main")} />;
  }

  return (
    <div className="flex flex-col h-screen bg-background">
      <TopNav
        activeScans={status === "running" ? 1 : 0}
        onHistoryClick={() => setView(view === "history" ? "main" : "history")}
        onSettingsClick={() => setView("settings")}
        onModulesClick={() => setSidebarOpen(true)}
        onTerminalToggle={() => setTerminalCollapsed(prev => !prev)}
        showModulesButton={isMobile}
      />

      <div className="flex flex-1 overflow-hidden">
        {/* Desktop sidebar */}
        {!isMobile && view !== "history" && <ScanSidebar modules={modules} onToggle={toggleModule} />}

        {/* History panel (replaces sidebar) */}
        {!isMobile && view === "history" && (
          <div className="w-72 border-r border-border bg-sidebar flex-shrink-0">
            <ScanHistoryPanel onClose={() => setView("main")} onLoadScan={() => {}} />
          </div>
        )}

        {/* Mobile sidebar as sheet */}
        {isMobile && (
          <Sheet open={sidebarOpen} onOpenChange={setSidebarOpen}>
            <SheetContent side="left" className="w-72 p-0 bg-sidebar border-border">
              <SheetHeader className="px-4 pt-4 pb-0">
                <SheetTitle className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
                  Scan Modules
                </SheetTitle>
              </SheetHeader>
              <ScanSidebar modules={modules} onToggle={toggleModule} embedded />
            </SheetContent>
          </Sheet>
        )}

        <main className="flex-1 overflow-y-auto p-3 sm:p-6 space-y-4 sm:space-y-6">
          <ScanLauncher
            status={status}
            onLaunch={startScan}
            onCancel={cancelScan}
            enabledModules={enabledModules}
          />
          <ScanProgress status={status} progress={progress} activeModule={activeModule} />
          {!terminalCollapsed && (
            <TerminalWindow lines={terminalLines} isRunning={status === "running"} />
          )}
          {showResults && <ResultsDashboard result={result} />}

          {/* Keyboard shortcuts hint */}
          <div className="text-[10px] font-mono text-muted-foreground/50 text-center py-2">
            Shortcuts: <kbd className="px-1 py-0.5 bg-secondary rounded text-[9px]">T</kbd> terminal · <kbd className="px-1 py-0.5 bg-secondary rounded text-[9px]">H</kbd> history · <kbd className="px-1 py-0.5 bg-secondary rounded text-[9px]">Esc</kbd> cancel
          </div>
        </main>
      </div>
    </div>
  );
};

export default Index;
