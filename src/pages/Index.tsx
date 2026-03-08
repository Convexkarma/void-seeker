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
import { useIsMobile } from "@/hooks/use-mobile";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";

const Index = () => {
  const [modules, setModules] = useState<ScanModule[]>(SCAN_MODULES);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { status, progress, activeModule, terminalLines, result, showResults, startScan, cancelScan } = useScanEngine();
  const isMobile = useIsMobile();

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
        onModulesClick={() => setSidebarOpen(true)}
        showModulesButton={isMobile}
      />

      <div className="flex flex-1 overflow-hidden">
        {/* Desktop sidebar */}
        {!isMobile && <ScanSidebar modules={modules} onToggle={toggleModule} />}

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
          <TerminalWindow lines={terminalLines} isRunning={status === "running"} />
          {showResults && <ResultsDashboard result={result} />}
        </main>
      </div>
    </div>
  );
};

export default Index;
