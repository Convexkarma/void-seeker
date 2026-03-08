import { Shield, History, Settings, Activity, Menu, Terminal } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface TopNavProps {
  activeScans: number;
  onHistoryClick: () => void;
  onSettingsClick: () => void;
  onModulesClick?: () => void;
  onTerminalToggle?: () => void;
  showModulesButton?: boolean;
}

export function TopNav({ activeScans, onHistoryClick, onSettingsClick, onModulesClick, onTerminalToggle, showModulesButton }: TopNavProps) {
  return (
    <header className="h-14 border-b border-border bg-card flex items-center justify-between px-3 sm:px-4">
      <div className="flex items-center gap-2 sm:gap-3">
        {showModulesButton && (
          <button
            onClick={onModulesClick}
            className="p-2 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
          >
            <Menu className="h-4 w-4" />
          </button>
        )}
        <Shield className="h-5 w-5 sm:h-6 sm:w-6 text-primary" />
        <span className="text-base sm:text-lg font-mono font-bold text-primary terminal-glow tracking-wider">
          AutoRecon
        </span>
        <span className="text-xs font-mono text-muted-foreground hidden sm:inline">v2.0</span>
        <Badge variant="outline" className="text-[9px] font-mono px-1.5 py-0 border-primary/20 text-primary/60 hidden sm:inline-flex">
          LOCAL
        </Badge>
      </div>

      <div className="flex items-center gap-1 sm:gap-2">
        {activeScans > 0 && (
          <Badge className="bg-primary/20 text-primary border border-primary/30 font-mono text-xs flex items-center gap-1.5 px-2 py-0.5">
            <Activity className="h-3 w-3 animate-pulse" />
            <span className="hidden sm:inline">{activeScans} active</span>
            <span className="sm:hidden">{activeScans}</span>
          </Badge>
        )}
        <button
          onClick={onTerminalToggle}
          className="p-2 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
          title="Toggle Terminal (T)"
        >
          <Terminal className="h-4 w-4" />
        </button>
        <button
          onClick={onHistoryClick}
          className="p-2 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
          title="History (H)"
        >
          <History className="h-4 w-4" />
        </button>
        <button
          onClick={onSettingsClick}
          className="p-2 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
          title="Settings"
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}
