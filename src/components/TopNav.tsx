import { Shield, History, Settings, Activity } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface TopNavProps {
  activeScans: number;
  onHistoryClick: () => void;
  onSettingsClick: () => void;
}

export function TopNav({ activeScans, onHistoryClick, onSettingsClick }: TopNavProps) {
  return (
    <header className="h-14 border-b border-border bg-card flex items-center justify-between px-4">
      <div className="flex items-center gap-3">
        <Shield className="h-6 w-6 text-primary" />
        <span className="text-lg font-mono font-bold text-primary terminal-glow tracking-wider">
          AutoRecon
        </span>
        <span className="text-xs font-mono text-muted-foreground">v2.0</span>
      </div>

      <div className="flex items-center gap-3">
        {activeScans > 0 && (
          <Badge className="bg-primary/20 text-primary border border-primary/30 font-mono text-xs flex items-center gap-1.5 px-2 py-0.5">
            <Activity className="h-3 w-3 animate-pulse" />
            {activeScans} active
          </Badge>
        )}
        <button
          onClick={onHistoryClick}
          className="p-2 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
        >
          <History className="h-4 w-4" />
        </button>
        <button
          onClick={onSettingsClick}
          className="p-2 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}
