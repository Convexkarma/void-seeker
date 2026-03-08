import { Switch } from "@/components/ui/switch";
import { SCAN_MODULES } from "@/data/scanConfig";
import { ScanModule } from "@/types/scan";
import * as Icons from "lucide-react";
import { LucideIcon } from "lucide-react";

interface ScanSidebarProps {
  modules: ScanModule[];
  onToggle: (id: string) => void;
}

function getIcon(name: string): LucideIcon {
  return (Icons as unknown as Record<string, LucideIcon>)[name] || Icons.Circle;
}

const categoryLabels: Record<string, string> = {
  discovery: "Discovery",
  fingerprint: "Fingerprint",
  active: "Active",
  passive: "Passive",
};

const categoryColors: Record<string, string> = {
  discovery: "text-terminal-blue",
  fingerprint: "text-terminal-cyan",
  active: "text-terminal-amber",
  passive: "text-terminal-purple",
};

export function ScanSidebar({ modules, onToggle }: ScanSidebarProps) {
  const grouped = modules.reduce((acc, mod) => {
    if (!acc[mod.category]) acc[mod.category] = [];
    acc[mod.category].push(mod);
    return acc;
  }, {} as Record<string, ScanModule[]>);

  return (
    <aside className="w-72 border-r border-border bg-sidebar overflow-y-auto">
      <div className="p-4">
        <h2 className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-4">
          Scan Modules
        </h2>
        {Object.entries(grouped).map(([category, mods]) => (
          <div key={category} className="mb-4">
            <h3 className={`text-[10px] font-mono uppercase tracking-widest mb-2 ${categoryColors[category]}`}>
              {categoryLabels[category]}
            </h3>
            <div className="space-y-1">
              {mods.map(mod => {
                const Icon = getIcon(mod.icon);
                return (
                  <div
                    key={mod.id}
                    className="flex items-center justify-between px-3 py-2 rounded-md hover:bg-secondary/50 transition-colors group"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Icon className={`h-3.5 w-3.5 flex-shrink-0 ${mod.enabled ? 'text-primary' : 'text-muted-foreground'}`} />
                      <div className="min-w-0">
                        <div className={`text-xs font-medium truncate ${mod.enabled ? 'text-card-foreground' : 'text-muted-foreground'}`}>
                          {mod.name}
                        </div>
                        <div className="text-[10px] text-muted-foreground truncate">{mod.tools}</div>
                      </div>
                    </div>
                    <Switch
                      checked={mod.enabled}
                      onCheckedChange={() => onToggle(mod.id)}
                      className="scale-75 data-[state=checked]:bg-primary"
                    />
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}
