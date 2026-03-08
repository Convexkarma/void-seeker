import { TechResult } from "@/types/scan";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle } from "lucide-react";

interface TechTabProps {
  technologies: TechResult[];
}

export function TechTab({ technologies }: TechTabProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {technologies.map(t => (
        <div key={t.name} className="bg-secondary/50 border border-border rounded-md p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono font-medium text-card-foreground">{t.name}</span>
            {t.outdated && <AlertTriangle className="h-3 w-3 text-terminal-amber" />}
          </div>
          <Badge variant="outline" className="text-[9px] font-mono border-border text-muted-foreground mb-1">
            {t.category}
          </Badge>
          {t.version && (
            <div className={`text-[10px] font-mono mt-1 ${t.outdated ? 'text-terminal-amber' : 'text-muted-foreground'}`}>
              v{t.version} {t.outdated && "⚠ outdated"}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
