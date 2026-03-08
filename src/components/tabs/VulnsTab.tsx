import { VulnResult } from "@/types/scan";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { XCircle } from "lucide-react";

interface VulnsTabProps {
  vulnerabilities: VulnResult[];
}

const severityStyles: Record<string, string> = {
  critical: "bg-severity-critical/20 text-severity-critical border-severity-critical/30",
  high: "bg-severity-high/20 text-severity-high border-severity-high/30",
  medium: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
  low: "bg-severity-low/20 text-severity-low border-severity-low/30",
  info: "bg-severity-info/20 text-severity-info border-severity-info/30",
};

export function VulnsTab({ vulnerabilities }: VulnsTabProps) {
  return (
    <div className="space-y-3">
      {vulnerabilities.map(v => (
        <div key={v.id} className="bg-secondary/30 border border-border rounded-md p-4">
          <div className="flex items-start justify-between mb-2">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className={`text-[10px] font-mono uppercase ${severityStyles[v.severity]}`}>
                {v.severity}
              </Badge>
              {v.cveId && (
                <span className="text-xs font-mono text-terminal-red">{v.cveId}</span>
              )}
            </div>
            <Button variant="ghost" size="sm" className="text-[10px] font-mono text-muted-foreground h-6 px-2 hover:text-card-foreground">
              <XCircle className="h-3 w-3 mr-1" /> False Positive
            </Button>
          </div>
          <h4 className="text-sm font-mono font-medium text-card-foreground mb-1">{v.title}</h4>
          <p className="text-xs font-mono text-primary/80 mb-2">{v.url}</p>
          <p className="text-xs text-muted-foreground mb-2">{v.description}</p>
          <div className="bg-terminal-bg/50 rounded px-3 py-2">
            <span className="text-[10px] font-mono text-terminal-green uppercase">Remediation: </span>
            <span className="text-xs font-mono text-card-foreground">{v.remediation}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
