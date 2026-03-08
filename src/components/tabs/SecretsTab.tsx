import { useState } from "react";
import { SecretResult } from "@/types/scan";
import { Badge } from "@/components/ui/badge";
import { Eye, EyeOff } from "lucide-react";

interface SecretsTabProps {
  secrets: SecretResult[];
}

const severityStyles: Record<string, string> = {
  critical: "bg-severity-critical/20 text-severity-critical border-severity-critical/30",
  high: "bg-severity-high/20 text-severity-high border-severity-high/30",
  medium: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
  low: "bg-severity-low/20 text-severity-low border-severity-low/30",
};

const typeLabels: Record<string, string> = {
  api_key: "API Key",
  token: "Token",
  password: "Password",
  email: "Email",
  bucket: "Cloud Bucket",
  github_dork: "GitHub Dork",
};

export function SecretsTab({ secrets }: SecretsTabProps) {
  const [revealed, setRevealed] = useState<Set<number>>(new Set());

  const toggle = (i: number) => {
    setRevealed(prev => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i); else next.add(i);
      return next;
    });
  };

  return (
    <div className="space-y-2">
      {secrets.map((s, i) => (
        <div key={i} className="flex items-center gap-3 bg-secondary/30 border border-border rounded-md px-4 py-3">
          <Badge variant="outline" className={`text-[9px] font-mono uppercase ${severityStyles[s.severity]}`}>
            {s.severity}
          </Badge>
          <Badge variant="outline" className="text-[9px] font-mono border-border text-muted-foreground">
            {typeLabels[s.type]}
          </Badge>
          <span className="text-xs font-mono text-muted-foreground">{s.source}</span>
          <span className="font-mono text-xs text-card-foreground flex-1 truncate">
            {revealed.has(i) ? s.value : "••••••••••••••"}
          </span>
          <button onClick={() => toggle(i)} className="text-muted-foreground hover:text-card-foreground">
            {revealed.has(i) ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </button>
        </div>
      ))}
    </div>
  );
}
