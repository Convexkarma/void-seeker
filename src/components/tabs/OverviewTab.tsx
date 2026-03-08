import { ScanResult, ScanFindings } from "@/types/scan";
import { Shield, Globe, Network, FolderSearch, Cpu, AlertTriangle } from "lucide-react";
import { emptyFindings } from "@/lib/resultMapper";

interface OverviewTabProps {
  result: ScanResult;
}

export function OverviewTab({ result }: OverviewTabProps) {
  const f: ScanFindings = result.findings || emptyFindings;
  const vulns = f.vulnerabilities || [];
  const subs = f.subdomains || [];
  const ports = f.ports || [];
  const dirs = f.directories || [];
  const tech = f.technologies || [];

  const critCount = vulns.filter(v => v.severity === "critical").length;
  const highCount = vulns.filter(v => v.severity === "high").length;
  const medCount = vulns.filter(v => v.severity === "medium").length;
  const lowCount = vulns.filter(v => v.severity === "low").length;

  // Simple attack surface score
  const score = Math.min(100, critCount * 25 + highCount * 15 + medCount * 5 + lowCount * 2 + ports.filter(p => p.risk === "high").length * 10);

  const cards = [
    { label: "Subdomains", value: subs.length, icon: Globe, color: "text-terminal-blue" },
    { label: "Open Ports", value: ports.length, icon: Network, color: "text-terminal-amber" },
    { label: "Vulnerabilities", value: vulns.length, icon: AlertTriangle, color: "text-terminal-red" },
    { label: "Directories", value: dirs.length, icon: FolderSearch, color: "text-terminal-purple" },
    { label: "Technologies", value: tech.length, icon: Cpu, color: "text-terminal-cyan" },
  ];

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {cards.map(c => (
          <div key={c.label} className="bg-secondary/50 border border-border rounded-md p-3 text-center">
            <c.icon className={`h-5 w-5 mx-auto mb-2 ${c.color}`} />
            <div className="text-2xl font-mono font-bold text-card-foreground">{c.value}</div>
            <div className="text-[10px] font-mono text-muted-foreground uppercase">{c.label}</div>
          </div>
        ))}
      </div>

      {/* Attack surface + severity */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="bg-secondary/50 border border-border rounded-md p-4">
          <h3 className="text-xs font-mono text-muted-foreground mb-3 uppercase">Attack Surface Score</h3>
          <div className="flex items-center gap-4">
            <div className={`text-5xl font-mono font-bold ${score >= 70 ? 'text-terminal-red' : score >= 40 ? 'text-terminal-amber' : 'text-terminal-green'}`}>
              {score}
            </div>
            <div className="text-xs font-mono text-muted-foreground">
              {score >= 70 ? "Critical Risk" : score >= 40 ? "Medium Risk" : "Low Risk"}
            </div>
          </div>
        </div>

        <div className="bg-secondary/50 border border-border rounded-md p-4">
          <h3 className="text-xs font-mono text-muted-foreground mb-3 uppercase">Severity Breakdown</h3>
          <div className="space-y-2">
            {[
              { label: "Critical", count: critCount, color: "bg-severity-critical" },
              { label: "High", count: highCount, color: "bg-severity-high" },
              { label: "Medium", count: medCount, color: "bg-severity-medium" },
              { label: "Low", count: lowCount, color: "bg-severity-low" },
            ].map(s => (
              <div key={s.label} className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${s.color}`} />
                <span className="text-xs font-mono text-muted-foreground w-16">{s.label}</span>
                <div className="flex-1 bg-muted rounded-full h-1.5">
                  <div className={`h-full rounded-full ${s.color}`} style={{ width: `${vulns.length > 0 ? (s.count / vulns.length) * 100 : 0}%` }} />
                </div>
                <span className="text-xs font-mono text-card-foreground w-4 text-right">{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
