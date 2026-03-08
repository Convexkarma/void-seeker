import { PortResult } from "@/types/scan";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

const DANGEROUS_PORTS = [21, 23, 445, 3389, 6379, 27017];

interface PortsTabProps {
  ports: PortResult[];
}

export function PortsTab({ ports }: PortsTabProps) {
  const riskColor = (risk: string) => {
    if (risk === "high") return "bg-severity-critical/20 text-severity-critical border-severity-critical/30";
    if (risk === "medium") return "bg-severity-medium/20 text-severity-medium border-severity-medium/30";
    return "bg-severity-low/20 text-severity-low border-severity-low/30";
  };

  return (
    <div className="space-y-4">
      {/* Visual port map */}
      <div className="flex flex-wrap gap-1.5">
        {ports.map(p => (
          <div
            key={p.port}
            className={`px-2 py-1 rounded text-[10px] font-mono border ${riskColor(p.risk)}`}
          >
            {p.port}
            {DANGEROUS_PORTS.includes(p.port) && " ⚠"}
          </div>
        ))}
      </div>

      <Table>
        <TableHeader>
          <TableRow className="border-border hover:bg-transparent">
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Port</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Protocol</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Service</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Version</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Risk</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">CVEs</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {ports.map(p => (
            <TableRow key={p.port} className="border-border hover:bg-secondary/30">
              <TableCell className="font-mono text-xs text-primary">
                {p.port}
                {DANGEROUS_PORTS.includes(p.port) && <span className="ml-1 text-terminal-red">⚠</span>}
              </TableCell>
              <TableCell className="font-mono text-xs text-card-foreground">{p.protocol}</TableCell>
              <TableCell className="font-mono text-xs text-card-foreground">{p.service}</TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">{p.version}</TableCell>
              <TableCell>
                <Badge variant="outline" className={`text-[9px] font-mono ${riskColor(p.risk)}`}>{p.risk}</Badge>
              </TableCell>
              <TableCell className="font-mono text-xs text-terminal-red">
                {p.cves?.join(", ") || "—"}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
