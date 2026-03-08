import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Clock, Trash2, Shield, ChevronRight } from "lucide-react";

interface ScanHistoryEntry {
  id: string;
  domain: string;
  date: string;
  status: string;
  vulnCounts?: { critical: number; high: number; medium: number; low: number };
}

interface ScanHistoryPanelProps {
  onClose: () => void;
  onLoadScan: (scanId: string) => void;
}

// Mock history for demo — in real usage, fetched from backend
const MOCK_HISTORY: ScanHistoryEntry[] = [
  {
    id: "scan-001",
    domain: "example.com",
    date: "2026-03-08 10:14",
    status: "completed",
    vulnCounts: { critical: 1, high: 2, medium: 2, low: 1 },
  },
  {
    id: "scan-002",
    domain: "testsite.org",
    date: "2026-03-07 15:30",
    status: "completed",
    vulnCounts: { critical: 0, high: 1, medium: 3, low: 2 },
  },
  {
    id: "scan-003",
    domain: "webapp.io",
    date: "2026-03-06 09:00",
    status: "cancelled",
    vulnCounts: { critical: 0, high: 0, medium: 1, low: 0 },
  },
];

export function ScanHistoryPanel({ onClose, onLoadScan }: ScanHistoryPanelProps) {
  const [history] = useState(MOCK_HISTORY);

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 text-primary" />
          <span className="text-xs font-mono font-semibold text-card-foreground uppercase">Scan History</span>
        </div>
        <Button variant="ghost" size="sm" onClick={onClose} className="text-xs font-mono h-6 px-2">
          Close
        </Button>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-3 space-y-2">
          {history.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground font-mono text-xs">
              No scan history yet
            </div>
          ) : (
            history.map(scan => (
              <button
                key={scan.id}
                onClick={() => onLoadScan(scan.id)}
                className="w-full text-left bg-secondary/30 border border-border rounded-md p-3 hover:border-primary/30 transition-colors group"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono font-medium text-card-foreground">{scan.domain}</span>
                  <ChevronRight className="h-3 w-3 text-muted-foreground group-hover:text-primary transition-colors" />
                </div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[10px] font-mono text-muted-foreground">{scan.date}</span>
                  <Badge
                    variant="outline"
                    className={`text-[9px] font-mono px-1.5 py-0 ${
                      scan.status === "completed"
                        ? "text-primary border-primary/30"
                        : "text-destructive border-destructive/30"
                    }`}
                  >
                    {scan.status}
                  </Badge>
                </div>
                {scan.vulnCounts && (
                  <div className="flex gap-1.5">
                    {scan.vulnCounts.critical > 0 && (
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-severity-critical/20 text-severity-critical">
                        {scan.vulnCounts.critical}C
                      </span>
                    )}
                    {scan.vulnCounts.high > 0 && (
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-severity-high/20 text-severity-high">
                        {scan.vulnCounts.high}H
                      </span>
                    )}
                    {scan.vulnCounts.medium > 0 && (
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-severity-medium/20 text-severity-medium">
                        {scan.vulnCounts.medium}M
                      </span>
                    )}
                    {scan.vulnCounts.low > 0 && (
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-severity-low/20 text-severity-low">
                        {scan.vulnCounts.low}L
                      </span>
                    )}
                  </div>
                )}
              </button>
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
