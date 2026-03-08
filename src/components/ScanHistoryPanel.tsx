import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Clock, Trash2, Shield, ChevronRight, Loader2 } from "lucide-react";
import { API } from "@/config/backend";

interface ScanHistoryEntry {
  id: string;
  domain: string;
  date: string;
  status: string;
  duration?: number;
}

interface ScanHistoryPanelProps {
  onClose: () => void;
  onLoadScan: (scanId: string) => void;
}

export function ScanHistoryPanel({ onClose, onLoadScan }: ScanHistoryPanelProps) {
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch(API.history);
      if (res.ok) {
        const data = await res.json();
        // Backend returns array of scan summaries
        const entries: ScanHistoryEntry[] = (Array.isArray(data) ? data : []).map((s: any) => ({
          id: s.id,
          domain: s.domain || "unknown",
          date: s.created_at || s.date || "",
          status: s.status || "unknown",
          duration: s.duration,
        }));
        setHistory(entries);
      }
    } catch {
      // Backend not available
    }
    setLoading(false);
  };

  const deleteScan = async (scanId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await fetch(API.deleteScan(scanId), { method: "DELETE" });
      setHistory(prev => prev.filter(s => s.id !== scanId));
    } catch {}
  };

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
          {loading ? (
            <div className="text-center py-8 text-muted-foreground font-mono text-xs flex items-center justify-center gap-2">
              <Loader2 className="h-3 w-3 animate-spin" /> Loading...
            </div>
          ) : history.length === 0 ? (
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
                  <div className="flex items-center gap-1">
                    <button
                      onClick={(e) => deleteScan(scan.id, e)}
                      className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive transition-opacity p-0.5"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                    <ChevronRight className="h-3 w-3 text-muted-foreground group-hover:text-primary transition-colors" />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-muted-foreground">
                    {scan.date ? new Date(scan.date).toLocaleString() : ""}
                  </span>
                  <Badge
                    variant="outline"
                    className={`text-[9px] font-mono px-1.5 py-0 ${
                      scan.status === "completed"
                        ? "text-primary border-primary/30"
                        : scan.status === "running"
                        ? "text-terminal-amber border-terminal-amber/30"
                        : "text-destructive border-destructive/30"
                    }`}
                  >
                    {scan.status}
                  </Badge>
                  {scan.duration != null && (
                    <span className="text-[10px] font-mono text-muted-foreground">{scan.duration}s</span>
                  )}
                </div>
              </button>
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
