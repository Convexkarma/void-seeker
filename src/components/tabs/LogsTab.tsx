import { LogEntry } from "@/types/scan";
import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Search, Copy } from "lucide-react";

interface LogsTabProps {
  logs: LogEntry[];
}

const levelColor: Record<string, string> = {
  info: "text-terminal-blue",
  warn: "text-terminal-amber",
  error: "text-terminal-red",
  success: "text-terminal-green",
};

export function LogsTab({ logs }: LogsTabProps) {
  const [search, setSearch] = useState("");

  const filtered = logs.filter(l =>
    l.message.toLowerCase().includes(search.toLowerCase()) ||
    l.module.toLowerCase().includes(search.toLowerCase())
  );

  const copyAll = () => {
    navigator.clipboard.writeText(filtered.map(l => `[${l.timestamp}] [${l.module}] ${l.message}`).join("\n"));
  };

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search logs..."
            className="pl-8 h-8 text-xs font-mono bg-secondary border-border"
          />
        </div>
        <button onClick={copyAll} className="p-2 rounded-md hover:bg-secondary text-muted-foreground hover:text-card-foreground">
          <Copy className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="bg-terminal-bg rounded-md p-3 max-h-96 overflow-y-auto font-mono text-xs leading-5 scanline">
        {filtered.map((l, i) => (
          <div key={i} className="flex gap-2">
            <span className="text-muted-foreground w-16 flex-shrink-0">{l.timestamp}</span>
            <span className={`w-20 flex-shrink-0 ${levelColor[l.level]}`}>[{l.module}]</span>
            <span className={levelColor[l.level]}>{l.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
