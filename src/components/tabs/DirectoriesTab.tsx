import { DirectoryResult } from "@/types/scan";

interface DirectoriesTabProps {
  directories: DirectoryResult[];
}

const statusColor = (code: number) => {
  if (code === 200) return "text-terminal-green";
  if (code === 301 || code === 302) return "text-terminal-blue";
  if (code === 401 || code === 403) return "text-terminal-amber";
  if (code >= 500) return "text-terminal-red";
  return "text-muted-foreground";
};

export function DirectoriesTab({ directories }: DirectoriesTabProps) {
  return (
    <div className="space-y-1">
      {directories.map(d => (
        <div
          key={d.path}
          className={`flex items-center gap-3 px-3 py-1.5 rounded font-mono text-xs ${d.interesting ? 'bg-terminal-amber/5 border border-terminal-amber/20' : 'hover:bg-secondary/30'}`}
        >
          <span className={`w-8 text-right ${statusColor(d.statusCode)}`}>{d.statusCode}</span>
          <span className={d.interesting ? 'text-terminal-amber' : 'text-card-foreground'}>{d.path}</span>
          {d.interesting && <span className="text-[9px] text-terminal-amber uppercase">interesting</span>}
          {d.size > 0 && <span className="text-muted-foreground ml-auto">{d.size}B</span>}
        </div>
      ))}
    </div>
  );
}
