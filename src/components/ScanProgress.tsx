import { Progress } from "@/components/ui/progress";
import { ScanStatus } from "@/types/scan";

interface ScanProgressProps {
  status: ScanStatus;
  progress: number;
  activeModule: string;
}

export function ScanProgress({ status, progress, activeModule }: ScanProgressProps) {
  if (status === "idle") return null;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {status === "running" && (
            <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          )}
          <span className="text-xs font-mono text-muted-foreground">
            {status === "running" ? `Running: ${activeModule}` : status === "completed" ? "Scan Complete" : "Cancelled"}
          </span>
        </div>
        <span className="text-xs font-mono text-primary">{progress}%</span>
      </div>
      <Progress
        value={progress}
        className="h-1.5 bg-secondary [&>div]:bg-primary"
      />
    </div>
  );
}
