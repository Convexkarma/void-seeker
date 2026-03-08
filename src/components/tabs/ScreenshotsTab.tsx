import { ScreenshotResult } from "@/types/scan";
import { useState } from "react";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Camera, ExternalLink } from "lucide-react";

interface ScreenshotsTabProps {
  screenshots: ScreenshotResult[];
}

export function ScreenshotsTab({ screenshots }: ScreenshotsTabProps) {
  const [selected, setSelected] = useState<ScreenshotResult | null>(null);

  if (screenshots.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground font-mono text-xs">
        No screenshots captured. Enable the Screenshot module and run gowitness.
      </div>
    );
  }

  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {screenshots.map((ss, i) => (
          <div
            key={i}
            className="bg-secondary/30 border border-border rounded-md overflow-hidden cursor-pointer hover:border-primary/50 transition-colors group"
            onClick={() => setSelected(ss)}
          >
            <div className="aspect-video bg-terminal-bg flex items-center justify-center relative">
              {ss.imageUrl ? (
                <img src={ss.imageUrl} alt={ss.title} className="w-full h-full object-cover" />
              ) : (
                <div className="flex flex-col items-center gap-2 text-muted-foreground">
                  <Camera className="h-8 w-8" />
                  <span className="text-[10px] font-mono">Preview unavailable</span>
                </div>
              )}
              <div className="absolute inset-0 bg-primary/0 group-hover:bg-primary/5 transition-colors" />
            </div>
            <div className="px-3 py-2 border-t border-border">
              <div className="text-xs font-mono text-card-foreground truncate">{ss.title}</div>
              <div className="text-[10px] font-mono text-primary/70 truncate flex items-center gap-1">
                <ExternalLink className="h-2.5 w-2.5" />
                {ss.url}
              </div>
            </div>
          </div>
        ))}
      </div>

      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-w-4xl bg-card border-border">
          {selected && (
            <div>
              <h3 className="text-sm font-mono font-semibold text-card-foreground mb-1">{selected.title}</h3>
              <p className="text-xs font-mono text-primary/70 mb-3">{selected.url}</p>
              <div className="bg-terminal-bg rounded-md aspect-video flex items-center justify-center">
                {selected.imageUrl ? (
                  <img src={selected.imageUrl} alt={selected.title} className="w-full h-full object-contain" />
                ) : (
                  <div className="text-muted-foreground font-mono text-sm">
                    <Camera className="h-12 w-12 mx-auto mb-2" />
                    Screenshot not available — run gowitness locally
                  </div>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
