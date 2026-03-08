import { useRef, useEffect } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";

interface TerminalLine {
  module: string;
  color: string;
  text: string;
}

interface TerminalWindowProps {
  lines: TerminalLine[];
  isRunning: boolean;
}

export function TerminalWindow({ lines, isRunning }: TerminalWindowProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  return (
    <div className="bg-terminal-bg border border-border rounded-md overflow-hidden">
      {/* Title bar */}
      <div className="flex items-center gap-2 px-3 py-1.5 bg-secondary/50 border-b border-border">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-terminal-red" />
          <div className="w-2.5 h-2.5 rounded-full bg-terminal-amber" />
          <div className="w-2.5 h-2.5 rounded-full bg-terminal-green" />
        </div>
        <span className="text-[10px] font-mono text-muted-foreground ml-2">autorecon — terminal</span>
      </div>
      {/* Output */}
      <ScrollArea className="h-64 p-3">
        <div className="font-mono text-xs leading-5 scanline">
          {lines.length === 0 && !isRunning && (
            <div className="text-muted-foreground">
              <span className="text-primary">$</span> Waiting for scan to start...
            </div>
          )}
          {lines.map((line, i) => (
            <div key={i} className={`text-${line.color}`}>
              {line.text}
            </div>
          ))}
          {isRunning && (
            <div className="text-primary">
              <span className="cursor-blink">█</span>
            </div>
          )}
          <div ref={bottomRef} />
        </div>
      </ScrollArea>
    </div>
  );
}
