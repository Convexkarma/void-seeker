import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Checkbox } from "@/components/ui/checkbox";
import { SCAN_PROFILES, WORDLISTS } from "@/data/scanConfig";
import { ScanConfig, ScanStatus } from "@/types/scan";
import { Crosshair, AlertTriangle } from "lucide-react";

interface ScanLauncherProps {
  status: ScanStatus;
  onLaunch: (config: ScanConfig) => void;
  onCancel: () => void;
  enabledModules: string[];
}

export function ScanLauncher({ status, onLaunch, onCancel, enabledModules }: ScanLauncherProps) {
  const [domain, setDomain] = useState("");
  const [profile, setProfile] = useState("standard");
  const [wordlist, setWordlist] = useState("common");
  const [threads, setThreads] = useState([50]);
  const [authorized, setAuthorized] = useState(false);

  const handleLaunch = () => {
    if (!domain || !authorized) return;
    onLaunch({
      domain,
      modules: enabledModules,
      profile,
      wordlist,
      threads: threads[0],
      authorized,
    });
  };

  return (
    <div className="space-y-4">
      {/* Legal disclaimer */}
      <div className="bg-destructive/10 border border-destructive/30 rounded-md p-3 flex items-start gap-2">
        <AlertTriangle className="h-4 w-4 text-destructive flex-shrink-0 mt-0.5" />
        <p className="text-xs text-destructive/90 font-mono">
          WARNING: Only scan targets you have explicit authorization to test. Unauthorized scanning is illegal.
        </p>
      </div>

      {/* Domain input */}
      <div>
        <label className="text-xs font-mono text-muted-foreground mb-1.5 block">TARGET DOMAIN</label>
        <Input
          value={domain}
          onChange={e => setDomain(e.target.value)}
          placeholder="example.com"
          className="font-mono bg-terminal-bg border-border text-primary placeholder:text-muted-foreground h-11 text-sm"
        />
      </div>

      {/* Config row */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-mono text-muted-foreground mb-1.5 block">SCAN PROFILE</label>
          <Select value={profile} onValueChange={setProfile}>
            <SelectTrigger className="font-mono text-xs bg-secondary border-border h-9">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-card border-border">
              {SCAN_PROFILES.map(p => (
                <SelectItem key={p.id} value={p.id} className="font-mono text-xs">
                  {p.name} ({p.duration})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs font-mono text-muted-foreground mb-1.5 block">WORDLIST</label>
          <Select value={wordlist} onValueChange={setWordlist}>
            <SelectTrigger className="font-mono text-xs bg-secondary border-border h-9">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-card border-border">
              {WORDLISTS.map(w => (
                <SelectItem key={w.id} value={w.id} className="font-mono text-xs">
                  {w.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Threads slider */}
      <div>
        <div className="flex justify-between mb-1.5">
          <label className="text-xs font-mono text-muted-foreground">THREADS</label>
          <span className="text-xs font-mono text-primary">{threads[0]}</span>
        </div>
        <Slider
          value={threads}
          onValueChange={setThreads}
          min={1}
          max={100}
          step={1}
          className="[&_[role=slider]]:bg-primary [&_[role=slider]]:border-primary"
        />
      </div>

      {/* Authorization checkbox */}
      <div className="flex items-center gap-2.5">
        <Checkbox
          id="auth"
          checked={authorized}
          onCheckedChange={(v) => setAuthorized(v === true)}
          className="border-primary data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground"
        />
        <label htmlFor="auth" className="text-xs font-mono text-muted-foreground cursor-pointer">
          I confirm I have authorization to scan this target
        </label>
      </div>

      {/* Launch button */}
      {status === "running" ? (
        <Button onClick={onCancel} variant="destructive" className="w-full h-11 font-mono text-sm">
          Cancel Scan
        </Button>
      ) : (
        <Button
          onClick={handleLaunch}
          disabled={!domain || !authorized}
          className="w-full h-11 font-mono text-sm bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-30 pulse-glow"
        >
          <Crosshair className="h-4 w-4 mr-2" />
          Launch Recon
        </Button>
      )}
    </div>
  );
}
