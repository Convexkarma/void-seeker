import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Save, RefreshCw, Check, X } from "lucide-react";
import { API } from "@/config/backend";

interface SettingsPageProps {
  onBack: () => void;
}

interface ToolStatus {
  installed: boolean;
  path: string;
  version?: string;
}

const API_KEY_FIELDS = [
  { key: "shodan", label: "Shodan", placeholder: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
  { key: "virustotal", label: "VirusTotal", placeholder: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
  { key: "censys_id", label: "Censys ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
  { key: "censys_secret", label: "Censys Secret", placeholder: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
  { key: "securitytrails", label: "SecurityTrails", placeholder: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
  { key: "ipinfo", label: "ipinfo.io", placeholder: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
  { key: "github", label: "GitHub Token", placeholder: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
];

const TOOL_NAMES = ["nmap", "subfinder", "amass", "httpx", "nuclei", "gobuster", "whatweb", "gowitness", "wafw00f", "dnsx", "theHarvester", "testssl.sh"];

export function SettingsPage({ onBack }: SettingsPageProps) {
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({});
  const [defaultWordlist, setDefaultWordlist] = useState("/usr/share/wordlists/dirb/common.txt");
  const [defaultThreads, setDefaultThreads] = useState("50");
  const [proxy, setProxy] = useState("");
  const [discordWebhook, setDiscordWebhook] = useState("");
  const [slackWebhook, setSlackWebhook] = useState("");
  const [toolStatus, setToolStatus] = useState<Record<string, ToolStatus>>({});
  const [saving, setSaving] = useState(false);
  const [checkingTools, setCheckingTools] = useState(false);

  useEffect(() => {
    fetch(API.settings)
      .then(r => r.json())
      .then(config => {
        setApiKeys(config.api_keys || {});
        setDefaultWordlist(config.default_wordlist || "");
        setDefaultThreads(String(config.default_threads || 50));
        setProxy(config.proxy || "");
        setDiscordWebhook(config.notifications?.discord_webhook || "");
        setSlackWebhook(config.notifications?.slack_webhook || "");
      })
      .catch(() => {});

    checkTools();
  }, []);

  const checkTools = async () => {
    setCheckingTools(true);
    try {
      const r = await fetch(API.toolsCheck, { method: "POST" });
      const data = await r.json();
      setToolStatus(data);
    } catch {
      // Backend not running
    }
    setCheckingTools(false);
  };

  const saveSettings = async () => {
    setSaving(true);
    try {
      await fetch(API.settings, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          api_keys: apiKeys,
          default_wordlist: defaultWordlist,
          default_threads: parseInt(defaultThreads) || 50,
          proxy,
          notifications: { discord_webhook: discordWebhook, slack_webhook: slackWebhook },
        }),
      });
    } catch {}
    setSaving(false);
  };

  return (
    <div className="flex flex-col h-screen bg-background">
      <header className="h-14 border-b border-border bg-card flex items-center px-4 gap-3">
        <Button variant="ghost" size="sm" onClick={onBack} className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4 mr-1" /> Back
        </Button>
        <span className="text-sm font-mono font-bold text-primary">Settings</span>
      </header>

      <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6 max-w-3xl">
        {/* API Keys */}
        <section className="space-y-3">
          <h2 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">API Keys</h2>
          <div className="grid gap-3">
            {API_KEY_FIELDS.map(f => (
              <div key={f.key} className="flex items-center gap-3">
                <label className="text-xs font-mono text-muted-foreground w-28 flex-shrink-0">{f.label}</label>
                <Input
                  type="password"
                  value={apiKeys[f.key] || ""}
                  onChange={e => setApiKeys(prev => ({ ...prev, [f.key]: e.target.value }))}
                  placeholder={f.placeholder}
                  className="font-mono text-xs bg-terminal-bg border-border h-8"
                />
                {apiKeys[f.key] ? (
                  <div className="w-2 h-2 rounded-full bg-primary flex-shrink-0" />
                ) : (
                  <div className="w-2 h-2 rounded-full bg-muted-foreground/30 flex-shrink-0" />
                )}
              </div>
            ))}
          </div>
        </section>

        {/* Defaults */}
        <section className="space-y-3">
          <h2 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Defaults</h2>
          <div className="grid gap-3">
            <div className="flex items-center gap-3">
              <label className="text-xs font-mono text-muted-foreground w-28 flex-shrink-0">Wordlist Path</label>
              <Input value={defaultWordlist} onChange={e => setDefaultWordlist(e.target.value)} className="font-mono text-xs bg-terminal-bg border-border h-8" />
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs font-mono text-muted-foreground w-28 flex-shrink-0">Threads</label>
              <Input value={defaultThreads} onChange={e => setDefaultThreads(e.target.value)} type="number" className="font-mono text-xs bg-terminal-bg border-border h-8 w-24" />
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs font-mono text-muted-foreground w-28 flex-shrink-0">HTTP Proxy</label>
              <Input value={proxy} onChange={e => setProxy(e.target.value)} placeholder="http://127.0.0.1:8080" className="font-mono text-xs bg-terminal-bg border-border h-8" />
            </div>
          </div>
        </section>

        {/* Notifications */}
        <section className="space-y-3">
          <h2 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Notifications</h2>
          <div className="grid gap-3">
            <div className="flex items-center gap-3">
              <label className="text-xs font-mono text-muted-foreground w-28 flex-shrink-0">Discord</label>
              <Input value={discordWebhook} onChange={e => setDiscordWebhook(e.target.value)} placeholder="https://discord.com/api/webhooks/..." className="font-mono text-xs bg-terminal-bg border-border h-8" />
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs font-mono text-muted-foreground w-28 flex-shrink-0">Slack</label>
              <Input value={slackWebhook} onChange={e => setSlackWebhook(e.target.value)} placeholder="https://hooks.slack.com/services/..." className="font-mono text-xs bg-terminal-bg border-border h-8" />
            </div>
          </div>
        </section>

        {/* Tool Status */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Installed Tools</h2>
            <Button variant="ghost" size="sm" onClick={checkTools} disabled={checkingTools} className="text-xs font-mono h-7">
              <RefreshCw className={`h-3 w-3 mr-1 ${checkingTools ? "animate-spin" : ""}`} /> Check
            </Button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {TOOL_NAMES.map(tool => {
              const status = toolStatus[tool];
              return (
                <div key={tool} className="flex items-center gap-2 bg-secondary/30 border border-border rounded px-3 py-2">
                  {status?.installed ? (
                    <Check className="h-3 w-3 text-primary flex-shrink-0" />
                  ) : (
                    <X className="h-3 w-3 text-destructive flex-shrink-0" />
                  )}
                  <span className="text-xs font-mono text-card-foreground">{tool}</span>
                </div>
              );
            })}
          </div>
        </section>

        {/* Save */}
        <Button onClick={saveSettings} disabled={saving} className="font-mono text-sm bg-primary text-primary-foreground hover:bg-primary/90">
          <Save className="h-4 w-4 mr-2" />
          {saving ? "Saving..." : "Save Settings"}
        </Button>
      </div>
    </div>
  );
}
