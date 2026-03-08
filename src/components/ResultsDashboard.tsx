import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScanResult } from "@/types/scan";
import { OverviewTab } from "./tabs/OverviewTab";
import { SubdomainsTab } from "./tabs/SubdomainsTab";
import { PortsTab } from "./tabs/PortsTab";
import { VulnsTab } from "./tabs/VulnsTab";
import { DirectoriesTab } from "./tabs/DirectoriesTab";
import { TechTab } from "./tabs/TechTab";
import { DnsTab } from "./tabs/DnsTab";
import { SecretsTab } from "./tabs/SecretsTab";
import { LogsTab } from "./tabs/LogsTab";

interface ResultsDashboardProps {
  result: ScanResult;
}

export function ResultsDashboard({ result }: ResultsDashboardProps) {
  const f = result.findings;
  const critCount = f.vulnerabilities.filter(v => v.severity === "critical").length;
  const highCount = f.vulnerabilities.filter(v => v.severity === "high").length;

  return (
    <div className="border border-border rounded-md bg-card overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-primary" />
          <h2 className="text-sm font-mono font-semibold text-card-foreground">
            Results — {result.domain}
          </h2>
        </div>
        <span className="text-[10px] font-mono text-muted-foreground">
          Completed {result.completedAt ? new Date(result.completedAt).toLocaleTimeString() : ""}
        </span>
      </div>

      <Tabs defaultValue="overview" className="w-full">
        <div className="border-b border-border overflow-x-auto">
          <TabsList className="bg-transparent h-auto p-0 rounded-none flex">
            {[
              { value: "overview", label: "Overview" },
              { value: "subdomains", label: `Subdomains (${f.subdomains.length})` },
              { value: "ports", label: `Ports (${f.ports.length})` },
              { value: "vulns", label: `Vulns (${f.vulnerabilities.length})`, alert: critCount + highCount > 0 },
              { value: "dirs", label: `Dirs (${f.directories.length})` },
              { value: "tech", label: `Tech (${f.technologies.length})` },
              { value: "dns", label: "DNS" },
              { value: "secrets", label: `Secrets (${f.secrets.length})` },
              { value: "logs", label: "Logs" },
            ].map(tab => (
              <TabsTrigger
                key={tab.value}
                value={tab.value}
                className="font-mono text-[11px] px-3 py-2.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:text-primary text-muted-foreground hover:text-card-foreground whitespace-nowrap"
              >
                {tab.label}
                {tab.alert && <span className="ml-1 w-1.5 h-1.5 rounded-full bg-destructive inline-block" />}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        <div className="p-4">
          <TabsContent value="overview"><OverviewTab result={result} /></TabsContent>
          <TabsContent value="subdomains"><SubdomainsTab subdomains={f.subdomains} /></TabsContent>
          <TabsContent value="ports"><PortsTab ports={f.ports} /></TabsContent>
          <TabsContent value="vulns"><VulnsTab vulnerabilities={f.vulnerabilities} /></TabsContent>
          <TabsContent value="dirs"><DirectoriesTab directories={f.directories} /></TabsContent>
          <TabsContent value="tech"><TechTab technologies={f.technologies} /></TabsContent>
          <TabsContent value="dns"><DnsTab dns={f.dns} /></TabsContent>
          <TabsContent value="secrets"><SecretsTab secrets={f.secrets} /></TabsContent>
          <TabsContent value="logs"><LogsTab logs={f.logs} /></TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
