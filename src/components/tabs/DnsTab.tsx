import { DnsResult } from "@/types/scan";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Check, X } from "lucide-react";

interface DnsTabProps {
  dns: DnsResult;
}

export function DnsTab({ dns }: DnsTabProps) {
  return (
    <div className="space-y-6">
      {/* Records */}
      <div className="grid grid-cols-2 gap-4">
        {[
          { label: "A Records", items: dns.a },
          { label: "AAAA Records", items: dns.aaaa },
          { label: "NS Records", items: dns.ns },
          { label: "CNAME Records", items: dns.cname },
          { label: "TXT Records", items: dns.txt },
        ].map(section => (
          <div key={section.label} className="bg-secondary/30 border border-border rounded-md p-3">
            <h4 className="text-[10px] font-mono text-muted-foreground uppercase mb-2">{section.label}</h4>
            {section.items.map((item, i) => (
              <div key={i} className="text-xs font-mono text-card-foreground py-0.5">{item}</div>
            ))}
          </div>
        ))}

        {/* MX */}
        <div className="bg-secondary/30 border border-border rounded-md p-3">
          <h4 className="text-[10px] font-mono text-muted-foreground uppercase mb-2">MX Records</h4>
          {dns.mx.map((mx, i) => (
            <div key={i} className="text-xs font-mono text-card-foreground py-0.5">
              <span className="text-muted-foreground">[{mx.priority}]</span> {mx.host}
            </div>
          ))}
        </div>
      </div>

      {/* WHOIS */}
      <div className="bg-secondary/30 border border-border rounded-md p-3">
        <h4 className="text-[10px] font-mono text-muted-foreground uppercase mb-2">WHOIS</h4>
        <div className="grid grid-cols-2 gap-2 text-xs font-mono">
          <div><span className="text-muted-foreground">Registrar:</span> <span className="text-card-foreground">{dns.whois.registrar}</span></div>
          <div><span className="text-muted-foreground">Created:</span> <span className="text-card-foreground">{dns.whois.createdDate}</span></div>
          <div><span className="text-muted-foreground">Expires:</span> <span className="text-card-foreground">{dns.whois.expiryDate}</span></div>
        </div>
      </div>

      {/* Security checks */}
      <div className="flex gap-4">
        {[
          { label: "SPF", present: dns.spf },
          { label: "DMARC", present: dns.dmarc },
          { label: "DKIM", present: dns.dkim },
        ].map(check => (
          <div key={check.label} className="flex items-center gap-2 bg-secondary/30 border border-border rounded-md px-3 py-2">
            {check.present ? <Check className="h-3.5 w-3.5 text-terminal-green" /> : <X className="h-3.5 w-3.5 text-terminal-red" />}
            <span className="text-xs font-mono text-card-foreground">{check.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
