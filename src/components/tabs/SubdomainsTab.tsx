import { SubdomainResult } from "@/types/scan";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

interface SubdomainsTabProps {
  subdomains: SubdomainResult[];
}

export function SubdomainsTab({ subdomains }: SubdomainsTabProps) {
  const statusColor = (code: number) => {
    if (code >= 200 && code < 300) return "text-terminal-green";
    if (code >= 300 && code < 400) return "text-terminal-blue";
    if (code >= 400 && code < 500) return "text-terminal-amber";
    return "text-terminal-red";
  };

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow className="border-border hover:bg-transparent">
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Subdomain</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">IP</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Status</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Title</TableHead>
            <TableHead className="font-mono text-[10px] text-muted-foreground uppercase">Tech</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {subdomains.map(s => (
            <TableRow key={s.subdomain} className="border-border hover:bg-secondary/30">
              <TableCell className="font-mono text-xs text-primary">{s.subdomain}</TableCell>
              <TableCell className="font-mono text-xs text-card-foreground">{s.ip}</TableCell>
              <TableCell className={`font-mono text-xs ${statusColor(s.statusCode)}`}>{s.statusCode}</TableCell>
              <TableCell className="font-mono text-xs text-card-foreground">{s.title}</TableCell>
              <TableCell>
                <div className="flex gap-1 flex-wrap">
                  {s.techStack.map(t => (
                    <Badge key={t} variant="outline" className="text-[9px] font-mono border-border text-muted-foreground px-1.5 py-0">{t}</Badge>
                  ))}
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
