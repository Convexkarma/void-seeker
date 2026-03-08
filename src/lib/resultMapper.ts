/**
 * Maps the backend per-tool results structure into the frontend ScanFindings shape.
 * Backend: { subfinder: { subdomains: [...] }, nmap: { ports: [...] }, ... }
 * Frontend: { subdomains: [...], ports: [...], vulnerabilities: [...], ... }
 */

import { ScanFindings, SubdomainResult, PortResult, VulnResult, DirectoryResult, TechResult, ScreenshotResult, DnsResult, SecretResult, LogEntry } from "@/types/scan";

const emptyDns: DnsResult = {
  a: [], aaaa: [], mx: [], ns: [], txt: [], cname: [],
  whois: { registrar: "", createdDate: "", expiryDate: "", nameServers: [] },
  spf: false, dmarc: false, dkim: false,
};

export const emptyFindings: ScanFindings = {
  subdomains: [],
  ports: [],
  vulnerabilities: [],
  directories: [],
  technologies: [],
  screenshots: [],
  dns: emptyDns,
  secrets: [],
  logs: [],
};

export function mapBackendResults(results: Record<string, any> | undefined): ScanFindings {
  if (!results) return emptyFindings;

  // If it already has the frontend shape (e.g. from mock data), return as-is
  if (Array.isArray(results.subdomains) || Array.isArray(results.vulnerabilities)) {
    return {
      subdomains: results.subdomains || [],
      ports: results.ports || [],
      vulnerabilities: results.vulnerabilities || [],
      directories: results.directories || [],
      technologies: results.technologies || [],
      screenshots: results.screenshots || [],
      dns: results.dns || emptyDns,
      secrets: results.secrets || [],
      logs: results.logs || [],
    };
  }

  // Map from per-tool backend structure
  const subdomains: SubdomainResult[] = [];
  const ports: PortResult[] = [];
  const vulnerabilities: VulnResult[] = [];
  const directories: DirectoryResult[] = [];
  const technologies: TechResult[] = [];
  const screenshots: ScreenshotResult[] = [];
  const secrets: SecretResult[] = [];
  let dns: DnsResult = { ...emptyDns };

  // Subdomains from subfinder + amass
  for (const key of ["subfinder", "amass"]) {
    const data = results[key];
    if (data?.subdomains) {
      for (const sub of data.subdomains) {
        if (typeof sub === "string") {
          subdomains.push({ subdomain: sub, ip: "", statusCode: 0, title: "", techStack: [] });
        }
      }
    }
  }

  // Enrich subdomains from httpx
  const httpx = results.httpx;
  if (httpx?.live_hosts) {
    for (const host of httpx.live_hosts) {
      const existing = subdomains.find(s => s.subdomain === host.host || s.subdomain === host.url?.replace(/^https?:\/\//, ""));
      if (existing) {
        existing.statusCode = host.status_code || host.statusCode || 0;
        existing.title = host.title || "";
        existing.techStack = host.technologies || host.techStack || [];
      }
    }
  }

  // Ports from nmap
  const nmap = results.nmap;
  if (nmap?.ports) {
    for (const p of nmap.ports) {
      ports.push({
        port: p.port,
        protocol: (p.protocol || "tcp").toUpperCase(),
        service: p.service || "",
        version: [p.product, p.version].filter(Boolean).join(" ") || p.version || "",
        risk: p.risk || "low",
        cves: p.cves || [],
      });
    }
  }

  // Vulnerabilities from nuclei
  const nuclei = results.nuclei;
  if (nuclei?.findings) {
    for (let i = 0; i < nuclei.findings.length; i++) {
      const f = nuclei.findings[i];
      const cveMatch = f.template ? f.template.match(/(CVE-\d{4}-\d+)/i) : null;
      vulnerabilities.push({
        id: `v${i + 1}`,
        severity: f.severity || "info",
        cveId: cveMatch ? cveMatch[1] : undefined,
        url: f.url || "",
        title: (f.template || "").replace(/[-_]/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase()),
        description: f.raw || `Detected by template: ${f.template}`,
        remediation: "Review and patch the affected component.",
        falsePositive: false,
      });
    }
  }

  // Directories from gobuster
  const gobuster = results.gobuster;
  if (gobuster?.directories) {
    for (const d of gobuster.directories) {
      directories.push({
        path: d.path || "",
        statusCode: d.status || d.statusCode || 0,
        size: d.size || 0,
        interesting: d.interesting || d.sensitive || false,
      });
    }
  }

  // Technologies from whatweb
  const whatweb = results.whatweb;
  if (whatweb?.technologies) {
    for (const t of whatweb.technologies) {
      technologies.push({
        name: t.name || "",
        category: t.category || "Other",
        version: t.version || undefined,
        outdated: t.outdated || false,
      });
    }
  }

  // Screenshots from gowitness
  const gowitness = results.gowitness;
  if (gowitness?.screenshots) {
    for (const s of gowitness.screenshots) {
      screenshots.push({
        url: s.url || "",
        imageUrl: s.image_url || s.imageUrl || "",
        title: s.title || s.url || "",
      });
    }
  }

  // DNS from dnsx + dig + whois
  const dnsx = results.dnsx;
  if (dnsx) {
    dns.a = dnsx.a || dnsx.A || [];
    dns.aaaa = dnsx.aaaa || dnsx.AAAA || [];
    dns.mx = (dnsx.mx || dnsx.MX || []).map((m: any) =>
      typeof m === "string" ? { host: m, priority: 10 } : m
    );
    dns.ns = dnsx.ns || dnsx.NS || [];
    dns.txt = dnsx.txt || dnsx.TXT || [];
    dns.cname = dnsx.cname || dnsx.CNAME || [];
  }

  const whoisData = results.whois;
  if (whoisData) {
    dns.whois = {
      registrar: whoisData.registrar || "",
      createdDate: whoisData.created_date || whoisData.createdDate || "",
      expiryDate: whoisData.expiry_date || whoisData.expiryDate || "",
      nameServers: whoisData.name_servers || whoisData.nameServers || [],
    };
    dns.spf = whoisData.spf ?? dns.spf;
    dns.dmarc = whoisData.dmarc ?? dns.dmarc;
    dns.dkim = whoisData.dkim ?? dns.dkim;
  }

  // Secrets from theHarvester
  const harvester = results.theHarvester;
  if (harvester?.emails) {
    for (const email of harvester.emails) {
      secrets.push({
        type: "email",
        source: "theHarvester",
        value: typeof email === "string" ? email : email.value || "",
        severity: "low",
      });
    }
  }

  return {
    subdomains,
    ports,
    vulnerabilities,
    directories,
    technologies,
    screenshots,
    dns,
    secrets,
    logs: [],
  };
}
