export interface ScanModule {
  id: string;
  name: string;
  tools: string;
  icon: string;
  enabled: boolean;
  category: "discovery" | "fingerprint" | "active" | "passive";
}

export interface ScanConfig {
  domain: string;
  modules: string[];
  profile: string;
  wordlist: string;
  threads: number;
  authorized: boolean;
}

export type ScanStatus = "idle" | "running" | "completed" | "failed" | "cancelled";

export interface ScanResult {
  id: string;
  domain: string;
  status: ScanStatus;
  startedAt: string;
  completedAt?: string;
  progress: number;
  activeModule?: string;
  findings: ScanFindings;
}

export interface ScanFindings {
  subdomains: SubdomainResult[];
  ports: PortResult[];
  vulnerabilities: VulnResult[];
  directories: DirectoryResult[];
  technologies: TechResult[];
  screenshots: ScreenshotResult[];
  dns: DnsResult;
  secrets: SecretResult[];
  logs: LogEntry[];
}

export interface SubdomainResult {
  subdomain: string;
  ip: string;
  statusCode: number;
  title: string;
  techStack: string[];
}

export interface PortResult {
  port: number;
  protocol: string;
  service: string;
  version: string;
  risk: "high" | "medium" | "low";
  cves?: string[];
}

export interface VulnResult {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cveId?: string;
  url: string;
  title: string;
  description: string;
  remediation: string;
  falsePositive: boolean;
}

export interface DirectoryResult {
  path: string;
  statusCode: number;
  size: number;
  interesting: boolean;
}

export interface TechResult {
  name: string;
  category: string;
  version?: string;
  outdated: boolean;
}

export interface ScreenshotResult {
  url: string;
  imageUrl: string;
  title: string;
}

export interface DnsResult {
  a: string[];
  aaaa: string[];
  mx: { host: string; priority: number }[];
  ns: string[];
  txt: string[];
  cname: string[];
  whois: {
    registrar: string;
    createdDate: string;
    expiryDate: string;
    nameServers: string[];
  };
  spf: boolean;
  dmarc: boolean;
  dkim: boolean;
}

export interface SecretResult {
  type: "api_key" | "token" | "password" | "email" | "bucket" | "github_dork";
  source: string;
  value: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface LogEntry {
  timestamp: string;
  module: string;
  level: "info" | "warn" | "error" | "success";
  message: string;
}
