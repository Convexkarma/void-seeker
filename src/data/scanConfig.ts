import { ScanModule } from "@/types/scan";

export const SCAN_MODULES: ScanModule[] = [
  { id: "subdomain", name: "Subdomain Enumeration", tools: "Subfinder + Amass", icon: "Globe", enabled: true, category: "discovery" },
  { id: "portscan", name: "Port Scanning", tools: "Nmap", icon: "Network", enabled: true, category: "discovery" },
  { id: "techfp", name: "Tech Fingerprinting", tools: "WhatWeb", icon: "Cpu", enabled: true, category: "fingerprint" },
  { id: "dirbrute", name: "Directory Brute Force", tools: "Gobuster/ffuf", icon: "FolderSearch", enabled: true, category: "active" },
  { id: "vulnscan", name: "Vulnerability Scanning", tools: "Nuclei", icon: "ShieldAlert", enabled: true, category: "active" },
  { id: "screenshot", name: "Screenshot Capture", tools: "gowitness", icon: "Camera", enabled: true, category: "passive" },
  { id: "waf", name: "WAF Detection", tools: "wafw00f", icon: "Shield", enabled: false, category: "fingerprint" },
  { id: "dns", name: "DNS Enumeration", tools: "dnsx", icon: "Server", enabled: true, category: "discovery" },
  { id: "asn", name: "ASN & IP Intel", tools: "whois + ipinfo.io", icon: "MapPin", enabled: false, category: "passive" },
  { id: "email", name: "Email Harvesting", tools: "theHarvester", icon: "Mail", enabled: false, category: "passive" },
  { id: "github", name: "GitHub Dorking", tools: "GitHub Search API", icon: "Github", enabled: false, category: "passive" },
  { id: "jsanalysis", name: "JS File Analysis", tools: "linkfinder/secretfinder", icon: "FileCode", enabled: false, category: "active" },
  { id: "ssl", name: "SSL/TLS Analysis", tools: "testssl.sh", icon: "Lock", enabled: true, category: "fingerprint" },
  { id: "cloud", name: "Cloud Storage Finder", tools: "S3/GCS buckets", icon: "Cloud", enabled: false, category: "passive" },
];

export const SCAN_PROFILES = [
  { id: "quick", name: "Quick", duration: "~5 min", description: "Fast passive recon" },
  { id: "standard", name: "Standard", duration: "~15 min", description: "Balanced scan" },
  { id: "deep", name: "Deep", duration: "~45 min", description: "Full active + passive" },
  { id: "stealth", name: "Stealth", duration: "~60 min", description: "Slow + passive only" },
];

export const WORDLISTS = [
  { id: "common", name: "Common (4k words)" },
  { id: "medium", name: "Medium (20k words)" },
  { id: "big", name: "Big (220k words)" },
  { id: "custom", name: "Custom Upload" },
];
