
import { LucideIcon } from 'lucide-react';

export interface MenuItem {
  name: string;
  path: string;
  icon: LucideIcon;
  badge?: number;
  alert?: boolean;
}

export enum DeviceStatus {
  ONLINE = 'online',
  OFFLINE = 'offline',
  RISK = 'risk',
  CRITICAL = 'critical'
}

export type PolicyCategory = 'Seguridad' | 'Red' | 'Datos' | 'Identidad' | 'Cumplimiento' | 'Sistema';

export interface Policy {
  id: string;
  name: string;
  description: string;
  category: PolicyCategory;
  enabled: boolean;
}

export interface NetworkPort {
  port: number;
  service: string;
  status: 'open' | 'closed' | 'filtered';
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface NetworkFinding {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface Device {
  id: string;
  name: string;
  type: 'PC' | 'Server' | 'Router' | 'Camera' | 'AWS Instance' | 'Firewall' | 'Switch';
  os: string;
  ip: string;
  status: DeviceStatus;
  cpu: number;
  ram: number;
  disk: number;
  network: string;
  agentVersion: string;
  latency: number;
  lastUpdate: string;
  lastOffline?: string;
  protectionActive: boolean;
  department: string;
  vulnerabilities: string[];
  policies: string[];
  ports?: NetworkPort[];
  findings?: NetworkFinding[];
  firmware?: string;
  serialNumber?: string;
}

export enum Severity {
  CRITICAL = 'Critical',
  HIGH = 'High',
  MEDIUM = 'Medium',
  LOW = 'Low'
}

export type LogCategory = 'SYSTEM' | 'SECURITY' | 'NETWORK' | 'USER' | 'SCAN';

export interface LogEntry {
  id: string;
  timestamp: string;
  category: LogCategory;
  severity: 'INFO' | 'NOTICE' | 'WARNING' | 'ERROR' | 'CRITICAL';
  message: string;
  origin: string;
  user: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  target: string;
  targetType: 'PC' | 'Server' | 'Camera' | 'Router';
  department: string;
  timestamp: string;
  status: 'Blocked' | 'Monitoring' | 'Pending' | 'Dismissed';
  attackerIp?: string;
}

export interface Vulnerability {
  id: string;
  cve: string;
  cvss: number;
  severity: Severity;
  target: string;
  status: 'Open' | 'Mitigated' | 'In Risk';
}
