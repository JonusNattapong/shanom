// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Unified CLI Configuration
 * 
 * Supports both Local Mode (Shanom Lite) and Enterprise Mode (Shanom Pro)
 * 
 * Local Mode:
 * - Direct CLI execution
 * - Local Docker containers
 * - File-based storage
 * - Single user/organization
 * 
 * Enterprise Mode:
 * - Platform API integration
 * - Remote or self-hosted runners
 * - Database-backed storage
 * - Multi-tenant with RBAC
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export type CLIMode = 'local' | 'enterprise';

export interface UnifiedCLIConfig {
  /** CLI operating mode */
  mode: CLIMode;
  
  /** CLI version */
  version: string;
  
  /** Local mode settings */
  local: {
    enabled: boolean;
    workspacesDir: string;
    promptsDir?: string;
    dockerNetwork: string;
    autoBuild: boolean;
  };
  
  /** Enterprise mode settings */
  enterprise: {
    enabled: boolean;
    apiEndpoint: string;
    apiKey?: string;
    organization?: string;
    project?: string;
    runnerMode: 'shared' | 'dedicated' | 'self-hosted';
    pollingInterval: number; // seconds
  };
  
  /** Authentication */
  auth: {
    mode: 'none' | 'api-key' | 'oauth' | 'sso';
    credentialsPath?: string;
    autoLogin: boolean;
  };
  
  /** Scan defaults */
  defaults: {
    outputFormat: 'markdown' | 'json' | 'sarif' | 'pdf';
    severityThreshold: 'info' | 'low' | 'medium' | 'high' | 'critical';
    maxScanDuration: number; // minutes
    parallelScans: number;
  };
  
  /** Logging */
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error';
    file?: string;
    json: boolean;
  };
}

/**
 * Default configuration for local mode
 */
export const DEFAULT_LOCAL_CONFIG: UnifiedCLIConfig = {
  mode: 'local',
  version: '1.0.0',
  
  local: {
    enabled: true,
    workspacesDir: path.join(os.homedir(), '.shanom', 'workspaces'),
    dockerNetwork: 'shanom-network',
    autoBuild: true,
  },
  
  enterprise: {
    enabled: false,
    apiEndpoint: 'https://api.shanom.io',
    runnerMode: 'shared',
    pollingInterval: 5,
  },
  
  auth: {
    mode: 'api-key',
    autoLogin: false,
  },
  
  defaults: {
    outputFormat: 'markdown',
    severityThreshold: 'info',
    maxScanDuration: 120,
    parallelScans: 2,
  },
  
  logging: {
    level: 'info',
    json: false,
  },
};

/**
 * Configuration file paths
 */
export function getConfigPaths() {
  const homeDir = os.homedir();
  
  return {
    // Global config
    globalConfig: path.join(homeDir, '.shanom', 'config.json'),
    
    // Enterprise-specific
    enterpriseConfig: path.join(homeDir, '.shanom', 'enterprise.json'),
    
    // Local credentials
    credentials: path.join(homeDir, '.shanom', 'credentials.json'),
    
    // Session/cache
    session: path.join(homeDir, '.shanom', 'session.json'),
    cache: path.join(homeDir, '.shanom', 'cache'),
    
    // Workspaces
    workspaces: path.join(homeDir, '.shanom', 'workspaces'),
    
    // Logs
    logs: path.join(homeDir, '.shanom', 'logs'),
  };
}

/**
 * Load CLI configuration
 */
export function loadConfig(): UnifiedCLIConfig {
  const paths = getConfigPaths();
  const config = { ...DEFAULT_LOCAL_CONFIG };
  
  // Load global config if exists
  if (fs.existsSync(paths.globalConfig)) {
    try {
      const globalConfig = JSON.parse(fs.readFileSync(paths.globalConfig, 'utf8'));
      Object.assign(config, globalConfig);
    } catch {
      // Ignore parse errors
    }
  }
  
  // Override from environment
  if (process.env.SHANOM_MODE) {
    config.mode = process.env.SHANOM_MODE as CLIMode;
  }
  
  if (process.env.SHANOM_API_ENDPOINT) {
    config.enterprise.apiEndpoint = process.env.SHANOM_API_ENDPOINT;
    config.enterprise.enabled = true;
    config.local.enabled = false;
  }
  
  if (process.env.SHANOM_API_KEY) {
    config.enterprise.apiKey = process.env.SHANOM_API_KEY;
    config.auth.mode = 'api-key';
  }
  
  if (process.env.SHANOM_ORGANIZATION) {
    config.enterprise.organization = process.env.SHANOM_ORGANIZATION;
  }
  
  // Validate mode
  if (config.mode === 'enterprise' && !config.enterprise.apiKey) {
    console.warn('Enterprise mode requires API key. Falling back to local mode.');
    config.mode = 'local';
    config.local.enabled = true;
    config.enterprise.enabled = false;
  }
  
  return config;
}

/**
 * Save CLI configuration
 */
export function saveConfig(config: Partial<UnifiedCLIConfig>): void {
  const paths = getConfigPaths();
  
  // Ensure directory exists
  fs.mkdirSync(path.dirname(paths.globalConfig), { recursive: true });
  
  // Merge with existing config
  const existing = loadConfig();
  const merged = { ...existing, ...config };
  
  fs.writeFileSync(paths.globalConfig, JSON.stringify(merged, null, 2), 'utf8');
}

/**
 * Initialize CLI directories
 */
export function initCLI(): void {
  const paths = getConfigPaths();
  
  for (const dirPath of [paths.workspaces, paths.cache, paths.logs]) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
  
  // Create default config if not exists
  if (!fs.existsSync(paths.globalConfig)) {
    saveConfig(DEFAULT_LOCAL_CONFIG);
  }
}

/**
 * Switch between local and enterprise mode
 */
export function switchMode(mode: CLIMode, options?: {
  apiEndpoint?: string;
  apiKey?: string;
  organization?: string;
}): void {
  const config = loadConfig();
  
  config.mode = mode;
  
  if (mode === 'local') {
    config.local.enabled = true;
    config.enterprise.enabled = false;
  } else {
    config.local.enabled = false;
    config.enterprise.enabled = true;
    
    if (options?.apiEndpoint) {
      config.enterprise.apiEndpoint = options.apiEndpoint;
    }
    if (options?.apiKey) {
      config.enterprise.apiKey = options.apiKey;
    }
    if (options?.organization) {
      config.enterprise.organization = options.organization;
    }
  }
  
  saveConfig(config);
}

/**
 * Get current mode display name
 */
export function getModeDisplayName(config?: UnifiedCLIConfig): string {
  const cfg = config || loadConfig();
  
  if (cfg.mode === 'enterprise') {
    return `Enterprise (${cfg.enterprise.organization || 'No Org'})`;
  }
  
  return 'Local (Shanom Lite)';
}

/**
 * Check if running in CI/CD environment
 */
export function isCI(): boolean {
  return !!(
    process.env.CI ||
    process.env.GITHUB_ACTIONS ||
    process.env.GITLAB_CI ||
    process.env.JENKINS_URL ||
    process.env.BUILDKITE ||
    process.env.TRAVIS
  );
}

/**
 * Get appropriate output format for environment
 */
export function getDefaultOutputFormat(config?: UnifiedCLIConfig): string {
  const cfg = config || loadConfig();
  
  if (isCI()) {
    return 'sarif'; // CI/CD prefers SARIF for integration
  }
  
  return cfg.defaults.outputFormat;
}

/**
 * Enterprise API Client
 */
export class EnterpriseAPIClient {
  private config: UnifiedCLIConfig['enterprise'];
  private baseURL: string;
  
  constructor(config: UnifiedCLIConfig['enterprise']) {
    this.config = config;
    this.baseURL = config.apiEndpoint.replace(/\/$/, '');
  }
  
  /**
   * Make authenticated API request
   */
  async request<T>(
    method: string,
    endpoint: string,
    body?: unknown
  ): Promise<{ success: boolean; data?: T; error?: string }> {
    const url = `${this.baseURL}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }
    
    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });
      
      if (!response.ok) {
        return {
          success: false,
          error: `HTTP ${response.status}: ${await response.text()}`,
        };
      }
      
      const data = await response.json() as T;
      return { success: true, data };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }
  
  /**
   * Get organizations
   */
  async getOrganizations(): Promise<{ id: string; name: string; slug: string }[]> {
    const result = await this.request<{ organizations: { id: string; name: string; slug: string }[] }>('GET', '/api/v1/organizations');
    return result.success ? result.data?.organizations || [] : [];
  }
  
  /**
   * Get projects
   */
  async getProjects(orgSlug: string): Promise<{ id: string; name: string; slug: string }[]> {
    const result = await this.request<{ projects: { id: string; name: string; slug: string }[] }>('GET', `/api/v1/organizations/${orgSlug}/projects`);
    return result.success ? result.data?.projects || [] : [];
  }
  
  /**
   * Trigger scan
   */
  async triggerScan(
    orgSlug: string,
    projectSlug: string,
    params: {
      targetUrl: string;
      repoUrl?: string;
      scanType: 'full' | 'sast' | 'sca' | 'secrets' | 'pentest';
      config?: Record<string, unknown>;
    }
  ): Promise<{ scanId: string; status: string } | null> {
    const result = await this.request<{ scan: { id: string; status: string } }>(
      'POST',
      `/api/v1/organizations/${orgSlug}/projects/${projectSlug}/scans`,
      params
    );
    
    if (result.success && result.data?.scan) {
      return { scanId: result.data.scan.id, status: result.data.scan.status };
    }
    
    return null;
  }
  
  /**
   * Get scan status
   */
  async getScanStatus(
    orgSlug: string,
    projectSlug: string,
    scanId: string
  ): Promise<{ status: string; progress: number; findings: number } | null> {
    const result = await this.request<{ scan: { status: string; progress: number; findingsCount: number } }>(
      'GET',
      `/api/v1/organizations/${orgSlug}/projects/${projectSlug}/scans/${scanId}`
    );
    
    if (result.success && result.data?.scan) {
      return {
        status: result.data.scan.status,
        progress: result.data.scan.progress,
        findings: result.data.scan.findingsCount,
      };
    }
    
    return null;
  }
  
  /**
   * Download scan report
   */
  async downloadReport(
    orgSlug: string,
    projectSlug: string,
    scanId: string,
    format: 'markdown' | 'json' | 'sarif' | 'pdf'
  ): Promise<Buffer | null> {
    const result = await fetch(
      `${this.baseURL}/api/v1/organizations/${orgSlug}/projects/${projectSlug}/scans/${scanId}/report?format=${format}`,
      {
        headers: {
          'Authorization': `Bearer ${this.config.apiKey || ''}`,
        },
      }
    );
    
    if (result.ok) {
      return Buffer.from(await result.arrayBuffer());
    }
    
    return null;
  }
}

/**
 * Login to enterprise platform
 */
export async function loginEnterprise(
  apiEndpoint: string,
  apiKey: string,
  organization?: string
): Promise<{ success: boolean; error?: string; organizations?: { id: string; name: string }[] }> {
  const client = new EnterpriseAPIClient({
    apiEndpoint,
    apiKey,
    runnerMode: 'shared',
    pollingInterval: 5,
    organization,
  });
  
  // Verify credentials by fetching organizations
  const orgs = await client.getOrganizations();
  
  if (orgs.length === 0 && organization) {
    return { success: false, error: 'Invalid API key or no access to organizations' };
  }
  
  // Save configuration
  switchMode('enterprise', { apiEndpoint, apiKey, organization });
  
  return {
    success: true,
    organizations: orgs.map(o => ({ id: o.id, name: o.name })),
  };
}

/**
 * Logout from enterprise platform
 */
export function logoutEnterprise(): void {
  switchMode('local');
}

/**
 * Get CLI status summary
 */
export function getCLIStatus(): {
  mode: CLIMode;
  version: string;
  enterpriseConnected: boolean;
  organization?: string;
  workspaceCount: number;
} {
  const config = loadConfig();
  const paths = getConfigPaths();
  
  let workspaceCount = 0;
  try {
    if (fs.existsSync(paths.workspaces)) {
      workspaceCount = fs.readdirSync(paths.workspaces).length;
    }
  } catch {
    // Ignore
  }
  
  return {
    mode: config.mode,
    version: config.version,
    enterpriseConnected: config.mode === 'enterprise' && !!config.enterprise.apiKey,
    organization: config.enterprise.organization,
    workspaceCount,
  };
}
