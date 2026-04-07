// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Enterprise Platform Configuration
 * 
 * Defines enterprise-specific configuration options for the Shanom AppSec Platform.
 * Supports multi-tenancy, RBAC, SSO, and centralized management.
 */

export interface EnterpriseConfig {
  /** Platform deployment mode */
  deploymentMode: 'local' | 'self-hosted' | 'managed-cloud';
  
  /** Organization settings */
  organization: {
    id: string;
    name: string;
    slug: string;
    plan: 'community' | 'starter' | 'professional' | 'enterprise';
    features: string[];
    quotas: OrganizationQuotas;
  };
  
  /** Authentication & Authorization */
  auth: {
    mode: 'local' | 'sso' | 'saml' | 'oidc';
    providers: AuthProvider[];
    sessionTimeout: number; // minutes
    mfaRequired: boolean;
    mfaMethods: ('totp' | 'sms' | 'email')[];
  };
  
  /** Access Control */
  rbac: {
    enabled: boolean;
    roles: RoleDefinition[];
    customRoles: boolean;
    permissions: Permission[];
  };
  
  /** Multi-tenancy */
  multitenancy: {
    enabled: boolean;
    isolationLevel: 'logical' | 'container' | 'vpc';
    dataResidency: string; // region code
    crossTenantAccess: boolean;
  };
  
  /** Audit & Compliance */
  audit: {
    enabled: boolean;
    retentionDays: number;
    exportFormats: ('json' | 'csv' | 'pdf')[];
    siemIntegration: boolean;
    complianceFrameworks: string[]; // SOC2, ISO27001, etc.
  };
  
  /** Integrations */
  integrations: {
    cicd: CiCDIntegration[];
    ticketing: TicketingIntegration[];
    messaging: MessagingIntegration[];
    scm: SCMIntegration[];
  };
  
  /** Security Policies */
  policies: {
    passwordPolicy: PasswordPolicy;
    ipAllowlist: string[];
    dataRetention: DataRetentionPolicy;
    vulnerabilitySLA: VulnerabilitySLA;
  };
  
  /** Infrastructure */
  infrastructure: {
    runnerMode: 'shared' | 'dedicated' | 'hybrid';
    autoScaling: boolean;
    maxParallelScans: number;
    resourceLimits: ResourceLimits;
  };
  
  /** Reporting & Dashboards */
  reporting: {
    customDashboards: boolean;
    scheduledReports: boolean;
    executiveReports: boolean;
    apiAccess: boolean;
  };
}

export interface OrganizationQuotas {
  maxProjects: number;
  maxUsers: number;
  maxScansPerMonth: number;
  maxConcurrentScans: number;
  storageGB: number;
  apiCallsPerMinute: number;
}

export interface AuthProvider {
  id: string;
  type: 'google' | 'github' | 'azure-ad' | 'okta' | 'saml' | 'oidc';
  name: string;
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface RoleDefinition {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  isDefault: boolean;
  isSystem: boolean;
}

export type Permission =
  // Organization
  | 'org:read' | 'org:write' | 'org:delete' | 'org:admin'
  // Projects
  | 'project:create' | 'project:read' | 'project:write' | 'project:delete'
  // Scans
  | 'scan:trigger' | 'scan:read' | 'scan:delete' | 'scan:configure'
  // Findings
  | 'finding:read' | 'finding:write' | 'finding:mark-false-positive'
  // Reports
  | 'report:read' | 'report:write' | 'report:export'
  // Admin
  | 'user:manage' | 'role:manage' | 'policy:manage' | 'integration:manage';

export interface CiCDIntegration {
  id: string;
  type: 'github-actions' | 'gitlab-ci' | 'jenkins' | 'azure-devops' | 'circleci' | 'travis';
  name: string;
  enabled: boolean;
  config: {
    webhookUrl?: string;
    apiToken?: string;
    pipelineConfig?: string;
    autoBlockOnFailure?: boolean;
    qualityGateRules?: QualityGateRule[];
  };
}

export interface QualityGateRule {
  severity: 'critical' | 'high' | 'medium' | 'low';
  maxFindings: number;
  failOnUntriaged: boolean;
}

export interface TicketingIntegration {
  id: string;
  type: 'jira' | 'azure-devops' | 'github-issues' | 'linear';
  enabled: boolean;
  config: {
    url: string;
    projectKey: string;
    issueType: string;
    autoCreate: boolean;
    severityMapping: Record<string, string>;
  };
}

export interface MessagingIntegration {
  id: string;
  type: 'slack' | 'teams' | 'discord' | 'webhook';
  enabled: boolean;
  config: {
    webhookUrl: string;
    channels: string[];
    notifyOn: ('scan-complete' | 'finding-critical' | 'policy-violation')[];
  };
}

export interface SCMIntegration {
  id: string;
  type: 'github' | 'gitlab' | 'bitbucket' | 'azure-repos';
  enabled: boolean;
  config: {
    url?: string;
    autoImportRepos: boolean;
    prScanning: boolean;
    autoComment: boolean;
    branchFilters: string[];
  };
}

export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  maxAgeDays: number;
  preventReuse: number;
}

export interface DataRetentionPolicy {
  scanResultsDays: number;
  auditLogsDays: number;
  rawDataDays: number;
  archiveEnabled: boolean;
}

export interface VulnerabilitySLA {
  critical: number; // hours
  high: number;     // hours
  medium: number;   // hours
  low: number;      // hours
  autoEscalate: boolean;
}

export interface ResourceLimits {
  maxScanDuration: number; // minutes
  maxMemoryPerScan: number; // MB
  maxCpuPerScan: number; // cores
  maxFileSize: number; // MB
}

/**
 * Default enterprise configuration for community/self-hosted
 */
export const DEFAULT_ENTERPRISE_CONFIG: EnterpriseConfig = {
  deploymentMode: 'local',
  
  organization: {
    id: 'default',
    name: 'Default Organization',
    slug: 'default',
    plan: 'community',
    features: ['sast', 'sca', 'secrets', 'pentest'],
    quotas: {
      maxProjects: 10,
      maxUsers: 5,
      maxScansPerMonth: 100,
      maxConcurrentScans: 2,
      storageGB: 50,
      apiCallsPerMinute: 100,
    },
  },
  
  auth: {
    mode: 'local',
    providers: [],
    sessionTimeout: 480, // 8 hours
    mfaRequired: false,
    mfaMethods: ['totp'],
  },
  
  rbac: {
    enabled: true,
    roles: [
      {
        id: 'admin',
        name: 'Administrator',
        description: 'Full access to organization',
        permissions: ['*'],
        isDefault: false,
        isSystem: true,
      },
      {
        id: 'security-engineer',
        name: 'Security Engineer',
        description: 'Can manage scans and view findings',
        permissions: [
          'org:read',
          'project:create', 'project:read', 'project:write',
          'scan:trigger', 'scan:read', 'scan:configure',
          'finding:read', 'finding:write', 'finding:mark-false-positive',
          'report:read', 'report:export',
        ],
        isDefault: true,
        isSystem: true,
      },
      {
        id: 'developer',
        name: 'Developer',
        description: 'Can view own project findings',
        permissions: [
          'org:read',
          'project:read',
          'scan:read',
          'finding:read',
          'report:read',
        ],
        isDefault: false,
        isSystem: true,
      },
      {
        id: 'viewer',
        name: 'Viewer',
        description: 'Read-only access',
        permissions: [
          'org:read',
          'project:read',
          'scan:read',
          'finding:read',
          'report:read',
        ],
        isDefault: false,
        isSystem: true,
      },
    ],
    customRoles: false,
    permissions: [],
  },
  
  multitenancy: {
    enabled: false,
    isolationLevel: 'logical',
    dataResidency: 'us-east-1',
    crossTenantAccess: false,
  },
  
  audit: {
    enabled: true,
    retentionDays: 90,
    exportFormats: ['json', 'csv'],
    siemIntegration: false,
    complianceFrameworks: [],
  },
  
  integrations: {
    cicd: [],
    ticketing: [],
    messaging: [],
    scm: [],
  },
  
  policies: {
    passwordPolicy: {
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      maxAgeDays: 90,
      preventReuse: 5,
    },
    ipAllowlist: [],
    dataRetention: {
      scanResultsDays: 365,
      auditLogsDays: 2555, // 7 years
      rawDataDays: 30,
      archiveEnabled: true,
    },
    vulnerabilitySLA: {
      critical: 24,
      high: 72,
      medium: 168, // 1 week
      low: 720,    // 30 days
      autoEscalate: true,
    },
  },
  
  infrastructure: {
    runnerMode: 'shared',
    autoScaling: false,
    maxParallelScans: 2,
    resourceLimits: {
      maxScanDuration: 120,  // 2 hours
      maxMemoryPerScan: 4096, // 4GB
      maxCpuPerScan: 2,
      maxFileSize: 100,     // 100MB
    },
  },
  
  reporting: {
    customDashboards: false,
    scheduledReports: false,
    executiveReports: true,
    apiAccess: true,
  },
};

/**
 * Load enterprise configuration from environment or config file
 */
export function loadEnterpriseConfig(): EnterpriseConfig {
  // In production, this would load from database or config management
  // For now, return default with environment overrides
  const config = { ...DEFAULT_ENTERPRISE_CONFIG };
  
  // Override from environment variables
  if (process.env.SHANOM_DEPLOYMENT_MODE) {
    config.deploymentMode = process.env.SHANOM_DEPLOYMENT_MODE as EnterpriseConfig['deploymentMode'];
  }
  
  if (process.env.SHANOM_ORG_PLAN) {
    config.organization.plan = process.env.SHANOM_ORG_PLAN as EnterpriseConfig['organization']['plan'];
  }
  
  if (process.env.SHANOM_MFA_REQUIRED === 'true') {
    config.auth.mfaRequired = true;
  }
  
  if (process.env.SHANOM_MULTITENANCY_ENABLED === 'true') {
    config.multitenancy.enabled = true;
  }
  
  return config;
}

/**
 * Check if feature is available for current plan
 */
export function isFeatureEnabled(config: EnterpriseConfig, feature: string): boolean {
  const planFeatures: Record<string, string[]> = {
    'community': ['sast', 'sca', 'secrets', 'pentest'],
    'starter': ['sast', 'sca', 'secrets', 'pentest', 'cicd-integration'],
    'professional': ['sast', 'sca', 'secrets', 'pentest', 'cicd-integration', 'ticketing-integration', 'api-access', 'custom-dashboards'],
    'enterprise': ['*'], // All features
  };
  
  const allowedFeatures = planFeatures[config.organization.plan] || [];
  return allowedFeatures.includes('*') || allowedFeatures.includes(feature);
}

/**
 * Get effective quotas (can be overridden for specific users/projects)
 */
export function getEffectiveQuotas(config: EnterpriseConfig, overrides?: Partial<OrganizationQuotas>): OrganizationQuotas {
  return {
    ...config.organization.quotas,
    ...overrides,
  };
}
