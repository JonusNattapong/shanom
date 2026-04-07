// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Multi-Tenancy Service
 * 
 * Manages tenant isolation, data residency, and cross-tenant access controls
 * for the Shanom Enterprise AppSec Platform.
 */

import { fs, path } from 'zx';
import type { ActivityLogger } from '../types/activity-logger.js';

export interface Tenant {
  id: string;
  slug: string;
  name: string;
  domain?: string;
  status: 'active' | 'suspended' | 'deactivated';
  plan: 'community' | 'starter' | 'professional' | 'enterprise';
  
  // Data residency
  region: string; // us-east-1, eu-west-1, ap-southeast-1, etc.
  dataResidency: 'us' | 'eu' | 'asia' | 'custom';
  
  // Settings
  settings: TenantSettings;
  
  // Quotas
  quotas: TenantQuotas;
  
  // Timestamps
  createdAt: Date;
  updatedAt: Date;
}

export interface TenantSettings {
  features: string[];
  authProviders: string[];
  mfaRequired: boolean;
  ssoEnabled: boolean;
  ipAllowlist: string[];
  dataRetentionDays: number;
  auditLogRetentionDays: number;
}

export interface TenantQuotas {
  maxProjects: number;
  maxUsers: number;
  maxScansPerDay: number;
  maxConcurrentScans: number;
  storageGB: number;
  apiCallsPerMinute: number;
}

export interface TenantContext {
  tenantId: string;
  userId: string;
  role: string;
  permissions: string[];
  impersonating?: string;
}

export interface TenantIsolation {
  level: 'logical' | 'container' | 'vpc';
  database: 'shared-schema' | 'schema-per-tenant' | 'database-per-tenant';
  storage: 'shared' | 'isolated';
  compute: 'shared' | 'dedicated' | 'hybrid';
}

export class MultiTenancyService {
  private tenants: Map<string, Tenant> = new Map();
  private logger?: ActivityLogger;
  private isolation: TenantIsolation;
  
  constructor(
    isolation: TenantIsolation,
    logger?: ActivityLogger
  ) {
    this.isolation = isolation;
    this.logger = logger;
  }
  
  /**
   * Create a new tenant (organization)
   */
  async createTenant(params: {
    name: string;
    slug: string;
    plan: Tenant['plan'];
    region?: string;
    adminEmail: string;
  }): Promise<Tenant> {
    const id = `tenant-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const tenant: Tenant = {
      id,
      slug: params.slug,
      name: params.name,
      status: 'active',
      plan: params.plan,
      region: params.region || 'us-east-1',
      dataResidency: this.mapRegionToResidency(params.region || 'us-east-1'),
      settings: this.getDefaultSettings(params.plan),
      quotas: this.getDefaultQuotas(params.plan),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    // Store tenant
    this.tenants.set(id, tenant);
    this.tenants.set(params.slug, tenant); // Also index by slug
    
    // Create tenant isolation resources
    await this.createTenantResources(tenant);
    
    this.logger?.info(`Created tenant ${tenant.slug} (${tenant.id}) with plan ${tenant.plan}`);
    
    return tenant;
  }
  
  /**
   * Get tenant by ID or slug
   */
  async getTenant(idOrSlug: string): Promise<Tenant | null> {
    return this.tenants.get(idOrSlug) || null;
  }
  
  /**
   * Update tenant settings
   */
  async updateTenant(
    tenantId: string,
    updates: Partial<Pick<Tenant, 'name' | 'settings' | 'quotas'>>
  ): Promise<Tenant | null> {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) return null;
    
    if (updates.name) tenant.name = updates.name;
    if (updates.settings) tenant.settings = { ...tenant.settings, ...updates.settings };
    if (updates.quotas) tenant.quotas = { ...tenant.quotas, ...updates.quotas };
    
    tenant.updatedAt = new Date();
    
    this.tenants.set(tenant.id, tenant);
    this.tenants.set(tenant.slug, tenant);
    
    return tenant;
  }
  
  /**
   * Suspend or deactivate tenant
   */
  async suspendTenant(tenantId: string, reason: string): Promise<boolean> {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) return false;
    
    tenant.status = 'suspended';
    tenant.updatedAt = new Date();
    
    // Stop all active scans for this tenant
    await this.stopTenantScans(tenantId);
    
    this.logger?.warn(`Suspended tenant ${tenantId}. Reason: ${reason}`);
    
    return true;
  }
  
  /**
   * Delete tenant and all data
   */
  async deleteTenant(tenantId: string): Promise<boolean> {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) return false;
    
    // Delete all tenant data
    await this.deleteTenantData(tenantId);
    
    // Remove from cache
    this.tenants.delete(tenant.id);
    this.tenants.delete(tenant.slug);
    
    this.logger?.info(`Deleted tenant ${tenantId}`);
    
    return true;
  }
  
  /**
   * Check if tenant has exceeded quotas
   */
  async checkQuota(tenantId: string, quotaType: keyof TenantQuotas): Promise<{
    allowed: boolean;
    current: number;
    limit: number;
    remaining: number;
  }> {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) {
      return { allowed: false, current: 0, limit: 0, remaining: 0 };
    }
    
    const limit = tenant.quotas[quotaType];
    const current = await this.getCurrentUsage(tenantId, quotaType);
    
    return {
      allowed: current < limit,
      current,
      limit,
      remaining: Math.max(0, limit - current),
    };
  }
  
  /**
   * Get tenant-specific data path (for storage isolation)
   */
  async getTenantDataPath(tenantId: string, dataType: 'scans' | 'reports' | 'audit' | 'cache'): Promise<string> {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) throw new Error(`Tenant ${tenantId} not found`);
    
    switch (this.isolation.storage) {
      case 'isolated':
        return path.join('/data/tenants', tenantId, dataType);
      case 'shared':
      default:
        return path.join('/data/shared', dataType, tenantId);
    }
  }
  
  /**
   * Get database connection config for tenant
   */
  async getTenantDatabaseConfig(tenantId: string): Promise<{
    host: string;
    database: string;
    schema?: string;
    poolSize: number;
  }> {
    switch (this.isolation.database) {
      case 'database-per-tenant':
        return {
          host: 'localhost',
          database: `shanom_${tenantId}`,
          poolSize: 5,
        };
      case 'schema-per-tenant':
        return {
          host: 'localhost',
          database: 'shanom_multi',
          schema: `tenant_${tenantId}`,
          poolSize: 5,
        };
      case 'shared-schema':
      default:
        return {
          host: 'localhost',
          database: 'shanom',
          poolSize: 10,
        };
    }
  }
  
  /**
   * Validate tenant context for operation
   */
  validateContext(context: TenantContext, requiredPermission?: string): boolean {
    // Check if tenant is active
    const tenant = this.tenants.get(context.tenantId);
    if (!tenant || tenant.status !== 'active') {
      return false;
    }
    
    // Check permission if required
    if (requiredPermission && !context.permissions.includes(requiredPermission)) {
      return false;
    }
    
    return true;
  }
  
  /**
   * List all tenants (admin only)
   */
  async listTenants(filters?: {
    status?: Tenant['status'];
    plan?: Tenant['plan'];
    region?: string;
  }): Promise<Tenant[]> {
    let tenants = Array.from(this.tenants.values());
    
    // Remove duplicates (both id and slug indexed)
    const seen = new Set<string>();
    tenants = tenants.filter(t => {
      if (seen.has(t.id)) return false;
      seen.add(t.id);
      return true;
    });
    
    if (filters?.status) {
      tenants = tenants.filter(t => t.status === filters.status);
    }
    if (filters?.plan) {
      tenants = tenants.filter(t => t.plan === filters.plan);
    }
    if (filters?.region) {
      tenants = tenants.filter(t => t.region === filters.region);
    }
    
    return tenants;
  }
  
  /**
   * Get tenant statistics
   */
  async getTenantStats(tenantId: string): Promise<{
    totalScans: number;
    activeScans: number;
    totalFindings: number;
    criticalFindings: number;
    totalUsers: number;
    storageUsed: number; // bytes
  }> {
    // In production, query from database
    return {
      totalScans: 0,
      activeScans: 0,
      totalFindings: 0,
      criticalFindings: 0,
      totalUsers: 0,
      storageUsed: 0,
    };
  }
  
  /**
   * Map AWS region to data residency zone
   */
  private mapRegionToResidency(region: string): Tenant['dataResidency'] {
    if (region.startsWith('eu-')) return 'eu';
    if (region.startsWith('ap-')) return 'asia';
    if (region.startsWith('us-')) return 'us';
    return 'custom';
  }
  
  /**
   * Get default settings for plan
   */
  private getDefaultSettings(plan: Tenant['plan']): TenantSettings {
    const baseSettings: TenantSettings = {
      features: ['sast', 'sca', 'secrets'],
      authProviders: ['local'],
      mfaRequired: false,
      ssoEnabled: false,
      ipAllowlist: [],
      dataRetentionDays: 365,
      auditLogRetentionDays: 2555,
    };
    
    switch (plan) {
      case 'enterprise':
        return {
          ...baseSettings,
          features: ['*'], // All features
          authProviders: ['local', 'sso', 'saml', 'oidc'],
          mfaRequired: true,
          ssoEnabled: true,
        };
      case 'professional':
        return {
          ...baseSettings,
          features: ['sast', 'sca', 'secrets', 'pentest', 'cicd', 'ticketing'],
          authProviders: ['local', 'sso'],
          ssoEnabled: true,
        };
      case 'starter':
        return {
          ...baseSettings,
          features: ['sast', 'sca', 'secrets'],
        };
      case 'community':
      default:
        return baseSettings;
    }
  }
  
  /**
   * Get default quotas for plan
   */
  private getDefaultQuotas(plan: Tenant['plan']): TenantQuotas {
    const quotas: Record<Tenant['plan'], TenantQuotas> = {
      community: {
        maxProjects: 3,
        maxUsers: 5,
        maxScansPerDay: 10,
        maxConcurrentScans: 1,
        storageGB: 10,
        apiCallsPerMinute: 60,
      },
      starter: {
        maxProjects: 10,
        maxUsers: 20,
        maxScansPerDay: 50,
        maxConcurrentScans: 2,
        storageGB: 50,
        apiCallsPerMinute: 300,
      },
      professional: {
        maxProjects: 50,
        maxUsers: 100,
        maxScansPerDay: 200,
        maxConcurrentScans: 5,
        storageGB: 250,
        apiCallsPerMinute: 1000,
      },
      enterprise: {
        maxProjects: 500,
        maxUsers: 500,
        maxScansPerDay: 1000,
        maxConcurrentScans: 20,
        storageGB: 1000,
        apiCallsPerMinute: 5000,
      },
    };
    
    return quotas[plan] || quotas.community;
  }
  
  /**
   * Create tenant-specific resources
   */
  private async createTenantResources(tenant: Tenant): Promise<void> {
    // Create tenant directories
    const dataPath = await this.getTenantDataPath(tenant.id, 'scans');
    await fs.ensureDir(dataPath);
    
    // Create database schema if needed
    if (this.isolation.database === 'schema-per-tenant') {
      // Create schema
      this.logger?.info(`Created schema for tenant ${tenant.id}`);
    } else if (this.isolation.database === 'database-per-tenant') {
      // Create database
      this.logger?.info(`Created database for tenant ${tenant.id}`);
    }
    
    // Initialize audit log
    this.logger?.info(`Initialized audit log for tenant ${tenant.id}`);
  }
  
  /**
   * Stop all scans for a tenant
   */
  private async stopTenantScans(tenantId: string): Promise<void> {
    this.logger?.info(`Stopping all scans for tenant ${tenantId}`);
    // Implementation would cancel active workflows
  }
  
  /**
   * Delete all tenant data
   */
  private async deleteTenantData(tenantId: string): Promise<void> {
    // Delete files
    for (const dataType of ['scans', 'reports', 'audit', 'cache'] as const) {
      const dataPath = await this.getTenantDataPath(tenantId, dataType);
      try {
        await fs.remove(dataPath);
      } catch {
        // Ignore errors
      }
    }
    
    // Delete database data
    this.logger?.info(`Deleted all data for tenant ${tenantId}`);
  }
  
  /**
   * Get current usage for quota type
   */
  private async getCurrentUsage(tenantId: string, quotaType: keyof TenantQuotas): Promise<number> {
    // In production, query from database/metrics
    return 0;
  }
}
