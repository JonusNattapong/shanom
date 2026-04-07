// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Enterprise Platform Module
 * 
 * Shanom Enterprise AppSec Platform - Full-featured security platform for organizations
 * with multi-tenancy, RBAC, SSO, and centralized management.
 * 
 * @example
 * ```typescript
 * import { EnterpriseConfig, MultiTenancyService } from './enterprise/index.js';
 * 
 * // Create enterprise tenant
 * const tenantService = new MultiTenancyService({
 *   level: 'logical',
 *   database: 'schema-per-tenant',
 *   storage: 'isolated',
 *   compute: 'shared'
 * });
 * 
 * const tenant = await tenantService.createTenant({
 *   name: 'Acme Corp',
 *   slug: 'acme',
 *   plan: 'enterprise',
 *   adminEmail: 'admin@acme.com'
 * });
 * ```
 */

// Enterprise Configuration
export {
  loadEnterpriseConfig,
  DEFAULT_ENTERPRISE_CONFIG,
  isFeatureEnabled,
  getEffectiveQuotas,
  type EnterpriseConfig,
  type OrganizationQuotas,
  type AuthProvider,
  type RoleDefinition,
  type Permission,
  type CiCDIntegration,
  type TicketingIntegration,
  type MessagingIntegration,
  type SCMIntegration,
  type PasswordPolicy,
  type DataRetentionPolicy,
  type VulnerabilitySLA,
  type ResourceLimits,
} from './config.js';

// Multi-Tenancy
export {
  MultiTenancyService,
  type Tenant,
  type TenantSettings,
  type TenantQuotas,
  type TenantContext,
  type TenantIsolation,
} from './multi-tenancy.js';
