// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Static-Dynamic Correlation Module
 * 
 * This module provides the core capability for correlating static analysis
 * findings (from CPG) with dynamic exploitation results. This is the key
 * differentiator that validates static findings with real exploits.
 * 
 * @example
 * ```typescript
 * import { CorrelationService } from './correlation/index.js';
 * 
 * const service = new CorrelationService({}, logger);
 * 
 * // Run complete workflow
 * const { staticAnalysis } = await service.runCompleteWorkflow(repoPath);
 * 
 * // After exploitation phase
 * await service.completeCorrelation(staticAnalysis, repoPath);
 * ```
 */

// Core correlation engine
export {
  StaticDynamicCorrelationEngine,
  DEFAULT_CORRELATION_CONFIG,
  type StaticFinding,
  type DynamicFinding,
  type CorrelatedFinding,
  type CorrelationConfig,
} from './engine.js';

// CPG findings injector
export {
  CPGFindingsInjector,
  type InjectedVulnerability,
  type InjectionResult,
} from './injector.js';

// Unified findings merger
export {
  UnifiedFindingsMerger,
  type ExploitationEvidence,
  type UnifiedFinding,
  type MergeResult,
} from './merger.js';

// Main service
export {
  CorrelationService,
  DEFAULT_CORRELATION_WORKFLOW_CONFIG,
  type CorrelationWorkflowConfig,
} from './service.js';
