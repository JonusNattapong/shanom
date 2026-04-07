// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Services Module
 *
 * Exports DI container and service classes for Shanom agent execution.
 * Services are pure domain logic with no Temporal dependencies.
 */

export type { AgentExecutionInput } from './agent-execution.js';
export { AgentExecutionService } from './agent-execution.js';

export { ConfigLoaderService } from './config-loader.js';
export type { ContainerDependencies } from './container.js';
export { Container, getOrCreateContainer, removeContainer } from './container.js';
export { ExploitationCheckerService } from './exploitation-checker.js';
export { loadPrompt } from './prompt-manager.js';
export { assembleFinalReport, injectModelIntoReport } from './reporting.js';
export { CPGAnalysisService } from './cpg-analysis.js';
export { CorrelationService } from '../correlation/service.js';

