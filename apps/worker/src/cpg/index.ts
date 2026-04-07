// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * CPG (Code Property Graph) Module - Index
 * 
 * Code Property Graph analysis engine with LLM reasoning at every node.
 * Provides sophisticated static analysis capabilities for security assessment.
 * 
 * @example
 * ```typescript
 * import { CPGEngine, DEFAULT_CPG_CONFIG } from './cpg/index.js';
 * 
 * const engine = new CPGEngine(DEFAULT_CPG_CONFIG, logger);
 * const result = await engine.analyzeProject('/path/to/project');
 * 
 * // Access findings
 * for (const finding of result.dataFlowFindings) {
 *   if (finding.isVulnerable) {
 *     console.log(`Vulnerable: ${finding.vulnerabilityType}`);
 *     console.log(`Source: ${finding.source.code}`);
 *     console.log(`Sink: ${finding.sink.code}`);
 *   }
 * }
 * ```
 */

// Core engine and configuration
export {
  CPGEngine,
  DEFAULT_CPG_CONFIG,
  type CPGEngineConfig,
  type CPGAnalysisResult,
} from './engine.js';

// Data models
export {
  CodePropertyGraph,
  type NodeType,
  type EdgeType,
  type CPGNode,
  type CPGEdge,
  type SourceLocation,
  type DataFlowFact,
  type TaintPropagation,
  type CPGBuilder,
  type SourceSinkPattern,
} from './models.js';

// LLM Reasoning
export {
  LLMNodeReasoner,
  type NodeAnalysisContext,
  type NodeAnalysisResult,
  type PathAnalysisResult,
} from './llm-reasoner.js';

// Data Flow Analysis
export {
  DataFlowAnalyzer,
  COMMON_SOURCES,
  COMMON_SINKS,
  type DataFlowFinding,
  type SourceDefinition,
  type SinkDefinition,
} from './data-flow-analyzer.js';

// Simple CPG Builder
export { SimpleCPGBuilder } from './simple-builder.js';
