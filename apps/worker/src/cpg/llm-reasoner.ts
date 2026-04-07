// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * LLM Reasoning Service for CPG Node Analysis
 * 
 * Performs contextual security analysis at each node in the Code Property Graph.
 * Uses LLM reasoning to understand sanitization, validation, and security implications
 * that pattern-based tools cannot detect.
 */

import { runClaudePrompt } from '../ai/claude-executor.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { CPGNode, DataFlowFact, CodePropertyGraph } from './models.js';

export interface NodeAnalysisContext {
  /** The node being analyzed */
  node: CPGNode;
  
  /** Parent nodes in AST */
  parents: CPGNode[];
  
  /** Child nodes in AST */
  children: CPGNode[];
  
  /** Data dependencies */
  dataDeps: CPGNode[];
  
  /** Control flow predecessors */
  controlFlowPreds: CPGNode[];
  
  /** Control flow successors */
  controlFlowSuccs: CPGNode[];
  
  /** Surrounding code context */
  surroundingCode: string;
  
  /** File context */
  fileContext: string;
}

export interface NodeAnalysisResult {
  /** Is this a source of untrusted data? */
  isSource: boolean;
  sourceType?: string;
  sourceConfidence: number;
  
  /** Is this a sink for sensitive operations? */
  isSink: boolean;
  sinkType?: string;
  sinkConfidence: number;
  
  /** Is this data sanitized/validated? */
  isSanitized: boolean;
  sanitizationMethod?: string;
  sanitizationConfidence: number;
  
  /** Is this data validated? */
  isValidated: boolean;
  validationMethod?: string;
  validationConfidence: number;
  
  /** Security assessment */
  securityImplications: string[];
  
  /** Recommended checks */
  recommendedChecks: string[];
  
  /** Confidence in overall assessment (0-1) */
  overallConfidence: number;
  
  /** Raw LLM reasoning output */
  reasoning: string;
}

export interface PathAnalysisResult {
  /** The analyzed path */
  path: string[];
  
  /** Is this path vulnerable? */
  isVulnerable: boolean;
  
  /** Vulnerability type if vulnerable */
  vulnerabilityType?: string;
  
  /** Detailed analysis for each node */
  nodeAnalyses: Map<string, NodeAnalysisResult>;
  
  /** Overall confidence */
  confidence: number;
  
  /** Is the path completely sanitized? */
  isFullySanitized: boolean;
  
  /** Where sanitization occurs if present */
  sanitizationPoints: string[];
  
  /** Reasoning summary */
  summary: string;
}

export class LLMNodeReasoner {
  private logger?: ActivityLogger;
  private modelTier: 'small' | 'medium' | 'large' = 'medium';
  
  constructor(logger?: ActivityLogger, modelTier: 'small' | 'medium' | 'large' = 'medium') {
    this.logger = logger;
    this.modelTier = modelTier;
  }
  
  /**
   * Analyze a single node for security properties
   */
  async analyzeNode(context: NodeAnalysisContext): Promise<NodeAnalysisResult> {
    const prompt = this.buildNodeAnalysisPrompt(context);
    
    const result = await runClaudePrompt(
      prompt,
      context.node.location.file,
      context.surroundingCode,
      `CPG Analysis: ${context.node.label}`,
      'cpg-node-analysis',
      undefined, // No audit session for CPG analysis
      this.logger,
      this.modelTier,
    );
    
    if (!result.success) {
      return this.createDefaultResult(`Analysis failed: ${result.error}`);
    }
    
    return this.parseNodeAnalysisResult(result.result || '');
  }
  
  /**
   * Analyze a data flow path from source to sink
   */
  async analyzePath(
    graph: CodePropertyGraph,
    path: string[],
    sourceDescription: string,
    sinkDescription: string
  ): Promise<PathAnalysisResult> {
    const nodes = path.map(id => graph.getNode(id)).filter((n): n is CPGNode => !!n);
    
    // Analyze each node
    const nodeAnalyses = new Map<string, NodeAnalysisResult>();
    for (const node of nodes) {
      const context = this.buildNodeContext(graph, node);
      const analysis = await this.analyzeNode(context);
      nodeAnalyses.set(node.id, analysis);
    }
    
    // Synthesize path analysis
    const pathPrompt = this.buildPathAnalysisPrompt(nodes, nodeAnalyses, sourceDescription, sinkDescription);
    
    const result = await runClaudePrompt(
      pathPrompt,
      graph.filePath,
      '',
      'CPG Path Analysis',
      'cpg-path-analysis',
      undefined,
      this.logger,
      this.modelTier,
    );
    
    return this.parsePathAnalysisResult(result.result || '', path, nodeAnalyses);
  }
  
  /**
   * Batch analyze multiple paths efficiently
   */
  async analyzePaths(
    graph: CodePropertyGraph,
    paths: Array<{ path: string[]; sourceDesc: string; sinkDesc: string }>
  ): Promise<PathAnalysisResult[]> {
    const results: PathAnalysisResult[] = [];
    
    for (const { path, sourceDesc, sinkDesc } of paths) {
      const result = await this.analyzePath(graph, path, sourceDesc, sinkDesc);
      results.push(result);
    }
    
    return results;
  }
  
  private buildNodeAnalysisPrompt(context: NodeAnalysisContext): string {
    const { node, parents, children, dataDeps, surroundingCode } = context;
    
    return `<role>
You are a security-focused code analysis expert. Your task is to analyze a specific node in a Code Property Graph (CPG) and determine its security properties.
</role>

<node_info>
Node Type: ${node.type}
Node Label: ${node.label}
File: ${node.location.file}:${node.location.lineStart}
Code: ${node.code}
</node_info>

<parent_context>
${parents.map(p => `- ${p.type}: ${p.code}`).join('\n') || 'None'}
</parent_context>

<child_context>
${children.map(c => `- ${c.type}: ${c.code}`).join('\n') || 'None'}
</child_context>

<data_dependencies>
${dataDeps.map(d => `- ${d.type}: ${d.code}`).join('\n') || 'None'}
</data_dependencies>

<surrounding_code>
${surroundingCode}
</surrounding_code>

<analysis_task>
Analyze this node and answer these specific questions:

1. Is this a SOURCE of untrusted data? (user input, API params, file reads, etc.)
   - If yes: What type of source? (USER_INPUT, API_PARAM, FILE_READ, etc.)
   - Confidence level (0.0-1.0)

2. Is this a SINK for sensitive operations? (SQL queries, command execution, etc.)
   - If yes: What type of sink? (SQL_EXEC, CMD_EXEC, FILE_WRITE, etc.)
   - Confidence level (0.0-1.0)

3. Is this data SANITIZED here?
   - If yes: What sanitization method? (escape_sql, html_encode, validate_regex, etc.)
   - Is the sanitization SUFFICIENT for the context?
   - Confidence level (0.0-1.0)

4. Is this data VALIDATED here?
   - If yes: What validation method? (type_check, length_check, regex_match, etc.)
   - Confidence level (0.0-1.0)

5. What are the security implications of this node?
   - List specific security concerns

6. What checks should be performed on data flowing through this node?
   - List recommended security validations
</analysis_task>

<output_format>
Respond in this exact format:

SOURCE: <yes/no>
SOURCE_TYPE: <type or "none">
SOURCE_CONFIDENCE: <0.0-1.0>

SINK: <yes/no>
SINK_TYPE: <type or "none">
SINK_CONFIDENCE: <0.0-1.0>

SANITIZED: <yes/no>
SANITIZATION_METHOD: <method or "none">
SANITIZATION_SUFFICIENT: <yes/no/partial>
SANITIZATION_CONFIDENCE: <0.0-1.0>

VALIDATED: <yes/no>
VALIDATION_METHOD: <method or "none">
VALIDATION_CONFIDENCE: <0.0-1.0>

SECURITY_IMPLICATIONS:
- <implication 1>
- <implication 2>

RECOMMENDED_CHECKS:
- <check 1>
- <check 2>

REASONING: <2-3 sentences explaining your assessment>
</output_format>`;
  }
  
  private buildPathAnalysisPrompt(
    nodes: CPGNode[],
    nodeAnalyses: Map<string, NodeAnalysisResult>,
    sourceDesc: string,
    sinkDesc: string
  ): string {
    const pathDescription = nodes.map(n => {
      const analysis = nodeAnalyses.get(n.id);
      return `- ${n.type} at ${n.location.file}:${n.location.lineStart}: ${n.code}
  Source: ${analysis?.isSource ? 'YES' : 'no'} | Sink: ${analysis?.isSink ? 'YES' : 'no'} | Sanitized: ${analysis?.isSanitized ? 'YES' : 'no'}`;
    }).join('\n');
    
    return `<role>
You are a security path analysis expert. Analyze a data flow path from source to sink to determine if it represents a vulnerability.
</role>

<path_info>
Source: ${sourceDesc}
Sink: ${sinkDesc}

Path Nodes (${nodes.length}):
${pathDescription}
</path_info>

<analysis_task>
Determine if this path is vulnerable by analyzing:

1. Is there a complete data flow from source to sink without interruption?
2. Is the data properly sanitized/validated at ANY point in the path?
3. Is the sanitization SUFFICIENT for the specific sink type?
4. Could an attacker exploit this path?

Consider that:
- Partial sanitization may not be sufficient
- Context matters: SQL escaping doesn't protect against XSS
- Multiple sanitization points should be evaluated
- Custom sanitizers need careful analysis
</analysis_task>

<output_format>
Respond in this exact format:

IS_VULNERABLE: <yes/no>
VULNERABILITY_TYPE: <type or "none">
CONFIDENCE: <0.0-1.0>

IS_FULLY_SANITIZED: <yes/no/partial>
SANITIZATION_POINTS: <count>

SUMMARY: <1-2 sentence assessment>
</output_format>`;
  }
  
  private buildNodeContext(graph: CodePropertyGraph, node: CPGNode): NodeAnalysisContext {
    const parents = graph.getPredecessors(node.id).filter(n => 
      graph.getEdgesTo(node.id).some(e => e.type === 'AST_PARENT' && e.from === n.id)
    );
    
    const children = graph.getSuccessors(node.id).filter(n =>
      graph.getEdgesFrom(node.id).some(e => e.type === 'AST_PARENT' && e.to === n.id)
    );
    
    const dataDeps = graph.getDataDependencies(node.id);
    const controlFlowPreds = graph.getPredecessors(node.id).filter(n =>
      graph.getEdgesTo(node.id).some(e => e.type.startsWith('CFG_') && e.from === n.id)
    );
    
    const controlFlowSuccs = graph.getControlFlowSuccessors(node.id);
    
    return {
      node,
      parents,
      children,
      dataDeps,
      controlFlowPreds,
      controlFlowSuccs,
      surroundingCode: node.code,
      fileContext: node.location.file,
    };
  }
  
  private parseNodeAnalysisResult(text: string): NodeAnalysisResult {
    const lines = text.split('\n');
    const getValue = (prefix: string): string => {
      const line = lines.find(l => l.trim().startsWith(prefix));
      return line ? line.split(':').slice(1).join(':').trim() : '';
    };
    
    const parseList = (prefix: string): string[] => {
      const startIdx = lines.findIndex(l => l.trim().startsWith(prefix));
      if (startIdx === -1) return [];
      
      const items: string[] = [];
      for (let i = startIdx + 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('- ')) {
          items.push(line.substring(2));
        } else if (!line.startsWith('  ') && line.length > 0) {
          break;
        }
      }
      return items;
    };
    
    return {
      isSource: getValue('SOURCE:').toLowerCase() === 'yes',
      sourceType: getValue('SOURCE_TYPE:') || undefined,
      sourceConfidence: parseFloat(getValue('SOURCE_CONFIDENCE:')) || 0.5,
      
      isSink: getValue('SINK:').toLowerCase() === 'yes',
      sinkType: getValue('SINK_TYPE:') || undefined,
      sinkConfidence: parseFloat(getValue('SINK_CONFIDENCE:')) || 0.5,
      
      isSanitized: getValue('SANITIZED:').toLowerCase() === 'yes',
      sanitizationMethod: getValue('SANITIZATION_METHOD:') || undefined,
      sanitizationConfidence: parseFloat(getValue('SANITIZATION_CONFIDENCE:')) || 0.5,
      
      isValidated: getValue('VALIDATED:').toLowerCase() === 'yes',
      validationMethod: getValue('VALIDATION_METHOD:') || undefined,
      validationConfidence: parseFloat(getValue('VALIDATION_CONFIDENCE:')) || 0.5,
      
      securityImplications: parseList('SECURITY_IMPLICATIONS:'),
      recommendedChecks: parseList('RECOMMENDED_CHECKS:'),
      
      overallConfidence: 0.7,
      reasoning: getValue('REASONING:') || text,
    };
  }
  
  private parsePathAnalysisResult(
    text: string,
    path: string[],
    nodeAnalyses: Map<string, NodeAnalysisResult>
  ): PathAnalysisResult {
    const lines = text.split('\n');
    const getValue = (prefix: string): string => {
      const line = lines.find(l => l.trim().startsWith(prefix));
      return line ? line.split(':').slice(1).join(':').trim() : '';
    };
    
    const sanitizationPoints: string[] = [];
    for (const [nodeId, analysis] of nodeAnalyses) {
      if (analysis.isSanitized) {
        sanitizationPoints.push(nodeId);
      }
    }
    
    return {
      path,
      isVulnerable: getValue('IS_VULNERABLE:').toLowerCase() === 'yes',
      vulnerabilityType: getValue('VULNERABILITY_TYPE:') || undefined,
      nodeAnalyses,
      confidence: parseFloat(getValue('CONFIDENCE:')) || 0.5,
      isFullySanitized: getValue('IS_FULLY_SANITIZED:').toLowerCase() === 'yes',
      sanitizationPoints,
      summary: getValue('SUMMARY:') || text,
    };
  }
  
  private createDefaultResult(reasoning: string): NodeAnalysisResult {
    return {
      isSource: false,
      isSink: false,
      isSanitized: false,
      isValidated: false,
      securityImplications: [],
      recommendedChecks: [],
      overallConfidence: 0,
      reasoning,
    };
  }
}
