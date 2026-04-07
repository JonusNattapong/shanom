// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Data Flow Analyzer for CPG
 * 
 * Traces data flow from sources (user input) to sinks (sensitive operations)
 * with LLM reasoning at each node to assess sanitization and validation.
 */

import type { ActivityLogger } from '../types/activity-logger.js';
import { LLMNodeReasoner, type PathAnalysisResult } from './llm-reasoner.js';
import { CodePropertyGraph, type CPGNode, type SourceSinkPattern, type NodeType } from './models.js';

export interface DataFlowFinding {
  /** Unique identifier */
  id: string;
  
  /** Vulnerability type */
  vulnerabilityType: string;
  
  /** Source node */
  source: CPGNode;
  
  /** Sink node */
  sink: CPGNode;
  
  /** Path through the code */
  path: CPGNode[];
  
  /** Is this a confirmed vulnerability? */
  isVulnerable: boolean;
  
  /** Confidence level (0-1) */
  confidence: number;
  
  /** Is data sanitized along the path? */
  isSanitized: boolean;
  
  /** Sanitization points if any */
  sanitizationPoints: CPGNode[];
  
  /** Detailed analysis */
  analysis: PathAnalysisResult;
  
  /** Recommended fix */
  recommendation: string;
}

export interface SourceDefinition {
  /** Source name/pattern */
  name: string;
  
  /** Description */
  description: string;
  
  /** Node types to match */
  nodeTypes: NodeType[];
  
  /** Code patterns (regex or strings) */
  patterns: (RegExp | string)[];
  
  /** Is this an entry point? */
  isEntryPoint?: boolean;
}

export interface SinkDefinition {
  /** Sink name/pattern */
  name: string;
  
  /** Description */
  description: string;
  
  /** Node types to match */
  nodeTypes: NodeType[];
  
  /** Code patterns (regex or strings) */
  patterns: (RegExp | string)[];
  
  /** Vulnerability category */
  vulnerabilityCategory: 'INJECTION' | 'XSS' | 'AUTH' | 'AUTHZ' | 'SSRF' | 'OTHER';
}

/**
 * Predefined source patterns for common vulnerabilities
 */
export const COMMON_SOURCES: SourceDefinition[] = [
  {
    name: 'HTTP_REQUEST_PARAMS',
    description: 'HTTP request parameters from web framework',
    nodeTypes: ['CALL', 'IDENTIFIER'],
    patterns: [
      /req\.params|req\.query|req\.body|request\.params/,
      /getParameter|getQueryString|getBody/,
      /\$_(GET|POST|REQUEST)/,
      /params\[:/, /params\[/,
    ],
    isEntryPoint: true,
  },
  {
    name: 'USER_INPUT',
    description: 'Direct user input functions',
    nodeTypes: ['CALL', 'IDENTIFIER'],
    patterns: [
      /readLine|readln|input|gets|scanf/,
      /prompt|confirm|dialog/,
      /process\.argv/,
      /os\.stdin/,
    ],
    isEntryPoint: true,
  },
  {
    name: 'FILE_READ',
    description: 'File read operations',
    nodeTypes: ['CALL'],
    patterns: [
      /fs\.readFile|readFileSync/,
      /File\.read|File\.open/,
      /fopen|fread/,
      /open\(.*['"]r/,
    ],
  },
  {
    name: 'ENVIRONMENT_VARS',
    description: 'Environment variables',
    nodeTypes: ['IDENTIFIER'],
    patterns: [
      /process\.env/,
      /os\.environ/,
      /ENV\[/,
      /getenv/,
    ],
  },
  {
    name: 'DATABASE_READ',
    description: 'Database query results',
    nodeTypes: ['CALL'],
    patterns: [
      /\.find\(|\.findOne\(|\.select\(|\.query\(/,
      /SELECT.*FROM/i,
      /fetchall|fetchone|cursor/,
    ],
  },
];

/**
 * Predefined sink patterns for common vulnerabilities
 */
export const COMMON_SINKS: SinkDefinition[] = [
  {
    name: 'SQL_EXECUTION',
    description: 'SQL query execution',
    nodeTypes: ['CALL'],
    patterns: [
      /query\(|execute\(|exec\(/,
      /SELECT|INSERT|UPDATE|DELETE.*FROM/i,
      /raw\(|rawQuery\(/,
      /\.sql\(|\.statement\(/,
    ],
    vulnerabilityCategory: 'INJECTION',
  },
  {
    name: 'COMMAND_EXECUTION',
    description: 'OS command execution',
    nodeTypes: ['CALL'],
    patterns: [
      /exec\(|execSync\(|spawn\(/,
      /system\(|popen\(|subprocess/,
      /eval\(|execScript/,
      /child_process/,
    ],
    vulnerabilityCategory: 'INJECTION',
  },
  {
    name: 'HTML_RENDERING',
    description: 'HTML/DOM output',
    nodeTypes: ['CALL', 'ASSIGNMENT'],
    patterns: [
      /innerHTML|outerHTML/,
      /document\.write/,
      /\.html\(|\.append\(/,
      /render_template|render_to_string/,
    ],
    vulnerabilityCategory: 'XSS',
  },
  {
    name: 'AUTHENTICATION',
    description: 'Authentication checks',
    nodeTypes: ['CALL'],
    patterns: [
      /authenticate\(|verify\(|checkPassword\(/,
      /login\(|signin\(|auth\(/,
      /validate_token|verify_jwt/,
    ],
    vulnerabilityCategory: 'AUTH',
  },
  {
    name: 'AUTHORIZATION',
    description: 'Authorization checks',
    nodeTypes: ['CALL'],
    patterns: [
      /authorize\(|can\(|may\(|checkPermission\(/,
      /isAllowed|hasAccess/,
      /require_role|require_permission/,
    ],
    vulnerabilityCategory: 'AUTHZ',
  },
  {
    name: 'HTTP_REQUEST',
    description: 'Outgoing HTTP requests',
    nodeTypes: ['CALL'],
    patterns: [
      /fetch\(|axios\.|request\(/,
      /urllib|http\.request|https\.request/,
      /curl|wget/,
    ],
    vulnerabilityCategory: 'SSRF',
  },
  {
    name: 'FILE_WRITE',
    description: 'File write operations',
    nodeTypes: ['CALL'],
    patterns: [
      /writeFile|writeFileSync/,
      /File\.write|File\.open/,
      /fopen.*['"]w/,
    ],
    vulnerabilityCategory: 'OTHER',
  },
];

export class DataFlowAnalyzer {
  private sources: SourceDefinition[];
  private sinks: SinkDefinition[];
  private reasoner: LLMNodeReasoner;
  private logger?: ActivityLogger;
  
  constructor(
    logger?: ActivityLogger,
    sources: SourceDefinition[] = COMMON_SOURCES,
    sinks: SinkDefinition[] = COMMON_SINKS,
    modelTier: 'small' | 'medium' | 'large' = 'medium'
  ) {
    this.logger = logger;
    this.sources = sources;
    this.sinks = sinks;
    this.reasoner = new LLMNodeReasoner(logger, modelTier);
  }
  
  /**
   * Analyze a CPG for data flow vulnerabilities
   */
  async analyze(graph: CodePropertyGraph): Promise<DataFlowFinding[]> {
    this.logger?.info(`Starting data flow analysis on ${graph.filePath}`);
    
    const findings: DataFlowFinding[] = [];
    
    // Find all sources
    const sources = this.findSources(graph);
    this.logger?.info(`Found ${sources.length} potential sources`);
    
    // Find all sinks
    const sinks = this.findSinks(graph);
    this.logger?.info(`Found ${sinks.length} potential sinks`);
    
    // For each source-sink pair, trace data flow
    for (const source of sources) {
      for (const sink of sinks) {
        const paths = this.findDataFlowPaths(graph, source, sink);
        
        for (const path of paths) {
          // Use LLM to analyze the path
          const analysis = await this.reasoner.analyzePath(
            graph,
            path.map(n => n.id),
            `${source.type} at ${source.location.file}:${source.location.lineStart}`,
            `${sink.type} at ${sink.location.file}:${sink.location.lineStart}`
          );
          
          const finding: DataFlowFinding = {
            id: `finding-${source.id}-${sink.id}-${Date.now()}`,
            vulnerabilityType: this.getVulnerabilityType(sink),
            source,
            sink,
            path,
            isVulnerable: analysis.isVulnerable,
            confidence: analysis.confidence,
            isSanitized: analysis.isFullySanitized,
            sanitizationPoints: analysis.sanitizationPoints.map(id => 
              graph.getNode(id)).filter((n): n is CPGNode => !!n),
            analysis,
            recommendation: this.generateRecommendation(analysis, source, sink),
          };
          
          findings.push(finding);
          
          this.logger?.info(
            `Data flow finding: ${finding.vulnerabilityType} ` +
            `(source: ${source.location.file}:${source.location.lineStart}, ` +
            `sink: ${sink.location.file}:${sink.location.lineStart}, ` +
            `vulnerable: ${finding.isVulnerable}, confidence: ${finding.confidence.toFixed(2)})`
          );
        }
      }
    }
    
    // Sort by confidence and vulnerability status
    findings.sort((a, b) => {
      if (a.isVulnerable && !b.isVulnerable) return -1;
      if (!a.isVulnerable && b.isVulnerable) return 1;
      return b.confidence - a.confidence;
    });
    
    this.logger?.info(`Data flow analysis complete: ${findings.length} findings`);
    return findings;
  }
  
  /**
   * Find all source nodes in the graph
   */
  private findSources(graph: CodePropertyGraph): CPGNode[] {
    const sources: CPGNode[] = [];
    const nodes = graph.getAllNodes();
    
    for (const node of nodes) {
      for (const sourceDef of this.sources) {
        if (this.matchesDefinition(node, sourceDef)) {
          sources.push(node);
          break;
        }
      }
    }
    
    return sources;
  }
  
  /**
   * Find all sink nodes in the graph
   */
  private findSinks(graph: CodePropertyGraph): CPGNode[] {
    const sinks: CPGNode[] = [];
    const nodes = graph.getAllNodes();
    
    for (const node of nodes) {
      for (const sinkDef of this.sinks) {
        if (this.matchesSinkDefinition(node, sinkDef)) {
          sinks.push(node);
          break;
        }
      }
    }
    
    return sinks;
  }
  
  /**
   * Check if a node matches a source definition
   */
  private matchesDefinition(node: CPGNode, def: SourceDefinition): boolean {
    // Check node type
    if (!def.nodeTypes.includes(node.type)) {
      return false;
    }
    
    // Check patterns
    const code = node.code.toLowerCase();
    for (const pattern of def.patterns) {
      if (typeof pattern === 'string') {
        if (code.includes(pattern.toLowerCase())) {
          return true;
        }
      } else {
        if (pattern.test(node.code)) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  /**
   * Check if a node matches a sink definition
   */
  private matchesSinkDefinition(node: CPGNode, def: SinkDefinition): boolean {
    // Check node type
    if (!def.nodeTypes.includes(node.type)) {
      return false;
    }
    
    // Check patterns
    const code = node.code.toLowerCase();
    for (const pattern of def.patterns) {
      if (typeof pattern === 'string') {
        if (code.includes(pattern.toLowerCase())) {
          return true;
        }
      } else {
        if (pattern.test(node.code)) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  /**
   * Find data flow paths between a source and sink
   */
  private findDataFlowPaths(graph: CodePropertyGraph, source: CPGNode, sink: CPGNode): CPGNode[][] {
    const paths: CPGNode[][] = [];
    
    // BFS with limited depth to find paths
    const maxDepth = 20;
    const queue: Array<{ node: CPGNode; path: CPGNode[]; visited: Set<string> }> = [
      { node: source, path: [source], visited: new Set([source.id]) }
    ];
    
    while (queue.length > 0) {
      const { node, path, visited } = queue.shift()!;
      
      // Check if we reached the sink
      if (node.id === sink.id && path.length > 1) {
        paths.push([...path]);
        if (paths.length >= 5) break; // Limit number of paths
        continue;
      }
      
      // Depth limit
      if (path.length >= maxDepth) {
        continue;
      }
      
      // Get successors via data flow edges
      const successors = this.getDataFlowSuccessors(graph, node)
        .filter(s => !visited.has(s.id));
      
      for (const successor of successors) {
        const newVisited = new Set(visited);
        newVisited.add(successor.id);
        queue.push({
          node: successor,
          path: [...path, successor],
          visited: newVisited
        });
      }
    }
    
    return paths;
  }
  
  /**
   * Get data flow successors (variables/data that flow from this node)
   */
  private getDataFlowSuccessors(graph: CodePropertyGraph, node: CPGNode): CPGNode[] {
    const successors: CPGNode[] = [];
    
    // Get direct data flow edges
    const edges = graph.getEdgesFrom(node.id);
    for (const edge of edges) {
      if (edge.type === 'DATA_FLOW' || edge.type === 'DEF') {
        const target = graph.getNode(edge.to);
        if (target) {
          successors.push(target);
        }
      }
    }
    
    // Get control flow successors (data can flow through control structures)
    const controlFlowSuccs = graph.getControlFlowSuccessors(node.id);
    for (const succ of controlFlowSuccs) {
      // Check if this is an assignment or return
      if (succ.type === 'ASSIGNMENT' || succ.type === 'RETURN' || succ.type === 'CALL') {
        successors.push(succ);
      }
    }
    
    return successors;
  }
  
  /**
   * Get vulnerability type for a sink
   */
  private getVulnerabilityType(sink: CPGNode): string {
    for (const sinkDef of this.sinks) {
      if (this.matchesSinkDefinition(sink, sinkDef)) {
        return sinkDef.vulnerabilityCategory;
      }
    }
    return 'UNKNOWN';
  }
  
  /**
   * Generate remediation recommendation
   */
  private generateRecommendation(analysis: PathAnalysisResult, source: CPGNode, sink: CPGNode): string {
    if (!analysis.isVulnerable) {
      return 'No immediate action required. Data flow appears properly sanitized.';
    }
    
    const recommendations: string[] = [];
    
    if (analysis.sanitizationPoints.length === 0) {
      recommendations.push(`Add input validation/sanitization between ${source.type} and ${sink.type}.`);
    } else {
      recommendations.push('Review existing sanitization - it may be insufficient for this sink type.');
    }
    
    // Add specific recommendations based on sink type
    const sinkCode = sink.code.toLowerCase();
    if (sinkCode.includes('sql') || sinkCode.includes('query')) {
      recommendations.push('Use parameterized queries/prepared statements instead of string concatenation.');
    } else if (sinkCode.includes('exec') || sinkCode.includes('spawn')) {
      recommendations.push('Avoid passing user input to command execution functions.');
    } else if (sinkCode.includes('html') || sinkCode.includes('inner')) {
      recommendations.push('Use context-aware output encoding (HTML entity encoding).');
    } else if (sinkCode.includes('http') || sinkCode.includes('fetch')) {
      recommendations.push('Validate and whitelist URLs before making outbound requests.');
    }
    
    return recommendations.join(' ');
  }
  
  /**
   * Export findings to JSON format for reporting
   */
  exportFindings(findings: DataFlowFinding[]): string {
    const exportData = findings.map(f => ({
      id: f.id,
      vulnerabilityType: f.vulnerabilityType,
      isVulnerable: f.isVulnerable,
      confidence: f.confidence,
      source: {
        file: f.source.location.file,
        line: f.source.location.lineStart,
        code: f.source.code,
      },
      sink: {
        file: f.sink.location.file,
        line: f.sink.location.lineStart,
        code: f.sink.code,
      },
      pathLength: f.path.length,
      isSanitized: f.isSanitized,
      sanitizationPoints: f.sanitizationPoints.map(s => ({
        file: s.location.file,
        line: s.location.lineStart,
        code: s.code,
      })),
      recommendation: f.recommendation,
    }));
    
    return JSON.stringify(exportData, null, 2);
  }
}
