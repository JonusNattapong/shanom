// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * CPG Engine - Main entry point for Code Property Graph analysis
 * 
 * Provides a high-level API for:
 * - Building CPG from source files
 * - Running data flow analysis
 * - Running control flow analysis
 * - Running LLM-based reasoning on nodes
 * - Exporting findings for security reports
 */

import { fs, path } from 'zx';
import type { ActivityLogger } from '../types/activity-logger.js';
import { DataFlowAnalyzer, type DataFlowFinding, COMMON_SOURCES, COMMON_SINKS } from './data-flow-analyzer.js';
import { LLMNodeReasoner, type NodeAnalysisResult, type PathAnalysisResult } from './llm-reasoner.js';
import { CodePropertyGraph, type CPGNode, type CPGBuilder, type SourceLocation, type NodeType, type EdgeType } from './models.js';
import { SimpleCPGBuilder } from './simple-builder.js';

export interface CPGEngineConfig {
  /** Enable LLM reasoning at each node */
  enableLLMReasoning: boolean;
  
  /** Model tier for LLM analysis */
  modelTier: 'small' | 'medium' | 'large';
  
  /** Maximum files to analyze per project */
  maxFiles: number;
  
  /** Maximum depth for path tracing */
  maxPathDepth: number;
  
  /** File extensions to analyze */
  supportedExtensions: string[];
  
  /** Enable DOT format export */
  enableVisualization: boolean;
}

export interface CPGAnalysisResult {
  /** Files analyzed */
  files: string[];
  
  /** Total nodes in all graphs */
  totalNodes: number;
  
  /** Total edges in all graphs */
  totalEdges: number;
  
  /** Data flow findings */
  dataFlowFindings: DataFlowFinding[];
  
  /** Entry points identified */
  entryPoints: CPGNode[];
  
  /** All CPGs built */
  graphs: CodePropertyGraph[];
  
  /** Duration in milliseconds */
  durationMs: number;
}

export const DEFAULT_CPG_CONFIG: CPGEngineConfig = {
  enableLLMReasoning: true,
  modelTier: 'medium',
  maxFiles: 100,
  maxPathDepth: 20,
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.rb', '.php'],
  enableVisualization: false,
};

export class CPGEngine {
  private config: CPGEngineConfig;
  private logger?: ActivityLogger;
  private dataFlowAnalyzer: DataFlowAnalyzer;
  private reasoner: LLMNodeReasoner;
  private builder: SimpleCPGBuilder;
  
  constructor(config: Partial<CPGEngineConfig> = {}, logger?: ActivityLogger) {
    this.config = { ...DEFAULT_CPG_CONFIG, ...config };
    this.logger = logger;
    this.dataFlowAnalyzer = new DataFlowAnalyzer(
      logger,
      COMMON_SOURCES,
      COMMON_SINKS,
      this.config.modelTier
    );
    this.reasoner = new LLMNodeReasoner(logger, this.config.modelTier);
    this.builder = new SimpleCPGBuilder();
  }
  
  /**
   * Analyze a single file and return its CPG
   */
  async analyzeFile(filePath: string, content?: string): Promise<CodePropertyGraph | null> {
    try {
      const fileContent = content || await fs.readFile(filePath, 'utf8');
      const graph = this.builder.buildFromFile(filePath, fileContent);
      
      this.logger?.info(`Built CPG for ${filePath}: ${graph.getAllNodes().length} nodes`);
      return graph;
    } catch (error) {
      this.logger?.warn(`Failed to analyze ${filePath}: ${error}`);
      return null;
    }
  }
  
  /**
   * Analyze an entire project directory
   */
  async analyzeProject(projectPath: string): Promise<CPGAnalysisResult> {
    const startTime = Date.now();
    this.logger?.info(`Starting CPG analysis of ${projectPath}`);
    
    // Find all source files
    const files = await this.findSourceFiles(projectPath);
    this.logger?.info(`Found ${files.length} source files`);
    
    // Limit files if needed
    const filesToAnalyze = files.slice(0, this.config.maxFiles);
    
    // Build CPGs for each file
    const graphs: CodePropertyGraph[] = [];
    for (const file of filesToAnalyze) {
      const graph = await this.analyzeFile(file);
      if (graph) {
        graphs.push(graph);
      }
    }
    
    // Calculate totals
    const totalNodes = graphs.reduce((sum, g) => sum + g.getAllNodes().length, 0);
    const totalEdges = graphs.reduce((sum, g) => sum + g.getAllEdges().length, 0);
    
    this.logger?.info(`Built ${graphs.length} CPGs with ${totalNodes} total nodes`);
    
    // Find entry points
    const entryPoints = graphs.flatMap(g => 
      g.getAllNodes().filter(n => n.isEntryPoint)
    );
    
    // Run data flow analysis on each graph
    const dataFlowFindings: DataFlowFinding[] = [];
    for (const graph of graphs) {
      const findings = await this.dataFlowAnalyzer.analyze(graph);
      dataFlowFindings.push(...findings);
    }
    
    const durationMs = Date.now() - startTime;
    
    this.logger?.info(
      `CPG analysis complete: ${dataFlowFindings.length} data flow findings in ${durationMs}ms`
    );
    
    return {
      files: filesToAnalyze,
      totalNodes,
      totalEdges,
      dataFlowFindings,
      entryPoints,
      graphs,
      durationMs,
    };
  }
  
  /**
   * Analyze specific files of interest (security-critical files)
   */
  async analyzeCriticalFiles(
    projectPath: string,
    criticalPatterns: RegExp[]
  ): Promise<CPGAnalysisResult> {
    const startTime = Date.now();
    
    // Find files matching critical patterns
    const allFiles = await this.findSourceFiles(projectPath);
    const criticalFiles = allFiles.filter(file => 
      criticalPatterns.some(pattern => pattern.test(file))
    );
    
    this.logger?.info(`Analyzing ${criticalFiles.length} critical files`);
    
    // Build CPGs
    const graphs: CodePropertyGraph[] = [];
    for (const file of criticalFiles) {
      const graph = await this.analyzeFile(file);
      if (graph) {
        graphs.push(graph);
      }
    }
    
    // Run analysis
    const totalNodes = graphs.reduce((sum, g) => sum + g.getAllNodes().length, 0);
    const totalEdges = graphs.reduce((sum, g) => sum + g.getAllEdges().length, 0);
    const entryPoints = graphs.flatMap(g => g.getAllNodes().filter(n => n.isEntryPoint));
    
    const dataFlowFindings: DataFlowFinding[] = [];
    for (const graph of graphs) {
      const findings = await this.dataFlowAnalyzer.analyze(graph);
      dataFlowFindings.push(...findings);
    }
    
    return {
      files: criticalFiles,
      totalNodes,
      totalEdges,
      dataFlowFindings,
      entryPoints,
      graphs,
      durationMs: Date.now() - startTime,
    };
  }
  
  /**
   * Perform LLM reasoning analysis on specific nodes
   */
  async analyzeNodeWithLLM(
    graph: CodePropertyGraph,
    nodeId: string
  ): Promise<NodeAnalysisResult | null> {
    if (!this.config.enableLLMReasoning) {
      return null;
    }
    
    const node = graph.getNode(nodeId);
    if (!node) {
      return null;
    }
    
    const context = this.buildNodeContext(graph, node);
    return await this.reasoner.analyzeNode(context);
  }
  
  /**
   * Export findings to security report format
   */
  exportSecurityReport(result: CPGAnalysisResult): string {
    const lines: string[] = [];
    
    lines.push('# CPG Security Analysis Report');
    lines.push('');
    lines.push(`**Files Analyzed:** ${result.files.length}`);
    lines.push(`**Total Nodes:** ${result.totalNodes}`);
    lines.push(`**Total Edges:** ${result.totalEdges}`);
    lines.push(`**Analysis Duration:** ${result.durationMs}ms`);
    lines.push('');
    
    // Entry points
    lines.push('## Entry Points');
    lines.push('');
    for (const ep of result.entryPoints.slice(0, 20)) {
      lines.push(`- \`${ep.fullName || ep.label}\` (${ep.location.file}:${ep.location.lineStart})`);
    }
    if (result.entryPoints.length > 20) {
      lines.push(`- ... and ${result.entryPoints.length - 20} more`);
    }
    lines.push('');
    
    // Data flow findings
    lines.push('## Data Flow Findings');
    lines.push('');
    
    const vulnerableFindings = result.dataFlowFindings.filter(f => f.isVulnerable);
    const sanitizedFindings = result.dataFlowFindings.filter(f => !f.isVulnerable && f.isSanitized);
    const safeFindings = result.dataFlowFindings.filter(f => !f.isVulnerable && !f.isSanitized);
    
    lines.push(`**Vulnerable Paths:** ${vulnerableFindings.length}`);
    lines.push(`**Sanitized Paths:** ${sanitizedFindings.length}`);
    lines.push(`**Safe Paths:** ${safeFindings.length}`);
    lines.push('');
    
    // Detailed vulnerable findings
    if (vulnerableFindings.length > 0) {
      lines.push('### Vulnerable Data Flows (Action Required)');
      lines.push('');
      
      for (const finding of vulnerableFindings.slice(0, 10)) {
        lines.push(`#### ${finding.vulnerabilityType}: ${finding.id}`);
        lines.push('');
        lines.push(`**Source:** \`${finding.source.code}\``);
        lines.push(`- File: ${finding.source.location.file}:${finding.source.location.lineStart}`);
        lines.push('');
        lines.push(`**Sink:** \`${finding.sink.code}\``);
        lines.push(`- File: ${finding.sink.location.file}:${finding.sink.location.lineStart}`);
        lines.push('');
        lines.push(`**Confidence:** ${(finding.confidence * 100).toFixed(1)}%`);
        lines.push('');
        lines.push(`**Recommendation:** ${finding.recommendation}`);
        lines.push('');
      }
    }
    
    return lines.join('\n');
  }
  
  /**
   * Export CPG visualization for debugging
   */
  async exportVisualization(result: CPGAnalysisResult, outputDir: string): Promise<void> {
    if (!this.config.enableVisualization) {
      return;
    }
    
    await fs.ensureDir(outputDir);
    
    for (const graph of result.graphs) {
      const dotContent = graph.toDotFormat();
      const outputFile = path.join(outputDir, `${path.basename(graph.filePath)}.dot`);
      await fs.writeFile(outputFile, dotContent, 'utf8');
    }
    
    this.logger?.info(`Exported CPG visualizations to ${outputDir}`);
  }
  
  /**
   * Find all source files in project
   */
  private async findSourceFiles(projectPath: string): Promise<string[]> {
    const files: string[] = [];
    
    async function recurse(dir: string) {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          await recurse(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (DEFAULT_CPG_CONFIG.supportedExtensions.includes(ext)) {
            files.push(fullPath);
          }
        }
      }
    }
    
    await recurse(projectPath);
    return files;
  }
  
  /**
   * Build analysis context for a node
   */
  private buildNodeContext(graph: CodePropertyGraph, node: CPGNode) {
    const parents = graph.getPredecessors(node.id).filter(n => 
      graph.getEdgesTo(node.id).some(e => e.type === 'AST_PARENT')
    );
    
    const children = graph.getSuccessors(node.id).filter(n =>
      graph.getEdgesFrom(node.id).some(e => e.type === 'AST_PARENT')
    );
    
    const dataDeps = graph.getDataDependencies(node.id);
    const controlFlowPreds = graph.getPredecessors(node.id).filter(n =>
      graph.getEdgesTo(node.id).some(e => e.type.startsWith('CFG_'))
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
}

// Re-export types
export * from './models.js';
export * from './llm-reasoner.js';
export * from './data-flow-analyzer.js';
export { SimpleCPGBuilder } from './simple-builder.js';
