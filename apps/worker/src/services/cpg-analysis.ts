// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * CPG Analysis Service for Pre-Recon Phase
 * 
 * Integrates the CPG (Code Property Graph) engine into the pre-reconnaissance
 * phase of the pentest workflow. Performs static analysis with LLM reasoning
 * at every node to identify vulnerabilities.
 */

import { fs, path } from 'zx';
import { CPGEngine, DEFAULT_CPG_CONFIG, type CPGAnalysisResult, type DataFlowFinding } from '../cpg/index.js';
import type { ActivityLogger } from '../types/activity-logger.js';

export interface CPGAnalysisOptions {
  /** Maximum files to analyze */
  maxFiles?: number;
  
  /** Enable LLM reasoning (slower but more accurate) */
  enableLLMReasoning?: boolean;
  
  /** Model tier for analysis */
  modelTier?: 'small' | 'medium' | 'large';
  
  /** Focus on specific vulnerability types */
  focusVulnTypes?: string[];
  
  /** Analyze only critical files (routes, controllers, auth) */
  criticalFilesOnly?: boolean;
}

export interface CPGFindingsReport {
  /** Summary statistics */
  summary: {
    filesAnalyzed: number;
    totalNodes: number;
    totalEdges: number;
    vulnerablePaths: number;
    sanitizedPaths: number;
    safePaths: number;
    analysisDurationMs: number;
  };
  
  /** Critical findings requiring attention */
  criticalFindings: DataFlowFinding[];
  
  /** All data flow findings */
  allFindings: DataFlowFinding[];
  
  /** Entry points identified */
  entryPoints: Array<{
    name: string;
    file: string;
    line: number;
    isEndpoint: boolean;
  }>;
  
  /** Security hotspots (files with most vulnerabilities) */
  hotspots: Array<{
    file: string;
    findingCount: number;
    vulnerabilityTypes: string[];
  }>;
  
  /** CPG analysis report in markdown */
  markdownReport: string;
}

export class CPGAnalysisService {
  private logger?: ActivityLogger;
  
  constructor(logger?: ActivityLogger) {
    this.logger = logger;
  }
  
  /**
   * Run CPG analysis on a project and generate security findings
   */
  async analyzeProject(
    projectPath: string,
    options: CPGAnalysisOptions = {}
  ): Promise<CPGFindingsReport> {
    const {
      maxFiles = 50,
      enableLLMReasoning = true,
      modelTier = 'medium',
      focusVulnTypes,
      criticalFilesOnly = false,
    } = options;
    
    this.logger?.info(`Starting CPG analysis on ${projectPath}`);
    
    // Initialize CPG engine
    const engine = new CPGEngine(
      {
        ...DEFAULT_CPG_CONFIG,
        maxFiles,
        enableLLMReasoning,
        modelTier,
      },
      this.logger
    );
    
    let result: CPGAnalysisResult;
    
    if (criticalFilesOnly) {
      // Analyze only security-critical files
      const criticalPatterns = [
        /routes?\./i,
        /controller/i,
        /auth/i,
        /middleware/i,
        /handler/i,
        /api/i,
        /server\./i,
        /app\./i,
      ];
      result = await engine.analyzeCriticalFiles(projectPath, criticalPatterns);
    } else {
      // Analyze entire project
      result = await engine.analyzeProject(projectPath);
    }
    
    // Filter findings if specific vulnerability types requested
    let findings = result.dataFlowFindings;
    if (focusVulnTypes && focusVulnTypes.length > 0) {
      findings = findings.filter(f => 
        focusVulnTypes.some(type => 
          f.vulnerabilityType.toLowerCase().includes(type.toLowerCase())
        )
      );
    }
    
    // Separate critical from non-critical
    const criticalFindings = findings.filter(f => 
      f.isVulnerable && f.confidence > 0.7
    );
    
    // Identify hotspots
    const hotspots = this.identifyHotspots(findings);
    
    // Format entry points
    const entryPoints = result.entryPoints.map(ep => ({
      name: ep.fullName || ep.label,
      file: ep.location.file,
      line: ep.location.lineStart,
      isEndpoint: ep.isEntryPoint || false,
    }));
    
    // Generate markdown report
    const markdownReport = this.generateFindingsReport(result, criticalFindings);
    
    return {
      summary: {
        filesAnalyzed: result.files.length,
        totalNodes: result.totalNodes,
        totalEdges: result.totalEdges,
        vulnerablePaths: findings.filter(f => f.isVulnerable).length,
        sanitizedPaths: findings.filter(f => !f.isVulnerable && f.isSanitized).length,
        safePaths: findings.filter(f => !f.isVulnerable && !f.isSanitized).length,
        analysisDurationMs: result.durationMs,
      },
      criticalFindings,
      allFindings: findings,
      entryPoints,
      hotspots,
      markdownReport,
    };
  }
  
  /**
   * Run quick CPG scan (faster, no LLM reasoning)
   */
  async quickScan(projectPath: string): Promise<CPGFindingsReport> {
    return this.analyzeProject(projectPath, {
      enableLLMReasoning: false,
      modelTier: 'small',
      maxFiles: 30,
      criticalFilesOnly: true,
    });
  }
  
  /**
   * Deep CPG analysis (slower, comprehensive)
   */
  async deepAnalysis(projectPath: string): Promise<CPGFindingsReport> {
    return this.analyzeProject(projectPath, {
      enableLLMReasoning: true,
      modelTier: 'large',
      maxFiles: 100,
      criticalFilesOnly: false,
    });
  }
  
  /**
   * Save CPG findings to deliverables directory
   */
  async saveFindings(
    findings: CPGFindingsReport,
    deliverablesPath: string
  ): Promise<void> {
    const cpgDir = path.join(deliverablesPath, 'cpg');
    await fs.ensureDir(cpgDir);
    
    // Save markdown report
    const reportPath = path.join(cpgDir, 'cpg_security_analysis.md');
    await fs.writeFile(reportPath, findings.markdownReport, 'utf8');
    
    // Save JSON findings for other agents
    const jsonPath = path.join(cpgDir, 'cpg_findings.json');
    await fs.writeFile(
      jsonPath,
      JSON.stringify(
        {
          summary: findings.summary,
          criticalFindings: findings.criticalFindings.map(f => ({
            id: f.id,
            type: f.vulnerabilityType,
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
            isSanitized: f.isSanitized,
            recommendation: f.recommendation,
          })),
          entryPoints: findings.entryPoints,
          hotspots: findings.hotspots,
        },
        null,
        2
      ),
      'utf8'
    );
    
    this.logger?.info(`CPG findings saved to ${cpgDir}`);
  }
  
  /**
   * Identify security hotspots (files with most vulnerabilities)
   */
  private identifyHotspots(findings: DataFlowFinding[]): Array<{
    file: string;
    findingCount: number;
    vulnerabilityTypes: string[];
  }> {
    const fileMap = new Map<string, { count: number; types: Set<string> }>();
    
    for (const finding of findings) {
      const file = finding.sink.location.file;
      const existing = fileMap.get(file) || { count: 0, types: new Set() };
      existing.count++;
      existing.types.add(finding.vulnerabilityType);
      fileMap.set(file, existing);
    }
    
    return Array.from(fileMap.entries())
      .map(([file, data]) => ({
        file,
        findingCount: data.count,
        vulnerabilityTypes: Array.from(data.types),
      }))
      .sort((a, b) => b.findingCount - a.findingCount)
      .slice(0, 10);
  }
  
  /**
   * Generate markdown findings report
   */
  private generateFindingsReport(
    result: CPGAnalysisResult,
    criticalFindings: DataFlowFinding[]
  ): string {
    const lines: string[] = [];
    
    lines.push('# CPG Security Analysis Report');
    lines.push('');
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(`This report presents findings from Code Property Graph (CPG) analysis,`);
    lines.push(`which combines Abstract Syntax Tree (AST), Control Flow Graph (CFG),`);
    lines.push(`and Program Dependence Graph (PDG) with LLM reasoning at every node.`);
    lines.push('');
    lines.push(`- **Files Analyzed:** ${result.files.length}`);
    lines.push(`- **Total Graph Nodes:** ${result.totalNodes.toLocaleString()}`);
    lines.push(`- **Total Graph Edges:** ${result.totalEdges.toLocaleString()}`);
    lines.push(`- **Critical Findings:** ${criticalFindings.length}`);
    lines.push(`- **Analysis Duration:** ${(result.durationMs / 1000).toFixed(1)}s`);
    lines.push('');
    
    // Entry points
    if (result.entryPoints.length > 0) {
      lines.push('## Entry Points Identified');
      lines.push('');
      for (const ep of result.entryPoints.slice(0, 15)) {
        lines.push(`### ${ep.fullName || ep.label}`);
        lines.push(`- **File:** \`${ep.location.file}\` (line ${ep.location.lineStart})`);
        lines.push(`- **Type:** ${ep.isEntryPoint ? 'Application Entry Point' : 'Internal Function'}`);
        lines.push(`- **Code:** \`${ep.code.substring(0, 100)}${ep.code.length > 100 ? '...' : ''}\``);
        lines.push('');
      }
      if (result.entryPoints.length > 15) {
        lines.push(`*... and ${result.entryPoints.length - 15} more entry points*`);
        lines.push('');
      }
    }
    
    // Critical findings
    if (criticalFindings.length > 0) {
      lines.push('## Critical Vulnerabilities (Action Required)');
      lines.push('');
      lines.push(`**${criticalFindings.length} vulnerable data flows identified with high confidence**`);
      lines.push('');
      
      // Group by vulnerability type
      const byType = new Map<string, DataFlowFinding[]>();
      for (const finding of criticalFindings) {
        const list = byType.get(finding.vulnerabilityType) || [];
        list.push(finding);
        byType.set(finding.vulnerabilityType, list);
      }
      
      for (const [vulnType, findings] of byType) {
        lines.push(`### ${vulnType} (${findings.length} findings)`);
        lines.push('');
        
        for (let i = 0; i < Math.min(findings.length, 5); i++) {
          const finding = findings[i];
          lines.push(`#### Finding ${i + 1}: ${finding.id}`);
          lines.push('');
          lines.push(`**Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
          lines.push('');
          lines.push('**Source (Untrusted Data Entry):**');
          lines.push(`- File: \`${finding.source.location.file}\` (line ${finding.source.location.lineStart})`);
          lines.push(`- Code: \`${finding.source.code}\``);
          lines.push('');
          lines.push('**Sink (Sensitive Operation):**');
          lines.push(`- File: \`${finding.sink.location.file}\` (line ${finding.sink.location.lineStart})`);
          lines.push(`- Code: \`${finding.sink.code}\``);
          lines.push('');
          
          if (finding.isSanitized) {
            lines.push('**Sanitization Status:** ⚠️ Partially Sanitized');
            lines.push('');
            lines.push('Sanitization points found but may be insufficient:');
            for (const point of finding.sanitizationPoints) {
              lines.push(`- \`${point.code}\` (${point.location.file}:${point.location.lineStart})`);
            }
          } else {
            lines.push('**Sanitization Status:** ❌ No Sanitization Detected');
          }
          lines.push('');
          
          lines.push('**Recommendation:**');
          lines.push(finding.recommendation);
          lines.push('');
          lines.push('---');
          lines.push('');
        }
        
        if (findings.length > 5) {
          lines.push(`*... and ${findings.length - 5} more ${vulnType} findings*`);
          lines.push('');
        }
      }
    } else {
      lines.push('## Vulnerability Findings');
      lines.push('');
      lines.push('✅ **No critical vulnerable data flows identified.**');
      lines.push('');
      lines.push('The CPG analysis did not detect any high-confidence vulnerable');
      lines.push('paths from sources to sinks. This could mean:');
      lines.push('- The code has proper input validation/sanitization');
      lines.push('- The analysis did not cover all relevant files');
      lines.push('- Vulnerabilities may exist but use complex patterns not detected');
      lines.push('');
    }
    
    // Methodology
    lines.push('## Analysis Methodology');
    lines.push('');
    lines.push('### Code Property Graph (CPG)');
    lines.push('');
    lines.push('The analysis uses a Code Property Graph combining:');
    lines.push('- **Abstract Syntax Tree (AST):** Code structure and syntax');
    lines.push('- **Control Flow Graph (CFG):** Execution order and branches');
    lines.push('- **Program Dependence Graph (PDG):** Data and control dependencies');
    lines.push('');
    lines.push('### LLM Reasoning at Every Node');
    lines.push('');
    lines.push('Unlike traditional SAST tools that use hardcoded patterns,');
    lines.push('this analysis employs LLM reasoning to evaluate:');
    lines.push('- Whether data at each node is sanitized/validated');
    lines.push('- Whether sanitization is sufficient for the specific context');
    lines.push('- Security implications of each code construct');
    lines.push('');
    lines.push('### Source-to-Sink Analysis');
    lines.push('');
    lines.push('Vulnerabilities are identified by tracing data flow from:');
    lines.push('- **Sources:** User input, HTTP parameters, file reads, etc.');
    lines.push('- **Sinks:** SQL queries, command execution, HTML rendering, etc.');
    lines.push('');
    lines.push('Each path is evaluated for sanitization completeness.');
    lines.push('');
    
    return lines.join('\n');
  }
}
