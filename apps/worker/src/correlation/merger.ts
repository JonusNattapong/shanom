// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Unified Findings Merger
 * 
 * Merges findings from multiple sources:
 * - CPG Static Analysis
 * - Dynamic Exploitation Results
 * - Vulnerability Analysis Agents
 * 
 * Produces a unified, deduplicated list of security findings.
 */

import { fs, path } from 'zx';
import type { CPGAnalysisResult, DataFlowFinding } from '../cpg/index.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { VulnType } from '../types/index.js';
import { 
  StaticDynamicCorrelationEngine, 
  DEFAULT_CORRELATION_CONFIG,
  type StaticFinding,
  type DynamicFinding,
  type CorrelatedFinding 
} from './engine.js';

export interface ExploitationEvidence {
  /** Vulnerability ID from exploitation */
  vulnId: string;
  
  /** Type */
  type: VulnType;
  
  /** Was exploitation successful? */
  exploited: boolean;
  
  /** Evidence details */
  evidence: {
    payload: string;
    response: string;
    screenshot?: string;
  };
  
  /** Target */
  target: {
    url: string;
    method: string;
    parameter?: string;
  };
  
  /** Confidence */
  confidence: number;
  
  /** Timestamp */
  timestamp: Date;
}

export interface UnifiedFinding {
  /** Unified ID */
  id: string;
  
  /** Title */
  title: string;
  
  /** Description */
  description: string;
  
  /** Vulnerability type */
  type: VulnType;
  
  /** Category (e.g., SQL Injection, XSS) */
  category: string;
  
  /** Severity */
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  
  /** Confidence (0-1) */
  confidence: number;
  
  /** Source of finding */
  sources: Array<{
    type: 'STATIC' | 'DYNAMIC' | 'CORRELATED';
    id: string;
    confidence: number;
  }>;
  
  /** Is this confirmed exploitable? */
  isExploitable: boolean;
  
  /** Has PoC/exploit? */
  hasExploit: boolean;
  
  /** Location in code */
  codeLocation?: {
    file: string;
    line: number;
    function?: string;
    code: string;
  };
  
  /** Network location */
  networkLocation?: {
    url: string;
    method: string;
    parameter?: string;
  };
  
  /** Exploitation details */
  exploitation?: {
    payload: string;
    evidence: string;
    complexity: 'SIMPLE' | 'MODERATE' | 'COMPLEX';
  };
  
  /** Remediation */
  remediation: {
    description: string;
    codeFix?: string;
    references: string[];
  };
  
  /** Metadata */
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    staticAnalysisId?: string;
    dynamicTestId?: string;
  };
}

export interface MergeResult {
  /** Total findings */
  total: number;
  
  /** Confirmed vulnerabilities (exploited) */
  confirmed: number;
  
  /** Unconfirmed (static only) */
  unconfirmed: number;
  
  /** Dynamic-only findings */
  dynamicOnly: number;
  
  /** False positives identified */
  falsePositives: number;
  
  /** Unified findings */
  findings: UnifiedFinding[];
  
  /** Statistics by type */
  byType: Record<string, number>;
  
  /** Statistics by severity */
  bySeverity: Record<string, number>;
}

export class UnifiedFindingsMerger {
  private correlationEngine: StaticDynamicCorrelationEngine;
  private logger?: ActivityLogger;
  
  constructor(logger?: ActivityLogger) {
    this.correlationEngine = new StaticDynamicCorrelationEngine(DEFAULT_CORRELATION_CONFIG);
    this.logger = logger;
  }
  
  /**
   * Merge CPG static analysis with dynamic exploitation results
   */
  async merge(
    cpgResult: CPGAnalysisResult,
    exploitationResults: ExploitationEvidence[]
  ): Promise<MergeResult> {
    this.logger?.info(`Merging ${cpgResult.dataFlowFindings.length} static findings with ${exploitationResults.length} dynamic results`);
    
    // Convert to internal formats
    const staticFindings = this.convertCPGToStatic(cpgResult.dataFlowFindings);
    const dynamicFindings = this.convertEvidenceToDynamic(exploitationResults);
    
    // Run correlation
    const correlated = this.correlationEngine.correlate(staticFindings, dynamicFindings);
    
    // Convert to unified format
    const unified = correlated.map(c => this.toUnifiedFinding(c));
    
    // Calculate statistics
    const result: MergeResult = {
      total: unified.length,
      confirmed: correlated.filter(c => c.status === 'CONFIRMED').length,
      unconfirmed: correlated.filter(c => c.status === 'UNCONFIRMED').length,
      dynamicOnly: correlated.filter(c => c.status === 'DYNAMIC_ONLY').length,
      falsePositives: correlated.filter(c => c.status === 'FALSE_POSITIVE').length,
      findings: unified,
      byType: this.calculateTypeStats(unified),
      bySeverity: this.calculateSeverityStats(unified),
    };
    
    this.logger?.info(`Merge complete: ${result.confirmed} confirmed, ${result.unconfirmed} unconfirmed, ${result.dynamicOnly} dynamic-only`);
    
    return result;
  }
  
  /**
   * Convert CPG findings to static format
   */
  private convertCPGToStatic(cpgFindings: DataFlowFinding[]): StaticFinding[] {
    return cpgFindings.map(f => ({
      id: f.id,
      vulnerabilityType: f.vulnerabilityType as StaticFinding['vulnerabilityType'],
      category: f.vulnerabilityType,
      source: {
        node: f.source,
        description: f.source.code,
      },
      sink: {
        node: f.sink,
        description: f.sink.code,
      },
      path: f.path,
      staticConfidence: f.confidence,
      isSanitized: f.isSanitized,
      sanitizationInfo: f.sanitizationPoints.length > 0 ? {
        points: f.sanitizationPoints,
        methods: [],
        isSufficient: false,
      } : undefined,
      codeContext: {
        functionName: f.sink.label,
        filePath: f.sink.location.file,
        lineStart: f.sink.location.lineStart,
        lineEnd: f.sink.location.lineEnd,
        codeSnippet: f.sink.code,
      },
      externallyReachable: true,
      reachableFrom: [],
    }));
  }
  
  /**
   * Convert exploitation evidence to dynamic format
   */
  private convertEvidenceToDynamic(evidence: ExploitationEvidence[]): DynamicFinding[] {
    return evidence.map(e => ({
      id: e.vulnId,
      vulnerabilityType: e.type,
      exploited: e.exploited,
      evidence: {
        payload: e.evidence.payload,
        response: e.evidence.response,
        screenshot: e.evidence.screenshot,
        requestDetails: JSON.stringify(e.target),
      },
      target: e.target,
      dynamicConfidence: e.confidence,
      timestamp: e.timestamp,
      complexity: 'MODERATE', // Default, would be determined by analysis
      impact: e.exploited ? 'HIGH' : 'MEDIUM',
    }));
  }
  
  /**
   * Convert correlated finding to unified format
   */
  private toUnifiedFinding(correlated: CorrelatedFinding): UnifiedFinding {
    const sources: UnifiedFinding['sources'] = [];
    
    if (correlated.staticFinding) {
      sources.push({
        type: correlated.status === 'CONFIRMED' ? 'CORRELATED' : 'STATIC',
        id: correlated.staticFinding.id,
        confidence: correlated.staticFinding.staticConfidence,
      });
    }
    
    if (correlated.dynamicFinding) {
      sources.push({
        type: correlated.status === 'DYNAMIC_ONLY' ? 'DYNAMIC' : 'CORRELATED',
        id: correlated.dynamicFinding.id,
        confidence: correlated.dynamicFinding.dynamicConfidence,
      });
    }
    
    return {
      id: correlated.id,
      title: this.generateTitle(correlated),
      description: this.generateDescription(correlated),
      type: (correlated.staticFinding?.vulnerabilityType || 
            correlated.dynamicFinding?.vulnerabilityType || 'OTHER') as VulnType,
      category: this.classifyCategory(correlated),
      severity: correlated.assessment.severity,
      confidence: correlated.assessment.confidence,
      sources,
      isExploitable: correlated.status === 'CONFIRMED',
      hasExploit: correlated.dynamicFinding?.exploited || false,
      codeLocation: correlated.assessment.fixLocation ? {
        file: correlated.assessment.fixLocation.file,
        line: correlated.assessment.fixLocation.line,
        function: correlated.staticFinding?.codeContext.functionName,
        code: correlated.assessment.fixLocation.code,
      } : undefined,
      networkLocation: correlated.dynamicFinding?.target ? {
        url: correlated.dynamicFinding.target.url,
        method: correlated.dynamicFinding.target.method,
        parameter: correlated.dynamicFinding.target.parameter,
      } : undefined,
      exploitation: correlated.dynamicFinding?.exploited ? {
        payload: correlated.dynamicFinding.evidence.payload,
        evidence: correlated.dynamicFinding.evidence.response,
        complexity: correlated.dynamicFinding.complexity,
      } : undefined,
      remediation: {
        description: correlated.assessment.recommendation,
        codeFix: correlated.assessment.fixLocation?.suggestion,
        references: this.generateReferences(correlated),
      },
      metadata: {
        createdAt: correlated.createdAt,
        updatedAt: correlated.updatedAt,
        staticAnalysisId: correlated.staticFinding?.id,
        dynamicTestId: correlated.dynamicFinding?.id,
      },
    };
  }
  
  /**
   * Generate finding title
   */
  private generateTitle(correlated: CorrelatedFinding): string {
    const type = correlated.staticFinding?.vulnerabilityType || 
                 correlated.dynamicFinding?.vulnerabilityType || 'Vulnerability';
    
    if (correlated.status === 'CONFIRMED') {
      return `Confirmed ${type} - Successfully Exploited`;
    } else if (correlated.status === 'UNCONFIRMED') {
      return `Potential ${type} - Requires Verification`;
    } else if (correlated.status === 'DYNAMIC_ONLY') {
      return `Discovered ${type} - Runtime Detection`;
    } else {
      return `${type} Finding`;
    }
  }
  
  /**
   * Generate finding description
   */
  private generateDescription(correlated: CorrelatedFinding): string {
    const parts: string[] = [];
    
    parts.push(correlated.correlation.explanation);
    
    if (correlated.status === 'CONFIRMED') {
      parts.push('This vulnerability was confirmed through both static analysis and dynamic exploitation.');
    } else if (correlated.status === 'UNCONFIRMED') {
      parts.push('Static analysis suggests a vulnerability, but dynamic testing could not confirm it.');
    }
    
    return parts.join(' ');
  }
  
  /**
   * Classify finding category
   */
  private classifyCategory(correlated: CorrelatedFinding): string {
    const vulnType = correlated.staticFinding?.vulnerabilityType || 
                      correlated.dynamicFinding?.vulnerabilityType || '';
    
    const categoryMap: Record<string, string> = {
      'INJECTION': 'Injection',
      'XSS': 'Cross-Site Scripting',
      'AUTH': 'Authentication',
      'AUTHZ': 'Authorization',
      'SSRF': 'Server-Side Request Forgery',
    };
    
    return categoryMap[vulnType] || 'Security Issue';
  }
  
  /**
   * Generate remediation references
   */
  private generateReferences(correlated: CorrelatedFinding): string[] {
    const refs: string[] = [];
    
    const vulnType = correlated.staticFinding?.vulnerabilityType || '';
    
    if (vulnType.includes('SQL')) {
      refs.push('https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html');
    } else if (vulnType.includes('XSS')) {
      refs.push('https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html');
    } else if (vulnType.includes('AUTH')) {
      refs.push('https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html');
    }
    
    refs.push('https://owasp.org/www-project-top-ten/');
    
    return refs;
  }
  
  /**
   * Calculate statistics by type
   */
  private calculateTypeStats(findings: UnifiedFinding[]): Record<string, number> {
    const stats: Record<string, number> = {};
    
    for (const finding of findings) {
      stats[finding.type] = (stats[finding.type] || 0) + 1;
    }
    
    return stats;
  }
  
  /**
   * Calculate statistics by severity
   */
  private calculateSeverityStats(findings: UnifiedFinding[]): Record<string, number> {
    const stats: Record<string, number> = {};
    
    for (const finding of findings) {
      stats[finding.severity] = (stats[finding.severity] || 0) + 1;
    }
    
    return stats;
  }
  
  /**
   * Export findings to SARIF format
   */
  exportToSARIF(result: MergeResult): string {
    const sarif = {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'Shanom Static-Dynamic Correlation',
            version: '1.0.0',
          },
        },
        results: result.findings.map(f => ({
          ruleId: f.type,
          level: this.mapSeverityToSARIF(f.severity),
          message: { text: f.description },
          locations: f.codeLocation ? [{
            physicalLocation: {
              artifactLocation: { uri: f.codeLocation.file },
              region: {
                startLine: f.codeLocation.line,
              },
            },
          }] : undefined,
          properties: {
            confidence: f.confidence,
            isExploitable: f.isExploitable,
            hasExploit: f.hasExploit,
          },
        })),
      }],
    };
    
    return JSON.stringify(sarif, null, 2);
  }
  
  /**
   * Map severity to SARIF level
   */
  private mapSeverityToSARIF(severity: UnifiedFinding['severity']): string {
    const map: Record<string, string> = {
      'CRITICAL': 'error',
      'HIGH': 'error',
      'MEDIUM': 'warning',
      'LOW': 'note',
      'INFO': 'note',
    };
    return map[severity] || 'warning';
  }
  
  /**
   * Save merged results to deliverables
   */
  async saveResults(
    result: MergeResult,
    deliverablesPath: string
  ): Promise<void> {
    const correlationDir = path.join(deliverablesPath, 'correlation');
    await fs.ensureDir(correlationDir);
    
    // Save unified findings as JSON
    const jsonPath = path.join(correlationDir, 'unified_findings.json');
    await fs.writeFile(
      jsonPath,
      JSON.stringify({
        summary: {
          total: result.total,
          confirmed: result.confirmed,
          unconfirmed: result.unconfirmed,
          dynamicOnly: result.dynamicOnly,
          falsePositives: result.falsePositives,
          byType: result.byType,
          bySeverity: result.bySeverity,
        },
        findings: result.findings,
      }, null, 2),
      'utf8'
    );
    
    // Save SARIF format
    const sarifPath = path.join(correlationDir, 'unified_findings.sarif');
    await fs.writeFile(sarifPath, this.exportToSARIF(result), 'utf8');
    
    // Generate markdown report
    const reportPath = path.join(correlationDir, 'correlation_report.md');
    await fs.writeFile(reportPath, this.generateMarkdownReport(result), 'utf8');
    
    this.logger?.info(`Saved unified findings to ${correlationDir}`);
  }
  
  /**
   * Generate markdown report
   */
  private generateMarkdownReport(result: MergeResult): string {
    const lines: string[] = [];
    
    lines.push('# Static-Dynamic Correlation Report');
    lines.push('');
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(`This report presents the correlation between static analysis (CPG) findings`);
    lines.push(`and dynamic exploitation results, providing validated vulnerabilities with`);
    lines.push(`both proof-of-concept exploits and precise code locations.`);
    lines.push('');
    lines.push(`- **Total Findings:** ${result.total}`);
    lines.push(`- **Confirmed Vulnerabilities:** ${result.confirmed}`);
    lines.push(`- **Unconfirmed (Static Only):** ${result.unconfirmed}`);
    lines.push(`- **Dynamic-Only Discoveries:** ${result.dynamicOnly}`);
    lines.push(`- **False Positives:** ${result.falsePositives}`);
    lines.push('');
    
    // By type
    lines.push('## Findings by Type');
    lines.push('');
    lines.push('| Type | Count |');
    lines.push('|------|-------|');
    for (const [type, count] of Object.entries(result.byType)) {
      lines.push(`| ${type} | ${count} |`);
    }
    lines.push('');
    
    // By severity
    lines.push('## Findings by Severity');
    lines.push('');
    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    for (const [sev, count] of Object.entries(result.bySeverity)) {
      lines.push(`| ${sev} | ${count} |`);
    }
    lines.push('');
    
    // Critical/High findings
    const criticalFindings = result.findings.filter(f => 
      f.severity === 'CRITICAL' || f.severity === 'HIGH'
    );
    
    if (criticalFindings.length > 0) {
      lines.push('## Critical & High Severity Findings');
      lines.push('');
      
      for (const finding of criticalFindings) {
        lines.push(`### ${finding.title}`);
        lines.push('');
        lines.push(`**Severity:** ${finding.severity}`);
        lines.push(`**Type:** ${finding.type}`);
        lines.push(`**Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
        lines.push(`**Status:** ${finding.isExploitable ? '✅ Confirmed Exploitable' : '⚠️ Unconfirmed'}`);
        lines.push('');
        lines.push(finding.description);
        lines.push('');
        
        if (finding.codeLocation) {
          lines.push('**Code Location:**');
          lines.push(`- File: \`${finding.codeLocation.file}\``);
          lines.push(`- Line: ${finding.codeLocation.line}`);
          if (finding.codeLocation.function) {
            lines.push(`- Function: \`${finding.codeLocation.function}\``);
          }
          lines.push(`- Code: \`${finding.codeLocation.code}\``);
          lines.push('');
        }
        
        if (finding.networkLocation) {
          lines.push('**Network Location:**');
          lines.push(`- URL: \`${finding.networkLocation.url}\``);
          lines.push(`- Method: ${finding.networkLocation.method}`);
          if (finding.networkLocation.parameter) {
            lines.push(`- Parameter: \`${finding.networkLocation.parameter}\``);
          }
          lines.push('');
        }
        
        if (finding.exploitation) {
          lines.push('**Exploitation Details:**');
          lines.push(`- Payload: \`${finding.exploitation.payload}\``);
          lines.push(`- Complexity: ${finding.exploitation.complexity}`);
          lines.push('');
        }
        
        lines.push('**Remediation:**');
        lines.push(finding.remediation.description);
        if (finding.remediation.codeFix) {
          lines.push('');
          lines.push(`Suggested fix: ${finding.remediation.codeFix}`);
        }
        lines.push('');
        lines.push('---');
        lines.push('');
      }
    }
    
    return lines.join('\n');
  }
}
