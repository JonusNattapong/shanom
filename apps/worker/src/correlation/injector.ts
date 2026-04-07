// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * CPG Findings Injector
 * 
 * Injects static analysis (CPG) findings into the exploitation queue.
 * This bridges the gap between static analysis and dynamic testing,
 * ensuring that CPG-identified vulnerabilities are tested dynamically.
 */

import { fs, path } from 'zx';
import type { CPGAnalysisResult, DataFlowFinding } from '../cpg/index.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { VulnType } from '../types/index.js';

export interface InjectedVulnerability {
  /** Unique ID */
  ID: string;
  
  /** Vulnerability type */
  vulnerability_type: string;
  
  /** Can this be exploited externally? */
  externally_exploitable: boolean;
  
  /** Confidence level */
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  
  /** Source information */
  source?: string;
  source_detail?: string;
  
  /** Path/sink information */
  path?: string;
  sink_call?: string;
  sink_function?: string;
  
  /** Context from CPG */
  code_location?: string;
  vulnerable_code_location?: string;
  
  /** Sanitization info */
  sanitization_observed?: string;
  encoding_observed?: string;
  
  /** Static analysis metadata */
  static_analysis: {
    finding_id: string;
    confidence_score: number;
    is_sanitized: boolean;
    file_path: string;
    line_number: number;
    code_snippet: string;
    data_flow_path: string[];
  };
  
  /** Notes for exploitation agent */
  notes?: string;
  exploitation_hypothesis?: string;
  suggested_exploit_technique?: string;
  
  /** Verification status */
  from_static_analysis: true;
  requires_dynamic_verification: true;
}

export interface InjectionResult {
  /** Vulnerability type */
  vulnType: VulnType;
  
  /** Original queue count */
  originalCount: number;
  
  /** Injected count */
  injectedCount: number;
  
  /** Final queue count */
  finalCount: number;
  
  /** Injected vulnerabilities */
  injected: InjectedVulnerability[];
  
  /** Path to updated queue file */
  queueFilePath: string;
}

export class CPGFindingsInjector {
  private logger?: ActivityLogger;
  
  constructor(logger?: ActivityLogger) {
    this.logger = logger;
  }
  
  /**
   * Inject CPG findings into all exploitation queues
   */
  async injectIntoQueues(
    cpgResult: CPGAnalysisResult,
    repoPath: string
  ): Promise<InjectionResult[]> {
    const results: InjectionResult[] = [];
    
    // Group findings by vulnerability type
    const findingsByType = this.groupFindingsByType(cpgResult.dataFlowFindings);
    
    // Inject into each vulnerability type queue
    for (const [vulnType, findings] of findingsByType) {
      if (findings.length === 0) continue;
      
      const result = await this.injectIntoQueue(
        vulnType as VulnType,
        findings,
        repoPath
      );
      
      results.push(result);
    }
    
    this.logger?.info(`Injected ${cpgResult.dataFlowFindings.length} CPG findings into exploitation queues`);
    
    return results;
  }
  
  /**
   * Inject findings into a specific vulnerability queue
   */
  private async injectIntoQueue(
    vulnType: VulnType,
    findings: DataFlowFinding[],
    repoPath: string
  ): Promise<InjectionResult> {
    const queueFileName = `${vulnType}_exploitation_queue.json`;
    const queuePath = path.join(repoPath, '.shanom', 'deliverables', queueFileName);
    
    // Read existing queue if present
    let existingQueue: { vulnerabilities: unknown[] } = { vulnerabilities: [] };
    try {
      if (await fs.pathExists(queuePath)) {
        const content = await fs.readFile(queuePath, 'utf8');
        existingQueue = JSON.parse(content);
      }
    } catch {
      // Queue doesn't exist or is invalid, start fresh
    }
    
    const originalCount = existingQueue.vulnerabilities.length;
    
    // Convert CPG findings to injection format
    const injectedVulns: InjectedVulnerability[] = findings.map(f => 
      this.convertFinding(vulnType, f)
    );
    
    // Merge with existing queue
    // Avoid duplicates by checking code location
    const existingLocations = new Set(
      existingQueue.vulnerabilities.map((v: unknown) => {
        const vuln = v as Record<string, unknown>;
        return `${vuln.code_location || vuln.vulnerable_code_location}`;
      })
    );
    
    const newVulns = injectedVulns.filter(v => {
      const location = v.code_location || v.vulnerable_code_location;
      return !existingLocations.has(location || '');
    });
    
    // Add to queue
    existingQueue.vulnerabilities.push(...newVulns);
    
    // Write updated queue
    await fs.ensureDir(path.dirname(queuePath));
    await fs.writeFile(queuePath, JSON.stringify(existingQueue, null, 2), 'utf8');
    
    this.logger?.info(`Injected ${newVulns.length} ${vulnType} findings into queue (total: ${existingQueue.vulnerabilities.length})`);
    
    return {
      vulnType,
      originalCount,
      injectedCount: newVulns.length,
      finalCount: existingQueue.vulnerabilities.length,
      injected: newVulns,
      queueFilePath: queuePath,
    };
  }
  
  /**
   * Group findings by vulnerability type
   */
  private groupFindingsByType(findings: DataFlowFinding[]): Map<string, DataFlowFinding[]> {
    const groups = new Map<string, DataFlowFinding[]>();
    
    for (const finding of findings) {
      // Map vulnerability type to our categories
      let category: string;
      const vulnType = finding.vulnerabilityType.toUpperCase();
      
      if (vulnType.includes('SQL') || vulnType.includes('COMMAND') || vulnType.includes('INJECTION')) {
        category = 'injection';
      } else if (vulnType.includes('XSS') || vulnType.includes('HTML')) {
        category = 'xss';
      } else if (vulnType.includes('AUTH') && !vulnType.includes('AUTHZ')) {
        category = 'auth';
      } else if (vulnType.includes('AUTHZ') || vulnType.includes('ACCESS') || vulnType.includes('IDOR')) {
        category = 'authz';
      } else if (vulnType.includes('SSRF') || vulnType.includes('REQUEST')) {
        category = 'ssrf';
      } else {
        // Skip uncategorized findings
        continue;
      }
      
      const list = groups.get(category) || [];
      list.push(finding);
      groups.set(category, list);
    }
    
    return groups;
  }
  
  /**
   * Convert a CPG finding to injection format
   */
  private convertFinding(vulnType: VulnType, finding: DataFlowFinding): InjectedVulnerability {
    // Determine confidence level
    let confidence: 'HIGH' | 'MEDIUM' | 'LOW';
    if (finding.confidence > 0.8) {
      confidence = 'HIGH';
    } else if (finding.confidence > 0.5) {
      confidence = 'MEDIUM';
    } else {
      confidence = 'LOW';
    }
    
    // Build exploitation hypothesis
    const hypothesis = this.buildExploitationHypothesis(finding);
    
    // Build suggested technique
    const technique = this.buildExploitTechnique(finding);
    
    return {
      ID: `cpg-${finding.id}`,
      vulnerability_type: finding.vulnerabilityType,
      externally_exploitable: true, // CPG findings from entry points are externally reachable
      confidence,
      
      source: finding.source.code,
      source_detail: `Variable: ${finding.source.label} at ${finding.source.location.file}:${finding.source.location.lineStart}`,
      
      path: finding.path.map(n => n.code).join(' → '),
      sink_call: finding.sink.code,
      sink_function: finding.sink.label,
      
      code_location: `${finding.sink.location.file}:${finding.sink.location.lineStart}`,
      vulnerable_code_location: `${finding.sink.location.file}:${finding.sink.location.lineStart}`,
      
      sanitization_observed: finding.isSanitized 
        ? `Sanitized at ${finding.sanitizationPoints.map(p => `${p.location.file}:${p.location.lineStart}`).join(', ')}`
        : 'No sanitization detected',
      
      static_analysis: {
        finding_id: finding.id,
        confidence_score: finding.confidence,
        is_sanitized: finding.isSanitized,
        file_path: finding.sink.location.file,
        line_number: finding.sink.location.lineStart,
        code_snippet: finding.sink.code,
        data_flow_path: finding.path.map(n => `${n.location.file}:${n.location.lineStart}`),
      },
      
      notes: `CPG Static Analysis Finding: ${finding.vulnerabilityType} from ${finding.source.label} to ${finding.sink.label}. Confidence: ${(finding.confidence * 100).toFixed(0)}%.`,
      exploitation_hypothesis: hypothesis,
      suggested_exploit_technique: technique,
      
      from_static_analysis: true,
      requires_dynamic_verification: true,
    };
  }
  
  /**
   * Build exploitation hypothesis based on finding
   */
  private buildExploitationHypothesis(finding: DataFlowFinding): string {
    const parts: string[] = [];
    
    parts.push(`The application receives untrusted input through ${finding.source.label}`);
    parts.push(`and passes it to ${finding.sink.label} without sufficient sanitization.`);
    
    if (finding.isSanitized) {
      parts.push(`Sanitization is applied but may be bypassable or insufficient.`);
    }
    
    parts.push(`An attacker could exploit this to:`);
    
    // Add specific impact based on type
    const vulnType = finding.vulnerabilityType.toLowerCase();
    if (vulnType.includes('sql')) {
      parts.push(`- Extract or modify database data`);
      parts.push(`- Execute administrative operations`);
    } else if (vulnType.includes('command')) {
      parts.push(`- Execute arbitrary system commands`);
      parts.push(`- Gain server access`);
    } else if (vulnType.includes('xss')) {
      parts.push(`- Execute JavaScript in victim's browser`);
      parts.push(`- Steal session cookies or credentials`);
    } else if (vulnType.includes('ssrf')) {
      parts.push(`- Access internal services`);
      parts.push(`- Bypass authentication or access controls`);
    } else if (vulnType.includes('auth')) {
      parts.push(`- Bypass authentication controls`);
      parts.push(`- Access unauthorized functionality`);
    }
    
    return parts.join(' ');
  }
  
  /**
   * Build exploit technique suggestion
   */
  private buildExploitTechnique(finding: DataFlowFinding): string {
    const vulnType = finding.vulnerabilityType.toLowerCase();
    
    if (vulnType.includes('sql')) {
      return `Attempt SQL injection payloads: ' OR '1'='1, UNION SELECT, time-based blind injection. Focus on the parameter identified in the code location.`;
    } else if (vulnType.includes('command')) {
      return `Attempt command injection payloads: ; ls, | cat /etc/passwd, $(whoami). Try both Unix and Windows command separators.`;
    } else if (vulnType.includes('xss')) {
      return `Attempt XSS payloads: <script>alert(1)</script>, <img src=x onerror=alert(1)>, javascript:alert(1). Check both reflected and stored contexts.`;
    } else if (vulnType.includes('ssrf')) {
      return `Attempt SSRF payloads: http://localhost, http://169.254.169.254/, file:///etc/passwd. Test URL parameter manipulation.`;
    } else if (vulnType.includes('auth')) {
      return `Attempt authentication bypass: SQL injection in username, forced browsing, parameter manipulation, JWT token tampering.`;
    } else if (vulnType.includes('authz')) {
      return `Attempt IDOR: Modify object IDs in requests, test horizontal/vertical privilege escalation, access other users' resources.`;
    }
    
    return `Analyze the code path and attempt targeted exploitation based on the vulnerability type.`;
  }
  
  /**
   * Create queue file from scratch with CPG findings only
   */
  async createQueueFromCPG(
    cpgResult: CPGAnalysisResult,
    repoPath: string
  ): Promise<string[]> {
    const createdFiles: string[] = [];
    
    const findingsByType = this.groupFindingsByType(cpgResult.dataFlowFindings);
    
    for (const [vulnType, findings] of findingsByType) {
      const queueFileName = `${vulnType}_exploitation_queue.json`;
      const queuePath = path.join(repoPath, '.shanom', 'deliverables', queueFileName);
      
      const vulns = findings.map(f => this.convertFinding(vulnType as VulnType, f));
      const queue = { vulnerabilities: vulns };
      
      await fs.ensureDir(path.dirname(queuePath));
      await fs.writeFile(queuePath, JSON.stringify(queue, null, 2), 'utf8');
      
      createdFiles.push(queuePath);
      this.logger?.info(`Created ${queueFileName} with ${vulns.length} CPG findings`);
    }
    
    return createdFiles;
  }
  
  /**
   * Get injection summary
   */
  getInjectionSummary(results: InjectionResult[]): {
    totalInjected: number;
    byType: Record<string, number>;
    totalInQueues: number;
  } {
    return {
      totalInjected: results.reduce((sum, r) => sum + r.injectedCount, 0),
      byType: Object.fromEntries(
        results.map(r => [r.vulnType, r.injectedCount])
      ),
      totalInQueues: results.reduce((sum, r) => sum + r.finalCount, 0),
    };
  }
}
