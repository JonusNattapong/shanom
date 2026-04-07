// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Correlation Service
 * 
 * Main service for integrating static-dynamic correlation into the pentest workflow.
 * Orchestrates CPG analysis, queue injection, and result correlation.
 */

import { fs, path } from 'zx';
import { CPGEngine, DEFAULT_CPG_CONFIG } from '../cpg/index.js';
import type { CPGAnalysisResult } from '../cpg/index.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { VulnType } from '../types/index.js';
import { CPGFindingsInjector } from './injector.js';
import { UnifiedFindingsMerger, type ExploitationEvidence } from './merger.js';

export interface CorrelationWorkflowConfig {
  /** Enable CPG static analysis */
  enableStaticAnalysis: boolean;
  
  /** Enable queue injection from CPG */
  enableQueueInjection: boolean;
  
  /** Enable correlation after exploitation */
  enableCorrelation: boolean;
  
  /** Model tier for CPG analysis */
  modelTier: 'small' | 'medium' | 'large';
  
  /** Max files to analyze */
  maxFiles: number;
  
  /** Analyze only critical files */
  criticalFilesOnly: boolean;
  
  /** Auto-save results */
  autoSave: boolean;
}

export const DEFAULT_CORRELATION_WORKFLOW_CONFIG: CorrelationWorkflowConfig = {
  enableStaticAnalysis: true,
  enableQueueInjection: true,
  enableCorrelation: true,
  modelTier: 'medium',
  maxFiles: 50,
  criticalFilesOnly: true,
  autoSave: true,
};

export class CorrelationService {
  private config: CorrelationWorkflowConfig;
  private logger?: ActivityLogger;
  private cpgEngine: CPGEngine;
  private injector: CPGFindingsInjector;
  private merger: UnifiedFindingsMerger;
  
  /** Store for exploitation results */
  private exploitationResults: ExploitationEvidence[] = [];
  
  constructor(
    config: Partial<CorrelationWorkflowConfig> = {},
    logger?: ActivityLogger
  ) {
    this.config = { ...DEFAULT_CORRELATION_WORKFLOW_CONFIG, ...config };
    this.logger = logger;
    
    this.cpgEngine = new CPGEngine(
      {
        ...DEFAULT_CPG_CONFIG,
        modelTier: this.config.modelTier,
        maxFiles: this.config.maxFiles,
      },
      logger
    );
    
    this.injector = new CPGFindingsInjector(logger);
    this.merger = new UnifiedFindingsMerger(logger);
  }
  
  /**
   * Phase 1: Run CPG Static Analysis
   * 
   * Called during pre-recon phase to analyze source code
   */
  async runStaticAnalysis(repoPath: string): Promise<CPGAnalysisResult | null> {
    if (!this.config.enableStaticAnalysis) {
      this.logger?.info('CPG static analysis disabled');
      return null;
    }
    
    this.logger?.info('Starting CPG static analysis...');
    
    try {
      let result: CPGAnalysisResult;
      
      if (this.config.criticalFilesOnly) {
        // Analyze only critical files (routes, controllers, auth)
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
        result = await this.cpgEngine.analyzeCriticalFiles(repoPath, criticalPatterns);
      } else {
        // Analyze entire project
        result = await this.cpgEngine.analyzeProject(repoPath);
      }
      
      // Save CPG results to deliverables
      const cpgDir = path.join(repoPath, '.shanom', 'deliverables', 'cpg');
      await fs.ensureDir(cpgDir);
      
      // Save JSON findings
      const jsonPath = path.join(cpgDir, 'cpg_findings.json');
      await fs.writeFile(
        jsonPath,
        JSON.stringify({
          summary: {
            filesAnalyzed: result.files.length,
            totalNodes: result.totalNodes,
            dataFlowFindings: result.dataFlowFindings.length,
            vulnerableFindings: result.dataFlowFindings.filter(f => f.isVulnerable).length,
            durationMs: result.durationMs,
          },
          findings: result.dataFlowFindings.map(f => ({
            id: f.id,
            type: f.vulnerabilityType,
            confidence: f.confidence,
            isVulnerable: f.isVulnerable,
            isSanitized: f.isSanitized,
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
            recommendation: f.recommendation,
          })),
          entryPoints: result.entryPoints.map(ep => ({
            name: ep.fullName || ep.label,
            file: ep.location.file,
            line: ep.location.lineStart,
          })),
        }, null, 2),
        'utf8'
      );
      
      // Save markdown report
      const reportPath = path.join(cpgDir, 'cpg_security_analysis.md');
      await fs.writeFile(reportPath, this.cpgEngine.exportSecurityReport(result), 'utf8');
      
      this.logger?.info(`CPG analysis complete: ${result.dataFlowFindings.length} findings (${result.dataFlowFindings.filter(f => f.isVulnerable).length} vulnerable)`);
      
      return result;
    } catch (error) {
      this.logger?.error(`CPG analysis failed: ${error}`);
      return null;
    }
  }
  
  /**
   * Phase 2: Inject CPG Findings into Exploitation Queues
   * 
   * Called before exploitation phase to enrich queues with static findings
   */
  async injectIntoQueues(
    cpgResult: CPGAnalysisResult,
    repoPath: string
  ): Promise<boolean> {
    if (!this.config.enableQueueInjection) {
      this.logger?.info('Queue injection disabled');
      return false;
    }
    
    this.logger?.info('Injecting CPG findings into exploitation queues...');
    
    try {
      const results = await this.injector.injectIntoQueues(cpgResult, repoPath);
      const summary = this.injector.getInjectionSummary(results);
      
      this.logger?.info(
        `Injected ${summary.totalInjected} findings into queues ` +
        `(total in queues: ${summary.totalInQueues})`
      );
      
      // Log by type
      for (const [type, count] of Object.entries(summary.byType)) {
        this.logger?.info(`  - ${type}: ${count} injected`);
      }
      
      return summary.totalInjected > 0;
    } catch (error) {
      this.logger?.error(`Queue injection failed: ${error}`);
      return false;
    }
  }
  
  /**
   * Phase 3: Record Exploitation Result
   * 
   * Called by exploitation agents to record their findings
   */
  recordExploitationResult(evidence: ExploitationEvidence): void {
    this.exploitationResults.push(evidence);
    this.logger?.info(
      `Recorded exploitation result: ${evidence.vulnId} ` +
      `(${evidence.exploited ? 'exploited' : 'not exploited'})`
    );
  }
  
  /**
   * Phase 4: Correlate and Merge Results
   * 
   * Called after exploitation phase to correlate static and dynamic findings
   */
  async correlateResults(
    cpgResult: CPGAnalysisResult | null,
    repoPath: string
  ): Promise<boolean> {
    if (!this.config.enableCorrelation) {
      this.logger?.info('Correlation disabled');
      return false;
    }
    
    if (!cpgResult) {
      this.logger?.warn('No CPG results available for correlation');
      return false;
    }
    
    if (this.exploitationResults.length === 0) {
      this.logger?.warn('No exploitation results available for correlation');
      return false;
    }
    
    this.logger?.info('Correlating static and dynamic findings...');
    
    try {
      // Merge findings
      const mergeResult = await this.merger.merge(
        cpgResult,
        this.exploitationResults
      );
      
      // Save results
      const deliverablesPath = path.join(repoPath, '.shanom', 'deliverables');
      await this.merger.saveResults(mergeResult, deliverablesPath);
      
      this.logger?.info(
        `Correlation complete: ` +
        `${mergeResult.confirmed} confirmed, ` +
        `${mergeResult.unconfirmed} unconfirmed, ` +
        `${mergeResult.dynamicOnly} dynamic-only`
      );
      
      // Log severity breakdown
      for (const [sev, count] of Object.entries(mergeResult.bySeverity)) {
        if (count > 0) {
          this.logger?.info(`  - ${sev}: ${count} findings`);
        }
      }
      
      return true;
    } catch (error) {
      this.logger?.error(`Correlation failed: ${error}`);
      return false;
    }
  }
  
  /**
   * Run complete correlation workflow
   * 
   * Convenience method for running all phases
   */
  async runCompleteWorkflow(repoPath: string): Promise<{
    staticAnalysis: CPGAnalysisResult | null;
    injectionSuccess: boolean;
    correlationSuccess: boolean;
  }> {
    // Phase 1: Static Analysis
    const cpgResult = await this.runStaticAnalysis(repoPath);
    
    // Phase 2: Inject into Queues (if we have results)
    let injectionSuccess = false;
    if (cpgResult && cpgResult.dataFlowFindings.length > 0) {
      injectionSuccess = await this.injectIntoQueues(cpgResult, repoPath);
    }
    
    // Phase 3 & 4: Exploitation happens separately via agents
    // Correlation will be called after exploitation completes
    
    return {
      staticAnalysis: cpgResult,
      injectionSuccess,
      correlationSuccess: false, // Will be set later after exploitation
    };
  }
  
  /**
   * Complete correlation after exploitation phase
   */
  async completeCorrelation(
    cpgResult: CPGAnalysisResult | null,
    repoPath: string
  ): Promise<boolean> {
    return await this.correlateResults(cpgResult, repoPath);
  }
  
  /**
   * Get exploitation results (for testing/debugging)
   */
  getExploitationResults(): ExploitationEvidence[] {
    return [...this.exploitationResults];
  }
  
  /**
   * Clear exploitation results
   */
  clearExploitationResults(): void {
    this.exploitationResults = [];
  }
  
  /**
   * Load exploitation evidence from exploitation deliverables
   */
  async loadExploitationEvidence(repoPath: string): Promise<ExploitationEvidence[]> {
    const deliverablesPath = path.join(repoPath, '.shanom', 'deliverables');
    const evidence: ExploitationEvidence[] = [];
    
    const vulnTypes: VulnType[] = ['injection', 'xss', 'auth', 'ssrf', 'authz'];
    
    for (const vulnType of vulnTypes) {
      const evidenceFile = path.join(deliverablesPath, `${vulnType}_exploitation_evidence.md`);
      
      try {
        if (await fs.pathExists(evidenceFile)) {
          const content = await fs.readFile(evidenceFile, 'utf8');
          
          // Parse evidence file for successful exploits
          // This is a simplified parser - real implementation would be more robust
          const exploitMatches = content.match(/Exploitation Successful[\s\S]*?(?=Exploitation Unsuccessful|$)/g);
          
          if (exploitMatches) {
            for (const match of exploitMatches) {
              const urlMatch = match.match(/Target:\s*(.+)/);
              const payloadMatch = match.match(/Payload:\s*(.+)/);
              
              evidence.push({
                vulnId: `${vulnType}-${Date.now()}`,
                type: vulnType,
                exploited: true,
                evidence: {
                  payload: payloadMatch?.[1] || 'unknown',
                  response: match,
                },
                target: {
                  url: urlMatch?.[1] || 'unknown',
                  method: 'POST', // Default assumption
                },
                confidence: 0.9,
                timestamp: new Date(),
              });
            }
          }
        }
      } catch {
        // File doesn't exist or can't be read
      }
    }
    
    this.logger?.info(`Loaded ${evidence.length} exploitation evidence from deliverables`);
    return evidence;
  }
}
