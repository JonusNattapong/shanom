// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Static-Dynamic Correlation Engine
 * 
 * Correlates findings from static analysis (CPG) with dynamic exploitation results.
 * This is the core differentiator that validates static findings with real exploits.
 * 
 * Architecture:
 * - CPG Static Analysis → Vulnerability Findings
 * - Dynamic Pentest → Exploitation Evidence
 * - Correlation Engine → Validated Vulnerabilities with Code Location
 */

import type { DataFlowFinding } from '../cpg/data-flow-analyzer.js';
import type { CPGNode } from '../cpg/models.js';

export interface StaticFinding {
  /** Unique ID from CPG analysis */
  id: string;
  
  /** Vulnerability type */
  vulnerabilityType: 'INJECTION' | 'XSS' | 'AUTH' | 'AUTHZ' | 'SSRF' | 'OTHER';
  
  /** Detailed category */
  category: string;
  
  /** Source node (where untrusted data enters) */
  source: {
    node: CPGNode;
    description: string;
  };
  
  /** Sink node (where vulnerability manifests) */
  sink: {
    node: CPGNode;
    description: string;
  };
  
  /** Data flow path */
  path: CPGNode[];
  
  /** Confidence from static analysis (0-1) */
  staticConfidence: number;
  
  /** Is data sanitized? */
  isSanitized: boolean;
  
  /** Sanitization details */
  sanitizationInfo?: {
    points: CPGNode[];
    methods: string[];
    isSufficient: boolean;
  };
  
  /** Code context */
  codeContext: {
    functionName?: string;
    filePath: string;
    lineStart: number;
    lineEnd: number;
    codeSnippet: string;
  };
  
  /** Whether this can be reached from external input */
  externallyReachable: boolean;
  
  /** Entry points that can reach this vulnerability */
  reachableFrom: string[];
}

export interface DynamicFinding {
  /** ID from exploitation */
  id: string;
  
  /** Vulnerability type */
  vulnerabilityType: string;
  
  /** Was exploitation successful? */
  exploited: boolean;
  
  /** Exploitation evidence */
  evidence: {
    payload: string;
    response: string;
    screenshot?: string;
    requestDetails: string;
  };
  
  /** Target endpoint */
  target: {
    url: string;
    method: string;
    parameter?: string;
  };
  
  /** Confidence from dynamic test (0-1) */
  dynamicConfidence: number;
  
  /** Timestamp */
  timestamp: Date;
  
  /** Exploitation complexity */
  complexity: 'SIMPLE' | 'MODERATE' | 'COMPLEX';
  
  /** Impact if exploited */
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface CorrelatedFinding {
  /** Unified ID */
  id: string;
  
  /** Correlation status */
  status: 'CONFIRMED' | 'UNCONFIRMED' | 'FALSE_POSITIVE' | 'DYNAMIC_ONLY';
  
  /** Static analysis component */
  staticFinding?: StaticFinding;
  
  /** Dynamic exploitation component */
  dynamicFinding?: DynamicFinding;
  
  /** Correlation metadata */
  correlation: {
    /** How well static and dynamic match (0-1) */
    matchScore: number;
    
    /** Matching method used */
    matchMethod: 'CODE_LOCATION' | 'ENDPOINT' | 'VULN_TYPE' | 'MANUAL';
    
    /** Human-readable explanation */
    explanation: string;
    
    /** Is the correlation high confidence? */
    isHighConfidence: boolean;
  };
  
  /** Final assessment */
  assessment: {
    /** Is this a real vulnerability? */
    isVulnerable: boolean;
    
    /** Overall confidence */
    confidence: number;
    
    /** Severity rating */
    severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    
    /** Recommended action */
    recommendation: string;
    
    /** Specific code location to fix */
    fixLocation?: {
      file: string;
      line: number;
      code: string;
      suggestion: string;
    };
  };
  
  /** Timestamps */
  createdAt: Date;
  updatedAt: Date;
}

export interface CorrelationConfig {
  /** Minimum match score to consider correlated */
  minMatchScore: number;
  
  /** Weight for code location matching */
  codeLocationWeight: number;
  
  /** Weight for vulnerability type matching */
  vulnTypeWeight: number;
  
  /** Weight for endpoint matching */
  endpointWeight: number;
  
  /** Auto-confirm if both static and dynamic agree */
  autoConfirmThreshold: number;
  
  /** Flag as false positive if dynamic contradicts static */
  falsePositiveThreshold: number;
}

export const DEFAULT_CORRELATION_CONFIG: CorrelationConfig = {
  minMatchScore: 0.6,
  codeLocationWeight: 0.4,
  vulnTypeWeight: 0.3,
  endpointWeight: 0.3,
  autoConfirmThreshold: 0.8,
  falsePositiveThreshold: 0.2,
};

export class StaticDynamicCorrelationEngine {
  private config: CorrelationConfig;
  private correlations: Map<string, CorrelatedFinding> = new Map();
  
  constructor(config: Partial<CorrelationConfig> = {}) {
    this.config = { ...DEFAULT_CORRELATION_CONFIG, ...config };
  }
  
  /**
   * Correlate static findings with dynamic findings
   */
  correlate(
    staticFindings: StaticFinding[],
    dynamicFindings: DynamicFinding[]
  ): CorrelatedFinding[] {
    const results: CorrelatedFinding[] = [];
    const matchedDynamic = new Set<string>();
    const matchedStatic = new Set<string>();
    
    // Try to match each static finding with dynamic findings
    for (const staticFinding of staticFindings) {
      let bestMatch: { finding: DynamicFinding; score: number; method: string } | null = null;
      
      for (const dynamicFinding of dynamicFindings) {
        const match = this.calculateMatchScore(staticFinding, dynamicFinding);
        
        if (match.score > this.config.minMatchScore) {
          if (!bestMatch || match.score > bestMatch.score) {
            bestMatch = {
              finding: dynamicFinding,
              score: match.score,
              method: match.method,
            };
          }
        }
      }
      
      if (bestMatch) {
        // Create correlated finding
        const correlated = this.createCorrelatedFinding(
          staticFinding,
          bestMatch.finding,
          bestMatch.score,
          bestMatch.method as CorrelatedFinding['correlation']['matchMethod']
        );
        
        results.push(correlated);
        matchedDynamic.add(bestMatch.finding.id);
        matchedStatic.add(staticFinding.id);
        this.correlations.set(correlated.id, correlated);
      }
    }
    
    // Add unconfirmed static findings (no dynamic match)
    for (const staticFinding of staticFindings) {
      if (!matchedStatic.has(staticFinding.id)) {
        const unconfirmed = this.createUnconfirmedFinding(staticFinding);
        results.push(unconfirmed);
        this.correlations.set(unconfirmed.id, unconfirmed);
      }
    }
    
    // Add dynamic-only findings (no static match)
    for (const dynamicFinding of dynamicFindings) {
      if (!matchedDynamic.has(dynamicFinding.id)) {
        const dynamicOnly = this.createDynamicOnlyFinding(dynamicFinding);
        results.push(dynamicOnly);
        this.correlations.set(dynamicOnly.id, dynamicOnly);
      }
    }
    
    // Sort by severity and confidence
    return this.sortFindings(results);
  }
  
  /**
   * Calculate match score between static and dynamic findings
   */
  private calculateMatchScore(
    staticFinding: StaticFinding,
    dynamicFinding: DynamicFinding
  ): { score: number; method: string } {
    let score = 0;
    const weights: string[] = [];
    
    // Vulnerability type match
    const vulnTypeScore = this.matchVulnType(
      staticFinding.vulnerabilityType,
      dynamicFinding.vulnerabilityType
    );
    score += vulnTypeScore * this.config.vulnTypeWeight;
    if (vulnTypeScore > 0.5) weights.push('vulnType');
    
    // Code location match (if dynamic has code location info)
    const codeLocationScore = this.matchCodeLocation(staticFinding, dynamicFinding);
    score += codeLocationScore * this.config.codeLocationWeight;
    if (codeLocationScore > 0.5) weights.push('codeLocation');
    
    // Endpoint match (if static has endpoint info)
    const endpointScore = this.matchEndpoint(staticFinding, dynamicFinding);
    score += endpointScore * this.config.endpointWeight;
    if (endpointScore > 0.5) weights.push('endpoint');
    
    // Determine match method
    let method: string;
    if (weights.includes('codeLocation') && weights.includes('vulnType')) {
      method = 'CODE_LOCATION';
    } else if (weights.includes('endpoint')) {
      method = 'ENDPOINT';
    } else if (weights.includes('vulnType')) {
      method = 'VULN_TYPE';
    } else {
      method = 'MANUAL';
    }
    
    return { score: Math.min(1, score), method };
  }
  
  /**
   * Match vulnerability types
   */
  private matchVulnType(staticType: string, dynamicType: string): number {
    const staticNormalized = staticType.toLowerCase();
    const dynamicNormalized = dynamicType.toLowerCase();
    
    // Direct match
    if (staticNormalized === dynamicNormalized) return 1.0;
    
    // Category match
    const categoryMap: Record<string, string[]> = {
      'injection': ['sql', 'command', 'code', 'template', 'ldap', 'xpath', 'nosql'],
      'xss': ['cross-site', 'reflected', 'stored', 'dom', 'javascript'],
      'auth': ['authentication', 'session', 'credential', 'password', 'login'],
      'authz': ['authorization', 'permission', 'access', 'idor', 'privilege'],
      'ssrf': ['ssrf', 'server-side', 'request', 'internal'],
    };
    
    for (const [category, keywords] of Object.entries(categoryMap)) {
      const staticMatches = keywords.some(k => staticNormalized.includes(k));
      const dynamicMatches = keywords.some(k => dynamicNormalized.includes(k));
      
      if (staticMatches && dynamicMatches) {
        return 0.8;
      }
    }
    
    // Partial match
    if (staticNormalized.includes(dynamicNormalized) || 
        dynamicNormalized.includes(staticNormalized)) {
      return 0.5;
    }
    
    return 0;
  }
  
  /**
   * Match code locations
   */
  private matchCodeLocation(
    staticFinding: StaticFinding,
    dynamicFinding: DynamicFinding
  ): number {
    // If dynamic finding doesn't have code location, we can't match
    if (!dynamicFinding.evidence.response) {
      return 0;
    }
    
    const staticFile = staticFinding.codeContext.filePath.toLowerCase();
    const staticLine = staticFinding.codeContext.lineStart;
    
    // Check if evidence mentions the file
    const evidence = dynamicFinding.evidence.response.toLowerCase();
    const fileMentioned = evidence.includes(staticFile) || 
                          evidence.includes(staticFile.split('/').pop() || '');
    
    if (fileMentioned) {
      return 0.9;
    }
    
    // Check for function name in evidence
    if (staticFinding.codeContext.functionName) {
      const funcName = staticFinding.codeContext.functionName.toLowerCase();
      if (evidence.includes(funcName)) {
        return 0.7;
      }
    }
    
    return 0;
  }
  
  /**
   * Match endpoints
   */
  private matchEndpoint(
    staticFinding: StaticFinding,
    dynamicFinding: DynamicFinding
  ): number {
    // Check if static finding mentions the dynamic target
    const targetUrl = dynamicFinding.target.url.toLowerCase();
    const targetParam = dynamicFinding.target.parameter?.toLowerCase();
    
    // Check if static source/sink relates to the endpoint
    const staticSource = staticFinding.source.description.toLowerCase();
    const staticSink = staticFinding.sink.description.toLowerCase();
    
    let score = 0;
    
    // URL path match
    const urlPath = new URL(targetUrl).pathname;
    if (staticSource.includes(urlPath) || staticSink.includes(urlPath)) {
      score += 0.5;
    }
    
    // Parameter match
    if (targetParam) {
      if (staticSource.includes(targetParam) || staticSink.includes(targetParam)) {
        score += 0.5;
      }
    }
    
    return Math.min(1, score);
  }
  
  /**
   * Create a correlated finding
   */
  private createCorrelatedFinding(
    staticFinding: StaticFinding,
    dynamicFinding: DynamicFinding,
    matchScore: number,
    matchMethod: CorrelatedFinding['correlation']['matchMethod']
  ): CorrelatedFinding {
    const id = `correlated-${staticFinding.id}-${dynamicFinding.id}`;
    
    // Determine status
    let status: CorrelatedFinding['status'];
    if (matchScore >= this.config.autoConfirmThreshold && dynamicFinding.exploited) {
      status = 'CONFIRMED';
    } else if (matchScore < this.config.falsePositiveThreshold) {
      status = 'FALSE_POSITIVE';
    } else {
      status = 'UNCONFIRMED';
    }
    
    // Calculate overall confidence
    const confidence = (staticFinding.staticConfidence + dynamicFinding.dynamicConfidence) / 2;
    
    // Determine severity
    const severity = this.calculateSeverity(staticFinding, dynamicFinding);
    
    return {
      id,
      status,
      staticFinding,
      dynamicFinding,
      correlation: {
        matchScore,
        matchMethod,
        explanation: this.generateExplanation(staticFinding, dynamicFinding, status, matchScore),
        isHighConfidence: matchScore >= this.config.autoConfirmThreshold,
      },
      assessment: {
        isVulnerable: status === 'CONFIRMED',
        confidence,
        severity,
        recommendation: this.generateRecommendation(staticFinding, dynamicFinding, status),
        fixLocation: {
          file: staticFinding.codeContext.filePath,
          line: staticFinding.codeContext.lineStart,
          code: staticFinding.codeContext.codeSnippet,
          suggestion: this.generateFixSuggestion(staticFinding, dynamicFinding),
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }
  
  /**
   * Create unconfirmed finding (static only)
   */
  private createUnconfirmedFinding(staticFinding: StaticFinding): CorrelatedFinding {
    return {
      id: `unconfirmed-${staticFinding.id}`,
      status: 'UNCONFIRMED',
      staticFinding,
      correlation: {
        matchScore: 0,
        matchMethod: 'MANUAL',
        explanation: 'Static analysis identified a potential vulnerability, but dynamic exploitation did not confirm it. This could be a false positive, or the vulnerability may require specific conditions to exploit.',
        isHighConfidence: false,
      },
      assessment: {
        isVulnerable: false,
        confidence: staticFinding.staticConfidence * 0.5,
        severity: 'MEDIUM',
        recommendation: 'Review manually. The static analysis suggests a vulnerability at this location, but dynamic testing could not confirm it.',
        fixLocation: {
          file: staticFinding.codeContext.filePath,
          line: staticFinding.codeContext.lineStart,
          code: staticFinding.codeContext.codeSnippet,
          suggestion: 'Review this code for potential security issues.',
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }
  
  /**
   * Create dynamic-only finding
   */
  private createDynamicOnlyFinding(dynamicFinding: DynamicFinding): CorrelatedFinding {
    return {
      id: `dynamic-only-${dynamicFinding.id}`,
      status: 'DYNAMIC_ONLY',
      dynamicFinding,
      correlation: {
        matchScore: 0,
        matchMethod: 'MANUAL',
        explanation: 'Dynamic exploitation found a vulnerability that was not identified by static analysis. This suggests a runtime-only vulnerability or a gap in static analysis coverage.',
        isHighConfidence: dynamicFinding.dynamicConfidence > 0.8,
      },
      assessment: {
        isVulnerable: dynamicFinding.exploited,
        confidence: dynamicFinding.dynamicConfidence,
        severity: this.mapDynamicSeverity(dynamicFinding.impact),
        recommendation: dynamicFinding.exploited 
          ? `Confirmed vulnerability at ${dynamicFinding.target.url}. Immediate fix required.`
          : 'Potential vulnerability detected but not successfully exploited.',
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }
  
  /**
   * Calculate overall severity
   */
  private calculateSeverity(
    staticFinding: StaticFinding,
    dynamicFinding: DynamicFinding
  ): CorrelatedFinding['assessment']['severity'] {
    // If exploited, consider impact
    if (dynamicFinding.exploited) {
      switch (dynamicFinding.impact) {
        case 'CRITICAL':
          return 'CRITICAL';
        case 'HIGH':
          return 'HIGH';
        case 'MEDIUM':
          return 'MEDIUM';
        default:
          return 'LOW';
      }
    }
    
    // Not exploited - base on static confidence
    if (staticFinding.staticConfidence > 0.8) {
      return 'HIGH';
    } else if (staticFinding.staticConfidence > 0.6) {
      return 'MEDIUM';
    } else {
      return 'LOW';
    }
  }
  
  /**
   * Map dynamic impact to severity
   */
  private mapDynamicSeverity(impact: DynamicFinding['impact']): CorrelatedFinding['assessment']['severity'] {
    switch (impact) {
      case 'CRITICAL':
        return 'CRITICAL';
      case 'HIGH':
        return 'HIGH';
      case 'MEDIUM':
        return 'MEDIUM';
      case 'LOW':
        return 'LOW';
      default:
        return 'INFO';
    }
  }
  
  /**
   * Generate human-readable explanation
   */
  private generateExplanation(
    staticFinding: StaticFinding,
    dynamicFinding: DynamicFinding,
    status: CorrelatedFinding['status'],
    matchScore: number
  ): string {
    const parts: string[] = [];
    
    parts.push(`Static analysis identified a ${staticFinding.vulnerabilityType} vulnerability`);
    parts.push(`at ${staticFinding.codeContext.filePath}:${staticFinding.codeContext.lineStart}.`);
    
    if (dynamicFinding.exploited) {
      parts.push(`Dynamic exploitation successfully confirmed this vulnerability`);
      parts.push(`at ${dynamicFinding.target.url}.`);
      parts.push(`Match confidence: ${(matchScore * 100).toFixed(0)}%.`);
    } else {
      parts.push(`Dynamic testing attempted exploitation but was not successful.`);
      parts.push(`This may be a false positive or require specific conditions.`);
    }
    
    return parts.join(' ');
  }
  
  /**
   * Generate recommendation
   */
  private generateRecommendation(
    staticFinding: StaticFinding,
    dynamicFinding: DynamicFinding,
    status: CorrelatedFinding['status']
  ): string {
    if (status === 'CONFIRMED') {
      return `Confirmed vulnerability. Fix the ${staticFinding.vulnerabilityType} issue at ${staticFinding.codeContext.filePath}:${staticFinding.codeContext.lineStart}. The vulnerability was successfully exploited at ${dynamicFinding.target.url}.`;
    } else if (status === 'UNCONFIRMED') {
      return `Potential vulnerability detected by static analysis but not confirmed dynamically. Review manually at ${staticFinding.codeContext.filePath}:${staticFinding.codeContext.lineStart}.`;
    } else if (status === 'FALSE_POSITIVE') {
      return `Likely false positive. Static analysis suggested a vulnerability, but dynamic testing contradicted this finding.`;
    } else {
      return `Dynamic-only finding. Review the vulnerability at ${dynamicFinding.target.url}.`;
    }
  }
  
  /**
   * Generate fix suggestion
   */
  private generateFixSuggestion(
    staticFinding: StaticFinding,
    dynamicFinding: DynamicFinding
  ): string {
    const suggestions: string[] = [];
    
    if (staticFinding.isSanitized && !staticFinding.sanitizationInfo?.isSufficient) {
      suggestions.push('Review existing sanitization - it may be insufficient for this context.');
    } else if (!staticFinding.isSanitized) {
      suggestions.push('Add input validation and sanitization.');
    }
    
    // Type-specific suggestions
    switch (staticFinding.vulnerabilityType) {
      case 'INJECTION':
        suggestions.push('Use parameterized queries/prepared statements.');
        break;
      case 'XSS':
        suggestions.push('Use context-aware output encoding.');
        break;
      case 'AUTH':
        suggestions.push('Implement proper authentication checks.');
        break;
      case 'AUTHZ':
        suggestions.push('Verify user permissions before access.');
        break;
      case 'SSRF':
        suggestions.push('Validate and whitelist URLs.');
        break;
    }
    
    return suggestions.join(' ');
  }
  
  /**
   * Sort findings by severity and confidence
   */
  private sortFindings(findings: CorrelatedFinding[]): CorrelatedFinding[] {
    const severityOrder = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1 };
    
    return findings.sort((a, b) => {
      // First by severity
      const sevDiff = severityOrder[b.assessment.severity] - severityOrder[a.assessment.severity];
      if (sevDiff !== 0) return sevDiff;
      
      // Then by confidence
      return b.assessment.confidence - a.assessment.confidence;
    });
  }
  
  /**
   * Get all correlations
   */
  getAllCorrelations(): CorrelatedFinding[] {
    return Array.from(this.correlations.values());
  }
  
  /**
   * Get confirmed vulnerabilities only
   */
  getConfirmedVulnerabilities(): CorrelatedFinding[] {
    return this.getAllCorrelations().filter(c => c.status === 'CONFIRMED');
  }
  
  /**
   * Export correlations to JSON
   */
  exportToJSON(): string {
    return JSON.stringify(this.getAllCorrelations(), null, 2);
  }
}
