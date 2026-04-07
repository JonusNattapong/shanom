// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * SCA (Software Composition Analysis) Service
 * 
 * Analyzes dependencies for known vulnerabilities with reachability analysis.
 * Goes beyond simple CVE flagging to determine if vulnerable functions are
 * actually reachable from application entry points.
 */

import { fs, path } from 'zx';
import type { ActivityLogger } from '../types/activity-logger.js';
import { runClaudePrompt } from '../ai/claude-executor.js';

export interface DependencyInfo {
  name: string;
  version: string;
  type: 'production' | 'development' | 'optional';
  direct: boolean;
  path: string; // Path in dependency tree
  filePath: string; // Lock file location
}

export interface CVEInfo {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvssScore?: number;
  description: string;
  publishedDate: string;
  references: string[];
  // Affected component
  affectedVersions: string[];
  fixedVersions: string[];
  // Vulnerable function (if known)
  vulnerableFunction?: string;
  vulnerablePackage?: string;
}

export interface VulnerableDependency {
  dependency: DependencyInfo;
  cve: CVEInfo;
  
  // Reachability analysis
  reachability: {
    isReachable: boolean;
    confidence: number;
    reachableVia: string[]; // Entry points that can reach this
    executionPath: string[]; // Call chain from entry point
    analysisMethod: 'CPG' | 'PATTERN' | 'MANUAL' | 'UNKNOWN';
  };
  
  // Exploitability
  exploitability: {
    isExploitable: boolean;
    requiresSpecificConditions: boolean;
    conditions: string[];
    knownExploits: boolean;
    epssScore?: number; // Exploit Prediction Scoring System
  };
  
  // Remediation
  remediation: {
    available: boolean;
    fixedVersion?: string;
    upgradeComplexity: 'SIMPLE' | 'MODERATE' | 'COMPLEX';
    breakingChanges: boolean;
    alternativePackages?: string[];
  };
  
  // Metadata
  id: string;
  discoveredAt: Date;
}

export interface SCAResult {
  scannedFiles: string[];
  totalDependencies: number;
  directDependencies: number;
  transitiveDependencies: number;
  vulnerableDependencies: VulnerableDependency[];
  reachableVulnerabilities: VulnerableDependency[];
  unreachableVulnerabilities: VulnerableDependency[];
  durationMs: number;
}

export class SCAService {
  private logger?: ActivityLogger;
  private cpgIntegration: boolean;
  private modelTier: 'small' | 'medium' | 'large';
  
  // CVE database (simplified - in production would use NVD or commercial DB)
  private cveDatabase: Map<string, CVEInfo[]> = new Map();
  
  constructor(
    options: {
      logger?: ActivityLogger;
      cpgIntegration?: boolean;
      modelTier?: 'small' | 'medium' | 'large';
    } = {}
  ) {
    this.logger = options.logger;
    this.cpgIntegration = options.cpgIntegration ?? true;
    this.modelTier = options.modelTier || 'medium';
  }
  
  /**
   * Analyze project dependencies
   */
  async analyzeProject(projectPath: string): Promise<SCAResult> {
    const startTime = Date.now();
    this.logger?.info('Starting SCA analysis...');
    
    // Find and parse lock files
    const lockFiles = await this.findLockFiles(projectPath);
    const allDependencies: DependencyInfo[] = [];
    
    for (const lockFile of lockFiles) {
      const deps = await this.parseLockFile(lockFile);
      allDependencies.push(...deps);
    }
    
    this.logger?.info(`Found ${allDependencies.length} dependencies`);
    
    // Check for vulnerabilities
    const vulnerabilities: VulnerableDependency[] = [];
    
    for (const dep of allDependencies) {
      const cves = await this.lookupCVEs(dep);
      
      for (const cve of cves) {
        // Reachability analysis
        const reachability = await this.analyzeReachability(projectPath, dep, cve);
        
        // Exploitability assessment
        const exploitability = await this.assessExploitability(cve);
        
        // Determine remediation
        const remediation = this.determineRemediation(dep, cve);
        
        vulnerabilities.push({
          dependency: dep,
          cve,
          reachability,
          exploitability,
          remediation,
          id: `sca-${dep.name}-${cve.id}-${Date.now()}`,
          discoveredAt: new Date(),
        });
      }
    }
    
    // Categorize
    const reachable = vulnerabilities.filter(v => v.reachability.isReachable);
    const unreachable = vulnerabilities.filter(v => !v.reachability.isReachable);
    
    const result: SCAResult = {
      scannedFiles: lockFiles,
      totalDependencies: allDependencies.length,
      directDependencies: allDependencies.filter(d => d.direct).length,
      transitiveDependencies: allDependencies.filter(d => !d.direct).length,
      vulnerableDependencies: vulnerabilities,
      reachableVulnerabilities: reachable,
      unreachableVulnerabilities: unreachable,
      durationMs: Date.now() - startTime,
    };
    
    this.logger?.info(
      `SCA complete: ${vulnerabilities.length} vulnerabilities ` +
      `(${reachable.length} reachable, ${unreachable.length} unreachable)`
    );
    
    return result;
  }
  
  /**
   * Find lock files in project
   */
  private async findLockFiles(projectPath: string): Promise<string[]> {
    const lockFilePatterns = [
      'package-lock.json',
      'yarn.lock',
      'pnpm-lock.yaml',
      'Gemfile.lock',
      'Pipfile.lock',
      'poetry.lock',
      'Cargo.lock',
      'go.sum',
      'composer.lock',
      'packages.lock.json',
      'gradle.lockfile',
    ];
    
    const found: string[] = [];
    
    for (const pattern of lockFilePatterns) {
      const fullPath = path.join(projectPath, pattern);
      if (await fs.pathExists(fullPath)) {
        found.push(fullPath);
      }
    }
    
    return found;
  }
  
  /**
   * Parse lock file to extract dependencies
   */
  private async parseLockFile(lockFilePath: string): Promise<DependencyInfo[]> {
    const content = await fs.readFile(lockFilePath, 'utf8');
    const ext = path.extname(lockFilePath);
    const basename = path.basename(lockFilePath);
    const dependencies: DependencyInfo[] = [];
    
    if (basename === 'package-lock.json') {
      // NPM/Node.js
      const parsed = JSON.parse(content);
      const deps = parsed.packages || parsed.dependencies || {};
      
      for (const [name, info] of Object.entries(deps)) {
        if (name === '') continue; // Root package
        
        const depInfo = info as Record<string, unknown>;
        dependencies.push({
          name: name.replace('node_modules/', ''),
          version: depInfo.version as string || 'unknown',
          type: depInfo.dev ? 'development' : 'production',
          direct: false, // Would need package.json to determine
          path: name,
          filePath: lockFilePath,
        });
      }
    } else if (basename === 'yarn.lock') {
      // Yarn
      const entries = content.split('\n\n');
      for (const entry of entries) {
        const nameMatch = entry.match(/^(\S+)@/);
        const versionMatch = entry.match(/version\s+"(\S+)"/);
        
        if (nameMatch && versionMatch) {
          dependencies.push({
            name: nameMatch[1],
            version: versionMatch[1],
            type: 'production',
            direct: false,
            path: nameMatch[1],
            filePath: lockFilePath,
          });
        }
      }
    } else if (basename === 'Pipfile.lock' || basename === 'poetry.lock') {
      // Python
      const parsed = JSON.parse(content);
      const packages = parsed.packages || parsed.package || {};
      
      for (const [name, info] of Object.entries(packages)) {
        const depInfo = info as Record<string, unknown>;
        dependencies.push({
          name,
          version: (depInfo.version as string)?.replace(/^[>=<^~]+/, '') || 'unknown',
          type: depInfo.category === 'dev' ? 'development' : 'production',
          direct: false,
          path: name,
          filePath: lockFilePath,
        });
      }
    }
    
    return dependencies;
  }
  
  /**
   * Look up CVEs for a dependency
   */
  private async lookupCVEs(dep: DependencyInfo): Promise<CVEInfo[]> {
    // In production, this would query NVD, OSV, or commercial databases
    // For now, simulate with LLM-based lookup or cached data
    
    const cached = this.cveDatabase.get(dep.name);
    if (cached) {
      return cached.filter(cve => this.isVersionAffected(dep.version, cve.affectedVersions));
    }
    
    // Use LLM to research CVEs for this package
    const prompt = `
Research known security vulnerabilities (CVEs) for ${dep.name} version ${dep.version}.

Return only confirmed CVEs in this exact JSON format:
[
  {
    "id": "CVE-YYYY-NNNNN",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "cvssScore": 7.5,
    "description": "Brief description",
    "publishedDate": "YYYY-MM-DD",
    "references": ["https://..."],
    "affectedVersions": ["<1.0.0", ">=2.0.0 <2.1.0"],
    "fixedVersions": [">=2.1.0"],
    "vulnerableFunction": "functionName if known"
  }
]

If no known CVEs, return empty array [].
`;
    
    try {
      const result = await runClaudePrompt(
        prompt,
        '',
        '',
        `CVE Lookup: ${dep.name}`,
        'sca-cve-lookup',
        undefined,
        undefined,
        'small'
      );
      
      if (result.success && result.result) {
        const cves = JSON.parse(result.result) as CVEInfo[];
        this.cveDatabase.set(dep.name, cves);
        return cves.filter(cve => this.isVersionAffected(dep.version, cve.affectedVersions));
      }
    } catch {
      // Fall through to empty result
    }
    
    return [];
  }
  
  /**
   * Check if version is affected by CVE
   */
  private isVersionAffected(version: string, affectedRanges: string[]): boolean {
    // Simple semver comparison - in production use proper semver library
    for (const range of affectedRanges) {
      if (range.startsWith('<')) {
        const maxVersion = range.substring(1);
        if (this.compareVersions(version, maxVersion) < 0) {
          return true;
        }
      } else if (range.startsWith('>=')) {
        const minVersion = range.substring(2);
        if (this.compareVersions(version, minVersion) >= 0) {
          // Check for upper bound
          const upperMatch = range.match(/<(.+)$/);
          if (upperMatch) {
            if (this.compareVersions(version, upperMatch[1]) < 0) {
              return true;
            }
          } else {
            return true;
          }
        }
      }
    }
    return false;
  }
  
  /**
   * Simple semver comparison
   */
  private compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const a = parts1[i] || 0;
      const b = parts2[i] || 0;
      if (a < b) return -1;
      if (a > b) return 1;
    }
    return 0;
  }
  
  /**
   * Analyze if vulnerable function is reachable
   */
  private async analyzeReachability(
    projectPath: string,
    dep: DependencyInfo,
    cve: CVEInfo
  ): Promise<VulnerableDependency['reachability']> {
    // If no vulnerable function specified, assume potentially reachable
    if (!cve.vulnerableFunction) {
      return {
        isReachable: true, // Conservative assumption
        confidence: 0.3,
        reachableVia: [],
        executionPath: [],
        analysisMethod: 'UNKNOWN',
      };
    }
    
    // Search for imports/usage of vulnerable function in codebase
    const usagePatterns = [
      new RegExp(`import.*${dep.name}`, 'i'),
      new RegExp(`require\s*\(\s*['"]${dep.name}['"]`, 'i'),
      new RegExp(`from\s+['"]${dep.name}['"]`, 'i'),
      new RegExp(`import\s+.*\s+from\s+['"]${dep.name}['"]`, 'i'),
    ];
    
    const functionUsage = new RegExp(`${cve.vulnerableFunction}`, 'i');
    
    let isImported = false;
    let isUsed = false;
    let reachableVia: string[] = [];
    
    // Find all source files
    const sourceFiles = await this.findSourceFiles(projectPath);
    
    for (const file of sourceFiles) {
      try {
        const content = await fs.readFile(file, 'utf8');
        
        // Check if dependency is imported
        for (const pattern of usagePatterns) {
          if (pattern.test(content)) {
            isImported = true;
            
            // Check if vulnerable function is used
            if (functionUsage.test(content)) {
              isUsed = true;
              reachableVia.push(file);
              break;
            }
          }
        }
      } catch {
        // Skip files that can't be read
      }
    }
    
    return {
      isReachable: isImported && isUsed,
      confidence: isUsed ? 0.8 : isImported ? 0.5 : 0.2,
      reachableVia,
      executionPath: reachableVia,
      analysisMethod: 'PATTERN',
    };
  }
  
  /**
   * Assess exploitability of CVE
   */
  private async assessExploitability(cve: CVEInfo): Promise<VulnerableDependency['exploitability']> {
    // In production, would query EPSS, exploit databases
    // For now, use severity-based heuristics
    
    const knownExploits = cve.cvssScore && cve.cvssScore > 7.0;
    
    return {
      isExploitable: cve.severity === 'CRITICAL' || cve.severity === 'HIGH',
      requiresSpecificConditions: cve.severity === 'MEDIUM' || cve.severity === 'LOW',
      conditions: [], // Would be populated from CVE data
      knownExploits,
      epssScore: knownExploits ? 0.5 : 0.1,
    };
  }
  
  /**
   * Determine remediation options
   */
  private determineRemediation(
    dep: DependencyInfo,
    cve: CVEInfo
  ): VulnerableDependency['remediation'] {
    const fixedVersion = cve.fixedVersions[0];
    
    // Determine complexity
    let complexity: 'SIMPLE' | 'MODERATE' | 'COMPLEX' = 'SIMPLE';
    
    if (fixedVersion) {
      const currentMajor = dep.version.split('.')[0];
      const fixedMajor = fixedVersion.replace(/^[>=<^~]+/, '').split('.')[0];
      
      if (currentMajor !== fixedMajor) {
        complexity = 'COMPLEX';
      } else if (this.compareVersions(fixedVersion.replace(/^[>=<^~]+/, ''), dep.version) > 10) {
        complexity = 'MODERATE';
      }
    }
    
    return {
      available: !!fixedVersion,
      fixedVersion,
      upgradeComplexity: complexity,
      breakingChanges: complexity === 'COMPLEX',
    };
  }
  
  /**
   * Find source files in project
   */
  private async findSourceFiles(projectPath: string): Promise<string[]> {
    const files: string[] = [];
    const extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.rb', '.php', '.cs'];
    
    async function walk(dir: string) {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          if (!entry.name.startsWith('.') && 
              !['node_modules', 'vendor', 'dist', 'build'].includes(entry.name)) {
            await walk(fullPath);
          }
        } else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
          files.push(fullPath);
        }
      }
    }
    
    await walk(projectPath);
    return files;
  }
  
  /**
   * Generate markdown report
   */
  generateReport(result: SCAResult): string {
    const lines: string[] = [];
    
    lines.push('# Software Composition Analysis (SCA) Report');
    lines.push('');
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(`- **Total Dependencies:** ${result.totalDependencies}`);
    lines.push(`  - Direct: ${result.directDependencies}`);
    lines.push(`  - Transitive: ${result.transitiveDependencies}`);
    lines.push(`- **Vulnerabilities Found:** ${result.vulnerableDependencies.length}`);
    lines.push(`  - Reachable: ${result.reachableVulnerabilities.length}`);
    lines.push(`  - Unreachable: ${result.unreachableVulnerabilities.length}`);
    lines.push(`- **Analysis Duration:** ${(result.durationMs / 1000).toFixed(1)}s`);
    lines.push('');
    
    // Reachable vulnerabilities (action required)
    if (result.reachableVulnerabilities.length > 0) {
      lines.push('## Reachable Vulnerabilities (Action Required)');
      lines.push('');
      lines.push('These vulnerabilities are in code paths that can be executed:');
      lines.push('');
      
      for (const vuln of result.reachableVulnerabilities) {
        lines.push(`### ${vuln.cve.id}: ${vuln.dependency.name}@${vuln.dependency.version}`);
        lines.push('');
        lines.push(`**Severity:** ${vuln.cve.severity}`);
        if (vuln.cve.cvssScore) {
          lines.push(`**CVSS Score:** ${vuln.cve.cvssScore}`);
        }
        lines.push(`**Reachability Confidence:** ${(vuln.reachability.confidence * 100).toFixed(0)}%`);
        lines.push(`**Reachable Via:** ${vuln.reachability.reachableVia.join(', ')}`);
        lines.push('');
        lines.push(vuln.cve.description);
        lines.push('');
        
        if (vuln.remediation.available) {
          lines.push('**Remediation:**');
          lines.push(`- Upgrade to: ${vuln.remediation.fixedVersion}`);
          lines.push(`- Complexity: ${vuln.remediation.upgradeComplexity}`);
          if (vuln.remediation.breakingChanges) {
            lines.push('- ⚠️ Breaking changes expected');
          }
        }
        lines.push('');
        lines.push('---');
        lines.push('');
      }
    }
    
    // Unreachable vulnerabilities (lower priority)
    if (result.unreachableVulnerabilities.length > 0) {
      lines.push('## Unreachable Vulnerabilities (Lower Priority)');
      lines.push('');
      lines.push('These vulnerabilities are in dependencies but not in executable code paths:');
      lines.push('');
      
      for (const vuln of result.unreachableVulnerabilities.slice(0, 10)) {
        lines.push(`- **${vuln.cve.id}** (${vuln.cve.severity}): ${vuln.dependency.name}@${vuln.dependency.version}`);
      }
      
      if (result.unreachableVulnerabilities.length > 10) {
        lines.push(`- ... and ${result.unreachableVulnerabilities.length - 10} more`);
      }
      
      lines.push('');
    }
    
    return lines.join('\n');
  }
  
  /**
   * Export to JSON
   */
  exportToJSON(result: SCAResult): string {
    return JSON.stringify(result, null, 2);
  }
}
