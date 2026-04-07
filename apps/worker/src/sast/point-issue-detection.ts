// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * SAST Point Issue Detection Service
 * 
 * Detects single-location vulnerabilities using pattern matching
 * enhanced with LLM-based contextual analysis:
 * - Weak cryptography
 * - Hardcoded credentials
 * - Insecure configuration
 * - Missing security headers
 * - Weak random number generation
 * - Disabled certificate validation
 * - Overly permissive CORS
 * - etc.
 */

import { fs, path } from 'zx';
import { runClaudePrompt } from '../ai/claude-executor.js';
import type { ActivityLogger } from '../types/activity-logger.js';

export interface PointIssueFinding {
  id: string;
  category: PointIssueCategory;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  title: string;
  description: string;
  filePath: string;
  lineNumber: number;
  codeSnippet: string;
  remediation: string;
  cweId?: string;
  owaspCategory?: string;
  references: string[];
}

export type PointIssueCategory =
  | 'WEAK_CRYPTO'
  | 'HARDCODED_SECRET'
  | 'INSECURE_CONFIG'
  | 'MISSING_SECURITY_HEADER'
  | 'WEAK_RANDOM'
  | 'DISABLED_CERT_VALIDATION'
  | 'PERMISSIVE_CORS'
  | 'DEBUG_ENABLED'
  | 'VERBOSE_ERROR'
  | 'INSECURE_DESERIALIZATION'
  | 'PATH_TRAVERSAL'
  | 'LDAP_INJECTION'
  | 'XML_EXTERNAL_ENTITY'
  | 'OPEN_REDIRECT'
  | 'CLICKJACKING'
  | 'CACHE_POISONING';

export interface PointIssuePattern {
  category: PointIssueCategory;
  severity: PointIssueFinding['severity'];
  title: string;
  description: string;
  cweId?: string;
  owaspCategory?: string;
  // Pattern matchers
  codePatterns: RegExp[];
  filePatterns: RegExp[];
  // Exclusions (to reduce false positives)
  excludePatterns?: RegExp[];
  // LLM validation prompt
  llmValidationPrompt?: string;
  remediation: string;
  references: string[];
}

/**
 * Predefined patterns for point issue detection
 */
export const POINT_ISSUE_PATTERNS: PointIssuePattern[] = [
  // Weak Cryptography
  {
    category: 'WEAK_CRYPTO',
    severity: 'HIGH',
    title: 'Weak Cryptographic Algorithm',
    description: 'Use of weak or deprecated cryptographic algorithms',
    cweId: 'CWE-327',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    codePatterns: [
      /md5\s*\(/i,
      /sha1\s*\(/i,
      /des\s*\(/i,
      /rc4\s*\(/i,
      /ecb\s*\(/i,
      /createHash\s*\(\s*['"]md5['"]/i,
      /createHash\s*\(\s*['"]sha1['"]/i,
      /Cipher\.getInstance\s*\(\s*['"]DES['"]/i,
      /algorithm:\s*['"]md5['"]/i,
      /algorithm:\s*['"]sha1['"]/i,
    ],
    filePatterns: [/\.(js|ts|java|py|go|cs|php|rb|swift|kt)$/i],
    remediation: 'Use strong cryptographic algorithms like SHA-256, SHA-3, or AES-256-GCM',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/327.html',
    ],
  },

  // Hardcoded Secrets
  {
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    title: 'Hardcoded Secret',
    description: 'API keys, passwords, or tokens hardcoded in source code',
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    codePatterns: [
      /api[_-]?key\s*[=:]\s*['"][a-zA-Z0-9]{16,}['"]/i,
      /password\s*[=:]\s*['"][^'"]{4,}['"]/i,
      /secret\s*[=:]\s*['"][a-zA-Z0-9]{16,}['"]/i,
      /token\s*[=:]\s*['"][a-zA-Z0-9]{16,}['"]/i,
      /aws_access_key_id\s*[=:]\s*['"][A-Z0-9]{20}['"]/i,
      /aws_secret_access_key\s*[=:]\s*['"][a-zA-Z0-9/+=]{40}['"]/i,
      /private[_-]?key\s*[=:]\s*['"]/i,
      /bearer\s+[a-zA-Z0-9_-]{20,}/i,
      /Basic\s+[a-zA-Z0-9+/]{20,}={0,2}/i,
    ],
    filePatterns: [/\.(js|ts|java|py|go|cs|php|rb|yaml|yml|json|xml|env|properties|conf)$/i],
    excludePatterns: [
      /example/i,
      /placeholder/i,
      /dummy/i,
      /test/i,
      /fake/i,
      /mock/i,
    ],
    remediation: 'Move secrets to environment variables, use a secrets manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/798.html',
    ],
  },

  // Insecure Configuration
  {
    category: 'INSECURE_CONFIG',
    severity: 'MEDIUM',
    title: 'Insecure Configuration',
    description: 'Security settings are disabled or misconfigured',
    cweId: 'CWE-16',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    codePatterns: [
      /disableSecurity\s*[=:]\s*true/i,
      /verifySSL\s*[=:]\s*false/i,
      /rejectUnauthorized\s*[=:]\s*false/i,
      /NODE_TLS_REJECT_UNAUTHORIZED.*0/i,
      /InsecureSkipVerify.*true/i,
      /ssl_verify_peer.*false/i,
      /VERIFY_NONE/i,
      /verify_mode.*NONE/i,
    ],
    filePatterns: [/\.(js|ts|java|py|go|cs|php|rb|yaml|yml|json|xml|conf)$/i],
    remediation: 'Enable security settings in production. Never disable SSL/TLS verification',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/16.html',
    ],
  },

  // Missing Security Headers
  {
    category: 'MISSING_SECURITY_HEADER',
    severity: 'MEDIUM',
    title: 'Missing Security Headers',
    description: 'HTTP security headers are not configured',
    cweId: 'CWE-693',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    codePatterns: [
      /res\.setHeader\s*\(\s*['"]X-Content-Type-Options['"]/i,
      /res\.setHeader\s*\(\s*['"]X-Frame-Options['"]/i,
      /res\.setHeader\s*\(\s*['"]Content-Security-Policy['"]/i,
      /res\.setHeader\s*\(\s*['"]Strict-Transport-Security['"]/i,
      /helmet\(\)/i,
      /app\.use\s*\(\s*helmet/i,
    ],
    filePatterns: [/\.(js|ts|java|py|go|cs|php|rb)$/i],
    remediation: 'Implement security headers using Helmet.js (Node.js), or manually set X-Content-Type-Options, X-Frame-Options, CSP, HSTS',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/693.html',
    ],
  },

  // Weak Random Number Generation
  {
    category: 'WEAK_RANDOM',
    severity: 'MEDIUM',
    title: 'Weak Random Number Generation',
    description: 'Predictable random values used for security purposes',
    cweId: 'CWE-338',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    codePatterns: [
      /Math\.random\s*\(\)/i,
      /Random\(\)/i,
      /srand\s*\(/i,
      /rand\s*\(/i,
      /java\.util\.Random/i,
    ],
    filePatterns: [/\.(js|ts|java|py|go|cs|c|cpp|php|rb)$/i],
    excludePatterns: [
      /test/i,
      /example/i,
      /demo/i,
    ],
    remediation: 'Use cryptographically secure random number generators: crypto.randomBytes (Node.js), SecureRandom (Java), secrets (Python), crypto/rand (Go)',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/338.html',
    ],
  },

  // Debug Mode Enabled
  {
    category: 'DEBUG_ENABLED',
    severity: 'HIGH',
    title: 'Debug Mode Enabled in Production',
    description: 'Debug or development mode is enabled',
    cweId: 'CWE-489',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    codePatterns: [
      /debug:\s*true/i,
      /DEBUG:\s*true/i,
      /app\.debug\s*[=:]\s*true/i,
      /FLASK_DEBUG\s*[=:]\s*true/i,
      /DEBUG_PROPAGATE_EXCEPTIONS\s*[=:]\s*true/i,
      /app\.run\s*\(\s*debug\s*[=:]\s*true/i,
    ],
    filePatterns: [/\.(js|ts|py|go|cs|php|rb|yaml|yml|json|env)$/i],
    remediation: 'Disable debug mode in production. Set DEBUG=false or remove debug configuration',
    references: [
      'https://cwe.mitre.org/data/definitions/489.html',
    ],
  },

  // Verbose Error Messages
  {
    category: 'VERBOSE_ERROR',
    severity: 'LOW',
    title: 'Verbose Error Messages',
    description: 'Detailed error messages may leak sensitive information',
    cweId: 'CWE-209',
    owaspCategory: 'A04:2021 - Insecure Design',
    codePatterns: [
      /console\.error\s*\(.*err/i,
      /printStackTrace/i,
      /res\.send\s*\(\s*err/i,
      /res\.json\s*\(\s*\{.*error.*err/i,
      /return.*error.*message/i,
    ],
    filePatterns: [/\.(js|ts|java|py|go|cs|php|rb)$/i],
    remediation: 'Return generic error messages to users. Log detailed errors server-side only',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/209.html',
    ],
  },

  // Insecure Deserialization
  {
    category: 'INSECURE_DESERIALIZATION',
    severity: 'CRITICAL',
    title: 'Insecure Deserialization',
    description: 'Deserialization of untrusted data',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    codePatterns: [
      /ObjectInputStream/i,
      /readObject\s*\(/i,
      /pickle\.loads/i,
      /yaml\.load\s*\(/i,
      /unserialize\s*\(/i,
      /JSON\.parse.*user/i,
      /\.from\s*\(.*req\./i,
    ],
    filePatterns: [/\.(js|ts|java|py|php|rb)$/i],
    remediation: 'Avoid deserializing untrusted data. Use JSON with schema validation instead of native serialization',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/502.html',
    ],
  },

  // Path Traversal
  {
    category: 'PATH_TRAVERSAL',
    severity: 'HIGH',
    title: 'Path Traversal',
    description: 'User input used in file path construction',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    codePatterns: [
      /fs\.readFile.*req\./i,
      /open\s*\(.*\+.*req\./i,
      /File\.open.*params/i,
      /send_file.*req\./i,
      /\.\.\//i,
    ],
    filePatterns: [/\.(js|ts|java|py|go|cs|php|rb)$/i],
    remediation: 'Validate and sanitize file paths. Use allowlists for acceptable paths. Never use user input directly in file paths',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/22.html',
    ],
  },

  // Open Redirect
  {
    category: 'OPEN_REDIRECT',
    severity: 'MEDIUM',
    title: 'Open Redirect',
    description: 'User-controlled redirect destination',
    cweId: 'CWE-601',
    owaspCategory: 'A01:2021 - Broken Access Control',
    codePatterns: [
      /res\.redirect.*req\./i,
      /location\.href.*=.*req\./i,
      /window\.location.*req\./i,
      /response\.sendRedirect.*req\./i,
      /redirect_to.*params/i,
    ],
    filePatterns: [/\.(js|ts|java|py|go|cs|php|rb)$/i],
    remediation: 'Use allowlists for redirect destinations. Validate URLs before redirecting',
    references: [
      'https://cwe.mitre.org/data/definitions/601.html',
    ],
  },
];

export class PointIssueDetectionService {
  private patterns: PointIssuePattern[];
  private useLLMValidation: boolean;
  private modelTier: 'small' | 'medium' | 'large';
  private logger?: ActivityLogger;

  constructor(
    options: {
      patterns?: PointIssuePattern[];
      useLLMValidation?: boolean;
      modelTier?: 'small' | 'medium' | 'large';
      logger?: ActivityLogger;
    } = {}
  ) {
    this.patterns = options.patterns || POINT_ISSUE_PATTERNS;
    this.useLLMValidation = options.useLLMValidation ?? true;
    this.modelTier = options.modelTier || 'small';
    this.logger = options.logger;
  }

  /**
   * Scan a single file for point issues
   */
  async scanFile(filePath: string, content?: string): Promise<PointIssueFinding[]> {
    const fileContent = content || await fs.readFile(filePath, 'utf8');
    const findings: PointIssueFinding[] = [];

    for (const pattern of this.patterns) {
      // Check if pattern applies to this file type
      if (!pattern.filePatterns.some(fp => fp.test(filePath))) {
        continue;
      }

      // Find matches
      for (const codePattern of pattern.codePatterns) {
        const matches = this.findAllMatches(fileContent, codePattern);

        for (const match of matches) {
          // Check exclusions
          if (this.isExcluded(match, pattern.excludePatterns || [])) {
            continue;
          }

          // LLM validation if enabled
          let confidence = 0.7;
          if (this.useLLMValidation) {
            const validation = await this.validateWithLLM(filePath, fileContent, match, pattern);
            confidence = validation.confidence;
            if (!validation.isValid) {
              continue;
            }
          }

          findings.push({
            id: `point-${pattern.category}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            category: pattern.category,
            severity: pattern.severity,
            confidence,
            title: pattern.title,
            description: pattern.description,
            filePath,
            lineNumber: this.getLineNumber(fileContent, match.index),
            codeSnippet: match.text.substring(0, 200),
            remediation: pattern.remediation,
            cweId: pattern.cweId,
            owaspCategory: pattern.owaspCategory,
            references: pattern.references,
          });
        }
      }
    }

    return findings;
  }

  /**
   * Scan entire project
   */
  async scanProject(projectPath: string): Promise<PointIssueFinding[]> {
    const allFindings: PointIssueFinding[] = [];
    const files = await this.findSourceFiles(projectPath);

    this.logger?.info(`Scanning ${files.length} files for point issues...`);

    for (const file of files) {
      try {
        const findings = await this.scanFile(file);
        allFindings.push(...findings);
      } catch (error) {
        this.logger?.warn(`Failed to scan ${file}: ${error}`);
      }
    }

    // Deduplicate
    const uniqueFindings = this.deduplicateFindings(allFindings);

    this.logger?.info(`Point issue scan complete: ${uniqueFindings.length} findings`);

    return uniqueFindings;
  }

  /**
   * Find all matches of a pattern in text
   */
  private findAllMatches(text: string, pattern: RegExp): Array<{ text: string; index: number }> {
    const matches: Array<{ text: string; index: number }> = [];
    let match;

    // Create new regex with global flag
    const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');

    while ((match = globalPattern.exec(text)) !== null) {
      matches.push({
        text: match[0],
        index: match.index,
      });
    }

    return matches;
  }

  /**
   * Check if match should be excluded
   */
  private isExcluded(match: { text: string }, excludePatterns: RegExp[]): boolean {
    return excludePatterns.some(ep => ep.test(match.text));
  }

  /**
   * Validate finding with LLM
   */
  private async validateWithLLM(
    filePath: string,
    content: string,
    match: { text: string; index: number },
    pattern: PointIssuePattern
  ): Promise<{ isValid: boolean; confidence: number }> {
    const lineNumber = this.getLineNumber(content, match.index);
    const surroundingCode = this.getSurroundingCode(content, match.index, 5);

    const prompt = `
You are a security code reviewer. Analyze this code snippet for the following potential issue:

Issue: ${pattern.title}
Description: ${pattern.description}

File: ${filePath}
Line: ${lineNumber}

Code snippet:
\`\`\`
${surroundingCode}
\`\`\`

Matched pattern:
\`\`\`
${match.text}
\`\`\`

Questions:
1. Is this a TRUE POSITIVE for the issue described? (yes/no)
2. Is this in test code, example code, or documentation? (yes/no)
3. Is the issue actually exploitable in this context? (yes/no/maybe)
4. Confidence score (0.0 to 1.0)

Answer in this exact format:
TRUE_POSITIVE: <yes/no>
IS_TEST_CODE: <yes/no>
EXPLOITABLE: <yes/no/maybe>
CONFIDENCE: <0.0-1.0>
REASONING: <brief explanation>
`;

    try {
      const result = await runClaudePrompt(
        prompt,
        filePath,
        surroundingCode,
        `Point Issue Validation: ${pattern.category}`,
        'sast-point-issue',
        undefined,
        undefined,
        this.modelTier
      );

      if (!result.success) {
        return { isValid: true, confidence: 0.6 }; // Default to accepting if LLM fails
      }

      const response = result.result || '';
      const truePositive = response.match(/TRUE_POSITIVE:\s*(yes|no)/i)?.[1]?.toLowerCase() === 'yes';
      const isTestCode = response.match(/IS_TEST_CODE:\s*(yes|no)/i)?.[1]?.toLowerCase() === 'yes';
      const confidenceMatch = response.match(/CONFIDENCE:\s*(0?\.\d+|1\.?0?)/);
      const confidence = confidenceMatch ? parseFloat(confidenceMatch[1]) : 0.6;

      return {
        isValid: truePositive && !isTestCode,
        confidence,
      };
    } catch {
      return { isValid: true, confidence: 0.6 };
    }
  }

  /**
   * Get line number from character index
   */
  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  /**
   * Get surrounding code for context
   */
  private getSurroundingCode(content: string, index: number, lines: number): string {
    const allLines = content.split('\n');
    const lineNumber = this.getLineNumber(content, index);
    const start = Math.max(0, lineNumber - lines - 1);
    const end = Math.min(allLines.length, lineNumber + lines);
    return allLines.slice(start, end).join('\n');
  }

  /**
   * Find all source files in project
   */
  private async findSourceFiles(projectPath: string): Promise<string[]> {
    const files: string[] = [];
    const extensions = new Set(['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.rb', '.php', '.cs', '.swift', '.kt', '.c', '.cpp', '.h']);

    async function walk(dir: string) {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'vendor') {
            await walk(fullPath);
          }
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (extensions.has(ext)) {
            files.push(fullPath);
          }
        }
      }
    }

    await walk(projectPath);
    return files;
  }

  /**
   * Deduplicate findings
   */
  private deduplicateFindings(findings: PointIssueFinding[]): PointIssueFinding[] {
    const seen = new Set<string>();
    const unique: PointIssueFinding[] = [];

    for (const finding of findings) {
      const key = `${finding.category}-${finding.filePath}-${finding.lineNumber}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(finding);
      }
    }

    return unique;
  }

  /**
   * Export findings to JSON
   */
  exportToJSON(findings: PointIssueFinding[]): string {
    return JSON.stringify(findings, null, 2);
  }

  /**
   * Generate markdown report
   */
  generateReport(findings: PointIssueFinding[]): string {
    const lines: string[] = [];

    lines.push('# Point Issue Detection Report');
    lines.push('');
    lines.push(`**Total Findings:** ${findings.length}`);
    lines.push('');

    // Group by severity
    const bySeverity: Record<string, PointIssueFinding[]> = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      INFO: [],
    };

    for (const finding of findings) {
      bySeverity[finding.severity].push(finding);
    }

    for (const [severity, items] of Object.entries(bySeverity)) {
      if (items.length === 0) continue;

      lines.push(`## ${severity} (${items.length})`);
      lines.push('');

      for (const finding of items) {
        lines.push(`### ${finding.title}`);
        lines.push('');
        lines.push(`**File:** \`${finding.filePath}\` (line ${finding.lineNumber})`);
        lines.push(`**Category:** ${finding.category}`);
        lines.push(`**Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
        lines.push(`**CWE:** ${finding.cweId || 'N/A'}`);
        lines.push('');
        lines.push(finding.description);
        lines.push('');
        lines.push('**Code:**');
        lines.push('```');
        lines.push(finding.codeSnippet);
        lines.push('```');
        lines.push('');
        lines.push('**Remediation:**');
        lines.push(finding.remediation);
        lines.push('');
        lines.push('**References:**');
        for (const ref of finding.references) {
          lines.push(`- ${ref}`);
        }
        lines.push('');
        lines.push('---');
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}
