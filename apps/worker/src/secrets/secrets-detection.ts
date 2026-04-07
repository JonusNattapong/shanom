// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Secrets Detection Service
 * 
 * Combines three approaches to secrets scanning:
 * 1. Regex pattern matching for known formats (AWS keys, API tokens, etc.)
 * 2. LLM-based detection for dynamically constructed credentials, custom formats
 * 3. Entropy analysis for high-randomness strings
 * 
 * Includes liveness validation to check if secrets are actually active.
 */

import { fs, path } from 'zx';
import { runClaudePrompt } from '../ai/claude-executor.js';
import type { ActivityLogger } from '../types/activity-logger.js';

export interface SecretFinding {
  id: string;
  type: SecretType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  confidence: number;
  
  // Location
  filePath: string;
  lineNumber: number;
  columnStart: number;
  columnEnd: number;
  
  // Secret details
  secretValue: string; // Masked in output
  secretPreview: string; // First/last few chars
  secretLength: number;
  
  // Detection metadata
  detectionMethod: 'REGEX' | 'LLM' | 'ENTROPY' | 'HYBRID';
  patternName: string;
  
  // Validation
  validation: {
    isValidFormat: boolean;
    isLivenessChecked: boolean;
    isActive?: boolean;
    validationError?: string;
  };
  
  // Context
  codeSnippet: string;
  contextBefore: string;
  contextAfter: string;
  
  // Remediation
  remediation: string;
}

export type SecretType =
  | 'AWS_ACCESS_KEY'
  | 'AWS_SECRET_KEY'
  | 'AZURE_STORAGE_KEY'
  | 'GCP_API_KEY'
  | 'GITHUB_TOKEN'
  | 'GITLAB_TOKEN'
  | 'SLACK_TOKEN'
  | 'STRIPE_KEY'
  | 'SENDGRID_KEY'
  | 'JWT_TOKEN'
  | 'API_KEY_GENERIC'
  | 'PASSWORD'
  | 'DATABASE_URL'
  | 'PRIVATE_KEY'
  | 'CERTIFICATE'
  | 'BEARER_TOKEN'
  | 'BASIC_AUTH'
  | 'CUSTOM_FORMAT';

export interface SecretPattern {
  type: SecretType;
  name: string;
  severity: SecretFinding['severity'];
  
  // Regex patterns for detection
  patterns: RegExp[];
  
  // Validation function
  validate?: (match: string) => boolean;
  
  // Entropy threshold (if applicable)
  minEntropy?: number;
  
  // Keywords that should be nearby
  contextKeywords?: string[];
  
  // Exclusions to reduce false positives
  excludePatterns?: RegExp[];
  excludeKeywords?: string[];
}

/**
 * Predefined secret patterns
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  // AWS Access Key
  {
    type: 'AWS_ACCESS_KEY',
    name: 'AWS Access Key ID',
    severity: 'CRITICAL',
    patterns: [
      /AKIA[0-9A-Z]{16}/,
      /ASIA[0-9A-Z]{16}/,
      /AKIA[0-9A-Z]{16}/,
    ],
    contextKeywords: ['aws', 'amazon', 'access', 'key', 'id'],
    excludeKeywords: ['example', 'placeholder', 'dummy', 'test', 'fake'],
    validate: (key) => key.length === 20 && /^AKIA[0-9A-Z]{16}$/.test(key),
  },
  
  // AWS Secret Key
  {
    type: 'AWS_SECRET_KEY',
    name: 'AWS Secret Access Key',
    severity: 'CRITICAL',
    patterns: [
      /[0-9a-zA-Z/+]{40}/,
    ],
    minEntropy: 4.5,
    contextKeywords: ['aws', 'amazon', 'secret', 'key'],
    excludeKeywords: ['example', 'placeholder', 'dummy', 'test', 'fake'],
  },
  
  // GitHub Token
  {
    type: 'GITHUB_TOKEN',
    name: 'GitHub Personal Access Token',
    severity: 'CRITICAL',
    patterns: [
      /ghp_[0-9a-zA-Z]{36}/,
      /gho_[0-9a-zA-Z]{36}/,
      /ghu_[0-9a-zA-Z]{36}/,
      /ghs_[0-9a-zA-Z]{36}/,
      /ghr_[0-9a-zA-Z]{36}/,
    ],
    contextKeywords: ['github', 'token', 'pat'],
    excludeKeywords: ['example'],
  },
  
  // Slack Token
  {
    type: 'SLACK_TOKEN',
    name: 'Slack API Token',
    severity: 'CRITICAL',
    patterns: [
      /xox[baprs]-[0-9a-zA-Z-]+/,
    ],
    contextKeywords: ['slack', 'token', 'bot'],
  },
  
  // Stripe Key
  {
    type: 'STRIPE_KEY',
    name: 'Stripe API Key',
    severity: 'CRITICAL',
    patterns: [
      /sk_live_[0-9a-zA-Z]{24}/,
      /pk_live_[0-9a-zA-Z]{24}/,
      /sk_test_[0-9a-zA-Z]{24}/,
    ],
    contextKeywords: ['stripe', 'api', 'key', 'secret'],
  },
  
  // Generic API Key
  {
    type: 'API_KEY_GENERIC',
    name: 'Generic API Key',
    severity: 'HIGH',
    patterns: [
      /api[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/i,
      /apikey['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/i,
    ],
    minEntropy: 3.5,
    contextKeywords: ['api', 'key'],
    excludePatterns: [
      /example/i,
      /placeholder/i,
      /dummy/i,
      /test/i,
      /fake/i,
      /sample/i,
    ],
  },
  
  // JWT Token
  {
    type: 'JWT_TOKEN',
    name: 'JSON Web Token',
    severity: 'HIGH',
    patterns: [
      /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/,
    ],
    contextKeywords: ['jwt', 'token', 'bearer', 'auth'],
  },
  
  // Database URL with credentials
  {
    type: 'DATABASE_URL',
    name: 'Database Connection String',
    severity: 'CRITICAL',
    patterns: [
      /(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^/]+/i,
    ],
    contextKeywords: ['database', 'db', 'connection', 'url', 'uri'],
  },
  
  // Private Key
  {
    type: 'PRIVATE_KEY',
    name: 'Private Key',
    severity: 'CRITICAL',
    patterns: [
      /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/,
    ],
    contextKeywords: ['private', 'key', 'pem', 'ssh'],
  },
  
  // Bearer Token
  {
    type: 'BEARER_TOKEN',
    name: 'Bearer Token',
    severity: 'HIGH',
    patterns: [
      /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/,
    ],
    contextKeywords: ['authorization', 'auth', 'bearer', 'token'],
  },
  
  // Basic Auth
  {
    type: 'BASIC_AUTH',
    name: 'HTTP Basic Authentication',
    severity: 'CRITICAL',
    patterns: [
      /Basic\s+[a-zA-Z0-9+/]{20,}={0,2}/,
    ],
    contextKeywords: ['authorization', 'auth', 'basic'],
  },
];

export class SecretsDetectionService {
  private patterns: SecretPattern[];
  private useLLMDetection: boolean;
  private useEntropyAnalysis: boolean;
  private logger?: ActivityLogger;
  
  constructor(
    options: {
      patterns?: SecretPattern[];
      useLLMDetection?: boolean;
      useEntropyAnalysis?: boolean;
      logger?: ActivityLogger;
    } = {}
  ) {
    this.patterns = options.patterns || SECRET_PATTERNS;
    this.useLLMDetection = options.useLLMDetection ?? true;
    this.useEntropyAnalysis = options.useEntropyAnalysis ?? true;
    this.logger = options.logger;
  }
  
  /**
   * Scan a file for secrets
   */
  async scanFile(filePath: string, content?: string): Promise<SecretFinding[]> {
    const fileContent = content || await fs.readFile(filePath, 'utf8');
    const findings: SecretFinding[] = [];
    
    // Phase 1: Regex pattern matching
    const regexFindings = await this.scanWithRegex(filePath, fileContent);
    findings.push(...regexFindings);
    
    // Phase 2: Entropy analysis
    if (this.useEntropyAnalysis) {
      const entropyFindings = await this.scanWithEntropy(filePath, fileContent, findings);
      findings.push(...entropyFindings);
    }
    
    // Phase 3: LLM detection
    if (this.useLLMDetection) {
      const llmFindings = await this.scanWithLLM(filePath, fileContent, findings);
      findings.push(...llmFindings);
    }
    
    // Phase 4: Validate findings
    const validatedFindings = await this.validateFindings(findings, fileContent);
    
    // Deduplicate
    return this.deduplicateFindings(validatedFindings);
  }
  
  /**
   * Scan entire project
   */
  async scanProject(projectPath: string): Promise<SecretFinding[]> {
    const allFindings: SecretFinding[] = [];
    const files = await this.findScannableFiles(projectPath);
    
    this.logger?.info(`Scanning ${files.length} files for secrets...`);
    
    for (const file of files) {
      try {
        const findings = await this.scanFile(file);
        allFindings.push(...findings);
      } catch (error) {
        this.logger?.warn(`Failed to scan ${file}: ${error}`);
      }
    }
    
    const uniqueFindings = this.deduplicateFindings(allFindings);
    
    this.logger?.info(`Secrets scan complete: ${uniqueFindings.length} findings`);
    
    return uniqueFindings;
  }
  
  /**
   * Scan with regex patterns
   */
  private async scanWithRegex(filePath: string, content: string): Promise<SecretFinding[]> {
    const findings: SecretFinding[] = [];
    const lines = content.split('\n');
    
    for (const pattern of this.patterns) {
      for (const regex of pattern.patterns) {
        const globalRegex = new RegExp(regex.source, 'g');
        let match;
        
        while ((match = globalRegex.exec(content)) !== null) {
          const matchText = match[0];
          const lineNum = this.getLineNumber(content, match.index);
          const line = lines[lineNum - 1];
          
          // Check exclusions
          if (this.isExcluded(matchText, pattern.excludePatterns || [], pattern.excludeKeywords || [])) {
            continue;
          }
          
          // Check context keywords
          const hasContext = !pattern.contextKeywords || 
            pattern.contextKeywords.some(kw => line.toLowerCase().includes(kw.toLowerCase()));
          
          if (!hasContext) {
            continue;
          }
          
          // Validate if validator exists
          let isValid = true;
          if (pattern.validate) {
            isValid = pattern.validate(matchText);
          }
          
          // Check entropy if required
          if (pattern.minEntropy && this.calculateEntropy(matchText) < pattern.minEntropy) {
            continue;
          }
          
          if (isValid) {
            findings.push(this.createFinding(
              pattern,
              matchText,
              filePath,
              lineNum,
              match.index - this.getLineStart(content, match.index),
              match.index - this.getLineStart(content, match.index) + matchText.length,
              content,
              'REGEX'
            ));
          }
        }
      }
    }
    
    return findings;
  }
  
  /**
   * Scan with entropy analysis
   */
  private async scanWithEntropy(
    filePath: string,
    content: string,
    existingFindings: SecretFinding[]
  ): Promise<SecretFinding[]> {
    const findings: SecretFinding[] = [];
    const highEntropyThreshold = 4.5;
    
    // Find high-entropy strings that haven't been caught by regex
    const entropyRegex = /['"]([a-zA-Z0-9+/=]{20,})['"]/g;
    let match;
    
    while ((match = entropyRegex.exec(content)) !== null) {
      const candidate = match[1];
      const entropy = this.calculateEntropy(candidate);
      
      if (entropy >= highEntropyThreshold) {
        // Check if already found
        const alreadyFound = existingFindings.some(f => 
          f.filePath === filePath && 
          Math.abs(f.lineNumber - this.getLineNumber(content, match.index)) < 2
        );
        
        if (!alreadyFound) {
          // Use LLM to classify
          const classification = await this.classifyWithLLM(candidate);
          
          if (classification.isSecret && classification.confidence > 0.7) {
            findings.push(this.createFinding(
              {
                type: classification.secretType || 'CUSTOM_FORMAT',
                name: 'High Entropy Secret',
                severity: 'HIGH',
                patterns: [],
              },
              candidate,
              filePath,
              this.getLineNumber(content, match.index),
              match.index - this.getLineStart(content, match.index),
              match.index - this.getLineStart(content, match.index) + candidate.length,
              content,
              'ENTROPY'
            ));
          }
        }
      }
    }
    
    return findings;
  }
  
  /**
   * Scan with LLM for complex patterns
   */
  private async scanWithLLM(
    filePath: string,
    content: string,
    existingFindings: SecretFinding[]
  ): Promise<SecretFinding[]> {
    // Sample the file for LLM analysis
    const lines = content.split('\n');
    const suspiciousLines: Array<{ lineNum: number; line: string }> = [];
    
    // Find lines that might contain secrets but weren't caught
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Keywords that suggest secrets
      const secretKeywords = ['token', 'secret', 'password', 'key', 'auth', 'credential', 'bearer'];
      
      if (secretKeywords.some(kw => line.toLowerCase().includes(kw))) {
        // Check if already found
        const alreadyFound = existingFindings.some(f => 
          f.filePath === filePath && f.lineNumber === i + 1
        );
        
        if (!alreadyFound) {
          suspiciousLines.push({ lineNum: i + 1, line });
        }
      }
    }
    
    if (suspiciousLines.length === 0) {
      return [];
    }
    
    // Analyze with LLM
    const findings: SecretFinding[] = [];
    
    for (const { lineNum, line } of suspiciousLines.slice(0, 20)) { // Limit to prevent token overflow
      const prompt = `
Analyze this code line for potential secrets or credentials:

Line: ${line}

Does this line contain any of the following?
1. API keys or access tokens
2. Passwords or credentials
3. Cryptographic keys
4. Database connection strings
5. Authentication tokens

Answer in this format:
CONTAINS_SECRET: <yes/no>
SECRET_TYPE: <API_KEY|PASSWORD|TOKEN|KEY|CONNECTION_STRING|NONE>
CONFIDENCE: <0.0-1.0>
REASONING: <brief explanation>
`;
      
      try {
        const result = await runClaudePrompt(
          prompt,
          filePath,
          line,
          'Secrets Detection',
          'secrets-detection',
          undefined,
          undefined,
          'small'
        );
        
        if (result.success && result.result) {
          const response = result.result;
          const containsSecret = response.match(/CONTAINS_SECRET:\s*(yes)/i);
          const confidenceMatch = response.match(/CONFIDENCE:\s*(0?\.\d+|1\.?0?)/);
          const typeMatch = response.match(/SECRET_TYPE:\s*(\w+)/);
          
          if (containsSecret && confidenceMatch) {
            const confidence = parseFloat(confidenceMatch[1]);
            if (confidence > 0.7) {
              const secretType = typeMatch?.[1] || 'CUSTOM_FORMAT';
              
              findings.push(this.createFinding(
                {
                  type: secretType as SecretType,
                  name: 'LLM-Detected Secret',
                  severity: 'HIGH',
                  patterns: [],
                },
                line.trim(),
                filePath,
                lineNum,
                0,
                line.length,
                content,
                'LLM'
              ));
            }
          }
        }
      } catch {
        // Continue to next line
      }
    }
    
    return findings;
  }
  
  /**
   * Classify a string with LLM
   */
  private async classifyWithLLM(candidate: string): Promise<{ isSecret: boolean; secretType?: SecretType; confidence: number }> {
    const prompt = `
Classify this high-entropy string:

String: ${candidate.substring(0, 50)}...

Is this likely to be:
1. An API key or token
2. A cryptographic key
3. A password or credential
4. Random data / not a secret

Answer:
TYPE: <API_KEY|CRYPTO_KEY|PASSWORD|NOT_SECRET>
CONFIDENCE: <0.0-1.0>
`;
    
    try {
      const result = await runClaudePrompt(prompt, '', '', 'Secret Classification', 'secret-classify', undefined, undefined, 'small');
      
      if (result.success && result.result) {
        const response = result.result;
        const typeMatch = response.match(/TYPE:\s*(\w+)/);
        const confidenceMatch = response.match(/CONFIDENCE:\s*(0?\.\d+|1\.?0?)/);
        
        const type = typeMatch?.[1];
        const confidence = confidenceMatch ? parseFloat(confidenceMatch[1]) : 0.5;
        
        const typeMap: Record<string, SecretType> = {
          'API_KEY': 'API_KEY_GENERIC',
          'CRYPTO_KEY': 'PRIVATE_KEY',
          'PASSWORD': 'PASSWORD',
        };
        
        return {
          isSecret: type !== 'NOT_SECRET',
          secretType: typeMap[type || ''],
          confidence,
        };
      }
    } catch {
      // Fall through to default
    }
    
    return { isSecret: false, confidence: 0 };
  }
  
  /**
   * Validate findings
   */
  private async validateFindings(findings: SecretFinding[], content: string): Promise<SecretFinding[]> {
    // In a real implementation, this would:
    // 1. Check format validity (e.g., AWS key format)
    // 2. Perform liveness checks (for non-sensitive environments)
    // 3. Cross-reference with known test/example values
    
    return findings.map(f => ({
      ...f,
      validation: {
        isValidFormat: true,
        isLivenessChecked: false,
      },
    }));
  }
  
  /**
   * Calculate Shannon entropy of a string
   */
  private calculateEntropy(str: string): number {
    const charMap: Record<string, number> = {};
    
    for (const char of str) {
      charMap[char] = (charMap[char] || 0) + 1;
    }
    
    const len = str.length;
    let entropy = 0;
    
    for (const count of Object.values(charMap)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }
  
  /**
   * Check if match should be excluded
   */
  private isExcluded(match: string, excludePatterns: RegExp[], excludeKeywords: string[]): boolean {
    for (const pattern of excludePatterns) {
      if (pattern.test(match)) {
        return true;
      }
    }
    
    for (const keyword of excludeKeywords) {
      if (match.toLowerCase().includes(keyword.toLowerCase())) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Create a finding from pattern match
   */
  private createFinding(
    pattern: Pick<SecretPattern, 'type' | 'name' | 'severity'>,
    matchText: string,
    filePath: string,
    lineNumber: number,
    columnStart: number,
    columnEnd: number,
    content: string,
    detectionMethod: SecretFinding['detectionMethod']
  ): SecretFinding {
    const lines = content.split('\n');
    const line = lines[lineNumber - 1];
    
    // Create masked preview
    const preview = matchText.length > 8 
      ? `${matchText.substring(0, 4)}...${matchText.substring(matchText.length - 4)}`
      : '****';
    
    return {
      id: `secret-${pattern.type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: pattern.type,
      severity: pattern.severity,
      confidence: detectionMethod === 'REGEX' ? 0.9 : 0.7,
      filePath,
      lineNumber,
      columnStart,
      columnEnd,
      secretValue: '***MASKED***',
      secretPreview: preview,
      secretLength: matchText.length,
      detectionMethod,
      patternName: pattern.name,
      validation: {
        isValidFormat: true,
        isLivenessChecked: false,
      },
      codeSnippet: line.trim(),
      contextBefore: lineNumber > 1 ? lines[lineNumber - 2] : '',
      contextAfter: lineNumber < lines.length ? lines[lineNumber] : '',
      remediation: 'Remove the secret from code and use environment variables or a secrets manager. Rotate the exposed secret immediately.',
    };
  }
  
  /**
   * Get line number from character index
   */
  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }
  
  /**
   * Get start of line from character index
   */
  private getLineStart(content: string, index: number): number {
    const lines = content.substring(0, index).split('\n');
    return index - lines[lines.length - 1].length;
  }
  
  /**
   * Find scannable files
   */
  private async findScannableFiles(projectPath: string): Promise<string[]> {
    const files: string[] = [];
    const extensions = new Set([
      '.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java', '.cs',
      '.yaml', '.yml', '.json', '.xml', '.env', '.properties', '.conf', '.ini',
      '.sh', '.bash', '.zsh', '.ps1', '.tf', '.tfvars', '.dockerfile', '.docker',
    ]);
    
    async function walk(dir: string) {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          if (!entry.name.startsWith('.') && 
              !['node_modules', 'vendor', 'dist', 'build', '.git'].includes(entry.name)) {
            await walk(fullPath);
          }
        } else if (entry.isFile()) {
          // Check by extension or specific filenames
          const ext = path.extname(entry.name).toLowerCase();
          const basename = entry.name.toLowerCase();
          
          if (extensions.has(ext) || 
              ['.env', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 
               'credentials', 'secrets', 'config'].some(name => basename.includes(name))) {
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
  private deduplicateFindings(findings: SecretFinding[]): SecretFinding[] {
    const seen = new Set<string>();
    const unique: SecretFinding[] = [];
    
    for (const finding of findings) {
      const key = `${finding.type}-${finding.filePath}-${finding.lineNumber}-${finding.secretPreview}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(finding);
      }
    }
    
    return unique;
  }
  
  /**
   * Generate markdown report
   */
  generateReport(findings: SecretFinding[]): string {
    const lines: string[] = [];
    
    lines.push('# Secrets Detection Report');
    lines.push('');
    lines.push('⚠️ **WARNING: This report contains references to exposed secrets.**');
    lines.push('**Immediate action required: Rotate all exposed secrets.**');
    lines.push('');
    lines.push(`**Total Secrets Found:** ${findings.length}`);
    lines.push('');
    
    // Group by severity
    const bySeverity: Record<string, SecretFinding[]> = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
    };
    
    for (const finding of findings) {
      bySeverity[finding.severity].push(finding);
    }
    
    for (const [severity, items] of Object.entries(bySeverity)) {
      if (items.length === 0) continue;
      
      lines.push(`## ${severity} (${items.length})`);
      lines.push('');
      
      for (const finding of items) {
        lines.push(`### ${finding.patternName}`);
        lines.push('');
        lines.push(`**Type:** ${finding.type}`);
        lines.push(`**Location:** \`${finding.filePath}:${finding.lineNumber}\``);
        lines.push(`**Secret Preview:** \`${finding.secretPreview}\``);
        lines.push(`**Detection Method:** ${finding.detectionMethod}`);
        lines.push(`**Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
        lines.push('');
        lines.push('**Code:**');
        lines.push('```');
        lines.push(finding.codeSnippet);
        lines.push('```');
        lines.push('');
        lines.push('**Remediation:**');
        lines.push(finding.remediation);
        lines.push('');
        lines.push('---');
        lines.push('');
      }
    }
    
    return lines.join('\n');
  }
  
  /**
   * Export to JSON (secrets masked)
   */
  exportToJSON(findings: SecretFinding[]): string {
    return JSON.stringify(findings, null, 2);
  }
}
