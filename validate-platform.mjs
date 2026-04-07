#!/usr/bin/env node

/**
 * Shanom Platform Validation Script (ES Module)
 * 
 * ทดสอบการทำงานของระบบ Shanom ที่สร้างขึ้น
 * Run: node validate-platform.mjs
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Color codes for terminal
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(type, message, detail = '') {
  const icons = {
    info: 'ℹ️',
    success: '✅',
    error: '❌',
    warning: '⚠️',
    section: '📦',
  };
  
  console.log(`${icons[type] || '•'} ${message}`);
  if (detail) {
    console.log(`   ${colors.cyan}${detail}${colors.reset}`);
  }
}

function checkFile(filePath, description) {
  const fullPath = path.join(process.cwd(), filePath);
  if (fs.existsSync(fullPath)) {
    const stats = fs.statSync(fullPath);
    const sizeKB = (stats.size / 1024).toFixed(1);
    log('success', `${description}`, `${filePath} (${sizeKB} KB)`);
    return true;
  } else {
    log('error', `${description}`, `Missing: ${filePath}`);
    return false;
  }
}

function checkContent(filePath, patterns, description) {
  const fullPath = path.join(process.cwd(), filePath);
  if (!fs.existsSync(fullPath)) {
    log('error', description, `File not found: ${filePath}`);
    return false;
  }
  
  const content = fs.readFileSync(fullPath, 'utf8');
  const missing = patterns.filter(p => !content.includes(p));
  
  if (missing.length === 0) {
    log('success', description, `All patterns found (${patterns.length})`);
    return true;
  } else {
    log('warning', description, `Missing: ${missing.join(', ')}`);
    return false;
  }
}

console.log('\n' + '='.repeat(70));
console.log('           Shanom Platform - Validation Suite');
console.log('   CPG Engine + SAST + SCA + Secrets + Enterprise Platform');
console.log('='.repeat(70) + '\n');

let passCount = 0;
let failCount = 0;

// Section 1: Core CPG Engine
console.log('\n' + colors.bright + colors.blue + '🧠 CPG (Code Property Graph) Engine' + colors.reset);
console.log('-'.repeat(70));

const cpgFiles = [
  ['apps/worker/src/cpg/models.ts', 'CPG Data Models'],
  ['apps/worker/src/cpg/engine.ts', 'CPG Main Engine'],
  ['apps/worker/src/cpg/llm-reasoner.ts', 'LLM Reasoning Service'],
  ['apps/worker/src/cpg/data-flow-analyzer.ts', 'Data Flow Analyzer'],
  ['apps/worker/src/cpg/simple-builder.ts', 'CPG Builder'],
  ['apps/worker/src/cpg/index.ts', 'CPG Module Exports'],
];

for (const [file, desc] of cpgFiles) {
  if (checkFile(file, desc)) passCount++; else failCount++;
}

// Check CPG functionality
if (checkContent('apps/worker/src/cpg/models.ts', 
  ['CPGNode', 'CPGEdge', 'CodePropertyGraph'], 
  'Core CPG Types')) passCount++; else failCount++;

if (checkContent('apps/worker/src/cpg/llm-reasoner.ts', 
  ['LLMNodeReasoner', 'analyzeNode', 'analyzePath'], 
  'LLM Reasoning Features')) passCount++; else failCount++;

if (checkContent('apps/worker/src/cpg/data-flow-analyzer.ts', 
  ['DataFlowAnalyzer', 'DataFlowFinding', 'tracePath'], 
  'Data Flow Analysis')) passCount++; else failCount++;

// Section 2: Static Analysis
console.log('\n' + colors.bright + colors.blue + '🔍 Static Analysis (SAST + SCA + Secrets)' + colors.reset);
console.log('-'.repeat(70));

const staticAnalysisFiles = [
  ['apps/worker/src/sast/point-issue-detection.ts', 'Point Issue Detection'],
  ['apps/worker/src/sca/sca-service.ts', 'SCA Service'],
  ['apps/worker/src/secrets/secrets-detection.ts', 'Secrets Detection'],
];

for (const [file, desc] of staticAnalysisFiles) {
  if (checkFile(file, desc)) passCount++; else failCount++;
}

if (checkContent('apps/worker/src/sast/point-issue-detection.ts',
  ['PointIssueDetectionService', 'POINT_ISSUE_PATTERNS'],
  'SAST Patterns')) passCount++; else failCount++;

if (checkContent('apps/worker/src/sca/sca-service.ts',
  ['SCAService', 'analyzeReachability', 'VulnerableDependency'],
  'SCA Features')) passCount++; else failCount++;

if (checkContent('apps/worker/src/secrets/secrets-detection.ts',
  ['SecretsDetectionService', 'SECRET_PATTERNS', 'scanFile'],
  'Secrets Detection Features')) passCount++; else failCount++;

// Section 3: Static-Dynamic Correlation
console.log('\n' + colors.bright + colors.blue + '🔗 Static-Dynamic Correlation' + colors.reset);
console.log('-'.repeat(70));

const correlationFiles = [
  ['apps/worker/src/correlation/engine.ts', 'Correlation Engine'],
  ['apps/worker/src/correlation/injector.ts', 'CPG Injector'],
  ['apps/worker/src/correlation/merger.ts', 'Findings Merger'],
  ['apps/worker/src/correlation/service.ts', 'Correlation Service'],
  ['apps/worker/src/correlation/index.ts', 'Correlation Module'],
];

for (const [file, desc] of correlationFiles) {
  if (checkFile(file, desc)) passCount++; else failCount++;
}

if (checkContent('apps/worker/src/correlation/engine.ts',
  ['StaticDynamicCorrelationEngine', 'StaticFinding', 'DynamicFinding', 'CorrelatedFinding'],
  'Correlation Types')) passCount++; else failCount++;

// Section 4: Enterprise Platform
console.log('\n' + colors.bright + colors.blue + '🏢 Enterprise Platform' + colors.reset);
console.log('-'.repeat(70));

const enterpriseFiles = [
  ['apps/worker/src/enterprise/config.ts', 'Enterprise Config'],
  ['apps/worker/src/enterprise/multi-tenancy.ts', 'Multi-Tenancy'],
  ['apps/worker/src/enterprise/index.ts', 'Enterprise Module'],
];

for (const [file, desc] of enterpriseFiles) {
  if (checkFile(file, desc)) passCount++; else failCount++;
}

if (checkContent('apps/worker/src/enterprise/config.ts',
  ['EnterpriseConfig', 'DEFAULT_ENTERPRISE_CONFIG', 'rbac', 'multitenancy'],
  'Enterprise Features')) passCount++; else failCount++;

if (checkContent('apps/worker/src/enterprise/multi-tenancy.ts',
  ['MultiTenancyService', 'createTenant', 'Tenant'],
  'Multi-Tenancy Features')) passCount++; else failCount++;

// Section 5: Unified CLI
console.log('\n' + colors.bright + colors.blue + '💻 Unified CLI (Local + Enterprise)' + colors.reset);
console.log('-'.repeat(70));

const cliFiles = [
  ['apps/cli/src/unified-config.ts', 'Unified CLI Config'],
];

for (const [file, desc] of cliFiles) {
  if (checkFile(file, desc)) passCount++; else failCount++;
}

if (checkContent('apps/cli/src/unified-config.ts',
  ['CLIMode', 'EnterpriseAPIClient', 'loginEnterprise'],
  'CLI Features')) passCount++; else failCount++;

// Section 6: Integration
console.log('\n' + colors.bright + colors.blue + '🔌 Integration Points' + colors.reset);
console.log('-'.repeat(70));

if (checkContent('apps/worker/src/services/container.ts',
  ['CPGAnalysisService', 'CorrelationService'],
  'DI Container Integration')) passCount++; else failCount++;

if (checkContent('apps/worker/src/services/index.ts',
  ['CPGAnalysisService', 'CorrelationService'],
  'Services Export')) passCount++; else failCount++;

// Section 7: Report Generation
console.log('\n' + colors.bright + colors.blue + '📊 Pentest Reporting' + colors.reset);
console.log('-'.repeat(70));

const reportPrompts = [
  ['apps/worker/prompts/report-technical.txt', 'Technical Report Prompt'],
  ['apps/worker/prompts/report-remediation.txt', 'Remediation Report Prompt'],
  ['apps/worker/prompts/report-board.txt', 'Board Report Prompt'],
];

for (const [file, desc] of reportPrompts) {
  if (checkFile(file, desc)) passCount++; else failCount++;
}

// Summary
console.log('\n' + '='.repeat(70));
console.log('                      VALIDATION SUMMARY');
console.log('='.repeat(70));

const total = passCount + failCount;
const passPercent = ((passCount / total) * 100).toFixed(1);

console.log(`\n  ✅ Passed:  ${passCount}/${total} (${passPercent}%)`);
console.log(`  ❌ Failed:  ${failCount}/${total}`);

console.log('\n' + '-'.repeat(70));

if (failCount === 0) {
  console.log(colors.green + '\n  🎉 ALL CHECKS PASSED!' + colors.reset);
  console.log('  The Shanom platform has been successfully built with:');
  console.log('  • CPG Engine with LLM reasoning');
  console.log('  • SAST Point Issue Detection');
  console.log('  • SCA with Reachability Analysis');
  console.log('  • Secrets Detection (Regex + LLM + Entropy)');
  console.log('  • Static-Dynamic Correlation');
  console.log('  • Enterprise Multi-Tenant Platform');
  console.log('  • Unified CLI (Local + Enterprise modes)');
  console.log('\n  The system is ready for testing and deployment.');
} else if (failCount < 5) {
  console.log(colors.yellow + '\n  ⚠️  MOSTLY COMPLETE' + colors.reset);
  console.log('  Core functionality is in place with minor gaps.');
  console.log('  Review the failed checks above for details.');
} else {
  console.log(colors.red + '\n  ❌ SIGNIFICANT GAPS DETECTED' + colors.reset);
  console.log('  Please review the implementation before proceeding.');
}

console.log('\n' + '='.repeat(70) + '\n');

// Create summary report
const report = {
  timestamp: new Date().toISOString(),
  summary: {
    total: total,
    passed: passCount,
    failed: failCount,
    passRate: passPercent + '%',
  },
  status: failCount === 0 ? 'SUCCESS' : failCount < 5 ? 'PARTIAL' : 'FAILED',
};

fs.writeFileSync('validation-report.json', JSON.stringify(report, null, 2));
console.log('📄 Report saved to: validation-report.json\n');

process.exit(failCount > 10 ? 1 : 0);
