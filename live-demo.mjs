#!/usr/bin/env node

/**
 * Shanom Live Demo Script
 * 
 * ทดสอบระบบ Shanom กับ vulnerable test application
 * Run: node live-demo.mjs
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

console.log('\n╔══════════════════════════════════════════════════════════════════╗');
console.log('║           Shanom Live Demo - CPG + SAST + SCA Test              ║');
console.log('╚══════════════════════════════════════════════════════════════════╝\n');

// Step 1: Check test app exists
const testAppPath = path.join(__dirname, 'test-app', 'app.js');
if (!fs.existsSync(testAppPath)) {
  console.error('❌ Test app not found. Please ensure test-app/app.js exists.');
  process.exit(1);
}

console.log('✅ Test application found at: test-app/app.js\n');

// Step 2: Validate Shanom modules exist
console.log('📦 Checking Shanom modules...\n');

const requiredModules = [
  'apps/worker/src/cpg/index.ts',
  'apps/worker/src/cpg/engine.ts',
  'apps/worker/src/sast/point-issue-detection.ts',
  'apps/worker/src/sca/sca-service.ts',
  'apps/worker/src/secrets/secrets-detection.ts',
  'apps/worker/src/correlation/engine.ts',
];

let allModulesExist = true;
for (const mod of requiredModules) {
  const modPath = path.join(__dirname, mod);
  if (fs.existsSync(modPath)) {
    console.log(`  ✅ ${mod}`);
  } else {
    console.log(`  ❌ ${mod} (missing)`);
    allModulesExist = false;
  }
}

if (!allModulesExist) {
  console.error('\n❌ Some modules are missing. Please build the project first.');
  process.exit(1);
}

console.log('\n✅ All Shanom modules are available!\n');

// Step 3: Simulate static analysis
console.log('🔍 Simulating Static Analysis on test-app...\n');

const testAppCode = fs.readFileSync(testAppPath, 'utf8');

// Check for vulnerabilities in code
const vulnerabilities = [];

// Check for hardcoded secrets
const secretPatterns = [
  { pattern: /API_KEY\s*=\s*['"]([^'"]+)['"]/, name: 'Hardcoded API Key', severity: 'CRITICAL' },
  { pattern: /DB_PASSWORD\s*=\s*['"]([^'"]+)['"]/, name: 'Hardcoded DB Password', severity: 'CRITICAL' },
  { pattern: /JWT_SECRET\s*=\s*['"]([^'"]+)['"]/, name: 'Hardcoded JWT Secret', severity: 'CRITICAL' },
  { pattern: /AWS_ACCESS_KEY\s*=\s*['"]([^'"]+)['"]/, name: 'Hardcoded AWS Key', severity: 'CRITICAL' },
];

for (const { pattern, name, severity } of secretPatterns) {
  if (pattern.test(testAppCode)) {
    vulnerabilities.push({ type: 'Secret', name, severity, evidence: 'Found in app.js' });
  }
}

// Check for SQL injection
if (testAppCode.includes("`SELECT * FROM users WHERE username = '${username}'`")) {
  vulnerabilities.push({ 
    type: 'SQL Injection', 
    name: 'SQL Injection in /api/users', 
    severity: 'CRITICAL',
    evidence: 'String interpolation in SQL query'
  });
}

if (testAppCode.includes("`SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`")) {
  vulnerabilities.push({ 
    type: 'SQL Injection', 
    name: 'SQL Injection in /api/login', 
    severity: 'CRITICAL',
    evidence: 'String interpolation in SQL query'
  });
}

// Check for XSS
if (testAppCode.includes('${q}') && testAppCode.includes('document.write')) {
  vulnerabilities.push({ 
    type: 'XSS', 
    name: 'Reflected XSS in /api/search', 
    severity: 'HIGH',
    evidence: 'User input reflected without encoding'
  });
}

// Check for Command Injection
if (testAppCode.includes('exec(`ping -c 1 ${host}`)')) {
  vulnerabilities.push({ 
    type: 'Command Injection', 
    name: 'Command Injection in /api/ping', 
    severity: 'CRITICAL',
    evidence: 'User input passed to exec()'
  });
}

// Check for Weak Crypto
if (testAppCode.includes("crypto.createHash('md5')")) {
  vulnerabilities.push({ 
    type: 'Weak Crypto', 
    name: 'MD5 Hash Usage', 
    severity: 'HIGH',
    evidence: 'Using deprecated MD5 algorithm'
  });
}

// Check for Insecure Deserialization
if (testAppCode.includes('eval(data)') || testAppCode.includes('eval(')) {
  vulnerabilities.push({ 
    type: 'Code Injection', 
    name: 'eval() usage', 
    severity: 'CRITICAL',
    evidence: 'User input passed to eval()'
  });
}

// Check for Path Traversal
if (testAppCode.includes("path.join(__dirname, 'files', filename)")) {
  vulnerabilities.push({ 
    type: 'Path Traversal', 
    name: 'Path Traversal in /api/file', 
    severity: 'HIGH',
    evidence: 'User input used in file path'
  });
}

// Check for SSRF
if (testAppCode.includes('client.get(url') && testAppCode.includes('url.startsWith')) {
  vulnerabilities.push({ 
    type: 'SSRF', 
    name: 'SSRF in /api/fetch', 
    severity: 'HIGH',
    evidence: 'User-controlled URL in HTTP request'
  });
}

// Check for Information Disclosure
if (testAppCode.includes('process.env') && testAppCode.includes('/api/debug')) {
  vulnerabilities.push({ 
    type: 'Info Disclosure', 
    name: 'Debug endpoint exposes secrets', 
    severity: 'CRITICAL',
    evidence: '/api/debug exposes environment and config'
  });
}

console.log(`Found ${vulnerabilities.length} vulnerabilities:\n`);

const severityColors = {
  'CRITICAL': '\x1b[31m', // Red
  'HIGH': '\x1b[33m',     // Yellow
  'MEDIUM': '\x1b[36m',   // Cyan
  'LOW': '\x1b[32m',      // Green
};

const reset = '\x1b[0m';

for (const vuln of vulnerabilities) {
  const color = severityColors[vuln.severity] || '';
  console.log(`${color}[${vuln.severity}]${reset} ${vuln.type}: ${vuln.name}`);
  console.log(`   Evidence: ${vuln.evidence}\n`);
}

// Summary
console.log('\n' + '═'.repeat(70));
console.log('                         ANALYSIS SUMMARY');
console.log('═'.repeat(70));

const bySeverity = {};
for (const v of vulnerabilities) {
  bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
}

console.log(`\nTotal Vulnerabilities: ${vulnerabilities.length}`);
console.log(`  CRITICAL: ${bySeverity['CRITICAL'] || 0}`);
console.log(`  HIGH:     ${bySeverity['HIGH'] || 0}`);
console.log(`  MEDIUM:   ${bySeverity['MEDIUM'] || 0}`);
console.log(`  LOW:      ${bySeverity['LOW'] || 0}`);

console.log('\n📋 Vulnerability Categories:');
const byType = {};
for (const v of vulnerabilities) {
  byType[v.type] = (byType[v.type] || 0) + 1;
}

for (const [type, count] of Object.entries(byType)) {
  console.log(`  • ${type}: ${count}`);
}

console.log('\n' + '═'.repeat(70));
console.log('\n✅ Static Analysis Complete!');
console.log('\nNext steps to run full Shanom scan:');
console.log('  1. Start test app: cd test-app && npm install && npm start');
console.log('  2. Run Shanom:   ./shanom start -u http://localhost:3000 -r ./test-app');
console.log('\n📝 Note: This is a simulated analysis.');
console.log('   For full CPG + Dynamic testing, run the actual Shanom scanner.\n');

// Generate report
const report = {
  timestamp: new Date().toISOString(),
  target: 'test-app/app.js',
  totalVulnerabilities: vulnerabilities.length,
  bySeverity,
  byType,
  findings: vulnerabilities,
};

fs.writeFileSync('demo-report.json', JSON.stringify(report, null, 2));
console.log('📄 Report saved to: demo-report.json\n');
