// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Vulnerable Test Application
 * 
 * แอป Node.js ที่มีช่องโหว่ต่าง ๆ สำหรับทดสอบ Shanom
 * - SQL Injection
 * - XSS
 * - Hardcoded secrets
 * - Weak crypto
 * - Command injection
 */

const express = require('express');
const sqlite3 = require('sqlite3');
const crypto = require('crypto');
const { exec } = require('child_process');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database
const db = new sqlite3.Database(':memory:');

// Hardcoded secrets (for testing secrets detection)
const API_KEY = 'ak_live_1234567890abcdef1234567890';
const DB_PASSWORD = 'SuperSecretPassword123!';
const JWT_SECRET = 'my-super-secret-jwt-key-1234567890';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    email TEXT,
    is_admin INTEGER DEFAULT 0
  )`);
  
  // Insert test users
  db.run("INSERT INTO users (username, password, email, is_admin) VALUES ('admin', 'admin123', 'admin@test.com', 1)");
  db.run("INSERT INTO users (username, password, email, is_admin) VALUES ('user1', 'pass123', 'user1@test.com', 0)");
  db.run("INSERT INTO users (username, password, email, is_admin) VALUES ('user2', 'pass456', 'user2@test.com', 0)");
});

// Vulnerable endpoint: SQL Injection
app.get('/api/users', (req, res) => {
  const { username } = req.query;
  
  // VULNERABLE: Direct string concatenation
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  
  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Vulnerable endpoint: SQL Injection (POST)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: SQL Injection
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  db.get(query, (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (row) {
      res.json({ success: true, user: row });
    } else {
      res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
  });
});

// Vulnerable endpoint: XSS
app.get('/api/search', (req, res) => {
  const { q } = req.query;
  
  // VULNERABLE: No output encoding
  res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${q}</p>
        <div id="results"></div>
        <script>
          // Reflect user input
          document.write("Searching for: " + "${q}");
        </script>
      </body>
    </html>
  `);
});

// Vulnerable endpoint: Command Injection
app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  
  // VULNERABLE: Command injection
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.json({ output: stdout });
  });
});

// Vulnerable endpoint: Insecure Deserialization
app.post('/api/process', (req, res) => {
  const { data } = req.body;
  
  // VULNERABLE: eval on user input
  try {
    const result = eval(data);
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Vulnerable: Weak crypto
app.post('/api/hash', (req, res) => {
  const { password } = req.body;
  
  // VULNERABLE: Using MD5
  const hash = crypto.createHash('md5').update(password).digest('hex');
  res.json({ hash });
});

// Vulnerable: Path traversal
app.get('/api/file', (req, res) => {
  const { filename } = req.query;
  const fs = require('fs');
  const path = require('path');
  
  // VULNERABLE: Path traversal
  const filePath = path.join(__dirname, 'files', filename);
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'File not found' });
    }
    res.send(data);
  });
});

// Admin endpoint - IDOR vulnerability
app.get('/api/admin/users/:id', (req, res) => {
  const { id } = req.params;
  const { adminToken } = req.headers;
  
  // Weak check - should verify session properly
  if (adminToken !== 'admin-secret-token') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
    if (err || !row) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(row);
  });
});

// SSRF endpoint
app.post('/api/fetch', (req, res) => {
  const { url } = req.body;
  const https = require('https');
  const http = require('http');
  
  // VULNERABLE: SSRF - no URL validation
  const client = url.startsWith('https') ? https : http;
  
  client.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => {
      res.json({ content: data.substring(0, 1000) });
    });
  }).on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
});

// Debug endpoint - information disclosure
app.get('/api/debug', (req, res) => {
  // VULNERABLE: Information disclosure
  res.json({
    env: process.env,
    config: {
      apiKey: API_KEY,
      dbPassword: DB_PASSWORD,
      jwtSecret: JWT_SECRET,
      awsAccessKey: AWS_ACCESS_KEY,
      awsSecretKey: AWS_SECRET_KEY,
    },
    stack: new Error().stack
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Home page
app.get('/', (req, res) => {
  res.send(`
    <h1>Shanom Test Application</h1>
    <p>This is a vulnerable application for testing Shanom security scanner.</p>
    <h2>Endpoints:</h2>
    <ul>
      <li>GET /api/users?username=test (SQL Injection)</li>
      <li>POST /api/login (SQL Injection)</li>
      <li>GET /api/search?q=test (XSS)</li>
      <li>POST /api/ping (Command Injection)</li>
      <li>POST /api/process (Insecure Deserialization)</li>
      <li>POST /api/hash (Weak Crypto - MD5)</li>
      <li>GET /api/file?filename=test.txt (Path Traversal)</li>
      <li>GET /api/admin/users/:id (IDOR)</li>
      <li>POST /api/fetch (SSRF)</li>
      <li>GET /api/debug (Information Disclosure)</li>
    </ul>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable test app running on http://localhost:${PORT}`);
  console.log('This application contains intentional security vulnerabilities for testing purposes.');
  console.log('DO NOT use in production!');
});

module.exports = app;
