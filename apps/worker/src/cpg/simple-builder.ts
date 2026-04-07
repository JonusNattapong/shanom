// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Simple CPG Builder
 * 
 * Creates a Code Property Graph using lightweight parsing techniques.
 * This is a simplified builder that uses regex and heuristics rather than
 * full language parsing. Suitable for quick security analysis.
 */

import { CodePropertyGraph, type CPGNode, type CPGEdge, type NodeType, type EdgeType, type SourceLocation } from './models.js';

export class SimpleCPGBuilder {
  private nodeCounter = 0;
  private edgeCounter = 0;
  
  /**
   * Build CPG from a single file
   */
  buildFromFile(filePath: string, content: string): CodePropertyGraph {
    const graph = new CodePropertyGraph(this.detectLanguage(filePath), filePath);
    const lines = content.split('\n');
    const ext = filePath.split('.').pop()?.toLowerCase() || '';
    
    // Track scope and function context
    let currentFunction: CPGNode | null = null;
    let currentBlock: CPGNode | null = null;
    let braceDepth = 0;
    const blockStack: CPGNode[] = [];
    
    // Process each line
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      
      // Detect function/method definitions
      const funcMatch = this.matchFunctionDefinition(line, ext);
      if (funcMatch) {
        const funcNode = this.createNode('METHOD', funcMatch.name, {
          file: filePath,
          lineStart: lineNum,
          lineEnd: lineNum,
          colStart: 0,
          colEnd: line.length,
        }, line, funcMatch.signature);
        
        funcNode.isEntryPoint = funcMatch.isEntryPoint;
        graph.addNode(funcNode);
        
        currentFunction = funcNode;
        currentBlock = funcNode;
        blockStack.push(funcNode);
        
        // Add function parameters as nodes
        for (const param of funcMatch.params) {
          const paramNode = this.createNode('PARAMETER', param, {
            file: filePath,
            lineStart: lineNum,
            lineEnd: lineNum,
            colStart: 0,
            colEnd: line.length,
          }, param);
          
          graph.addNode(paramNode);
          graph.addEdge(this.createEdge('AST_PARENT', funcNode.id, paramNode.id));
          
          // Parameters are sources of untrusted data for entry points
          if (funcMatch.isEntryPoint) {
            paramNode.properties.isSource = true;
            paramNode.properties.sourceType = 'USER_INPUT';
          }
        }
      }
      
      // Detect control structures
      const controlMatch = this.matchControlStructure(line);
      if (controlMatch) {
        const controlNode = this.createNode(
          controlMatch.type as NodeType,
          controlMatch.label,
          {
            file: filePath,
            lineStart: lineNum,
            lineEnd: lineNum,
            colStart: 0,
            colEnd: line.length,
          },
          line
        );
        
        graph.addNode(controlNode);
        
        // Connect to parent block
        if (currentBlock) {
          graph.addEdge(this.createEdge('AST_PARENT', currentBlock.id, controlNode.id));
          graph.addEdge(this.createEdge('CFG_NEXT', currentBlock.id, controlNode.id));
        }
        
        currentBlock = controlNode;
        blockStack.push(controlNode);
        braceDepth++;
      }
      
      // Track brace depth for block scoping
      braceDepth += (line.match(/{/g) || []).length;
      braceDepth -= (line.match(/}/g) || []).length;
      
      if (braceDepth < blockStack.length && blockStack.length > 0) {
        blockStack.pop();
        currentBlock = blockStack[blockStack.length - 1] || currentFunction;
      }
      
      // Detect function calls (potential sinks)
      const callMatches = this.matchFunctionCalls(line, ext);
      for (const call of callMatches) {
        const callNode = this.createNode('CALL', call.name, {
          file: filePath,
          lineStart: lineNum,
          lineEnd: lineNum,
          colStart: 0,
          colEnd: line.length,
        }, line);
        
        // Mark as sink if it's a sensitive operation
        if (this.isSensitiveSink(call.name)) {
          callNode.properties.isSink = true;
          callNode.properties.sinkType = this.classifySinkType(call.name);
        }
        
        graph.addNode(callNode);
        
        // Connect to current block
        if (currentBlock) {
          graph.addEdge(this.createEdge('AST_PARENT', currentBlock.id, callNode.id));
        }
        
        // Add arguments
        for (let j = 0; j < call.args.length; j++) {
          const arg = call.args[j];
          const argNode = this.createNode('ARGUMENT', `arg${j}`, {
            file: filePath,
            lineStart: lineNum,
            lineEnd: lineNum,
            colStart: 0,
            colEnd: line.length,
          }, arg);
          
          graph.addNode(argNode);
          graph.addEdge(this.createEdge('ARGUMENT_OF', argNode.id, callNode.id));
          
          // Create data flow from variables to arguments
          const vars = this.extractVariables(arg);
          for (const varName of vars) {
            // Try to find definition of this variable
            const defNode = this.findVariableDefinition(graph, varName, lineNum);
            if (defNode) {
              graph.addEdge(this.createEdge('DATA_FLOW', defNode.id, argNode.id));
            }
          }
        }
      }
      
      // Detect variable assignments
      const assignMatch = line.match(/(?:const|let|var)?\s*(\w+)\s*=\s*(.+?)(?:;|$)/);
      if (assignMatch) {
        const varName = assignMatch[1];
        const value = assignMatch[2];
        
        const assignNode = this.createNode('ASSIGNMENT', `${varName} = ...`, {
          file: filePath,
          lineStart: lineNum,
          lineEnd: lineNum,
          colStart: 0,
          colEnd: line.length,
        }, line);
        
        graph.addNode(assignNode);
        
        if (currentBlock) {
          graph.addEdge(this.createEdge('AST_PARENT', currentBlock.id, assignNode.id));
        }
        
        // Check if RHS contains user input
        if (this.isUserInputSource(value)) {
          assignNode.properties.isSource = true;
          assignNode.properties.sourceType = 'USER_INPUT';
        }
        
        // Check if RHS contains sanitization
        if (this.isSanitization(value)) {
          assignNode.properties.isSanitized = true;
          assignNode.properties.sanitizerType = this.classifySanitizer(value);
        }
      }
      
      // Detect return statements
      if (line.trim().startsWith('return')) {
        const returnNode = this.createNode('RETURN', 'return', {
          file: filePath,
          lineStart: lineNum,
          lineEnd: lineNum,
          colStart: 0,
          colEnd: line.length,
        }, line);
        
        returnNode.isExitPoint = true;
        graph.addNode(returnNode);
        
        if (currentBlock) {
          graph.addEdge(this.createEdge('AST_PARENT', currentBlock.id, returnNode.id));
        }
        if (currentFunction) {
          graph.addEdge(this.createEdge('CFG_NEXT', returnNode.id, currentFunction.id));
        }
      }
    }
    
    return graph;
  }
  
  /**
   * Build CPGs from multiple files
   */
  buildFromProject(projectPath: string, files: Array<{ path: string; content: string }>): CodePropertyGraph[] {
    return files.map(file => this.buildFromFile(file.path, file.content));
  }
  
  private createNode(
    type: NodeType,
    label: string,
    location: SourceLocation,
    code: string,
    signature?: string
  ): CPGNode {
    this.nodeCounter++;
    return {
      id: `node_${this.nodeCounter}`,
      type,
      label,
      location,
      properties: {},
      code: code.trim(),
      signature,
      fullName: signature,
    };
  }
  
  private createEdge(type: EdgeType, from: string, to: string): CPGEdge {
    this.edgeCounter++;
    return {
      id: `edge_${this.edgeCounter}`,
      type,
      from,
      to,
    };
  }
  
  private detectLanguage(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase() || '';
    const langMap: Record<string, string> = {
      'js': 'javascript',
      'ts': 'typescript',
      'jsx': 'javascript',
      'tsx': 'typescript',
      'py': 'python',
      'java': 'java',
      'go': 'go',
      'rb': 'ruby',
      'php': 'php',
      'cs': 'csharp',
      'cpp': 'cpp',
      'c': 'c',
      'rs': 'rust',
    };
    return langMap[ext] || 'unknown';
  }
  
  private matchFunctionDefinition(line: string, ext: string): {
    name: string;
    params: string[];
    signature: string;
    isEntryPoint: boolean;
  } | null {
    // JavaScript/TypeScript
    const jsMatch = line.match(/(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/);
    if (jsMatch) {
      const params = jsMatch[2].split(',').map(p => p.trim()).filter(p => p);
      return {
        name: jsMatch[1],
        params,
        signature: line.trim(),
        isEntryPoint: this.isEntryPointFunction(jsMatch[1]),
      };
    }
    
    // Arrow functions with exports (handlers)
    const arrowMatch = line.match(/export\s+(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/);
    if (arrowMatch) {
      const params = arrowMatch[2].split(',').map(p => p.trim()).filter(p => p);
      return {
        name: arrowMatch[1],
        params,
        signature: line.trim(),
        isEntryPoint: this.isEntryPointFunction(arrowMatch[1]),
      };
    }
    
    // Method definitions
    const methodMatch = line.match(/(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*{/);
    if (methodMatch && !['if', 'while', 'for', 'switch', 'catch'].includes(methodMatch[1])) {
      const params = methodMatch[2].split(',').map(p => p.trim()).filter(p => p);
      return {
        name: methodMatch[1],
        params,
        signature: line.trim(),
        isEntryPoint: false,
      };
    }
    
    // Python
    const pyMatch = line.match(/def\s+(\w+)\s*\(([^)]*)\)/);
    if (pyMatch) {
      const params = pyMatch[2].split(',').map(p => p.trim()).filter(p => p && p !== 'self');
      return {
        name: pyMatch[1],
        params,
        signature: line.trim(),
        isEntryPoint: this.isEntryPointFunction(pyMatch[1]),
      };
    }
    
    return null;
  }
  
  private isEntryPointFunction(name: string): boolean {
    const entryPoints = [
      'handler', 'main', 'app', 'server', 'router',
      'get', 'post', 'put', 'delete', 'patch',
      'onRequest', 'onEvent', 'trigger',
      'lambda_handler', 'cloud_function',
    ];
    return entryPoints.some(ep => name.toLowerCase().includes(ep));
  }
  
  private matchControlStructure(line: string): { type: string; label: string } | null {
    const trimmed = line.trim();
    
    if (trimmed.startsWith('if')) {
      return { type: 'IF', label: 'if' };
    }
    if (trimmed.startsWith('for')) {
      return { type: 'FOR', label: 'for' };
    }
    if (trimmed.startsWith('while')) {
      return { type: 'WHILE', label: 'while' };
    }
    if (trimmed.startsWith('try')) {
      return { type: 'TRY', label: 'try' };
    }
    if (trimmed.startsWith('catch')) {
      return { type: 'CATCH', label: 'catch' };
    }
    
    return null;
  }
  
  private matchFunctionCalls(line: string, ext: string): Array<{ name: string; args: string[] }> {
    const calls: Array<{ name: string; args: string[] }> = [];
    
    // Match function calls: name(args)
    const callRegex = /(\w+)\s*\(([^)]*)\)/g;
    let match;
    
    while ((match = callRegex.exec(line)) !== null) {
      const name = match[1];
      const argsStr = match[2];
      const args = argsStr.split(',').map(a => a.trim()).filter(a => a);
      
      calls.push({ name, args });
    }
    
    return calls;
  }
  
  private isSensitiveSink(name: string): boolean {
    const sinks = [
      'query', 'exec', 'execute', 'run',
      'eval', 'execScript', 'Function',
      'innerHTML', 'outerHTML', 'document.write',
      'fetch', 'axios', 'request',
      'readFile', 'writeFile', 'appendFile',
      'spawn', 'execSync', 'execFile',
      'open', 'popen', 'system',
    ];
    return sinks.some(s => name.toLowerCase().includes(s.toLowerCase()));
  }
  
  private classifySinkType(name: string): string {
    const lower = name.toLowerCase();
    if (lower.includes('query') || lower.includes('exec') && lower.includes('sql')) {
      return 'SQL_EXECUTION';
    }
    if (lower.includes('eval') || lower.includes('exec')) {
      return 'COMMAND_EXECUTION';
    }
    if (lower.includes('html') || lower.includes('write')) {
      return 'HTML_RENDERING';
    }
    if (lower.includes('fetch') || lower.includes('axios') || lower.includes('request')) {
      return 'HTTP_REQUEST';
    }
    if (lower.includes('file') || lower.includes('read') || lower.includes('write')) {
      return 'FILE_OPERATION';
    }
    return 'OTHER';
  }
  
  private isUserInputSource(value: string): boolean {
    const patterns = [
      /req\./,
      /request\./,
      /params/,
      /query/,
      /body/,
      /input/,
      /prompt/,
      /argv/,
      /process\.env/,
    ];
    return patterns.some(p => p.test(value));
  }
  
  private isSanitization(value: string): boolean {
    const sanitizers = [
      'escape', 'encode', 'sanitize', 'validate',
      'strip', 'clean', 'purify', 'filter',
      'parseInt', 'parseFloat', 'Number(',
      'DOMPurify', 'he.encode',
    ];
    return sanitizers.some(s => value.includes(s));
  }
  
  private classifySanitizer(value: string): string {
    if (value.includes('escape') || value.includes('encode')) {
      return 'ENCODING';
    }
    if (value.includes('validate') || value.includes('check')) {
      return 'VALIDATION';
    }
    if (value.includes('sanitize') || value.includes('clean')) {
      return 'SANITIZATION';
    }
    if (value.includes('parseInt') || value.includes('parseFloat') || value.includes('Number(')) {
      return 'TYPE_CONVERSION';
    }
    return 'GENERAL';
  }
  
  private extractVariables(code: string): string[] {
    const vars: string[] = [];
    const regex = /\b([a-zA-Z_][a-zA-Z0-9_]*)\b/g;
    let match;
    
    while ((match = regex.exec(code)) !== null) {
      const word = match[1];
      // Filter out keywords
      if (![
        'if', 'else', 'for', 'while', 'return', 'function', 'const', 'let', 'var',
        'async', 'await', 'try', 'catch', 'throw', 'new', 'this', 'true', 'false', 'null',
      ].includes(word)) {
        vars.push(word);
      }
    }
    
    return [...new Set(vars)];
  }
  
  private findVariableDefinition(graph: CodePropertyGraph, varName: string, beforeLine: number): CPGNode | null {
    const assignments = graph.getAllNodes().filter(n => 
      n.type === 'ASSIGNMENT' && 
      n.code.includes(varName) &&
      n.location.lineStart < beforeLine
    );
    
    // Return the most recent assignment
    assignments.sort((a, b) => b.location.lineStart - a.location.lineStart);
    return assignments[0] || null;
  }
}
