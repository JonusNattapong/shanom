// Copyright (C) 2025 JonusNattapong
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Code Property Graph (CPG) Data Models
 * 
 * CPG combines Abstract Syntax Tree (AST), Control Flow Graph (CFG),
 * and Program Dependence Graph (PDG) into a unified property graph.
 * 
 * References:
 * - Yamaguchi et al. "Modeling and Discovering Vulnerabilities with Code Property Graphs"
 * - https://docs.joern.io/cpg-spec/
 */

export type NodeType = 
  // AST Nodes
  | 'FILE' | 'NAMESPACE' | 'PACKAGE' | 'CLASS' | 'INTERFACE' | 'TRAIT'
  | 'METHOD' | 'FUNCTION' | 'CONSTRUCTOR' | 'DESTRUCTOR'
  | 'PARAMETER' | 'LOCAL' | 'FIELD' | 'MEMBER'
  | 'BLOCK' | 'IF' | 'ELSE' | 'WHILE' | 'FOR' | 'FOREACH'
  | 'TRY' | 'CATCH' | 'FINALLY' | 'THROW' | 'RETURN'
  | 'CALL' | 'ARGUMENT' | 'LITERAL' | 'IDENTIFIER'
  | 'BINARY_OP' | 'UNARY_OP' | 'ASSIGNMENT' | 'INDEX_ACCESS'
  // Control Flow
  | 'CFG_ENTRY' | 'CFG_EXIT' | 'CFG_NODE'
  // Data Flow
  | 'SOURCE' | 'SINK' | 'SANITIZER' | 'VALIDATOR'
  // Program Dependence
  | 'PDG_DATA_DEP' | 'PDG_CONTROL_DEP';

export type EdgeType =
  // AST Edges
  | 'AST_PARENT' | 'AST_CHILD'
  | 'CONTAINS' | 'DECLARED_IN' | 'DEFINED_BY'
  // Control Flow Edges
  | 'CFG_NEXT' | 'CFG_PREV' | 'CFG_TRUE' | 'CFG_FALSE'
  | 'CFG_ENTRY' | 'CFG_EXIT' | 'CFG_JUMP'
  // Data Flow Edges
  | 'DATA_FLOW' | 'DEF' | 'USE' | 'REACHES'
  | 'TAINTED_BY' | 'SANITIZED_BY' | 'VALIDATED_BY'
  // Call Graph Edges
  | 'CALLS' | 'CALLED_BY' | 'ARGUMENT_OF' | 'RECEIVER_OF'
  // Type/Structural Edges
  | 'INHERITS_FROM' | 'IMPLEMENTS' | 'OVERRIDES'
  | 'REFERS_TO' | 'ASSIGNED_TO' | 'READ_FROM';

export interface CPGNode {
  /** Unique identifier for this node */
  id: string;
  
  /** Node type classification */
  type: NodeType;
  
  /** Human-readable label */
  label: string;
  
  /** Source code location */
  location: SourceLocation;
  
  /** Language-specific properties */
  properties: Record<string, unknown>;
  
  /** Code snippet at this node */
  code: string;
  
  /** Signature for methods/functions */
  signature?: string;
  
  /** Full qualified name */
  fullName?: string;
  
  /** Is this a control structure? */
  isControlStructure?: boolean;
  
  /** Is this an entry/exit point? */
  isEntryPoint?: boolean;
  isExitPoint?: boolean;
}

export interface SourceLocation {
  /** File path */
  file: string;
  
  /** Line number (1-indexed) */
  lineStart: number;
  lineEnd: number;
  
  /** Column number (0-indexed) */
  colStart: number;
  colEnd: number;
}

export interface CPGEdge {
  /** Unique identifier */
  id: string;
  
  /** Edge type */
  type: EdgeType;
  
  /** Source node ID */
  from: string;
  
  /** Target node ID */
  to: string;
  
  /** Additional properties */
  properties?: Record<string, unknown>;
}

export interface DataFlowFact {
  /** Variable/identifier being tracked */
  variable: string;
  
  /** Node where this fact was established */
  nodeId: string;
  
  /** Type of data flow fact */
  factType: 'DEF' | 'USE' | 'TAINT' | 'SANITIZE' | 'VALIDATE';
  
  /** Confidence level (0-1) */
  confidence: number;
  
  /** Is this a source of untrusted data? */
  isSource?: boolean;
  
  /** Is this a sink for sensitive operations? */
  isSink?: boolean;
  
  /** Is this data sanitized/validated? */
  isSanitized?: boolean;
  
  /** Sanitization methods applied */
  sanitizers?: string[];
}

export interface TaintPropagation {
  /** Source node (where untrusted data enters) */
  source: CPGNode;
  
  /** Sink node (where data could cause harm) */
  sink: CPGNode;
  
  /** Path through the graph */
  path: string[]; // Node IDs
  
  /** Data flow facts along the path */
  facts: DataFlowFact[];
  
  /** Is the path sanitized? */
  isSanitized: boolean;
  
  /** Sanitization nodes encountered */
  sanitizationNodes: CPGNode[];
  
  /** Confidence score (0-1) */
  confidence: number;
}

export class CodePropertyGraph {
  private nodes: Map<string, CPGNode> = new Map();
  private edges: Map<string, CPGEdge> = new Map();
  private adjacencyList: Map<string, Set<string>> = new Map();
  private reverseAdjacency: Map<string, Set<string>> = new Map();
  
  constructor(public readonly language: string, public readonly filePath: string) {}
  
  addNode(node: CPGNode): void {
    this.nodes.set(node.id, node);
    if (!this.adjacencyList.has(node.id)) {
      this.adjacencyList.set(node.id, new Set());
      this.reverseAdjacency.set(node.id, new Set());
    }
  }
  
  addEdge(edge: CPGEdge): void {
    this.edges.set(edge.id, edge);
    this.adjacencyList.get(edge.from)?.add(edge.to);
    this.reverseAdjacency.get(edge.to)?.add(edge.from);
  }
  
  getNode(id: string): CPGNode | undefined {
    return this.nodes.get(id);
  }
  
  getEdge(id: string): CPGEdge | undefined {
    return this.edges.get(id);
  }
  
  getSuccessors(nodeId: string): CPGNode[] {
    const successorIds = this.adjacencyList.get(nodeId) || new Set();
    return Array.from(successorIds)
      .map(id => this.nodes.get(id))
      .filter((n): n is CPGNode => n !== undefined);
  }
  
  getPredecessors(nodeId: string): CPGNode[] {
    const predecessorIds = this.reverseAdjacency.get(nodeId) || new Set();
    return Array.from(predecessorIds)
      .map(id => this.nodes.get(id))
      .filter((n): n is CPGNode => n !== undefined);
  }
  
  getEdgesFrom(nodeId: string): CPGEdge[] {
    return Array.from(this.edges.values()).filter(e => e.from === nodeId);
  }
  
  getEdgesTo(nodeId: string): CPGEdge[] {
    return Array.from(this.edges.values()).filter(e => e.to === nodeId);
  }
  
  getAllNodes(): CPGNode[] {
    return Array.from(this.nodes.values());
  }
  
  getAllEdges(): CPGEdge[] {
    return Array.from(this.edges.values());
  }
  
  getNodesByType(type: NodeType): CPGNode[] {
    return this.getAllNodes().filter(n => n.type === type);
  }
  
  getCallSites(): CPGNode[] {
    return this.getAllNodes().filter(n => 
      n.type === 'CALL' || n.type === 'METHOD' || n.type === 'FUNCTION'
    );
  }
  
  getEntryPoints(): CPGNode[] {
    return this.getAllNodes().filter(n => n.isEntryPoint);
  }
  
  getExitPoints(): CPGNode[] {
    return this.getAllNodes().filter(n => n.isExitPoint);
  }
  
  /**
   * Find data flow paths from sources to sinks
   */
  findDataFlowPaths(
    sourcePredicates: ((node: CPGNode) => boolean)[],
    sinkPredicates: ((node: CPGNode) => boolean)[]
  ): TaintPropagation[] {
    const sources = this.getAllNodes().filter(n => 
      sourcePredicates.some(pred => pred(n))
    );
    const sinks = this.getAllNodes().filter(n => 
      sinkPredicates.some(pred => pred(n))
    );
    
    const paths: TaintPropagation[] = [];
    
    for (const source of sources) {
      for (const sink of sinks) {
        const path = this.findPath(source.id, sink.id, ['DATA_FLOW', 'DEF', 'USE']);
        if (path.length > 0) {
          paths.push({
            source,
            sink,
            path: path.map(n => n.id),
            facts: [], // Would be populated by data flow analysis
            isSanitized: false, // Would be determined by sanitizer detection
            sanitizationNodes: [],
            confidence: 1.0,
          });
        }
      }
    }
    
    return paths;
  }
  
  /**
   * Find path between two nodes using specific edge types
   */
  private findPath(
    startId: string, 
    endId: string, 
    allowedEdgeTypes: EdgeType[]
  ): CPGNode[] {
    // BFS to find shortest path
    const queue: { nodeId: string; path: string[] }[] = [{ nodeId: startId, path: [startId] }];
    const visited = new Set<string>([startId]);
    
    while (queue.length > 0) {
      const { nodeId, path } = queue.shift()!;
      
      if (nodeId === endId) {
        return path.map(id => this.nodes.get(id)).filter((n): n is CPGNode => n !== undefined);
      }
      
      const outgoingEdges = this.getEdgesFrom(nodeId)
        .filter(e => allowedEdgeTypes.includes(e.type));
      
      for (const edge of outgoingEdges) {
        if (!visited.has(edge.to)) {
          visited.add(edge.to);
          queue.push({ nodeId: edge.to, path: [...path, edge.to] });
        }
      }
    }
    
    return [];
  }
  
  /**
   * Get control flow successors (next executable statements)
   */
  getControlFlowSuccessors(nodeId: string): CPGNode[] {
    const cfgEdges = this.getEdgesFrom(nodeId)
      .filter(e => e.type.startsWith('CFG_'));
    return cfgEdges
      .map(e => this.nodes.get(e.to))
      .filter((n): n is CPGNode => n !== undefined);
  }
  
  /**
   * Get data dependencies for a node
   */
  getDataDependencies(nodeId: string): CPGNode[] {
    const dataEdges = this.getEdgesTo(nodeId)
      .filter(e => ['DATA_FLOW', 'DEF', 'REACHES'].includes(e.type));
    return dataEdges
      .map(e => this.nodes.get(e.from))
      .filter((n): n is CPGNode => n !== undefined);
  }
  
  /**
   * Export graph to DOT format for visualization
   */
  toDotFormat(): string {
    const lines = ['digraph CPG {'];
    lines.push('  rankdir=TB;');
    lines.push('  node [shape=box, style=filled];');
    
    // Add nodes
    for (const node of this.getAllNodes()) {
      const color = this.getNodeColor(node.type);
      const label = node.label.replace(/"/g, '\\"');
      lines.push(`  "${node.id}" [label="${label}\\n${node.type}", fillcolor="${color}"];`);
    }
    
    // Add edges
    for (const edge of this.getAllEdges()) {
      const color = this.getEdgeColor(edge.type);
      lines.push(`  "${edge.from}" -> "${edge.to}" [label="${edge.type}", color="${color}"];`);
    }
    
    lines.push('}');
    return lines.join('\n');
  }
  
  private getNodeColor(type: NodeType): string {
    const colors: Record<string, string> = {
      'METHOD': 'lightblue',
      'FUNCTION': 'lightblue',
      'CALL': 'yellow',
      'IF': 'lightgreen',
      'FOR': 'lightgreen',
      'WHILE': 'lightgreen',
      'LITERAL': 'orange',
      'IDENTIFIER': 'white',
      'SOURCE': 'red',
      'SINK': 'darkred',
      'SANITIZER': 'green',
    };
    return colors[type] || 'lightgray';
  }
  
  private getEdgeColor(type: EdgeType): string {
    const colors: Record<string, string> = {
      'DATA_FLOW': 'blue',
      'CFG_NEXT': 'black',
      'CALLS': 'purple',
      'AST_PARENT': 'gray',
    };
    return colors[type] || 'black';
  }
}

/**
 * CPG Builder interface - implemented per language
 */
export interface CPGBuilder {
  readonly language: string;
  readonly supportedExtensions: string[];
  
  buildFromFile(filePath: string, content: string): Promise<CodePropertyGraph>;
  buildFromProject(projectPath: string): Promise<CodePropertyGraph[]>;
}

/**
 * Source/Sink patterns for vulnerability detection
 */
export interface SourceSinkPattern {
  vulnerabilityType: string;
  sources: Array<{
    pattern: RegExp | string;
    nodeTypes: NodeType[];
    description: string;
  }>;
  sinks: Array<{
    pattern: RegExp | string;
    nodeTypes: NodeType[];
    description: string;
  }>;
  sanitizers?: Array<{
    pattern: RegExp | string;
    nodeTypes: NodeType[];
    description: string;
  }>;
}
