#!/usr/bin/env python3
"""
Codebase Graph Generator
Analyzes the AI-IDS codebase and generates dependency graphs
"""

import os
import ast
import json
import networkx as nx
from pathlib import Path
from collections import defaultdict
import pydot

class CodebaseAnalyzer:
    def __init__(self, root_path):
        self.root_path = Path(root_path)
        self.graph = nx.DiGraph()
        self.modules = {}
        self.imports = defaultdict(set)
        self.classes = defaultdict(list)
        self.functions = defaultdict(list)
        
    def analyze(self):
        """Analyze entire codebase"""
        print("[*] Scanning codebase...")
        self._scan_python_files()
        print(f"[+] Found {len(self.modules)} Python modules")
        
        print("[*] Analyzing imports...")
        self._analyze_imports()
        print(f"[+] Found {len(self.imports)} import relationships")
        
        print("[*] Building graph...")
        self._build_graph()
        
        return self.graph
    
    def _scan_python_files(self):
        """Scan all Python files in codebase"""
        for py_file in self.root_path.rglob("*.py"):
            # Skip __pycache__ and test files
            if "__pycache__" in str(py_file):
                continue
            
            rel_path = py_file.relative_to(self.root_path)
            module_name = str(rel_path).replace("\\", "/").replace(".py", "").replace("/", ".")
            
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    tree = ast.parse(content)
                    
                    self.modules[module_name] = {
                        "path": str(rel_path),
                        "size": len(content),
                        "lines": len(content.split('\n')),
                        "classes": [],
                        "functions": [],
                        "imports": []
                    }
                    
                    # Extract classes and functions
                    for node in ast.walk(tree):
                        if isinstance(node, ast.ClassDef):
                            self.modules[module_name]["classes"].append(node.name)
                            self.classes[module_name].append(node.name)
                        elif isinstance(node, ast.FunctionDef):
                            self.modules[module_name]["functions"].append(node.name)
                            self.functions[module_name].append(node.name)
                    
                    # Extract imports
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                self.modules[module_name]["imports"].append(alias.name)
                                self.imports[module_name].add(alias.name)
                        elif isinstance(node, ast.ImportFrom):
                            if node.module:
                                self.modules[module_name]["imports"].append(node.module)
                                self.imports[module_name].add(node.module)
            except Exception as e:
                print(f"[!] Error analyzing {py_file}: {e}")
    
    def _analyze_imports(self):
        """Analyze import relationships"""
        for module, imports in self.imports.items():
            for imp in imports:
                # Only track internal imports
                if any(imp.startswith(prefix) for prefix in ["ai_architecture", "attacker", "decoder", "database", "network", "validation", "threat_intelligence", "cnn", "rnn"]):
                    self.graph.add_edge(module, imp)
    
    def _build_graph(self):
        """Build dependency graph"""
        for module in self.modules:
            self.graph.add_node(module, **self.modules[module])
        
        for source, targets in self.imports.items():
            for target in targets:
                if target in self.modules:
                    self.graph.add_edge(source, target)
    
    def export_json(self, output_path):
        """Export graph as JSON"""
        data = {
            "modules": self.modules,
            "imports": {k: list(v) for k, v in self.imports.items()},
            "classes": {k: v for k, v in self.classes.items()},
            "functions": {k: v for k, v in self.functions.items()},
            "graph": {
                "nodes": list(self.graph.nodes()),
                "edges": list(self.graph.edges())
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Exported JSON graph to {output_path}")
    
    def export_dot(self, output_path):
        """Export graph as DOT format"""
        dot_graph = pydot.Dot(graph_type='digraph', rankdir='LR')
        dot_graph.set_node_defaults(shape='box', style='rounded,filled', fillcolor='lightblue')
        
        # Add nodes with colors based on module type
        for node in self.graph.nodes():
            if "attacker" in node:
                color = "lightcoral"
            elif "decoder" in node:
                color = "lightgreen"
            elif "database" in node:
                color = "lightyellow"
            elif "network" in node:
                color = "lightcyan"
            elif "validation" in node:
                color = "plum"
            elif "threat_intelligence" in node:
                color = "peachpuff"
            else:
                color = "lightblue"
            
            dot_node = pydot.Node(node, fillcolor=color)
            dot_graph.add_node(dot_node)
        
        # Add edges
        for source, target in self.graph.edges():
            dot_graph.add_edge(pydot.Edge(source, target))
        
        dot_graph.write_raw(output_path)
        print(f"[+] Exported DOT graph to {output_path}")
    
    def export_svg(self, output_path):
        """Export graph as SVG"""
        try:
            dot_graph = pydot.Dot(graph_type='digraph', rankdir='LR')
            dot_graph.set_node_defaults(shape='box', style='rounded,filled', fillcolor='lightblue')
            
            for node in self.graph.nodes():
                if "attacker" in node:
                    color = "lightcoral"
                elif "decoder" in node:
                    color = "lightgreen"
                elif "database" in node:
                    color = "lightyellow"
                elif "network" in node:
                    color = "lightcyan"
                elif "validation" in node:
                    color = "plum"
                elif "threat_intelligence" in node:
                    color = "peachpuff"
                else:
                    color = "lightblue"
                
                dot_node = pydot.Node(node, fillcolor=color, fontsize='10')
                dot_graph.add_node(dot_node)
            
            for source, target in self.graph.edges():
                dot_graph.add_edge(pydot.Edge(source, target, fontsize='8'))
            
            dot_graph.write_svg(output_path)
            print(f"[+] Exported SVG graph to {output_path}")
        except Exception as e:
            print(f"[!] SVG export skipped (graphviz not installed): {e}")
    
    def print_stats(self):
        """Print codebase statistics"""
        print("\n" + "="*60)
        print("CODEBASE STATISTICS")
        print("="*60)
        
        total_lines = sum(m["lines"] for m in self.modules.values())
        total_classes = sum(len(c) for c in self.classes.values())
        total_functions = sum(len(f) for f in self.functions.values())
        
        print(f"Total Modules: {len(self.modules)}")
        print(f"Total Lines of Code: {total_lines:,}")
        print(f"Total Classes: {total_classes}")
        print(f"Total Functions: {total_functions}")
        print(f"Total Import Relationships: {len(self.imports)}")
        print(f"Graph Nodes: {self.graph.number_of_nodes()}")
        print(f"Graph Edges: {self.graph.number_of_edges()}")
        
        print("\n" + "="*60)
        print("TOP MODULES BY SIZE")
        print("="*60)
        
        sorted_modules = sorted(self.modules.items(), key=lambda x: x[1]["lines"], reverse=True)
        for module, info in sorted_modules[:10]:
            print(f"{module:50} {info['lines']:6} lines")
        
        print("\n" + "="*60)
        print("MODULE DEPENDENCIES")
        print("="*60)
        
        for module in sorted(self.modules.keys()):
            if self.imports[module]:
                print(f"\n{module}:")
                for imp in sorted(self.imports[module]):
                    print(f"  → {imp}")


def main():
    import sys
    
    root_path = Path(__file__).parent.parent
    
    print("[*] AI-IDS Codebase Graph Generator")
    print(f"[*] Analyzing: {root_path}")
    
    analyzer = CodebaseAnalyzer(root_path)
    graph = analyzer.analyze()
    
    # Create output directory
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)
    
    # Export in multiple formats
    analyzer.export_json(output_dir / "codebase_graph.json")
    analyzer.export_dot(output_dir / "codebase_graph.dot")
    analyzer.export_svg(output_dir / "codebase_graph.svg")
    
    # Print statistics
    analyzer.print_stats()
    
    print("\n[+] Graph generation complete!")
    print(f"[+] Output files in: {output_dir}")


if __name__ == "__main__":
    main()
