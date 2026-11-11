// ============================================================================
// dependency-resolver.js - Directed Acyclic Graph (DAG) Order Resolver
// Topological sort with cycle detection
// ============================================================================

class DependencyResolver {
    constructor() {
        this.nodes = new Map();
    }

    addModule(moduleName, dependenciesArray = []) {
        if (!this.nodes.has(moduleName)) {
            this.nodes.set(moduleName, new Set());
        }
        dependenciesArray.forEach(dep => {
            this.nodes.get(moduleName).add(dep);
            if (!this.nodes.has(dep)) {
                this.nodes.set(dep, new Set());
            }
        });
    }

    resolveExecutionOrder() {
        const visited = new Set();
        const stack = new Set();
        const order = [];

        const visit = (node) => {
            if (stack.has(node)) {
                throw new Error(`Circular dependency detected: "${node}"`);
            }
            if (!visited.has(node)) {
                stack.add(node);
                const deps = this.nodes.get(node) || new Set();
                deps.forEach(dep => visit(dep));
                stack.delete(node);
                visited.add(node);
                order.push(node);
            }
        };

        for (const node of this.nodes.keys()) {
            visit(node);
        }

        return order;
    }

    getDependencies(moduleName) {
        return Array.from(this.nodes.get(moduleName) || []);
    }

    getDependents(moduleName) {
        const dependents = [];
        for (const [node, deps] of this.nodes) {
            if (deps.has(moduleName)) dependents.push(node);
        }
        return dependents;
    }

    toGraph() {
        const graph = {};
        for (const [node, deps] of this.nodes) {
            graph[node] = Array.from(deps);
        }
        return graph;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = DependencyResolver;
} else if (typeof window !== 'undefined') {
    window.DependencyResolver = DependencyResolver;
}
