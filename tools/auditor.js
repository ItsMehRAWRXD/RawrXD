// ============================================================================
// auditor.js - AgenticAuditor v2
// Static analysis: HTML, JS, CSS, Electron, Runtime, Panel passes
// ============================================================================

const fs = require('fs');
const path = require('path');

class AgenticAuditor {
    constructor(projectRoot) {
        this.root = projectRoot;
        this.errors = [];
        this.warnings = [];
        this.stats = { htmlChecked: 0, jsChecked: 0, cssChecked: 0 };
    }

    auditAll() {
        console.log('=== AgenticAuditor v2: Project-Wide Validation ===\n');
        this.scanDirectory(this.root);
        this.printReport();
        return this.errors.length === 0;
    }

    scanDirectory(dir) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
                this.scanDirectory(fullPath);
            } else if (entry.isFile()) {
                if (entry.name.endsWith('.html')) this.auditHTML(fullPath);
                if (entry.name.endsWith('.js')) this.auditJS(fullPath);
                if (entry.name.endsWith('.css')) this.auditCSS(fullPath);
            }
        }
    }

    // --- HTML Pass ---
    auditHTML(filePath) {
        this.stats.htmlChecked++;
        const content = fs.readFileSync(filePath, 'utf-8');

        // Duplicate IDs
        const idRegex = /id=["']([^"']+)["']/g;
        const ids = [];
        let match;
        while ((match = idRegex.exec(content)) !== null) {
            if (ids.includes(match[1])) {
                this.errors.push({ file: filePath, type: 'HTML', severity: 'error', detail: `Duplicate DOM ID: "${match[1]}"` });
            }
            ids.push(match[1]);
        }

        // Inline onclick
        if (/onclick\s*=\s*["']/.test(content)) {
            this.errors.push({ file: filePath, type: 'Anti-Pattern', severity: 'error', detail: 'Inline onclick handlers found. Use EventBus instead.' });
        }

        // Missing IDs on interactive elements
        const interactiveTags = content.match(/<(button|input|select|textarea|a)\b[^>]*>/g);
        if (interactiveTags) {
            for (const tag of interactiveTags) {
                if (!/id\s*=\s*["']/.test(tag)) {
                    this.warnings.push({ file: filePath, type: 'HTML', severity: 'warning', detail: `Interactive element missing id: ${tag.substring(0, 40)}` });
                }
            }
        }

        // Orphan buttons (not inside a form or nav)
        if (/<button[^>]*>[\s\S]*?<\/button>/g.test(content)) {
            // Check if inside a form or nav
            const buttonBlocks = content.match(/<button[^>]*>[\s\S]*?<\/button>/g) || [];
            for (const btn of buttonBlocks) {
                if (!content.includes('<form') && !content.includes('<nav')) {
                    this.warnings.push({ file: filePath, type: 'HTML', severity: 'warning', detail: 'Orphan button outside form/nav' });
                    break;
                }
            }
        }

        // Missing CSS/JS references
        if (!content.includes('<link rel="stylesheet"') && !content.includes('<style')) {
            this.warnings.push({ file: filePath, type: 'HTML', severity: 'warning', detail: 'No CSS reference found' });
        }
        if (!content.includes('<script')) {
            this.warnings.push({ file: filePath, type: 'HTML', severity: 'warning', detail: 'No script reference found' });
        }
    }

    // --- JS Pass ---
    auditJS(filePath) {
        this.stats.jsChecked++;
        const content = fs.readFileSync(filePath, 'utf-8');

        // Unsafe require('electron') outside preload/main
        if (/require\s*\(\s*['"]electron['"]\s*\)/.test(content) &&
            !filePath.includes('preload') && !filePath.includes('main')) {
            this.errors.push({ file: filePath, type: 'Security', severity: 'error', detail: 'Unsafe require("electron") outside boundary layer' });
        }

        // Direct getElementById bypassing Runtime
        if (/document\.getElementById\s*\(/.test(content)) {
            this.errors.push({ file: filePath, type: 'Architecture', severity: 'error', detail: 'Direct getElementById. Use RawrRuntime.requireElement instead.' });
        }

        // Undefined variables check (basic)
        const varDeclarations = content.match(/(?:var|let|const)\s+(\w+)/g) || [];
        const declared = new Set(varDeclarations.map(v => v.split(/\s+/)[1]));
        const refs = content.match(/\b(\w+)\s*(?=\()/g) || [];
        for (const ref of refs) {
            const name = ref.trim();
            if (name.length > 1 && !declared.has(name) &&
                !['if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'typeof',
                  'new', 'delete', 'throw', 'else', 'case', 'break', 'continue', 'in',
                  'of', 'class', 'import', 'export', 'from', 'async', 'await', 'yield',
                  'this', 'super', 'window', 'document', 'console', 'setTimeout',
                  'setInterval', 'fetch', 'Promise', 'Array', 'Object', 'String',
                  'Number', 'Boolean', 'Math', 'Date', 'JSON', 'RegExp', 'Map', 'Set',
                  'Error', 'Symbol', 'BigInt', 'null', 'true', 'false', 'undefined',
                  'RawrRuntime', 'EventBus', 'module', 'exports', 'require', 'process',
                  'Buffer', '__dirname', '__filename'].includes(name)) {
                this.warnings.push({ file: filePath, type: 'JS', severity: 'warning', detail: `Possible undefined reference: "${name}"` });
            }
        }

        // Missing imports/exports check
        if (content.includes('import ') && !content.includes('export ') && !filePath.includes('node_modules')) {
            this.warnings.push({ file: filePath, type: 'JS', severity: 'warning', detail: 'File has imports but no exports' });
        }
    }

    // --- CSS Pass ---
    auditCSS(filePath) {
        this.stats.cssChecked++;
        const content = fs.readFileSync(filePath, 'utf-8');

        // Unused animations
        const animNames = content.match(/@keyframes\s+(\w+)/g) || [];
        for (const anim of animNames) {
            const name = anim.split(/\s+/)[1];
            if (!content.includes(`animation-name: ${name}`) && !content.includes(`animation: ${name}`)) {
                this.warnings.push({ file: filePath, type: 'CSS', severity: 'warning', detail: `Unused @keyframes: "${name}"` });
            }
        }

        // Unused CSS variables
        const cssVars = content.match(/--[\w-]+/g) || [];
        for (const v of cssVars) {
            if (!content.includes(`var(${v})`)) {
                this.warnings.push({ file: filePath, type: 'CSS', severity: 'warning', detail: `Unused CSS variable: "${v}"` });
            }
        }
    }

    // --- Electron Pass ---
    auditElectron(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8');

        if (content.includes('window.electronAPI') && !filePath.includes('preload')) {
            this.errors.push({ file: filePath, type: 'Electron', severity: 'error', detail: 'Direct window.electronAPI access. Use getNativeBridge() instead.' });
        }
        if (content.includes('require(') && !filePath.includes('preload') && !filePath.includes('main')) {
            this.errors.push({ file: filePath, type: 'Electron', severity: 'error', detail: 'require() in renderer process. Use preload bridge.' });
        }
    }

    // --- Runtime Pass ---
    auditRuntime(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8');

        // Duplicate event listeners
        const addEventListenerCount = (content.match(/addEventListener/g) || []).length;
        const removeEventListenerCount = (content.match(/removeEventListener/g) || []).length;
        if (addEventListenerCount > removeEventListenerCount + 3) {
            this.warnings.push({ file: filePath, type: 'Runtime', severity: 'warning', detail: `Potential listener leak: ${addEventListenerCount} add vs ${removeEventListenerCount} remove` });
        }

        // setInterval without clearInterval
        const intervals = (content.match(/setInterval/g) || []).length;
        const clearIntervals = (content.match(/clearInterval/g) || []).length;
        if (intervals > clearIntervals) {
            this.warnings.push({ file: filePath, type: 'Runtime', severity: 'warning', detail: `Potential interval leak: ${intervals} set vs ${clearIntervals} clear` });
        }
    }

    printReport() {
        console.log('\n--- AUDIT METRICS ---');
        console.log(`  HTML: ${this.stats.htmlChecked} files`);
        console.log(`  JS:   ${this.stats.jsChecked} files`);
        console.log(`  CSS:  ${this.stats.cssChecked} files`);

        if (this.errors.length === 0 && this.warnings.length === 0) {
            console.log('\n  PASS: No issues found.');
            return;
        }

        if (this.errors.length > 0) {
            console.log(`\n  ERRORS (${this.errors.length}):`);
            this.errors.forEach(e => console.log(`    [${e.type}] ${path.relative(this.root, e.file)}: ${e.detail}`));
        }

        if (this.warnings.length > 0) {
            console.log(`\n  WARNINGS (${this.warnings.length}):`);
            this.warnings.forEach(w => console.log(`    [${w.type}] ${path.relative(this.root, w.file)}: ${w.detail}`));
        }
    }
}

module.exports = AgenticAuditor;

if (require.main === module) {
    const auditor = new AgenticAuditor(path.join(__dirname, '..'));
    const passed = auditor.auditAll();
    process.exit(passed ? 0 : 1);
}
