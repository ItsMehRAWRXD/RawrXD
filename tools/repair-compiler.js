// ============================================================================
// repair-compiler.js - Autonomous Self-Healing Compiler
// Detects issues from AgenticAuditor and auto-fixes source files
// ============================================================================

const fs = require('fs');
const path = require('path');

class SelfHealingCompiler {
    constructor(projectRoot) {
        this.root = projectRoot;
        this.repairLog = [];
    }

    executeHealingPass(issues) {
        console.log('\n=== SelfHealingCompiler: Autonomous Repair Pass ===\n');

        issues.forEach(issue => {
            try {
                if (issue.type === 'Architecture' && issue.detail.includes('document.getElementById')) {
                    this.healDOMContractBypass(issue.file);
                } else if (issue.type === 'Anti-Pattern' && issue.detail.includes('onclick=')) {
                    this.healInlineEvents(issue.file);
                } else if (issue.type === 'Security' && issue.detail.includes('require')) {
                    this.healRequireStatement(issue.file);
                }
            } catch (e) {
                console.error(`[Repair] Failed on ${issue.file}:`, e.message);
            }
        });

        this.generateReport();
    }

    healDOMContractBypass(filePath) {
        let content = fs.readFileSync(filePath, 'utf-8');
        const original = /document\.getElementById\((['"`].+?['"`])\)/g;

        if (original.test(content)) {
            content = content.replace(original, 'RawrRuntime.requireElement($1)');
            fs.writeFileSync(filePath, content, 'utf-8');
            this.repairLog.push({
                file: filePath,
                fix: 'Replaced getElementById with RawrRuntime.requireElement'
            });
        }
    }

    healInlineEvents(filePath) {
        let content = fs.readFileSync(filePath, 'utf-8');
        const inlineClickRegex = /<button([^>]+)onclick=["'](.+?)\(?(.*?)\)?["']([^>]*)>(.*?)<\/button>/g;

        if (inlineClickRegex.test(content)) {
            const injections = [];
            content = content.replace(inlineClickRegex, (match, before, funcName, args, after, innerText) => {
                const id = `rawr-auto-${Math.random().toString(36).substring(2, 7)}`;
                injections.push(`
document.addEventListener('DOMContentLoaded', () => {
    const el = document.getElementById('${id}');
    if (el) el.addEventListener('click', () => {
        if (typeof ${funcName} === 'function') ${funcName}(${args || ''});
    });
});`);
                return `<button${before} id="${id}"${after}>${innerText}</button>`;
            });

            if (injections.length > 0) {
                content += `\n<script>\n${injections.join('\n')}\n</script>`;
            }

            fs.writeFileSync(filePath, content, 'utf-8');
            this.repairLog.push({
                file: filePath,
                fix: `Decoupled ${injections.length} inline onclick handlers`
            });
        }
    }

    healRequireStatement(filePath) {
        let content = fs.readFileSync(filePath, 'utf-8');
        if (content.includes("require('electron')") || content.includes('require("electron")')) {
            content = content.replace(/require\(['"]electron['"]\)/g, 'window.electronAPI');
            fs.writeFileSync(filePath, content, 'utf-8');
            this.repairLog.push({
                file: filePath,
                fix: 'Replaced require("electron") with window.electronAPI'
            });
        }
    }

    generateReport() {
        console.log('\n--- REPAIR LOG ---');
        if (this.repairLog.length === 0) {
            console.log('No repairs needed.');
        } else {
            this.repairLog.forEach(log => {
                console.log(`[REPAIRED] ${path.relative(this.root, log.file)}:`);
                console.log(`  -> ${log.fix}`);
            });
        }
    }
}

module.exports = SelfHealingCompiler;
