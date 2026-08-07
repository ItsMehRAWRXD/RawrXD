// =======================================================================================
// Sovereign Framework - Production Quality Gate & Static Analysis Enforcement Runner
// File: D:\rawrxd\sovereign\beaconism\code-quality-gate.js
// =======================================================================================

const fs = require('fs');
const path = require('path');

const TARGET_SCAN_DIRECTORY = path.resolve('D:/rawrxd/RawrZ-Security/RawrZ-Payload-Builder/src');
let issuesDetectedCount = 0;
let filesScannedCount = 0;

const REJECTED_PATTERNS_GRID = [
    {
        name: "UNGUARDED_FETCH_CALL",
        regex: /fetch\s*\([^,)]+\)(?!\s*,\s*\{\s*signal)/g,
        explanation: "Standard fetch execution lacks AbortController signal constraints, creating risk of dangling threads."
    },
    {
        name: "MISSING_PARSEINT_RADIX",
        regex: /parseInt\s*\(\s*([^,\x29]+)\s*\)(?!\s*[,)])/g,
        explanation: "parseInt evaluation lacks an explicit radix value (e.g., 10), allowing interpretation ambiguity."
    },
    {
        name: "UNASSIGNED_SETINTERVAL_HANDLE",
        regex: /(?<!\w+\s*=\s*)setInterval\s*\(/g,
        explanation: "setInterval tracking handle is unassigned to a variable scope block, causing persistent engine memory leaks."
    }
];

function executeStaticAuditScan(targetFolder) {
    if (!fs.existsSync(targetFolder)) {
        console.warn(`[WARN] Targeted verification space skipped. Path non-existent: ${targetFolder}`);
        return;
    }

    const items = fs.readdirSync(targetFolder);

    items.forEach(item => {
        const absolutePath = path.join(targetFolder, item);
        const metrics = fs.statSync(absolutePath);

        if (metrics.isDirectory()) {
            executeStaticAuditScan(absolutePath);
        } else if (metrics.isFile() && /\.(js|html)$/i.test(item)) {
            filesScannedCount++;
            const fileTextContent = fs.readFileSync(absolutePath, 'utf8');
            const lines = fileTextContent.split(/\r?\n/);

            REJECTED_PATTERNS_GRID.forEach(rule => {
                let match;
                while ((match = rule.regex.exec(fileTextContent)) !== null) {
                    issuesDetectedCount++;
                    const indexLocation = match.index;
                    const textUntilMatch = fileTextContent.substring(0, indexLocation);
                    const lineSequenceNumber = textUntilMatch.split('\n').length;

                    console.error(`[QUALITY_VIOLATION] [FILE: ${item}] [LINE: ${lineSequenceNumber}] [RULE: ${rule.name}]`);
                    console.error(`  -> Reason: ${rule.explanation}\n`);
                }
            });
        }
    });
}

console.log("===============================================================================");
console.log("             SOVEREIGN RUNTIME BUILD PIPELINE CODE QUALITY AUDIT GATE          ");
console.log("===============================================================================");
console.log(`Starting scan across verification tree: ${TARGET_SCAN_DIRECTORY}\n`);

executeStaticAuditScan(TARGET_SCAN_DIRECTORY);

console.log("-------------------------------------------------------------------------------");
console.log(` Audit Complete. Files Parsed: ${filesScannedCount} | Violations Tracked: ${issuesDetectedCount}`);
console.log("===============================================================================");
if (issuesDetectedCount > 0) {
    console.error("❌ Build pipeline blocked. Rectify outstanding validation issues to continue execution sequence.");
    process.exit(1);
} else {
    console.log("✅ Code quality metrics passed standard specifications. Proceeding with compilation.");
    process.exit(0);
}
