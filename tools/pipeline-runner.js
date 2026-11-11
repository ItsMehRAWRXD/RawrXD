// ============================================================================
// pipeline-runner.js - Integrated Audit-Repair-Test Loop
// Iterative validation with self-healing until clean or max attempts
// ============================================================================

const path = require('path');
const AgenticAuditor = require('./auditor.js');
const SelfHealingCompiler = require('./repair-compiler.js');

class PipelineRunner {
    constructor() {
        this.projectRoot = path.join(__dirname, '..');
        this.maxIterations = 3;
    }

    executePipeline() {
        console.log('================================================================');
        console.log('  ENTERPRISE STABILITY PIPELINE RUNNER');
        console.log('================================================================\n');

        let passes = 0;
        let clean = false;

        while (passes < this.maxIterations && !clean) {
            passes++;
            console.log(`\n--- Cycle ${passes}/${this.maxIterations} ---`);

            const auditor = new AgenticAuditor(this.projectRoot);
            auditor.scanDirectory(this.projectRoot);

            if (auditor.errors.length === 0) {
                console.log(`\nPASS: Clean on cycle ${passes}.`);
                clean = true;
                break;
            }

            console.log(`\nFound ${auditor.errors.length} errors. Running self-heal...`);

            const healer = new SelfHealingCompiler(this.projectRoot);
            healer.executeHealingPass(auditor.errors);

            console.log('Re-auditing after repairs...');
        }

        console.log('\n================================================================');
        if (clean) {
            console.log('  STATUS: PRODUCTION READY');
            console.log('================================================================');
            process.exit(0);
        } else {
            console.error('  STATUS: MAX ATTEMPTS EXHAUSTED - MANUAL INTERVENTION REQUIRED');
            console.log('================================================================');
            process.exit(1);
        }
    }
}

const runner = new PipelineRunner();
runner.executePipeline();
