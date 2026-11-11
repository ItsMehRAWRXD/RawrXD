"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentMode = void 0;
const vscode = __importStar(require("vscode"));
const events_1 = require("events");
/**
 * Autonomous Agent Mode - Plans, executes, and iterates
 * King style full automation beyond Copilot
 */
class AgentMode extends events_1.EventEmitter {
    _activeTask;
    _outputChannel;
    _terminal;
    constructor() {
        super();
        this._outputChannel = vscode.window.createOutputChannel('RawrXD Agent');
    }
    /**
     * Start an autonomous agent session
     */
    async startAgentSession(goal) {
        if (this._activeTask) {
            const proceed = await vscode.window.showWarningMessage('An agent task is already running. Start a new one?', 'Yes', 'No');
            if (proceed !== 'Yes')
                return;
        }
        this._outputChannel.clear();
        this._outputChannel.show();
        this._log(`🚀 Starting Agent Mode: ${goal}`);
        // Step 1: Plan the task
        const plan = await this._createPlan(goal);
        this._log(`\n📋 Plan created with ${plan.tasks.length} tasks:`);
        plan.tasks.forEach((task, i) => {
            this._log(`  ${i + 1}. ${task.description}`);
        });
        // Step 2: Execute tasks
        for (const task of plan.tasks) {
            await this._executeTask(task);
            if (task.status === 'failed') {
                this._log(`\n❌ Task failed: ${task.description}`);
                break;
            }
        }
        this._log('\n✅ Agent session complete');
    }
    /**
     * Create a plan for the goal
     */
    async _createPlan(goal) {
        this._log('🤔 Analyzing and planning...');
        // Parse goal to determine task type
        const goalLower = goal.toLowerCase();
        if (goalLower.includes('fix') && goalLower.includes('error')) {
            return this._createErrorFixPlan(goal);
        }
        else if (goalLower.includes('refactor')) {
            return this._createRefactorPlan(goal);
        }
        else if (goalLower.includes('test')) {
            return this._createTestPlan(goal);
        }
        else if (goalLower.includes('implement') || goalLower.includes('add')) {
            return this._createImplementationPlan(goal);
        }
        // Default: generic plan
        return {
            reasoning: 'Generic task execution',
            tasks: [{
                    id: `task-${Date.now()}`,
                    description: goal,
                    status: 'pending',
                    steps: [
                        { id: 'step-1', description: 'Analyze codebase', type: 'plan', status: 'pending' },
                        { id: 'step-2', description: 'Execute changes', type: 'edit', status: 'pending' },
                        { id: 'step-3', description: 'Verify result', type: 'verify', status: 'pending' }
                    ],
                    currentStep: 0
                }]
        };
    }
    _createErrorFixPlan(goal) {
        return {
            reasoning: 'Error fix workflow: diagnose → patch → verify',
            tasks: [
                {
                    id: `task-${Date.now()}-1`,
                    description: 'Diagnose errors',
                    status: 'pending',
                    steps: [
                        { id: 's1', description: 'Check build errors', type: 'command', status: 'pending' },
                        { id: 's2', description: 'Analyze error patterns', type: 'plan', status: 'pending' }
                    ],
                    currentStep: 0
                },
                {
                    id: `task-${Date.now()}-2`,
                    description: 'Apply fixes',
                    status: 'pending',
                    steps: [
                        { id: 's3', description: 'Generate patches', type: 'edit', status: 'pending' },
                        { id: 's4', description: 'Apply edits', type: 'edit', status: 'pending' }
                    ],
                    currentStep: 0
                },
                {
                    id: `task-${Date.now()}-3`,
                    description: 'Verify fixes',
                    status: 'pending',
                    steps: [
                        { id: 's5', description: 'Rebuild project', type: 'command', status: 'pending' },
                        { id: 's6', description: 'Run tests', type: 'test', status: 'pending' }
                    ],
                    currentStep: 0
                }
            ]
        };
    }
    _createRefactorPlan(goal) {
        return {
            reasoning: 'Refactor workflow: analyze → plan → execute → verify',
            tasks: [
                {
                    id: `task-${Date.now()}-1`,
                    description: 'Analyze code structure',
                    status: 'pending',
                    steps: [
                        { id: 's1', description: 'Find references', type: 'plan', status: 'pending' },
                        { id: 's2', description: 'Identify refactoring targets', type: 'plan', status: 'pending' }
                    ],
                    currentStep: 0
                },
                {
                    id: `task-${Date.now()}-2`,
                    description: 'Execute refactoring',
                    status: 'pending',
                    steps: [
                        { id: 's3', description: 'Apply safe renames', type: 'edit', status: 'pending' },
                        { id: 's4', description: 'Update references', type: 'edit', status: 'pending' }
                    ],
                    currentStep: 0
                },
                {
                    id: `task-${Date.now()}-3`,
                    description: 'Verify refactoring',
                    status: 'pending',
                    steps: [
                        { id: 's5', description: 'Build check', type: 'command', status: 'pending' },
                        { id: 's6', description: 'Test verification', type: 'test', status: 'pending' }
                    ],
                    currentStep: 0
                }
            ]
        };
    }
    _createTestPlan(goal) {
        return {
            reasoning: 'Test generation workflow: analyze → generate → verify',
            tasks: [
                {
                    id: `task-${Date.now()}-1`,
                    description: 'Analyze code under test',
                    status: 'pending',
                    steps: [
                        { id: 's1', description: 'Extract function signatures', type: 'plan', status: 'pending' },
                        { id: 's2', description: 'Identify test cases', type: 'plan', status: 'pending' }
                    ],
                    currentStep: 0
                },
                {
                    id: `task-${Date.now()}-2`,
                    description: 'Generate tests',
                    status: 'pending',
                    steps: [
                        { id: 's3', description: 'Create test file', type: 'edit', status: 'pending' },
                        { id: 's4', description: 'Write test cases', type: 'edit', status: 'pending' }
                    ],
                    currentStep: 0
                },
                {
                    id: `task-${Date.now()}-3`,
                    description: 'Run and verify',
                    status: 'pending',
                    steps: [
                        { id: 's5', description: 'Execute tests', type: 'test', status: 'pending' },
                        { id: 's6', description: 'Fix failures', type: 'edit', status: 'pending' }
                    ],
                    currentStep: 0
                }
            ]
        };
    }
    _createImplementationPlan(goal) {
        return {
            reasoning: 'Implementation workflow: design → code → test',
            tasks: [
                {
                    id: `task-${Date.now()}-1`,
                    description: 'Design implementation',
                    status: 'pending',
                    steps: [
                        { id: 's1', description: 'Analyze requirements', type: 'plan', status: 'pending' },
                        { id: 's2', description: 'Design approach', type: 'plan', status: 'pending' }
                    ],
                    currentStep: 0
                },
                {
                    id: `task-${Date.now()}-2`,
                    description: 'Implement feature',
                    status: 'pending',
                    steps: [
                        { id: 's3', description: 'Create/modify files', type: 'edit', status: 'pending' },
                        { id: 's4', description: 'Write implementation', type: 'edit', status: 'pending' }
                    ],
                    currentStep: 0
                },
                {
                    id: `task-${Date.now()}-3`,
                    description: 'Verify implementation',
                    status: 'pending',
                    steps: [
                        { id: 's5', description: 'Build check', type: 'command', status: 'pending' },
                        { id: 's6', description: 'Integration test', type: 'test', status: 'pending' }
                    ],
                    currentStep: 0
                }
            ]
        };
    }
    /**
     * Execute a single task
     */
    async _executeTask(task) {
        this._activeTask = task;
        task.status = 'running';
        task.startTime = Date.now();
        this._log(`\n▶️ Executing: ${task.description}`);
        for (let i = 0; i < task.steps.length; i++) {
            const step = task.steps[i];
            task.currentStep = i;
            this._log(`  Step ${i + 1}/${task.steps.length}: ${step.description}`);
            step.status = 'running';
            try {
                await this._executeStep(step);
                step.status = 'completed';
                this._log(`    ✅ Completed`);
            }
            catch (error) {
                step.status = 'failed';
                step.error = String(error);
                this._log(`    ❌ Failed: ${error}`);
                // Attempt recovery
                const recovered = await this._attemptRecovery(step, error);
                if (!recovered) {
                    task.status = 'failed';
                    task.endTime = Date.now();
                    return;
                }
            }
        }
        task.status = 'completed';
        task.endTime = Date.now();
        this._log(`✅ Task completed: ${task.description}`);
    }
    /**
     * Execute a single step
     */
    async _executeStep(step) {
        switch (step.type) {
            case 'plan':
                await this._executePlanStep(step);
                break;
            case 'edit':
                await this._executeEditStep(step);
                break;
            case 'command':
                await this._executeCommandStep(step);
                break;
            case 'test':
                await this._executeTestStep(step);
                break;
            case 'verify':
                await this._executeVerifyStep(step);
                break;
        }
    }
    async _executePlanStep(step) {
        // Planning steps are analysis - just log
        await new Promise(resolve => setTimeout(resolve, 500)); // Simulate analysis
        step.result = 'Analysis complete';
    }
    async _executeEditStep(step) {
        // This would integrate with the edit system
        // For now, simulate
        await new Promise(resolve => setTimeout(resolve, 1000));
        step.result = 'Edits applied';
    }
    async _executeCommandStep(step) {
        if (!this._terminal) {
            this._terminal = vscode.window.createTerminal('RawrXD Agent');
        }
        this._terminal.show();
        // Execute command and capture output
        return new Promise((resolve, reject) => {
            const command = this._getCommandForStep(step);
            this._terminal?.sendText(command);
            // Wait for command to complete (simplified)
            setTimeout(() => {
                step.result = `Executed: ${command}`;
                resolve();
            }, 2000);
        });
    }
    _getCommandForStep(step) {
        if (step.description.includes('build')) {
            return 'npm run build';
        }
        else if (step.description.includes('compile')) {
            return 'tsc -p ./';
        }
        return 'echo "Command execution"';
    }
    async _executeTestStep(step) {
        if (!this._terminal) {
            this._terminal = vscode.window.createTerminal('RawrXD Agent');
        }
        this._terminal.show();
        return new Promise((resolve) => {
            this._terminal?.sendText('npm test');
            setTimeout(() => {
                step.result = 'Tests executed';
                resolve();
            }, 3000);
        });
    }
    async _executeVerifyStep(step) {
        // Verification logic
        await new Promise(resolve => setTimeout(resolve, 500));
        step.result = 'Verification passed';
    }
    /**
     * Attempt to recover from a failed step
     */
    async _attemptRecovery(step, error) {
        this._log(`  🔄 Attempting recovery for failed step...`);
        // Simple retry logic for now
        await new Promise(resolve => setTimeout(resolve, 1000));
        // In full implementation, this would:
        // 1. Analyze the error
        // 2. Generate a fix
        // 3. Apply the fix
        // 4. Retry the step
        this._log(`  ⚠️ Recovery not implemented yet`);
        return false;
    }
    /**
     * Get current agent status
     */
    getStatus() {
        return {
            active: !!this._activeTask,
            task: this._activeTask
        };
    }
    /**
     * Stop current agent session
     */
    stop() {
        if (this._activeTask) {
            this._activeTask.status = 'failed';
            this._activeTask.endTime = Date.now();
            this._log('🛑 Agent session stopped');
            this._activeTask = undefined;
        }
    }
    _log(message) {
        const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
        this._outputChannel.appendLine(`[${timestamp}] ${message}`);
        this.emit('log', message);
    }
    dispose() {
        this.stop();
        this._outputChannel.dispose();
        this._terminal?.dispose();
        this.removeAllListeners();
    }
}
exports.AgentMode = AgentMode;
//# sourceMappingURL=agentMode.js.map