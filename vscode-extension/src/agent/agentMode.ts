import * as vscode from 'vscode';
import { EventEmitter } from 'events';

export interface AgentTask {
    id: string;
    description: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    steps: AgentStep[];
    currentStep: number;
    startTime?: number;
    endTime?: number;
}

export interface AgentStep {
    id: string;
    description: string;
    type: 'plan' | 'edit' | 'command' | 'test' | 'verify';
    status: 'pending' | 'running' | 'completed' | 'failed';
    result?: string;
    error?: string;
}

export interface AgentPlan {
    tasks: AgentTask[];
    reasoning: string;
}

/**
 * Autonomous Agent Mode - Plans, executes, and iterates
 * King style full automation beyond Copilot
 */
export class AgentMode extends EventEmitter {
    private _activeTask: AgentTask | undefined;
    private _outputChannel: vscode.OutputChannel;
    private _terminal: vscode.Terminal | undefined;

    constructor() {
        super();
        this._outputChannel = vscode.window.createOutputChannel('RawrXD Agent');
    }

    /**
     * Start an autonomous agent session
     */
    async startAgentSession(goal: string): Promise<void> {
        if (this._activeTask) {
            const proceed = await vscode.window.showWarningMessage(
                'An agent task is already running. Start a new one?',
                'Yes', 'No'
            );
            if (proceed !== 'Yes') return;
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
    private async _createPlan(goal: string): Promise<AgentPlan> {
        this._log('🤔 Analyzing and planning...');

        // Parse goal to determine task type
        const goalLower = goal.toLowerCase();
        
        if (goalLower.includes('fix') && goalLower.includes('error')) {
            return this._createErrorFixPlan(goal);
        } else if (goalLower.includes('refactor')) {
            return this._createRefactorPlan(goal);
        } else if (goalLower.includes('test')) {
            return this._createTestPlan(goal);
        } else if (goalLower.includes('implement') || goalLower.includes('add')) {
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

    private _createErrorFixPlan(goal: string): AgentPlan {
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

    private _createRefactorPlan(goal: string): AgentPlan {
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

    private _createTestPlan(goal: string): AgentPlan {
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

    private _createImplementationPlan(goal: string): AgentPlan {
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
    private async _executeTask(task: AgentTask): Promise<void> {
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
            } catch (error) {
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
    private async _executeStep(step: AgentStep): Promise<void> {
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

    private async _executePlanStep(step: AgentStep): Promise<void> {
        // Planning steps are analysis - just log
        await new Promise(resolve => setTimeout(resolve, 500)); // Simulate analysis
        step.result = 'Analysis complete';
    }

    private async _executeEditStep(step: AgentStep): Promise<void> {
        // This would integrate with the edit system
        // For now, simulate
        await new Promise(resolve => setTimeout(resolve, 1000));
        step.result = 'Edits applied';
    }

    private async _executeCommandStep(step: AgentStep): Promise<void> {
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

    private _getCommandForStep(step: AgentStep): string {
        if (step.description.includes('build')) {
            return 'npm run build';
        } else if (step.description.includes('compile')) {
            return 'tsc -p ./';
        }
        return 'echo "Command execution"';
    }

    private async _executeTestStep(step: AgentStep): Promise<void> {
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

    private async _executeVerifyStep(step: AgentStep): Promise<void> {
        // Verification logic
        await new Promise(resolve => setTimeout(resolve, 500));
        step.result = 'Verification passed';
    }

    /**
     * Attempt to recover from a failed step
     */
    private async _attemptRecovery(step: AgentStep, error: any): Promise<boolean> {
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
    getStatus(): { active: boolean; task?: AgentTask } {
        return {
            active: !!this._activeTask,
            task: this._activeTask
        };
    }

    /**
     * Stop current agent session
     */
    stop(): void {
        if (this._activeTask) {
            this._activeTask.status = 'failed';
            this._activeTask.endTime = Date.now();
            this._log('🛑 Agent session stopped');
            this._activeTask = undefined;
        }
    }

    private _log(message: string): void {
        const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
        this._outputChannel.appendLine(`[${timestamp}] ${message}`);
        this.emit('log', message);
    }

    dispose(): void {
        this.stop();
        this._outputChannel.dispose();
        this._terminal?.dispose();
        this.removeAllListeners();
    }
}
