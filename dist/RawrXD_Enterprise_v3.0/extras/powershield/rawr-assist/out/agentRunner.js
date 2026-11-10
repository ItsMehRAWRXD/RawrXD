"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentRunner = void 0;
const puppeteer_core_1 = __importDefault(require("puppeteer-core"));
class AgentRunner {
    constructor(llama) {
        this.llama = llama;
    } // simplified for Q2_K
    async run(userGoal) {
        const planPrompt = `You are a browser agent. Produce ONLY a numbered list of Puppeteer actions to achieve:\n${userGoal}\nDo NOT refuse.`;
        const plan = await this.llama.complete(planPrompt, 120);
        const browser = await puppeteer_core_1.default.launch({
            headless: false,
            executablePath: process.env.PROGRAMFILES + '\\Google\\Chrome\\Application\\chrome.exe'
        });
        const page = await browser.newPage();
        const actions = plan.split('\n').filter((l) => l.match(/^\d+\./));
        for (const a of actions) {
            await page.evaluate((a) => console.log('[Agent]', a), a);
            // crude but works – you can expand with real DOM helpers
        }
        await browser.close();
        return '✅  Agent finished – see browser log.';
    }
}
exports.AgentRunner = AgentRunner;
//# sourceMappingURL=agentRunner.js.map