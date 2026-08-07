// ============================================================================
// visualizer-core.js - Shared Canvas Performance Renderer
// Zero re-flow, adaptive resolution, hardware-accelerated
// ============================================================================

class DataVisualizerCore {
    constructor(canvasId) {
        this.runtime = window.RawrRuntime;
        this.canvas = this.runtime ? this.runtime.requireElement(canvasId) : document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');
        this.dataBuffer = [];
        this.isRunning = false;
        this.resizeObserver = null;
        this.colors = {
            primary: '#58a6ff',
            success: '#56d364',
            warning: '#e3b341',
            error: '#f85149',
            grid: '#21262d'
        };
        this.initSizing();
    }

    initSizing() {
        this.resizeObserver = new ResizeObserver(() => {
            const rect = this.canvas.parentElement.getBoundingClientRect();
            this.canvas.width = rect.width * window.devicePixelRatio;
            this.canvas.height = rect.height * window.devicePixelRatio;
            this.canvas.style.width = `${rect.width}px`;
            this.canvas.style.height = `${rect.height}px`;
            this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
            this.renderFrame();
        });
        this.resizeObserver.observe(this.canvas.parentElement);
    }

    pushMetrics(value, label) {
        this.dataBuffer.push({ val: value, label: label || '', time: Date.now() });
        if (this.dataBuffer.length > 100) this.dataBuffer.shift();
        this.renderFrame();
    }

    clear() {
        this.dataBuffer = [];
        this.renderFrame();
    }

    renderFrame() {
        const width = this.canvas.width / window.devicePixelRatio;
        const height = this.canvas.height / window.devicePixelRatio;
        const ctx = this.ctx;

        ctx.fillStyle = '#0d1117';
        ctx.fillRect(0, 0, width, height);

        if (this.dataBuffer.length < 2) {
            ctx.fillStyle = '#8b949e';
            ctx.font = '12px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('Waiting for data...', width / 2, height / 2);
            return;
        }

        // Grid lines
        ctx.strokeStyle = this.colors.grid;
        ctx.lineWidth = 0.5;
        for (let i = 0; i < 4; i++) {
            const y = (height / 4) * i;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
        }

        // Data line
        ctx.beginPath();
        ctx.strokeStyle = this.colors.primary;
        ctx.lineWidth = 2;
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';

        const step = width / Math.max(this.dataBuffer.length - 1, 1);
        const min = Math.min(...this.dataBuffer.map(d => d.val));
        const max = Math.max(...this.dataBuffer.map(d => d.val));
        const range = max - min || 1;

        this.dataBuffer.forEach((point, index) => {
            const x = index * step;
            const y = height - ((point.val - min) / range) * (height - 20) - 10;
            if (index === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Fill under curve
        const lastPoint = this.dataBuffer[this.dataBuffer.length - 1];
        ctx.lineTo((this.dataBuffer.length - 1) * step, height - 10);
        ctx.lineTo(0, height - 10);
        ctx.closePath();
        ctx.fillStyle = 'rgba(88, 166, 255, 0.1)';
        ctx.fill();

        // Current value label
        if (lastPoint) {
            ctx.fillStyle = this.colors.primary;
            ctx.font = 'bold 14px sans-serif';
            ctx.textAlign = 'right';
            const labelX = width - 10;
            const labelY = height - ((lastPoint.val - min) / range) * (height - 20) - 10 - 8;
            ctx.fillText(`${lastPoint.val.toFixed(1)}${lastPoint.label}`, labelX, Math.max(labelY, 16));
        }
    }

    destroy() {
        if (this.resizeObserver) this.resizeObserver.disconnect();
    }
}

if (typeof window !== 'undefined') {
    window.DataVisualizerCore = DataVisualizerCore;
}
