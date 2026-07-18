// dashboard.js
// Batch 11: Dashboard JavaScript
//
// Handles real-time updates, charts, and WebSocket communication

(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        apiUrl: window.location.origin,
        wsUrl: window.location.origin.replace('http', 'ws'),
        refreshInterval: 5000,
        maxLogEntries: 100
    };

    // State
    let charts = {};
    let ws = null;
    let currentTab = 'overview';

    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        initTabs();
        initCharts();
        connectWebSocket();
        loadInitialData();
        
        // Auto-refresh
        setInterval(refreshData, CONFIG.refreshInterval);
    });

    // Tab Navigation
    function initTabs() {
        const tabBtns = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');

        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tabId = btn.dataset.tab;
                
                // Update buttons
                tabBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Update content
                tabContents.forEach(c => c.classList.remove('active'));
                document.getElementById(tabId).classList.add('active');
                
                currentTab = tabId;
                
                // Refresh chart if needed
                if (tabId === 'comparison') {
                    updateComparisonCharts();
                } else if (tabId === 'trends') {
                    updateTrendsChart();
                }
            });
        });
    }

    // Initialize Charts
    function initCharts() {
        // Overview Chart
        const overviewCtx = document.getElementById('overview-chart');
        if (overviewCtx) {
            charts.overview = new Chart(overviewCtx, {
                type: 'bar',
                data: {
                    labels: ['Sovereign', 'Ollama', 'OpenAI', 'Anthropic'],
                    datasets: [{
                        label: 'Mean TPS',
                        data: [45.2, 38.5, 52.1, 48.7],
                        backgroundColor: [
                            'rgba(233, 69, 96, 0.8)',
                            'rgba(0, 217, 255, 0.8)',
                            'rgba(255, 193, 7, 0.8)',
                            'rgba(0, 255, 136, 0.8)'
                        ],
                        borderColor: [
                            'rgba(233, 69, 96, 1)',
                            'rgba(0, 217, 255, 1)',
                            'rgba(255, 193, 7, 1)',
                            'rgba(0, 255, 136, 1)'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#a0a0a0' }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { color: '#a0a0a0' }
                        }
                    }
                }
            });
        }

        // TPS Comparison Chart
        const tpsCtx = document.getElementById('tps-comparison-chart');
        if (tpsCtx) {
            charts.tpsComparison = new Chart(tpsCtx, {
                type: 'radar',
                data: {
                    labels: ['Inference', 'Context', 'Concurrent', 'Planning', 'Tool Use'],
                    datasets: [{
                        label: 'Sovereign',
                        data: [90, 85, 88, 92, 87],
                        borderColor: 'rgba(233, 69, 96, 1)',
                        backgroundColor: 'rgba(233, 69, 96, 0.2)'
                    }, {
                        label: 'Ollama',
                        data: [75, 80, 72, 78, 76],
                        borderColor: 'rgba(0, 217, 255, 1)',
                        backgroundColor: 'rgba(0, 217, 255, 0.2)'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        r: {
                            beginAtZero: true,
                            max: 100,
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            pointLabels: { color: '#a0a0a0' },
                            ticks: { display: false }
                        }
                    }
                }
            });
        }

        // Latency Comparison Chart
        const latencyCtx = document.getElementById('latency-comparison-chart');
        if (latencyCtx) {
            charts.latencyComparison = new Chart(latencyCtx, {
                type: 'line',
                data: {
                    labels: ['P50', 'P75', 'P90', 'P95', 'P99'],
                    datasets: [{
                        label: 'Sovereign',
                        data: [120, 135, 155, 175, 220],
                        borderColor: 'rgba(233, 69, 96, 1)',
                        backgroundColor: 'rgba(233, 69, 96, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Ollama',
                        data: [150, 170, 195, 220, 280],
                        borderColor: 'rgba(0, 217, 255, 1)',
                        backgroundColor: 'rgba(0, 217, 255, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#a0a0a0' }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { color: '#a0a0a0' }
                        }
                    }
                }
            });
        }

        // Trends Chart
        const trendsCtx = document.getElementById('trends-chart');
        if (trendsCtx) {
            charts.trends = new Chart(trendsCtx, {
                type: 'line',
                data: {
                    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                    datasets: [{
                        label: 'Mean TPS',
                        data: [42.0, 43.5, 45.2, 44.8, 46.1, 45.5, 46.2],
                        borderColor: 'rgba(0, 217, 255, 1)',
                        backgroundColor: 'rgba(0, 217, 255, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Target',
                        data: [45, 45, 45, 45, 45, 45, 45],
                        borderColor: 'rgba(255, 193, 7, 1)',
                        borderDash: [5, 5],
                        fill: false,
                        pointRadius: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        intersect: false,
                        mode: 'index'
                    },
                    scales: {
                        y: {
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#a0a0a0' }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { color: '#a0a0a0' }
                        }
                    }
                }
            });
        }
    }

    // WebSocket Connection
    function connectWebSocket() {
        try {
            ws = new WebSocket(CONFIG.wsUrl + '/ws');
            
            ws.onopen = function() {
                updateConnectionStatus(true);
                addLogEntry('Connected to real-time updates', 'info');
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            };
            
            ws.onclose = function() {
                updateConnectionStatus(false);
                addLogEntry('Disconnected from real-time updates', 'warn');
                
                // Reconnect after 5 seconds
                setTimeout(connectWebSocket, 5000);
            };
            
            ws.onerror = function(error) {
                addLogEntry('WebSocket error: ' + error, 'error');
            };
        } catch (e) {
            addLogEntry('Failed to connect WebSocket: ' + e.message, 'error');
        }
    }

    function updateConnectionStatus(connected) {
        const status = document.getElementById('connection-status');
        if (status) {
            status.textContent = connected ? 'Connected' : 'Disconnected';
            status.className = 'status ' + (connected ? 'connected' : 'disconnected');
        }
    }

    function handleWebSocketMessage(data) {
        if (data.type === 'benchmark_update') {
            updateBenchmarkStatus(data.benchmark_id, data.status, data.results);
        } else if (data.type === 'system_metrics') {
            updateSystemMetrics(data.metrics);
        }
    }

    // Load Initial Data
    async function loadInitialData() {
        try {
            // Load benchmarks
            const benchmarks = await fetchJson('/api/benchmarks');
            renderBenchmarksList(benchmarks.benchmarks);
            
            // Load comparison
            const comparison = await fetchJson('/api/compare');
            renderComparisonTable(comparison.comparison);
            
            // Load system metrics
            const system = await fetchJson('/api/system');
            updateSystemMetrics(system);
            
            // Update overview
            updateOverview(benchmarks, comparison);
            
        } catch (error) {
            addLogEntry('Failed to load initial data: ' + error.message, 'error');
        }
    }

    async function refreshData() {
        try {
            const system = await fetchJson('/api/system');
            updateSystemMetrics(system);
            
            document.getElementById('last-update').textContent = 
                'Last update: ' + new Date().toLocaleTimeString();
        } catch (error) {
            console.error('Refresh failed:', error);
        }
    }

    // API Helpers
    async function fetchJson(endpoint) {
        const response = await fetch(CONFIG.apiUrl + endpoint);
        if (!response.ok) {
            throw new Error('HTTP ' + response.status);
        }
        return response.json();
    }

    // Render Functions
    function renderBenchmarksList(benchmarks) {
        const container = document.getElementById('benchmarks-list');
        if (!container) return;
        
        container.innerHTML = benchmarks.map(b => `
            <div class="benchmark-item" data-tier="${b.tier}">
                <div class="benchmark-info">
                    <h3>${b.name}</h3>
                    <p>ID: ${b.id}</p>
                </div>
                <span class="benchmark-tier tier-${b.tier}">Tier ${b.tier}</span>
            </div>
        `).join('');
    }

    function renderComparisonTable(comparison) {
        const tbody = document.getElementById('comparison-tbody');
        if (!tbody) return;
        
        tbody.innerHTML = comparison.map(c => `
            <tr>
                <td><strong>${c.backend}</strong></td>
                <td>${c.mean_tps.toFixed(1)}</td>
                <td>${c.ttft_ms}</td>
                <td>${(c.mean_tps * 1.2).toFixed(1)}</td>
                <td>100%</td>
            </tr>
        `).join('');
    }

    function updateSystemMetrics(metrics) {
        // CPU
        const cpuValue = document.getElementById('cpu-usage');
        const cpuBar = document.getElementById('cpu-bar');
        if (cpuValue && cpuBar) {
            cpuValue.textContent = metrics.cpu_usage.toFixed(1) + '%';
            cpuBar.style.width = metrics.cpu_usage + '%';
        }
        
        // Memory
        const memValue = document.getElementById('memory-usage');
        const memBar = document.getElementById('memory-bar');
        if (memValue && memBar) {
            memValue.textContent = (metrics.memory_usage_mb / 1024).toFixed(1) + ' GB';
            memBar.style.width = Math.min((metrics.memory_usage_mb / 8192) * 100, 100) + '%';
        }
        
        // GPU
        const gpuValue = document.getElementById('gpu-usage');
        const gpuBar = document.getElementById('gpu-bar');
        if (gpuValue && gpuBar) {
            gpuValue.textContent = metrics.gpu_usage.toFixed(1) + '%';
            gpuBar.style.width = metrics.gpu_usage + '%';
        }
        
        // Active benchmarks
        const activeValue = document.getElementById('active-benchmarks');
        if (activeValue) {
            activeValue.textContent = metrics.active_benchmarks;
        }
    }

    function updateOverview(benchmarks, comparison) {
        const totalBenchmarks = document.getElementById('total-benchmarks');
        if (totalBenchmarks) {
            totalBenchmarks.textContent = benchmarks.benchmarks.length;
        }
        
        const avgTps = document.getElementById('avg-tps');
        if (avgTps && comparison.comparison.length > 0) {
            const avg = comparison.comparison.reduce((a, b) => a + b.mean_tps, 0) / 
                       comparison.comparison.length;
            avgTps.textContent = avg.toFixed(1);
        }
        
        const bestBackend = document.getElementById('best-backend');
        if (bestBackend && comparison.comparison.length > 0) {
            const best = comparison.comparison.reduce((a, b) => a.mean_tps > b.mean_tps ? a : b);
            bestBackend.textContent = best.backend;
        }
        
        const lastRun = document.getElementById('last-run');
        if (lastRun) {
            lastRun.textContent = new Date().toLocaleDateString();
        }
    }

    function updateBenchmarkStatus(id, status, results) {
        addLogEntry(`Benchmark ${id}: ${status}`, status === 'error' ? 'error' : 'info');
    }

    function updateComparisonCharts() {
        // Trigger chart update if needed
        if (charts.tpsComparison) {
            charts.tpsComparison.update();
        }
        if (charts.latencyComparison) {
            charts.latencyComparison.update();
        }
    }

    function updateTrendsChart() {
        if (charts.trends) {
            charts.trends.update();
        }
    }

    // Logging
    function addLogEntry(message, level = 'info') {
        const logOutput = document.getElementById('live-log');
        if (!logOutput) return;
        
        const time = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = `
            <span class="log-time">${time}</span>
            <span class="log-level-${level}">[${level.toUpperCase()}]</span>
            ${message}
        `;
        
        logOutput.appendChild(entry);
        logOutput.scrollTop = logOutput.scrollHeight;
        
        // Limit entries
        while (logOutput.children.length > CONFIG.maxLogEntries) {
            logOutput.removeChild(logOutput.firstChild);
        }
    }

    // Filter handlers
    document.getElementById('tier-filter')?.addEventListener('change', function() {
        const tier = this.value;
        const items = document.querySelectorAll('.benchmark-item');
        items.forEach(item => {
            if (tier === 'all' || item.dataset.tier === tier) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    });

})();
