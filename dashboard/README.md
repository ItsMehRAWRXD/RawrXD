# RawrXD Measurement Dashboard

Real-time visualization of measurement framework results with historical trend tracking.

## Features

- **Live Metrics**: Current values for all architectural claims
- **Trend Charts**: Historical performance over time
- **Four Gates Status**: Visual indicator of validation gates
- **Recent Runs**: Table of recent test executions
- **REST API**: Programmatic access to measurement data

## Quick Start

### Option 1: Static Dashboard (No Server)

Simply open `index.html` in a web browser:

```bash
# On Windows
start dashboard\index.html

# On macOS
open dashboard/index.html

# On Linux
xdg-open dashboard/index.html
```

The dashboard will load with sample data. To use real data, modify the `loadData()` function to fetch from your API.

### Option 2: With Python Server (Recommended)

```bash
# Navigate to dashboard directory
cd dashboard

# Start the server
python server.py

# Or specify a custom port
python server.py 9000
```

Then open http://localhost:8080/ in your browser.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/metrics` | Current measurement values |
| `GET /api/history` | Historical data for charts |
| `GET /api/runs` | Recent test runs |
| `GET /api/baseline` | Baseline configuration |
| `GET /api/summary` | Summary report |

## Integration with CI/CD

### GitHub Actions

Add a step to upload results to the dashboard:

```yaml
- name: Upload to Dashboard
  run: |
    python scripts/upload-to-dashboard.py \
      --url https://your-dashboard-url.com/api/metrics \
      --file reports/measurement_report.json
```

### Local Development

For local development with live data:

1. Run measurement tests:
   ```powershell
   .\scripts\Run-MeasurementFramework.ps1
   ```

2. Start dashboard server:
   ```bash
   python dashboard/server.py
   ```

3. Configure dashboard to read from `reports/` directory by modifying `server.py`.

## Customization

### Adding New Metrics

1. Update `sampleData` in `index.html`:
   ```javascript
   const sampleData = {
       metrics: {
           your_new_metric: {
               value: 42,
               target: 50,
               unit: "units",
               status: "pass",
               trend: +5
           }
       }
   };
   ```

2. Add a card in `createSummaryCards()`:
   ```javascript
   const cards = [
       { key: 'your_new_metric', name: 'Your Metric', icon: '📊' }
   ];
   ```

3. Add a chart in the charts grid.

### Styling

The dashboard uses a GitHub-inspired dark theme. Modify CSS variables in the `<style>` section to customize:

```css
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --border: #30363d;
    --text-primary: #f0f6fc;
    --text-secondary: #8b949e;
    --accent: #58a6ff;
    --success: #238636;
    --warning: #d29922;
    --error: #da3633;
}
```

## Architecture

```
dashboard/
├── index.html          # Main dashboard UI
├── server.py           # Python HTTP server with REST API
├── README.md           # This file
└── api/                # (Optional) API implementation
    ├── metrics.py
    ├── history.py
    └── runs.py
```

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

Requires ES6+ and Chart.js 3.x.

## License

Same as RawrXD project.
