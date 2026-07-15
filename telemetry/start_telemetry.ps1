# Sovereign Engine Telemetry Startup
# Run this on the Ops Machine to start monitoring

Write-Host "Starting Prometheus..." -ForegroundColor Yellow
Start-Process -FilePath "prometheus.exe" -ArgumentList "--config.file=prometheus.yml" -WorkingDirectory "D:\RawrXD\telemetry\prometheus" -WindowStyle Hidden

Write-Host "Starting Grafana (if installed)..." -ForegroundColor Yellow
# Start-Process -FilePath "grafana-server.exe" -WorkingDirectory "C:\Program Files\Grafana" -WindowStyle Hidden

Write-Host "Telemetry aggregation started!" -ForegroundColor Green
Write-Host "Dashboard: http://localhost:3000" -ForegroundColor Gray
Write-Host "Prometheus: http://localhost:9090" -ForegroundColor Gray
