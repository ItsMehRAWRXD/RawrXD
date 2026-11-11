# RawrXD Web UI

A modern, responsive web interface for RawrXD LLM inference platform.

## Features

- **Chat Interface**: Real-time chat with streaming responses
- **Model Management**: Browse, download, and manage models
- **Playground**: Test prompts with adjustable parameters
- **Monitoring Dashboard**: View performance metrics and charts
- **Settings**: Configure server connection and preferences

## Quick Start

### Option 1: Direct File Open
Simply open `index.html` in a modern web browser.

### Option 2: Serve with Python
```bash
cd web
python -m http.server 8081
```
Then open http://localhost:8081

### Option 3: Serve with Node.js
```bash
cd web
npx serve
```

## Configuration

The Web UI connects to RawrXD server at `http://localhost:8080` by default.

To change the server URL:
1. Open Settings (⚙️ icon)
2. Enter your server URL
3. Click Save

## Screenshots

### Chat View
- Interactive chat interface
- Streaming responses
- Markdown rendering with code highlighting
- Suggested prompts

### Models View
- Grid of available models
- Download status
- Model information (size, parameters, quantization)
- One-click download

### Playground View
- Test prompts with live parameters
- Temperature, max tokens, top-p, top-k controls
- Real-time output with stats

### Monitoring View
- Request rate metrics
- Latency distribution
- Token throughput
- GPU utilization

### Settings View
- Server URL configuration
- API key (if required)
- Theme selection
- About information

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Development

The Web UI is built with vanilla HTML, CSS, and JavaScript:
- No build step required
- No dependencies (uses CDN for libraries)
- Responsive design
- Dark theme optimized

## File Structure

```
web/
├── index.html      # Main HTML structure
├── styles.css      # Complete styling
├── app.js          # Application logic
└── README.md       # This file
```

## Integration with RawrXD

The Web UI communicates with RawrXD via:
- REST API (`/v1/chat/completions`, `/v1/completions`)
- Server-Sent Events for streaming
- Health endpoint for status checking

## Customization

### Themes
Edit CSS variables in `styles.css`:
```css
:root {
    --bg-primary: #0f0f0f;
    --accent-primary: #3b82f6;
    /* ... */
}
```

### Adding Features
The app is structured as a class in `app.js`:
```javascript
class RawrXDApp {
    // Add your custom methods here
}
```

## License

MIT License - See LICENSE file for details.
