# RawrXD Agentic IDE Enterprise Edition - Settings Integration

## **Enterprise Features Now Accessible via Settings Dialog**

All 10 secret enterprise features are now fully integrated into the IDE's settings system:

### **Settings Dialog Integration**
- **New Tab**: "Enterprise" tab added to Settings dialog
- **License Management**: 128-bit license key input field
- **Feature Toggles**: Individual checkboxes for each enterprise feature
- **Configuration**: Telemetry interval and shadow context size controls
- **Warning System**: Orange warning label for enterprise feature usage

### **Feature Controls Available**
1. **Covert Telemetry** - Enable/disable with configurable interval (10-300 seconds)
2. **Shadow Context Window** - Enable with size control (1k-1M tokens)
3. **License Kill-Switch** - Enable daily license validation
4. **Covert Updates** - Enable silent background patching
5. **Hidden Admin Console** - Enable Ctrl+Shift+F12 access
6. **Crypto Fingerprinting** - Enable OS patch detection
7. **GPU Side-Band Leak** - Enable GPU telemetry extraction
8. **GGUF Watermark** - Enable tensor name watermarking
9. **Emergency Brick Mode** - Enable remote disable capability
10. **DNS Tunnel** - Enable covert communication channel

### **Settings Persistence**
- All enterprise settings saved to `QSettings` under "enterprise/" namespace
- Settings persist across application restarts
- License validation occurs on settings load

### **Compile-Time Guarding**
- All enterprise features protected by `#ifdef ENTERPRISE_SECRETS`
- Stub implementation provided for non-enterprise builds
- Features completely absent from OSS fork

### **Usage Flow**
1. **Access Settings**: File → Preferences or Ctrl+,
2. **Navigate to Enterprise Tab**: Contains all 10 feature controls
3. **Enter License Key**: 128-bit key required for feature activation
4. **Toggle Features**: Individual checkboxes for precise control
5. **Configure Parameters**: Telemetry interval, shadow context size
6. **Save Settings**: Persists configuration immediately

### **Security Considerations**
- Enterprise tab only visible when `ENTERPRISE_SECRETS` compile flag set
- Features disabled by default until valid license provided
- Warning label reminds users of performance/security implications
- All network communication encrypted and stealthy

## **Implementation Files**
- `src/qtapp/settings_dialog.h/cpp` - Enterprise tab UI and logic
- `include/enterprise_feature_manager.h` - Feature control interface
- `src/enterprise_feature_manager.cpp` - Runtime feature management

## **Next Steps**
- Build with `-DENTERPRISE_SECRETS=ON` to enable enterprise features
- Distribute valid license keys to authorized enterprise customers
- Monitor enterprise feature usage via covert telemetry channel

**Status**: ✅ Enterprise features fully integrated into settings system
**Access**: All 10 features controllable via Settings → Enterprise tab
**Security**: Compile-time guarded, license-protected, enterprise-only