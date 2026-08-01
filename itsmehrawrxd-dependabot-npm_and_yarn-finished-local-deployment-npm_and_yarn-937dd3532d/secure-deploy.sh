#!/bin/bash
# RawrZ Security Platform - Secure Deployment Script
# Ensures no tokens or sensitive data are exposed during deployment

set -e

echo "RawrZ Security Platform - Secure Deployment"
echo "==========================================="

# Function to clean sensitive data
clean_sensitive_data() {
    echo "Cleaning sensitive data..."
    
    # Remove any potential token files
    find . -name "*.token" -delete 2>/dev/null || true
    find . -name "*.key" -delete 2>/dev/null || true
    find . -name "*.pem" -delete 2>/dev/null || true
    find . -name "*.p12" -delete 2>/dev/null || true
    find . -name "*.pfx" -delete 2>/dev/null || true
    
    # Remove any .env files that might contain secrets
    find . -name ".env*" -delete 2>/dev/null || true
    
    # Remove any backup files that might contain sensitive data
    find . -name "*.bak" -delete 2>/dev/null || true
    find . -name "*.backup" -delete 2>/dev/null || true
    
    # Remove any log files that might contain sensitive information
    find . -name "*.log" -delete 2>/dev/null || true
    
    # Remove any temporary files
    find . -name "*.tmp" -delete 2>/dev/null || true
    find . -name "*.temp" -delete 2>/dev/null || true
    
    echo "✅ Sensitive data cleaned"
}

# Function to validate no sensitive data remains
validate_clean() {
    echo "Validating no sensitive data remains..."
    
    # Check for common sensitive patterns
    if grep -r -i "password\|secret\|token\|key\|api_key" . --exclude-dir=.git --exclude="*.md" --exclude="*.txt" | grep -v "public domain" | grep -v "example" | grep -v "placeholder"; then
        echo "❌ Potential sensitive data found!"
        exit 1
    fi
    
    echo "✅ No sensitive data detected"
}

# Function to create secure .gitignore
create_secure_gitignore() {
    echo "Creating secure .gitignore..."
    
    cat > .gitignore << 'EOF'
# Sensitive files
*.token
*.key
*.pem
*.p12
*.pfx
.env*
*.bak
*.backup
*.log
*.tmp
*.temp

# Node modules
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/

# nyc test coverage
.nyc_output

# Dependency directories
jspm_packages/

# Optional npm cache directory
.npm

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variables file
.env

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Docker
.dockerignore

# Temporary files
*.tmp
*.temp
EOF

    echo "✅ Secure .gitignore created"
}

# Function to check for hardcoded credentials
check_hardcoded_credentials() {
    echo "Checking for hardcoded credentials..."
    
    # Patterns to check for
    patterns=(
        "password\s*=\s*['\"][^'\"]+['\"]"
        "secret\s*=\s*['\"][^'\"]+['\"]"
        "token\s*=\s*['\"][^'\"]+['\"]"
        "api_key\s*=\s*['\"][^'\"]+['\"]"
        "private_key\s*=\s*['\"][^'\"]+['\"]"
    )
    
    for pattern in "${patterns[@]}"; do
        if grep -r -E "$pattern" . --exclude-dir=.git --exclude="*.md" --exclude="*.txt" | grep -v "example" | grep -v "placeholder"; then
            echo "❌ Potential hardcoded credentials found!"
            exit 1
        fi
    done
    
    echo "✅ No hardcoded credentials detected"
}

# Function to prepare deployment
prepare_deployment() {
    echo "Preparing deployment..."
    
    # Clean sensitive data
    clean_sensitive_data
    
    # Create secure gitignore
    create_secure_gitignore
    
    # Check for hardcoded credentials
    check_hardcoded_credentials
    
    # Validate clean
    validate_clean
    
    echo "✅ Deployment prepared securely"
}

# Function to deploy to GitHub
deploy_to_github() {
    echo "Deploying to GitHub..."
    
    # Check if git is initialized
    if [ ! -d ".git" ]; then
        echo "Initializing git repository..."
        git init
        git remote add origin https://github.com/ItsMehRAWRXD/itsmehrawrxd.git
    fi
    
    # Add all files
    git add .
    
    # Check for any sensitive data before commit
    if git diff --cached --name-only | grep -E "\.(token|key|pem|p12|pfx|env|bak|backup|log|tmp|temp)$"; then
        echo "❌ Sensitive files detected in staging area!"
        exit 1
    fi
    
    # Commit changes
    git commit -m "Secure deployment: RawrZ Security Platform with PowerShell one-liners

- Added PowerShell one-liner engine with 25+ security operations
- Created interactive web panels for all one-liners
- Integrated encryption, anti-analysis, process, network, persistence tools
- Added credential harvesting, file operations, monitoring capabilities
- All source code released to public domain
- No sensitive data or tokens included
- Ready for production deployment"

    # Push to GitHub
    git push origin main
    
    echo "✅ Successfully deployed to GitHub"
}

# Function to create deployment package
create_deployment_package() {
    echo "Creating deployment package..."
    
    # Create deployment directory
    mkdir -p RawrZDeployment
    
    # Copy essential files
    cp -r src/ RawrZDeployment/
    cp -r public/ RawrZDeployment/
    cp api-server-real.js RawrZDeployment/
    cp Dockerfile RawrZDeployment/
    cp package.json RawrZDeployment/
    cp *.ps1 RawrZDeployment/ 2>/dev/null || true
    cp *.asm RawrZDeployment/ 2>/dev/null || true
    cp *.c RawrZDeployment/ 2>/dev/null || true
    cp *.h RawrZDeployment/ 2>/dev/null || true
    cp *.inc RawrZDeployment/ 2>/dev/null || true
    cp *.sh RawrZDeployment/ 2>/dev/null || true
    
    # Create deployment README
    cat > RawrZDeployment/README.md << 'EOF'
# RawrZ Security Platform - Deployment Package

## Overview
This package contains the complete RawrZ Security Platform with PowerShell one-liners and interactive web panels.

## Features
- 25+ PowerShell one-liners for security operations
- Interactive web interface for all tools
- Encryption, anti-analysis, process manipulation
- Network tools, persistence, credential harvesting
- File operations, monitoring, reconnaissance

## Installation
1. Install Node.js and npm
2. Run: npm install
3. Start: node api-server-real.js
4. Access: http://localhost:3000

## Security Notice
All tools are for educational and authorized security testing purposes only.
Use responsibly and in compliance with applicable laws.

## Public Domain
All source code is released to the public domain.
EOF

    # Create ZIP package
    zip -r RawrZDeployment.zip RawrZDeployment/
    
    echo "✅ Deployment package created: RawrZDeployment.zip"
}

# Main execution
main() {
    echo "Starting secure deployment process..."
    
    # Prepare deployment
    prepare_deployment
    
    # Create deployment package
    create_deployment_package
    
    # Deploy to GitHub
    deploy_to_github
    
    echo ""
    echo "🎉 Secure deployment completed successfully!"
    echo "📦 Deployment package: RawrZDeployment.zip"
    echo "🌐 GitHub repository updated"
    echo "🔒 No sensitive data exposed"
    echo ""
    echo "Next steps:"
    echo "1. Deploy to your droplet using the deployment scripts"
    echo "2. Access the platform at http://YOUR_DROPLET_IP:3000"
    echo "3. Use the PowerShell one-liner panels for security operations"
}

# Run main function
main "$@"
