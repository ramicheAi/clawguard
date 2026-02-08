#!/bin/bash
# ClawGuard Installation Script

set -e

echo "🔒 Installing ClawGuard - OpenClaw Security Scanner"
echo "=================================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "Please install Python 3.8 or higher from python.org"
    exit 1
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    echo "Please install pip: python3 -m ensurepip --upgrade"
    exit 1
fi

# Create virtual environment
echo "📦 Creating Python virtual environment..."
python3 -m venv ~/.clawguard-venv

# Activate and install
echo "⚙️ Installing ClawGuard..."
source ~/.clawguard-venv/bin/activate
pip install --upgrade pip
pip install -e .

# Create symlink
echo "🔗 Creating symlink..."
sudo ln -sf ~/.clawguard-venv/bin/clawguard /usr/local/bin/clawguard 2>/dev/null || true

if [ -f /usr/local/bin/clawguard ]; then
    echo "✅ Symlink created at /usr/local/bin/clawguard"
else
    echo "⚠️ Could not create symlink (no sudo). You can run:"
    echo "   source ~/.clawguard-venv/bin/activate && clawguard"
fi

# First scan
echo "🔍 Running initial security scan..."
clawguard scan

echo ""
echo "🎉 Installation complete!"
echo ""
echo "Usage:"
echo "  clawguard scan          # Run security scan"
echo "  clawguard monitor       # Continuous monitoring"
echo "  clawguard score         # Get security score"
echo "  clawguard --help        # Show all commands"
echo ""
echo "Upgrade to ClawGuard Pro:"
echo "  • Real-time monitoring"
echo "  • Automated patching"
echo "  • Team dashboard"
echo "  • Priority support"
echo ""
echo "Visit: https://clawguard.ai"
echo "Pricing: $49/month | $499 lifetime"