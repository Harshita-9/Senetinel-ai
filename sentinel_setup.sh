#!/bin/bash

# SENTINEL AI - Automated Setup Script

set -e

echo "=================================================="
echo "  SENTINEL AI - Autonomous Security Analyst"
echo "  Setup & Installation Script"
echo "=================================================="
echo ""

# Check Python version
echo "🔍 Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.10"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo "❌ Error: Python 3.10+ required. Found: $python_version"
    exit 1
fi
echo "✅ Python $python_version detected"

# Check if Docker is installed
echo ""
echo "🔍 Checking Docker..."
if command -v docker &> /dev/null; then
    echo "✅ Docker is installed"
    docker_installed=true
else
    echo "⚠️  Docker not found. Install Docker for full setup."
    docker_installed=false
fi

# Create virtual environment
echo ""
echo "🔧 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo ""
echo "📁 Creating directory structure..."
mkdir -p logs data ml_models/trained

# Copy environment file
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  IMPORTANT: Edit .env file with your API keys!"
else
    echo "✅ .env file already exists"
fi

# Docker setup
if [ "$docker_installed" = true ]; then
    echo ""
    read -p "🐳 Start services with Docker? (y/n): " start_docker
    
    if [ "$start_docker" = "y" ] || [ "$start_docker" = "Y" ]; then
        echo "🚀 Starting Docker services..."
        docker-compose up -d postgres neo4j qdrant
        
        echo "⏳ Waiting for services to be ready..."
        sleep 10
        
        echo "✅ Services started successfully"
    fi
fi

# Initialize database
echo ""
echo "🗄️  Initializing databases..."
python -c "from core.database import db_manager; print('✅ Database initialized')"

echo ""
echo "=================================================="
echo "  ✨ SENTINEL AI Setup Complete! ✨"
echo "=================================================="
echo ""
echo "Quick Start Commands:"
echo ""
echo "1. Start API:"
echo "   python -m uvicorn api.main:app --reload"
echo ""
echo "2. Start Dashboard:"
echo "   streamlit run dashboard/app.py"
echo ""
echo "3. Start Full System:"
echo "   python main.py"
echo ""
echo "4. With Docker:"
echo "   docker-compose up"
echo ""
echo "📖 Documentation: README.md"
echo "🔧 Configuration: .env"
echo "🌐 Dashboard: http://localhost:8501"
echo "🔌 API: http://localhost:8000"
echo ""
echo "⚠️  Don't forget to:"
echo "   1. Edit .env with your ANTHROPIC_API_KEY"
echo "   2. Configure database passwords"
echo ""
echo "=================================================="