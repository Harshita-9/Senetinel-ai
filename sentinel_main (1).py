#!/usr/bin/env python3
"""
SENTINEL AI - Autonomous Security Analyst
Main Entry Point
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.orchestrator import OrchestratorAgent
from utils.logger import sentinel_logger as logger
from core.config import settings

async def main():
    """Main entry point for SENTINEL AI"""
    
    logger.info("=" * 70)
    logger.info("  ____  _____ _   _ _____ ___ _   _ _____ _     ")
    logger.info(" / ___|| ____| \\ | |_   _|_ _| \\ | | ____| |    ")
    logger.info(" \\___ \\|  _| |  \\| | | |  | ||  \\| |  _| | |    ")
    logger.info("  ___) | |___| |\\  | | |  | || |\\  | |___| |___ ")
    logger.info(" |____/|_____|_| \\_| |_| |___|_| \\_|_____|_____|")
    logger.info("")
    logger.info("         Autonomous AI Security Analyst v" + settings.VERSION)
    logger.info("=" * 70)
    logger.info("")
    
    try:
        orchestrator = OrchestratorAgent()
        
        logger.info("🚀 Initializing multi-agent system...")
        logger.info(f"📊 Configuration: {settings.PROJECT_NAME}")
        logger.info(f"🔐 Auto-remediation: {'ENABLED' if settings.AUTO_REMEDIATION else 'DISABLED'}")
        logger.info(f"🍯 Honeypots: {'ACTIVE' if settings.HONEYPOT_ENABLED else 'INACTIVE'}")
        logger.info("")
        
        await orchestrator.start()
    
    except KeyboardInterrupt:
        logger.info("\n🛑 Shutdown initiated by user")
        if orchestrator:
            await orchestrator.shutdown()
    
    except Exception as e:
        logger.error(f"❌ Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\n👋 SENTINEL AI terminated")
        sys.exit(0)