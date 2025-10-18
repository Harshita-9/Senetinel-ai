# agents/__init__.py
"""SENTINEL AI - Multi-Agent System"""
from agents.watcher import WatcherAgent
from agents.investigator import InvestigatorAgent
from agents.healer import HealerAgent
from agents.economist import EconomistAgent
from agents.librarian import LibrarianAgent
from agents.orchestrator import OrchestratorAgent

__all__ = [
    'WatcherAgent',
    'InvestigatorAgent',
    'HealerAgent',
    'EconomistAgent',
    'LibrarianAgent',
    'OrchestratorAgent'
]

# core/__init__.py
"""SENTINEL AI - Core Components"""
from core.config import settings
from core.database import db_manager, neo4j_manager, vector_manager
from core.models import (
    ThreatDetection,
    Investigation,
    RemediationAction,
    FinancialImpact,
    Playbook,
    SeverityLevel,
    IncidentStatus,
    AttackType
)

__all__ = [
    'settings',
    'db_manager',
    'neo4j_manager',
    'vector_manager',
    'ThreatDetection',
    'Investigation',
    'RemediationAction',
    'FinancialImpact',
    'Playbook',
    'SeverityLevel',
    'IncidentStatus',
    'AttackType'
]

# api/__init__.py
"""SENTINEL AI - REST API"""
from api.main import app

__all__ = ['app']

# dashboard/__init__.py
"""SENTINEL AI - Dashboard"""
__version__ = "1.0.0"

# ml_models/__init__.py
"""SENTINEL AI - Machine Learning Models"""
__version__ = "1.0.0"

# knowledge_base/__init__.py
"""SENTINEL AI - Knowledge Base Management"""
__version__ = "1.0.0"

# infrastructure/__init__.py
"""SENTINEL AI - Infrastructure Management"""
__version__ = "1.0.0"

# secret_weapons/__init__.py
"""SENTINEL AI - Advanced Security Features"""
from secret_weapons.darkweb_monitor import DarkWebMonitor
from secret_weapons.threat_predictor import ThreatPredictor
from secret_weapons.ransomware_negotiator import RansomwareNegotiator
from secret_weapons.alert_system import AlertSystem
from secret_weapons.virustotal_integration import VirusTotalIntegration

__all__ = [
    'DarkWebMonitor',
    'ThreatPredictor',
    'RansomwareNegotiator',
    'AlertSystem',
    'VirusTotalIntegration'
]

# utils/__init__.py
"""SENTINEL AI - Utilities"""
from utils.logger import sentinel_logger
from utils.helpers import (
    hash_string,
    is_valid_ip,
    format_currency,
    calculate_time_diff,
    sanitize_input
)

__all__ = [
    'sentinel_logger',
    'hash_string',
    'is_valid_ip',
    'format_currency',
    'calculate_time_diff',
    'sanitize_input'
]

# tests/__init__.py
"""SENTINEL AI - Test Suite"""
__version__ = "1.0.0"