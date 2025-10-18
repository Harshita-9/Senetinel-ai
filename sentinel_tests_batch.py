# tests/test_watcher.py
import pytest
import asyncio
from agents.watcher import WatcherAgent
from core.models import AttackType

@pytest.mark.asyncio
async def test_watcher_init():
    watcher = WatcherAgent()
    assert watcher is not None

@pytest.mark.asyncio
async def test_detect_sql_injection():
    watcher = WatcherAgent()
    threat = await watcher.detect_threat(
        "192.168.1.1", "10.0.0.1", 443,
        "admin' OR '1'='1'--"
    )
    assert threat is not None
    assert threat.attack_type == AttackType.SQL_INJECTION

# tests/test_investigator.py
import pytest
from agents.investigator import InvestigatorAgent

@pytest.mark.asyncio
async def test_investigator_init():
    investigator = InvestigatorAgent()
    assert investigator is not None

# tests/test_healer.py
import pytest
from agents.healer import HealerAgent

@pytest.mark.asyncio
async def test_healer_init():
    healer = HealerAgent()
    assert healer is not None

# tests/test_economist.py
import pytest
from agents.economist import EconomistAgent

@pytest.mark.asyncio
async def test_economist_init():
    economist = EconomistAgent()
    assert economist is not None

@pytest.mark.asyncio
async def test_cost_calculation():
    economist = EconomistAgent()
    assert economist.attack_cost_base is not None

# tests/test_librarian.py
import pytest
from agents.librarian import LibrarianAgent

@pytest.mark.asyncio
async def test_librarian_init():
    librarian = LibrarianAgent()
    assert librarian is not None

# tests/test_orchestrator.py
import pytest
from agents.orchestrator import OrchestratorAgent

@pytest.mark.asyncio
async def test_orchestrator_init():
    orchestrator = OrchestratorAgent()
    assert orchestrator is not None
    assert len(orchestrator.agent_states) == 5