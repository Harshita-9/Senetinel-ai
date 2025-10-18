import asyncio
from typing import Dict, List
from datetime import datetime
from enum import Enum

from agents.watcher import WatcherAgent
from agents.investigator import InvestigatorAgent
from agents.healer import HealerAgent
from agents.economist import EconomistAgent
from agents.librarian import LibrarianAgent
from core.config import settings
from core.models import SeverityLevel, IncidentStatus
from core.database import db_manager
from utils.logger import sentinel_logger as logger

class AgentState(str, Enum):
    IDLE = "idle"
    ACTIVE = "active"
    ERROR = "error"

class OrchestratorAgent:
    def __init__(self):
        self.watcher = WatcherAgent()
        self.investigator = InvestigatorAgent()
        self.healer = HealerAgent()
        self.economist = EconomistAgent()
        self.librarian = LibrarianAgent()
        
        self.running = False
        self.agent_states = {
            "watcher": AgentState.IDLE,
            "investigator": AgentState.IDLE,
            "healer": AgentState.IDLE,
            "economist": AgentState.IDLE,
            "librarian": AgentState.IDLE
        }
        
        self.incident_queue = asyncio.Queue()
        self.processing_incidents = set()
    
    async def start(self):
        logger.info("=" * 60)
        logger.info("SENTINEL AI Security Analyst - System Activation")
        logger.info("=" * 60)
        
        self.running = True
        
        tasks = [
            self.run_watcher(),
            self.process_incident_queue(),
            self.monitor_system_health()
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
            await self.shutdown()
        except Exception as e:
            logger.error(f"Orchestrator error: {e}")
            await self.shutdown()
    
    async def run_watcher(self):
        self.agent_states["watcher"] = AgentState.ACTIVE
        logger.info("Watcher Agent: ACTIVE")
        
        try:
            await self.watcher.start_monitoring()
        except Exception as e:
            logger.error(f"Watcher agent error: {e}")
            self.agent_states["watcher"] = AgentState.ERROR
    
    async def process_incident_queue(self):
        logger.info("Incident processing queue: ACTIVE")
        
        while self.running:
            try:
                await self.scan_for_new_incidents()
                await asyncio.sleep(10)
            except Exception as e:
                logger.error(f"Queue processing error: {e}")
    
    async def scan_for_new_incidents(self):
        try:
            with db_manager.get_session() as session:
                from core.models import IncidentORM
                
                unprocessed = session.query(IncidentORM).filter_by(
                    status=IncidentStatus.DETECTED.value
                ).all()
                
                for incident in unprocessed:
                    if incident.id not in self.processing_incidents:
                        await self.incident_queue.put(incident.id)
                        self.processing_incidents.add(incident.id)
                        asyncio.create_task(self.handle_incident(incident.id))
        
        except Exception as e:
            logger.error(f"Error scanning for incidents: {e}")
    
    async def handle_incident(self, incident_id: str):
        logger.info(f"Processing incident: {incident_id}")
        
        try:
            incident_data = await self.get_incident_data(incident_id)
            if not incident_data:
                return
            
            severity = SeverityLevel(incident_data['severity'])
            
            if severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                await self.handle_critical_incident(incident_id, incident_data)
            else:
                await self.handle_standard_incident(incident_id, incident_data)
        
        except Exception as e:
            logger.error(f"Error handling incident {incident_id}: {e}")
        finally:
            self.processing_incidents.discard(incident_id)
    
    async def handle_critical_incident(self, incident_id: str, incident_data: Dict):
        logger.warning(f"CRITICAL INCIDENT: {incident_id}")
        
        investigation_task = asyncio.create_task(
            self.run_investigation(incident_id)
        )
        
        financial_task = asyncio.create_task(
            self.run_financial_analysis(incident_id)
        )
        
        investigation = await investigation_task
        financial_impact = await financial_task
        
        if settings.AUTO_REMEDIATION:
            remediation = await self.run_remediation(incident_id)
            
            if remediation and remediation.success:
                logger.info(f"Auto-remediation successful for {incident_id}")
            else:
                logger.warning(f"Auto-remediation failed for {incident_id} - Manual intervention required")
        
        await self.run_documentation(incident_id)
        
        await self.send_alerts(incident_id, investigation, financial_impact)
    
    async def handle_standard_incident(self, incident_id: str, incident_data: Dict):
        logger.info(f"Standard incident workflow: {incident_id}")
        
        investigation = await self.run_investigation(incident_id)
        
        financial_impact = await self.run_financial_analysis(incident_id)
        
        if investigation and investigation.recommendations:
            remediation = await self.run_remediation(incident_id)
        
        await self.run_documentation(incident_id)
    
    async def run_investigation(self, incident_id: str):
        self.agent_states["investigator"] = AgentState.ACTIVE
        logger.info(f"Investigator analyzing: {incident_id}")
        
        try:
            investigation = await self.investigator.investigate_incident(incident_id)
            self.agent_states["investigator"] = AgentState.IDLE
            return investigation
        except Exception as e:
            logger.error(f"Investigation failed: {e}")
            self.agent_states["investigator"] = AgentState.ERROR
            return None
    
    async def run_financial_analysis(self, incident_id: str):
        self.agent_states["economist"] = AgentState.ACTIVE
        logger.info(f"Economist calculating impact: {incident_id}")
        
        try:
            impact = await self.economist.calculate_financial_impact(incident_id)
            self.agent_states["economist"] = AgentState.IDLE
            return impact
        except Exception as e:
            logger.error(f"Financial analysis failed: {e}")
            self.agent_states["economist"] = AgentState.ERROR
            return None
    
    async def run_remediation(self, incident_id: str):
        self.agent_states["healer"] = AgentState.ACTIVE
        logger.info(f"Healer remediating: {incident_id}")
        
        try:
            remediation = await self.healer.remediate_incident(incident_id)
            self.agent_states["healer"] = AgentState.IDLE
            return remediation
        except Exception as e:
            logger.error(f"Remediation failed: {e}")
            self.agent_states["healer"] = AgentState.ERROR
            return None
    
    async def run_documentation(self, incident_id: str):
        self.agent_states["librarian"] = AgentState.ACTIVE
        logger.info(f"Librarian documenting: {incident_id}")
        
        try:
            success = await self.librarian.document_incident(incident_id)
            self.agent_states["librarian"] = AgentState.IDLE
            return success
        except Exception as e:
            logger.error(f"Documentation failed: {e}")
            self.agent_states["librarian"] = AgentState.ERROR
            return False
    
    async def get_incident_data(self, incident_id: str) -> Dict:
        try:
            with db_manager.get_session() as session:
                from core.models import IncidentORM
                incident = session.query(IncidentORM).filter_by(id=incident_id).first()
                
                if incident:
                    return {
                        "id": incident.id,
                        "severity": incident.severity,
                        "attack_type": incident.attack_type,
                        "status": incident.status
                    }
        except Exception as e:
            logger.error(f"Error fetching incident: {e}")
        return {}
    
    async def send_alerts(self, incident_id: str, investigation, financial_impact):
        try:
            logger.warning("=" * 60)
            logger.warning(f"SECURITY ALERT: {incident_id}")
            logger.warning("=" * 60)
            
            if investigation:
                logger.warning(f"Analysis: {investigation.analysis[:200]}...")
            
            if financial_impact:
                logger.warning(f"Financial Impact: ${financial_impact.total_impact:,.2f}")
            
            logger.warning("=" * 60)
        
        except Exception as e:
            logger.error(f"Alert sending failed: {e}")
    
    async def monitor_system_health(self):
        logger.info("System health monitoring: ACTIVE")
        
        while self.running:
            try:
                await asyncio.sleep(60)
                await self.log_system_status()
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
    
    async def log_system_status(self):
        try:
            stats = await self.get_system_stats()
            
            logger.info("=" * 60)
            logger.info("SYSTEM STATUS REPORT")
            logger.info("=" * 60)
            logger.info(f"Total Incidents: {stats.get('total_incidents', 0)}")
            logger.info(f"Active Processing: {len(self.processing_incidents)}")
            logger.info(f"Resolved: {stats.get('resolved_incidents', 0)}")
            logger.info(f"Auto-Resolved: {stats.get('auto_resolved', 0)}")
            logger.info(f"Automation Rate: {stats.get('automation_rate', 0):.1f}%")
            logger.info("=" * 60)
            
            for agent, state in self.agent_states.items():
                logger.info(f"{agent.title()}: {state.value.upper()}")
            
            logger.info("=" * 60)
        
        except Exception as e:
            logger.error(f"Status logging error: {e}")
    
    async def get_system_stats(self) -> Dict:
        try:
            stats = await self.librarian.get_knowledge_base_stats()
            return stats
        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            return {}
    
    async def shutdown(self):
        logger.info("Initiating graceful shutdown...")
        self.running = False
        
        self.watcher.stop_monitoring()
        
        logger.info("Waiting for pending incidents to complete...")
        timeout = 30
        waited = 0
        
        while self.processing_incidents and waited < timeout:
            await asyncio.sleep(1)
            waited += 1
        
        if self.processing_incidents:
            logger.warning(f"{len(self.processing_incidents)} incidents did not complete")
        
        logger.info("SENTINEL AI - Shutdown complete")
    
    async def get_dashboard_data(self) -> Dict:
        try:
            with db_manager.get_session() as session:
                from core.models import IncidentORM, PlaybookORM
                from sqlalchemy import func
                
                total_incidents = session.query(IncidentORM).count()
                
                by_severity = session.query(
                    IncidentORM.severity,
                    func.count(IncidentORM.id)
                ).group_by(IncidentORM.severity).all()
                
                by_type = session.query(
                    IncidentORM.attack_type,
                    func.count(IncidentORM.id)
                ).group_by(IncidentORM.attack_type).all()
                
                resolved = session.query(IncidentORM).filter_by(
                    status=IncidentStatus.RESOLVED.value
                ).count()
                
                auto_resolved = session.query(IncidentORM).filter_by(
                    auto_resolved=True
                ).count()
                
                total_financial_impact = 0
                incidents_with_impact = session.query(IncidentORM).filter(
                    IncidentORM.financial_impact_data.isnot(None)
                ).all()
                
                for incident in incidents_with_impact:
                    if incident.financial_impact_data:
                        total_financial_impact += incident.financial_impact_data.get('total_impact', 0)
                
                playbooks = session.query(PlaybookORM).count()
                
                return {
                    "total_incidents": total_incidents,
                    "resolved": resolved,
                    "auto_resolved": auto_resolved,
                    "automation_rate": (auto_resolved / resolved * 100) if resolved > 0 else 0,
                    "by_severity": dict(by_severity),
                    "by_type": dict(by_type),
                    "total_financial_impact": total_financial_impact,
                    "total_playbooks": playbooks,
                    "agent_states": {k: v.value for k, v in self.agent_states.items()},
                    "processing_queue": len(self.processing_incidents)
                }
        
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            return {}