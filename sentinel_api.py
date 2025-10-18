import asyncio
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from typing import Dict, List

from agents.orchestrator import OrchestratorAgent
from core.config import settings
from core.database import db_manager
from utils.logger import sentinel_logger as logger

orchestrator = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global orchestrator
    logger.info("Starting SENTINEL API")
    
    orchestrator = OrchestratorAgent()
    asyncio.create_task(orchestrator.start())
    
    yield
    
    if orchestrator:
        await orchestrator.shutdown()
    logger.info("SENTINEL API shutdown complete")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "operational"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "agents": orchestrator.agent_states if orchestrator else {},
        "timestamp": asyncio.get_event_loop().time()
    }

@app.get("/api/dashboard")
async def get_dashboard() -> Dict:
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    try:
        data = await orchestrator.get_dashboard_data()
        return data
    except Exception as e:
        logger.error(f"Dashboard data error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents")
async def get_incidents(
    limit: int = 50,
    status: str = None,
    severity: str = None
) -> List[Dict]:
    try:
        with db_manager.get_session() as session:
            from core.models import IncidentORM
            
            query = session.query(IncidentORM)
            
            if status:
                query = query.filter_by(status=status)
            if severity:
                query = query.filter_by(severity=severity)
            
            incidents = query.order_by(
                IncidentORM.timestamp.desc()
            ).limit(limit).all()
            
            return [
                {
                    "id": inc.id,
                    "timestamp": inc.timestamp.isoformat(),
                    "attack_type": inc.attack_type,
                    "severity": inc.severity,
                    "status": inc.status,
                    "source_ip": inc.source_ip,
                    "confidence_score": inc.confidence_score,
                    "auto_resolved": inc.auto_resolved
                }
                for inc in incidents
            ]
    
    except Exception as e:
        logger.error(f"Error fetching incidents: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents/{incident_id}")
async def get_incident_detail(incident_id: str) -> Dict:
    try:
        with db_manager.get_session() as session:
            from core.models import IncidentORM
            
            incident = session.query(IncidentORM).filter_by(id=incident_id).first()
            
            if not incident:
                raise HTTPException(status_code=404, detail="Incident not found")
            
            return {
                "id": incident.id,
                "timestamp": incident.timestamp.isoformat(),
                "attack_type": incident.attack_type,
                "severity": incident.severity,
                "status": incident.status,
                "source_ip": incident.source_ip,
                "destination_ip": incident.destination_ip,
                "confidence_score": incident.confidence_score,
                "indicators": incident.indicators,
                "investigation": incident.investigation_data,
                "remediation": incident.remediation_data,
                "financial_impact": incident.financial_impact_data,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
                "auto_resolved": incident.auto_resolved
            }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching incident detail: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/playbooks")
async def get_playbooks() -> List[Dict]:
    try:
        with db_manager.get_session() as session:
            from core.models import PlaybookORM
            
            playbooks = session.query(PlaybookORM).all()
            
            return [
                {
                    "id": pb.id,
                    "name": pb.name,
                    "attack_type": pb.attack_type,
                    "success_rate": pb.success_rate,
                    "avg_resolution_time": pb.avg_resolution_time,
                    "usage_count": pb.usage_count,
                    "created_at": pb.created_at.isoformat()
                }
                for pb in playbooks
            ]
    
    except Exception as e:
        logger.error(f"Error fetching playbooks: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/financial-report/{incident_id}")
async def get_financial_report(incident_id: str) -> Dict:
    try:
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Service unavailable")
        
        report = await orchestrator.economist.generate_executive_report(incident_id)
        
        return {
            "incident_id": incident_id,
            "report": report
        }
    
    except Exception as e:
        logger.error(f"Error generating financial report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
async def get_statistics() -> Dict:
    try:
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Service unavailable")
        
        stats = await orchestrator.librarian.get_knowledge_base_stats()
        
        with db_manager.get_session() as session:
            from core.models import IncidentORM
            from sqlalchemy import func
            from datetime import datetime, timedelta
            
            last_24h = datetime.utcnow() - timedelta(hours=24)
            incidents_24h = session.query(IncidentORM).filter(
                IncidentORM.timestamp >= last_24h
            ).count()
            
            total_prevented_cost = 0
            resolved_incidents = session.query(IncidentORM).filter_by(
                auto_resolved=True
            ).all()
            
            for inc in resolved_incidents:
                if inc.financial_impact_data:
                    total_prevented_cost += inc.financial_impact_data.get('total_impact', 0)
        
        stats.update({
            "incidents_last_24h": incidents_24h,
            "total_prevented_cost": total_prevented_cost
        })
        
        return stats
    
    except Exception as e:
        logger.error(f"Error fetching statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)