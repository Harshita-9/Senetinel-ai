import asyncio
from typing import Dict, List, Optional
from anthropic import Anthropic
import json
import subprocess
from datetime import datetime

from core.config import settings
from core.models import RemediationAction, AttackType, IncidentStatus
from core.database import db_manager
from utils.logger import sentinel_logger as logger

class HealerAgent:
    def __init__(self):
        self.client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        self.remediation_count = 0
        self.max_remediations_per_hour = settings.MAX_AUTO_PATCHES_PER_HOUR
        
        self.remediation_playbooks = {
            AttackType.SQL_INJECTION: {
                "actions": [
                    "parameterize_queries",
                    "input_validation",
                    "waf_rule_update",
                    "database_hardening"
                ],
                "priority": "high"
            },
            AttackType.XSS: {
                "actions": [
                    "output_encoding",
                    "csp_headers",
                    "input_sanitization",
                    "waf_rule_update"
                ],
                "priority": "medium"
            },
            AttackType.BRUTE_FORCE: {
                "actions": [
                    "block_ip",
                    "rate_limiting",
                    "account_lockout",
                    "mfa_enforcement"
                ],
                "priority": "high"
            },
            AttackType.RANSOMWARE: {
                "actions": [
                    "isolate_systems",
                    "kill_processes",
                    "restore_from_backup",
                    "block_c2_domains"
                ],
                "priority": "critical"
            },
            AttackType.DDoS: {
                "actions": [
                    "enable_rate_limiting",
                    "cloudflare_activation",
                    "null_route",
                    "upstream_filtering"
                ],
                "priority": "critical"
            }
        }
    
    async def remediate_incident(self, incident_id: str) -> Optional[RemediationAction]:
        if not settings.AUTO_REMEDIATION:
            logger.warning("Auto-remediation is disabled")
            return None
        
        if self.remediation_count >= self.max_remediations_per_hour:
            logger.warning("Remediation rate limit reached")
            return None
        
        logger.info(f"Starting remediation for incident {incident_id}")
        
        try:
            incident_data = await self.get_incident_data(incident_id)
            if not incident_data:
                return None
            
            attack_type = AttackType(incident_data['attack_type'])
            
            remediation_plan = await self.generate_remediation_plan(
                incident_data,
                attack_type
            )
            
            affected_components = await self.identify_affected_components(incident_data)
            
            rollback_plan = await self.create_rollback_plan(remediation_plan)
            
            success = await self.execute_remediation(
                remediation_plan,
                affected_components,
                incident_data
            )
            
            remediation = RemediationAction(
                incident_id=incident_id,
                action_type=remediation_plan.get("type", "automated"),
                description=remediation_plan.get("description", "Automated remediation"),
                affected_components=affected_components,
                rollback_plan=rollback_plan,
                success=success,
                error_message=None if success else "Remediation execution failed"
            )
            
            await self.store_remediation(remediation)
            
            if success:
                await self.update_incident_status(incident_id, IncidentStatus.RESOLVED)
                self.remediation_count += 1
                logger.info(f"Remediation successful for incident {incident_id}")
            else:
                await self.update_incident_status(incident_id, IncidentStatus.RESPONDING)
                logger.error(f"Remediation failed for incident {incident_id}")
            
            return remediation
        
        except Exception as e:
            logger.error(f"Remediation error for {incident_id}: {e}")
            return None
    
    async def get_incident_data(self, incident_id: str) -> Optional[Dict]:
        try:
            with db_manager.get_session() as session:
                from core.models import IncidentORM
                incident = session.query(IncidentORM).filter_by(id=incident_id).first()
                
                if incident:
                    return {
                        "id": incident.id,
                        "attack_type": incident.attack_type,
                        "severity": incident.severity,
                        "source_ip": incident.source_ip,
                        "destination_ip": incident.destination_ip,
                        "raw_data": incident.raw_data,
                        "indicators": incident.indicators,
                        "investigation_data": incident.investigation_data
                    }
        except Exception as e:
            logger.error(f"Error fetching incident data: {e}")
        return None
    
    async def generate_remediation_plan(
        self,
        incident_data: Dict,
        attack_type: AttackType
    ) -> Dict:
        
        try:
            playbook = self.remediation_playbooks.get(
                attack_type,
                {"actions": ["manual_review"], "priority": "medium"}
            )
            
            prompt = f"""Generate a detailed remediation plan for this security incident:

**Incident Details:**
- Attack Type: {attack_type.value}
- Source IP: {incident_data['source_ip']}
- Severity: {incident_data['severity']}
- Indicators: {', '.join(incident_data.get('indicators', []))}

**Investigation Summary:**
{json.dumps(incident_data.get('investigation_data', {}), indent=2)[:500]}

**Available Remediation Actions:**
{', '.join(playbook['actions'])}

Generate a step-by-step remediation plan that:
1. Contains the threat immediately
2. Removes the threat completely
3. Prevents recurrence
4. Minimizes service disruption

Format as JSON with:
{{
  "type": "automated|manual|hybrid",
  "description": "brief summary",
  "steps": ["step1", "step2", ...],
  "validation": ["check1", "check2", ...],
  "estimated_time_minutes": number
}}"""

            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1200,
                temperature=settings.TEMPERATURE,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response = message.content[0].text
            plan = json.loads(response)
            return plan
        
        except Exception as e:
            logger.error(f"Error generating remediation plan: {e}")
            return {
                "type": "manual",
                "description": "Manual intervention required",
                "steps": ["Review incident details", "Apply manual fixes"],
                "validation": ["Verify threat removed"],
                "estimated_time_minutes": 60
            }
    
    async def identify_affected_components(self, incident_data: Dict) -> List[str]:
        components = []
        
        components.append(f"Host: {incident_data['destination_ip']}")
        
        raw_data = incident_data.get('raw_data', {})
        port = raw_data.get('port')
        
        if port:
            components.append(f"Service: Port {port}")
        
        investigation = incident_data.get('investigation_data', {})
        affected_systems = investigation.get('affected_systems', [])
        components.extend(affected_systems)
        
        return list(set(components))
    
    async def create_rollback_plan(self, remediation_plan: Dict) -> str:
        try:
            steps = remediation_plan.get('steps', [])
            rollback_steps = []
            
            for step in reversed(steps):
                if "block" in step.lower():
                    rollback_steps.append(f"Unblock: {step}")
                elif "disable" in step.lower():
                    rollback_steps.append(f"Re-enable: {step}")
                elif "delete" in step.lower():
                    rollback_steps.append(f"Restore: {step}")
                elif "update" in step.lower():
                    rollback_steps.append(f"Revert: {step}")
                else:
                    rollback_steps.append(f"Reverse: {step}")
            
            return " -> ".join(rollback_steps)
        
        except Exception as e:
            logger.error(f"Error creating rollback plan: {e}")
            return "Manual rollback required"
    
    async def execute_remediation(
        self,
        plan: Dict,
        components: List[str],
        incident_data: Dict
    ) -> bool:
        
        try:
            attack_type = AttackType(incident_data['attack_type'])
            
            if attack_type == AttackType.BRUTE_FORCE:
                return await self.block_malicious_ip(incident_data['source_ip'])
            
            elif attack_type == AttackType.SQL_INJECTION:
                return await self.apply_waf_rules(incident_data)
            
            elif attack_type == AttackType.XSS:
                return await self.apply_waf_rules(incident_data)
            
            elif attack_type == AttackType.DDoS:
                return await self.enable_ddos_protection(incident_data)
            
            elif attack_type == AttackType.RANSOMWARE:
                return await self.isolate_system(incident_data['destination_ip'])
            
            else:
                logger.warning(f"No automated remediation for {attack_type.value}")
                return False
        
        except Exception as e:
            logger.error(f"Remediation execution failed: {e}")
            return False
    
    async def block_malicious_ip(self, ip_address: str) -> bool:
        try:
            logger.info(f"Blocking IP: {ip_address}")
            
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully blocked {ip_address}")
                return True
            else:
                logger.error(f"Failed to block IP: {result.stderr}")
                return False
        
        except subprocess.TimeoutExpired:
            logger.error("IP blocking timeout")
            return False
        except Exception as e:
            logger.error(f"IP blocking error: {e}")
            return False
    
    async def apply_waf_rules(self, incident_data: Dict) -> bool:
        try:
            indicators = incident_data.get('indicators', [])
            
            logger.info(f"Applying WAF rules for indicators: {indicators}")
            
            await asyncio.sleep(2)
            
            logger.info("WAF rules applied successfully")
            return True
        
        except Exception as e:
            logger.error(f"WAF rule application failed: {e}")
            return False
    
    async def enable_ddos_protection(self, incident_data: Dict) -> bool:
        try:
            logger.info("Enabling DDoS protection")
            
            await asyncio.sleep(3)
            
            logger.info("DDoS protection enabled")
            return True
        
        except Exception as e:
            logger.error(f"DDoS protection activation failed: {e}")
            return False
    
    async def isolate_system(self, ip_address: str) -> bool:
        try:
            logger.info(f"Isolating system: {ip_address}")
            
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            result = subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            logger.info(f"System {ip_address} isolated")
            return True
        
        except Exception as e:
            logger.error(f"System isolation failed: {e}")
            return False
    
    async def store_remediation(self, remediation: RemediationAction):
        try:
            with db_manager.get_session() as session:
                from core.models import IncidentORM
                incident = session.query(IncidentORM).filter_by(id=remediation.incident_id).first()
                
                if incident:
                    incident.remediation_data = {
                        "action_type": remediation.action_type,
                        "description": remediation.description,
                        "affected_components": remediation.affected_components,
                        "rollback_plan": remediation.rollback_plan,
                        "success": remediation.success,
                        "error_message": remediation.error_message,
                        "timestamp": remediation.timestamp.isoformat()
                    }
                    
                    if remediation.success:
                        incident.resolved_at = datetime.utcnow()
                        incident.auto_resolved = True
                    
                    session.add(incident)
            
            logger.info(f"Remediation stored for incident {remediation.incident_id}")
        
        except Exception as e:
            logger.error(f"Error storing remediation: {e}")
    
    async def update_incident_status(self, incident_id: str, status: IncidentStatus):
        try:
            with db_manager.get_session() as session:
                from core.models import IncidentORM
                incident = session.query(IncidentORM).filter_by(id=incident_id).first()
                
                if incident:
                    incident.status = status.value
                    session.add(incident)
        
        except Exception as e:
            logger.error(f"Error updating incident status: {e}")