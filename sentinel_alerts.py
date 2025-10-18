"""
BONUS FEATURE: Multi-Channel Alert System
Email, Slack, and webhook notifications for critical incidents
"""

import asyncio
import aiohttp
from typing import Dict, List
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from core.config import settings
from utils.logger import sentinel_logger as logger

class AlertSystem:
    def __init__(self):
        self.email_enabled = getattr(settings, 'EMAIL_ENABLED', False)
        self.slack_enabled = getattr(settings, 'SLACK_ENABLED', False)
        self.webhook_enabled = getattr(settings, 'WEBHOOK_ENABLED', False)
        
        # Email config
        self.smtp_server = getattr(settings, 'SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = getattr(settings, 'SMTP_PORT', 587)
        self.smtp_user = getattr(settings, 'SMTP_USER', '')
        self.smtp_password = getattr(settings, 'SMTP_PASSWORD', '')
        self.alert_recipients = getattr(settings, 'ALERT_RECIPIENTS', [])
        
        # Slack config
        self.slack_webhook_url = getattr(settings, 'SLACK_WEBHOOK_URL', '')
        
        # Custom webhook
        self.webhook_url = getattr(settings, 'WEBHOOK_URL', '')
    
    async def send_alert(
        self,
        incident_id: str,
        severity: str,
        attack_type: str,
        financial_impact: float = 0,
        summary: str = ""
    ):
        """Send alert through all configured channels"""
        
        alert_data = {
            "incident_id": incident_id,
            "severity": severity,
            "attack_type": attack_type,
            "financial_impact": financial_impact,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        tasks = []
        
        if self.email_enabled and severity in ['high', 'critical']:
            tasks.append(self.send_email_alert(alert_data))
        
        if self.slack_enabled:
            tasks.append(self.send_slack_alert(alert_data))
        
        if self.webhook_enabled:
            tasks.append(self.send_webhook_alert(alert_data))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_email_alert(self, alert_data: Dict):
        """Send email alert"""
        try:
            subject = f"🚨 SENTINEL ALERT: {alert_data['severity'].upper()} - {alert_data['attack_type']}"
            
            body = f"""
SENTINEL AI Security Alert
{'=' * 50}

Incident ID: {alert_data['incident_id']}
Severity: {alert_data['severity'].upper()}
Attack Type: {alert_data['attack_type']}
Financial Impact: ${alert_data['financial_impact']:,.2f}
Timestamp: {alert_data['timestamp']}

Summary:
{alert_data['summary']}

{'=' * 50}
View details: http://localhost:8501

This is an automated alert from SENTINEL AI.
"""
            
            msg = MIMEMultipart()
            msg['From'] = self.smtp_user
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                
                for recipient in self.alert_recipients:
                    msg['To'] = recipient
                    server.send_message(msg)
            
            logger.info(f"Email alert sent for incident {alert_data['incident_id']}")
        
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
    
    async def send_slack_alert(self, alert_data: Dict):
        """Send Slack alert"""
        try:
            severity_emoji = {
                'low': '🟢',
                'medium': '🟡',
                'high': '🟠',
                'critical': '🔴'
            }.get(alert_data['severity'], '⚪')
            
            message = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{severity_emoji} SENTINEL Security Alert"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Severity:*\n{alert_data['severity'].upper()}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Attack Type:*\n{alert_data['attack_type']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Incident ID:*\n`{alert_data['incident_id']}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Financial Impact:*\n${alert_data['financial_impact']:,.2f}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Summary:*\n{alert_data['summary'][:200]}..."
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "View Dashboard"
                                },
                                "url": "http://localhost:8501"
                            }
                        ]
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.slack_webhook_url, json=message) as response:
                    if response.status == 200:
                        logger.info(f"Slack alert sent for incident {alert_data['incident_id']}")
                    else:
                        logger.error(f"Slack alert failed: {response.status}")
        
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
    
    async def send_webhook_alert(self, alert_data: Dict):
        """Send webhook alert to custom endpoint"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=alert_data) as response:
                    if response.status == 200:
                        logger.info(f"Webhook alert sent for incident {alert_data['incident_id']}")
                    else:
                        logger.error(f"Webhook alert failed: {response.status}")
        
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")

alert_system = AlertSystem()