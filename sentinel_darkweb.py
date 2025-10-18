"""
SECRET WEAPON #1: Dark Web Monitoring
Monitors paste sites and dark web sources for leaked credentials and threats
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional
from datetime import datetime
import re
import hashlib

from core.config import settings
from core.database import db_manager
from utils.logger import sentinel_logger as logger

class DarkWebMonitor:
    def __init__(self):
        self.paste_sites = [
            "https://pastebin.com/api_scraping.php",
            "https://ghostbin.com/api/recent",
            "https://privatebin.net/api/pastes"
        ]
        
        self.monitored_keywords = [
            "password", "credentials", "api_key", "secret",
            "breach", "dump", "database", "leaked"
        ]
        
        self.email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        self.ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        self.api_key_pattern = r'[A-Za-z0-9]{32,}'
        
        self.active = False
    
    async def start_monitoring(self):
        """Start continuous dark web monitoring"""
        if not settings.DARK_WEB_ENABLED:
            logger.warning("Dark Web monitoring is disabled in config")
            return
        
        self.active = True
        logger.info("🕵️ Dark Web Monitor: ACTIVE")
        
        while self.active:
            try:
                await self.scan_paste_sites()
                await self.scan_breach_databases()
                await asyncio.sleep(3600)
            except Exception as e:
                logger.error(f"Dark web monitoring error: {e}")
                await asyncio.sleep(300)
    
    async def scan_paste_sites(self):
        """Scan public paste sites for leaked data"""
        logger.info("Scanning paste sites...")
        
        async with aiohttp.ClientSession() as session:
            tasks = [
                self.scan_pastebin(session),
                self.scan_ghostbin(session)
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def scan_pastebin(self, session: aiohttp.ClientSession):
        """Scan Pastebin for sensitive data"""
        try:
            url = "https://scrape.pastebin.com/api_scraping.php"
            params = {"limit": 100}
            
            async with session.get(url, params=params, timeout=30) as response:
                if response.status == 200:
                    pastes = await response.json()
                    
                    for paste in pastes:
                        await self.analyze_paste(paste)
        
        except Exception as e:
            logger.debug(f"Pastebin scan error: {e}")
    
    async def scan_ghostbin(self, session: aiohttp.ClientSession):
        """Scan Ghostbin for sensitive data"""
        try:
            url = "https://ghostbin.com/api/recent"
            
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    pastes = await response.json()
                    
                    for paste in pastes:
                        await self.analyze_paste(paste)
        
        except Exception as e:
            logger.debug(f"Ghostbin scan error: {e}")
    
    async def analyze_paste(self, paste_data: Dict):
        """Analyze paste content for sensitive data"""
        try:
            content = paste_data.get('content', '').lower()
            title = paste_data.get('title', '').lower()
            
            if not content:
                return
            
            relevance_score = 0
            findings = []
            
            for keyword in self.monitored_keywords:
                if keyword in content or keyword in title:
                    relevance_score += 1
                    findings.append(f"keyword:{keyword}")
            
            emails = re.findall(self.email_pattern, content)
            if emails:
                relevance_score += len(emails) * 2
                findings.append(f"emails:{len(emails)}")
            
            ips = re.findall(self.ip_pattern, content)
            if ips:
                relevance_score += len(ips)
                findings.append(f"ips:{len(ips)}")
            
            api_keys = re.findall(self.api_key_pattern, content)
            if api_keys:
                relevance_score += len(api_keys) * 3
                findings.append(f"api_keys:{len(api_keys)}")
            
            if relevance_score >= 3:
                await self.create_alert({
                    "source": "paste_site",
                    "paste_id": paste_data.get('key', 'unknown'),
                    "url": paste_data.get('url', ''),
                    "title": paste_data.get('title', 'Untitled'),
                    "relevance_score": relevance_score,
                    "findings": findings,
                    "emails_found": emails[:10],
                    "timestamp": datetime.utcnow()
                })
                
                logger.warning(f"⚠️ Potential data leak detected: {paste_data.get('title', 'Untitled')} (score: {relevance_score})")
        
        except Exception as e:
            logger.debug(f"Paste analysis error: {e}")
    
    async def scan_breach_databases(self):
        """Check for organization in known breach databases"""
        logger.info("Checking breach databases...")
        
        domains_to_monitor = self.get_monitored_domains()
        
        for domain in domains_to_monitor:
            await self.check_haveibeenpwned(domain)
    
    def get_monitored_domains(self) -> List[str]:
        """Get list of domains to monitor"""
        return [
            "example.com",
            "company.com"
        ]
    
    async def check_haveibeenpwned(self, domain: str):
        """Check domain against HaveIBeenPwned API"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{domain}"
                headers = {
                    "User-Agent": "SENTINEL-AI-Security-Monitor"
                }
                
                async with session.get(url, headers=headers, timeout=30) as response:
                    if response.status == 200:
                        breaches = await response.json()
                        
                        if breaches:
                            await self.create_alert({
                                "source": "haveibeenpwned",
                                "domain": domain,
                                "breaches_found": len(breaches),
                                "breach_names": [b.get('Name') for b in breaches[:5]],
                                "timestamp": datetime.utcnow()
                            })
                            
                            logger.warning(f"⚠️ {domain} found in {len(breaches)} breaches")
        
        except Exception as e:
            logger.debug(f"HaveIBeenPwned check error: {e}")
    
    async def create_alert(self, alert_data: Dict):
        """Create alert for detected threat"""
        try:
            alert_id = hashlib.sha256(
                f"{alert_data.get('source')}{alert_data.get('timestamp')}".encode()
            ).hexdigest()[:16]
            
            with db_manager.get_session() as session:
                from core.models import ThreatIntelORM
                
                threat = ThreatIntelORM(
                    id=alert_id,
                    source=alert_data.get('source', 'dark_web'),
                    threat_type='data_leak',
                    ioc_type='paste',
                    ioc_value=alert_data.get('paste_id', alert_data.get('domain', 'unknown')),
                    confidence=alert_data.get('relevance_score', 5) / 10.0,
                    metadata=alert_data
                )
                session.add(threat)
            
            logger.info(f"Dark web alert created: {alert_id}")
        
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
    
    def stop(self):
        """Stop monitoring"""
        self.active = False
        logger.info("Dark Web Monitor: STOPPED")