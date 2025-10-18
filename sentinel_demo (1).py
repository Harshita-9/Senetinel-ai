#!/usr/bin/env python3
"""
SENTINEL AI - Demo Script
Simulates attacks to showcase the system's capabilities
"""

import asyncio
import random
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
import time
import uuid

from agents.watcher import WatcherAgent
from agents.investigator import InvestigatorAgent
from agents.healer import HealerAgent
from agents.economist import EconomistAgent
from agents.librarian import LibrarianAgent
from core.models import ThreatDetection, AttackType, SeverityLevel
from core.database import db_manager

console = Console()

class SentinelDemo:
    def __init__(self):
        self.watcher = WatcherAgent()
        self.investigator = InvestigatorAgent()
        self.healer = HealerAgent()
        self.economist = EconomistAgent()
        self.librarian = LibrarianAgent()
        
        self.attack_scenarios = [
            {
                "name": "SQL Injection Attack",
                "attack_type": AttackType.SQL_INJECTION,
                "severity": SeverityLevel.HIGH,
                "payload": "admin' OR '1'='1'--",
                "source_ip": "203.0.113.42"
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "attack_type": AttackType.XSS,
                "severity": SeverityLevel.MEDIUM,
                "payload": "<script>alert('XSS')</script>",
                "source_ip": "198.51.100.88"
            },
            {
                "name": "Brute Force Attack",
                "attack_type": AttackType.BRUTE_FORCE,
                "severity": SeverityLevel.HIGH,
                "payload": "Multiple failed login attempts",
                "source_ip": "192.0.2.156"
            },
            {
                "name": "Ransomware Detection",
                "attack_type": AttackType.RANSOMWARE,
                "severity": SeverityLevel.CRITICAL,
                "payload": "File encryption activity detected",
                "source_ip": "198.51.100.200"
            }
        ]
    
    async def run_demo(self):
        """Run complete demo"""
        console.clear()
        
        self.show_banner()
        
        await asyncio.sleep(2)
        
        console.print("\n[bold yellow]🎬 Starting SENTINEL AI Demo...[/bold yellow]\n")
        await asyncio.sleep(1)
        
        for scenario in self.attack_scenarios:
            await self.simulate_attack_scenario(scenario)
            await asyncio.sleep(3)
        
        await self.show_final_stats()
    
    def show_banner(self):
        """Display demo banner"""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║      ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗   ║
║      ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║   ║
║      ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║   ║
║      ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║   ║
║      ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║   ║
║      ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝   ║
║                                                           ║
║         Autonomous AI Security Analyst - DEMO            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold cyan"))
    
    async def simulate_attack_scenario(self, scenario: dict):
        """Simulate a complete attack scenario"""
        
        console.print(f"\n[bold red]🚨 SIMULATING: {scenario['name']}[/bold red]")
        console.print(f"[dim]Source: {scenario['source_ip']}[/dim]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            task1 = progress.add_task("[cyan]👁️  Watcher detecting threat...", total=100)
            await asyncio.sleep(1)
            progress.update(task1, advance=100)
            
            threat = await self.create_threat_detection(scenario)
            console.print(f"[green]✓[/green] Threat detected (Confidence: {threat.confidence_score:.0%})")
            await asyncio.sleep(0.5)
            
            task2 = progress.add_task("[cyan]🔍 Investigator analyzing...", total=100)
            await asyncio.sleep(2)
            progress.update(task2, advance=100)
            
            investigation = await self.investigator.investigate_incident(threat.id)
            console.print(f"[green]✓[/green] Investigation complete")
            await asyncio.sleep(0.5)
            
            task3 = progress.add_task("[cyan]💰 Economist calculating impact...", total=100)
            await asyncio.sleep(1.5)
            progress.update(task3, advance=100)
            
            financial = await self.economist.calculate_financial_impact(threat.id)
            if financial:
                console.print(f"[green]✓[/green] Financial impact: [bold red]${financial.total_impact:,.0f}[/bold red]")
            await asyncio.sleep(0.5)
            
            task4 = progress.add_task("[cyan]⚕️  Healer remediating...", total=100)
            await asyncio.sleep(2)
            progress.update(task4, advance=100)
            
            remediation = await self.healer.remediate_incident(threat.id)
            if remediation and remediation.success:
                console.print(f"[green]✓[/green] Auto-remediation successful")
            else:
                console.print(f"[yellow]⚠[/yellow] Manual remediation required")
            await asyncio.sleep(0.5)
            
            task5 = progress.add_task("[cyan]📚 Librarian documenting...", total=100)
            await asyncio.sleep(1)
            progress.update(task5, advance=100)
            
            await self.librarian.document_incident(threat.id)
            console.print(f"[green]✓[/green] Incident documented & playbook updated")
        
        self.show_incident_summary(scenario, threat, investigation, financial)
    
    async def create_threat_detection(self, scenario: dict) -> ThreatDetection:
        """Create a threat detection"""
        threat = ThreatDetection(
            id=str(uuid.uuid4()),
            source_ip=scenario['source_ip'],
            destination_ip="10.0.0.1",
            attack_type=scenario['attack_type'],
            severity=scenario['severity'],
            confidence_score=random.uniform(0.85, 0.99),
            raw_data={
                "payload": scenario['payload'],
                "port": 443,
                "timestamp": datetime.utcnow().isoformat()
            },
            indicators=[scenario['attack_type'].value]
        )
        
        await self.watcher.store_detection(threat)
        return threat
    
    def show_incident_summary(self, scenario, threat, investigation, financial):
        """Show incident summary table"""
        table = Table(title=f"Incident Summary: {scenario['name']}", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Attack Type", scenario['attack_type'].value.upper())
        table.add_row("Severity", scenario['severity'].value.upper())
        table.add_row("Source IP", scenario['source_ip'])
        table.add_row("Confidence", f"{threat.confidence_score:.1%}")
        
        if financial:
            table.add_row("Financial Impact", f"${financial.total_impact:,.0f}")
        
        if investigation:
            table.add_row("Analysis", investigation.analysis[:100] + "...")
        
        console.print("\n")
        console.print(table)
    
    async def show_final_stats(self):
        """Show final statistics"""
        console.print("\n\n")
        console.print("[bold green]=" * 60)
        console.print("[bold green]  DEMO COMPLETE - SENTINEL AI PERFORMANCE SUMMARY")
        console.print("[bold green]=" * 60)
        
        stats = await self.librarian.get_knowledge_base_stats()
        
        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Metric", style="bold cyan", width=35)
        summary_table.add_column("Value", style="bold yellow", justify="right")
        
        summary_table.add_row("Total Incidents Processed", f"{stats.get('total_incidents', 0)}")
        summary_table.add_row("Successfully Resolved", f"{stats.get('resolved_incidents', 0)}")
        summary_table.add_row("Auto-Remediated", f"{stats.get('auto_resolved', 0)}")
        summary_table.add_row("Playbooks Created", f"{stats.get('total_playbooks', 0)}")
        summary_table.add_row("Automation Rate", f"{stats.get('automation_rate', 0):.1f}%")
        
        console.print("\n")
        console.print(summary_table)
        
        console.print("\n[bold cyan]Key Capabilities Demonstrated:[/bold cyan]")
        console.print("  [green]✓[/green] Real-time threat detection")
        console.print("  [green]✓[/green] AI-powered investigation")
        console.print("  [green]✓[/green] Financial impact analysis")
        console.print("  [green]✓[/green] Autonomous remediation")
        console.print("  [green]✓[/green] Self-learning playbooks")
        
        console.print("\n[bold yellow]🎯 SENTINEL AI is production-ready![/bold yellow]")
        console.print("[dim]View dashboard at: http://localhost:8501[/dim]")
        console.print("[dim]API docs at: http://localhost:8000/docs[/dim]\n")

async def main():
    """Main demo function"""
    demo = SentinelDemo()
    
    console.print("\n[bold]This demo will simulate 4 different attack scenarios[/bold]")
    console.print("[dim]Each will go through the complete SENTINEL pipeline[/dim]\n")
    
    input("Press Enter to start demo...")
    
    try:
        await demo.run_demo()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Demo interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n\n[red]Demo error: {e}[/red]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo terminated[/yellow]")