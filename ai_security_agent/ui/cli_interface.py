"""Command-line interface for the security agent."""
import asyncio
import argparse
import sys
from typing import Optional
from pathlib import Path

from ..core.agent import SecurityAgent
from ..core.config import Config
from ..core.logger import setup_logging
from .progress_display import ProgressDisplay

class CLIInterface:
    """Command-line interface for interacting with the security agent."""
    
    def __init__(self):
        self.config = Config()
        self.logger = setup_logging()
        self.agent: Optional[SecurityAgent] = None
        self.progress = ProgressDisplay()
    
    async def run(self):
        """Run the CLI interface."""
        parser = self._create_parser()
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        # Initialize agent
        self.progress.show_info("Initializing Security Agent...")
        self.agent = SecurityAgent()
        await self.agent.start()
        
        try:
            # Execute command
            if args.command == 'scan':
                await self._cmd_scan(args)
            elif args.command == 'full-audit':
                await self._cmd_full_audit(args)
            elif args.command == 'report':
                await self._cmd_report(args)
            elif args.command == 'list':
                await self._cmd_list()
            elif args.command == 'status':
                await self._cmd_status()
            else:
                parser.print_help()
        finally:
            await self.agent.stop()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            description='AI-Powered Security Auditing Assistant',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python main.py scan example.com
  python main.py scan example.com --quick
  python main.py full-audit example.com
  python main.py report example.com
  python main.py list
  python main.py status
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Run a security scan')
        scan_parser.add_argument('target', help='Target domain or IP')
        scan_parser.add_argument('--quick', action='store_true', help='Quick scan')
        scan_parser.add_argument('--web', action='store_true', help='Web-focused scan')
        scan_parser.add_argument('--output', '-o', help='Output file for results')
        
        # Full audit command
        audit_parser = subparsers.add_parser('full-audit', help='Run comprehensive full audit')
        audit_parser.add_argument('target', help='Target domain or IP')
        audit_parser.add_argument('--output', '-o', help='Output directory for results')
        
        # Report command
        report_parser = subparsers.add_parser('report', help='Generate report from previous scan')
        report_parser.add_argument('target', help='Target domain or IP')
        report_parser.add_argument('--format', choices=['html', 'pdf', 'json'], default='html', help='Report format')
        report_parser.add_argument('--output', '-o', help='Output file')
        
        # List command
        subparsers.add_parser('list', help='List previous scans')
        
        # Status command
        subparsers.add_parser('status', help='Show agent status')
        
        return parser
    
    async def _cmd_scan(self, args):
        """Handle scan command."""
        self.progress.show_info(f"Starting scan on target: {args.target}")
        
        scan_type = "quick" if args.quick else ("targeted" if args.web else "full")
        
        options = {}
        if args.web:
            options['web_scan'] = True
        
        # Run scan with progress
        async for phase in self._run_scan_with_progress(args.target, scan_type, options):
            self.progress.update_phase(phase)
        
        self.progress.show_success(f"Scan completed for {args.target}")
        
        # Show summary
        results = self.agent.scan_results.get(args.target, {})
        findings = results.get('analysis', {}).get('vulnerabilities', [])
        self.progress.show_summary(findings)
        
        # Save output if requested
        if args.output:
            await self._save_output(args.output, results)
    
    async def _cmd_full_audit(self, args):
        """Handle full-audit command."""
        self.progress.show_info(f"Starting full audit on target: {args.target}")
        
        # Run audit with phases
        phases = [
            'Phase 1: Initial Reconnaissance',
            'Phase 2: Service Enumeration',
            'Phase 3: Vulnerability Scanning',
            'Phase 4: Deep Analysis',
            'Phase 5: Report Generation'
        ]
        
        for phase in phases:
            self.progress.start_phase(phase)
            await asyncio.sleep(1)  # Simulate work
        
        results = await self.agent.run_full_audit(args.target)
        
        self.progress.show_success(f"Full audit completed for {args.target}")
        
        # Show report location
        if results.get('report_path'):
            self.progress.show_info(f"Report saved to: {results['report_path']}")
    
    async def _cmd_report(self, args):
        """Handle report command."""
        self.progress.show_info(f"Generating report for {args.target}")
        
        # Check if results exist
        if args.target not in self.agent.scan_results:
            self.progress.show_error(f"No scan results found for {args.target}")
            return
        
        # Generate report
        report_path = await self.agent.generate_report(args.target)
        
        self.progress.show_success(f"Report generated: {report_path}")
    
    async def _cmd_list(self):
        """Handle list command."""
        history = self.agent.get_scan_history()
        
        if not history:
            self.progress.show_info("No previous scans found")
            return
        
        self.progress.show_info("Previous Scans:")
        for entry in history:
            self.progress.show_info(
                f"  • {entry['target']} - "
                f"First: {entry.get('first_seen', 'Unknown')} - "
                f"Scans: {entry.get('scan_count', 0)}"
            )
    
    async def _cmd_status(self):
        """Handle status command."""
        status = self.agent.get_status()
        
        self.progress.show_info("Agent Status:")
        self.progress.show_info(f"  • Running: {status['is_running']}")
        self.progress.show_info(f"  • Scans completed: {status['scans_completed']}")
        self.progress.show_info(f"  • Targets in memory: {status['memory_stats']['targets']}")
        self.progress.show_info(f"  • Task manager: {status['task_manager_status']}")
    
    async def _run_scan_with_progress(self, target: str, scan_type: str, options: dict):
        """Run scan and yield phases for progress display."""
        phases = [
            'Planning scan strategy',
            'Running initial reconnaissance',
            'Analyzing results',
            'Running targeted scans',
            'Generating report'
        ]
        
        for phase in phases:
            yield phase
            await asyncio.sleep(1)  # Simulate work
        
        # Actually run the scan
        await self.agent.run_scan(target, scan_type, options)
    
    async def _save_output(self, output_path: str, results: dict):
        """Save results to file."""
        import json
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.progress.show_success(f"Results saved to {path}")