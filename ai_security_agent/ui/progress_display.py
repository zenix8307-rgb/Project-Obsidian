"""Progress display utilities for CLI."""
import sys
from typing import List, Dict, Any
from datetime import datetime

class ProgressDisplay:
    """Handles progress display in the terminal."""
    
    def __init__(self):
        self.current_phase = None
        self.phase_start_time = None
        self.phase_times = {}
    
    def start_phase(self, phase_name: str):
        """Start a new phase and display it."""
        self.current_phase = phase_name
        self.phase_start_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"▶ {phase_name}")
        print(f"{'='*60}")
    
    def update_phase(self, phase_name: str):
        """Update current phase display."""
        if phase_name != self.current_phase:
            if self.current_phase and self.phase_start_time:
                duration = datetime.now() - self.phase_start_time
                self.phase_times[self.current_phase] = duration
                print(f"✓ {self.current_phase} completed in {self._format_duration(duration)}")
            
            self.start_phase(phase_name)
    
    def show_progress(self, current: int, total: int, message: str = ""):
        """Show progress bar."""
        percentage = (current / total) * 100
        bar_length = 40
        filled_length = int(bar_length * current // total)
        
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        print(f"\r  [{bar}] {percentage:.1f}% {message}", end='')
        sys.stdout.flush()
        
        if current == total:
            print()
    
    def show_info(self, message: str):
        """Show info message."""
        print(f"ℹ {message}")
    
    def show_success(self, message: str):
        """Show success message."""
        print(f"✓ {message}")
    
    def show_warning(self, message: str):
        """Show warning message."""
        print(f"⚠ {message}")
    
    def show_error(self, message: str):
        """Show error message."""
        print(f"✗ {message}")
    
    def show_summary(self, findings: List[Dict[str, Any]]):
        """Show summary of findings."""
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        
        # Count by severity
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'Info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Display counts
        print(f"Total Findings: {len(findings)}")
        print(f"  Critical: {severity_counts['Critical']}")
        print(f"  High: {severity_counts['High']}")
        print(f"  Medium: {severity_counts['Medium']}")
        print(f"  Low: {severity_counts['Low']}")
        print(f"  Info: {severity_counts['Info']}")
        
        # Show top findings
        if findings:
            print(f"\nTop Critical Findings:")
            critical = [f for f in findings if f.get('severity') == 'Critical'][:3]
            for finding in critical:
                print(f"  • {finding.get('name', 'Unknown')}")
    
    def show_tool_start(self, tool_name: str):
        """Show tool execution start."""
        print(f"  → Running {tool_name}...")
    
    def show_tool_complete(self, tool_name: str, status: str = "success"):
        """Show tool execution completion."""
        if status == "success":
            print(f"    ✓ {tool_name} completed")
        else:
            print(f"    ✗ {tool_name} failed")
    
    def _format_duration(self, duration) -> str:
        """Format duration for display."""
        total_seconds = int(duration.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}m {seconds}s"
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"