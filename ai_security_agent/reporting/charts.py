"""Chart generator for security reports."""
from typing import Dict, List, Any
import json

class ChartGenerator:
    """Generates charts for security reports."""
    
    async def generate_all(self, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate all charts for the report.
        
        Args:
            data: Report data
        
        Returns:
            Dictionary mapping chart names to chart data (SVG/Base64)
        """
        charts = {
            'risk_distribution': await self.generate_risk_distribution(data.get('risk_distribution', {})),
            'findings_by_category': await self.generate_findings_by_category(data.get('findings', [])),
            'timeline': await self.generate_timeline_chart(data.get('timeline', []))
        }
        
        return charts
    
    async def generate_risk_distribution(self, distribution: Dict[str, int]) -> str:
        """Generate risk distribution pie chart (SVG)."""
        if not distribution:
            return ""
        
        # Simple SVG pie chart
        total = sum(distribution.values())
        if total == 0:
            return ""
        
        colors = {
            'Critical': '#ff7b72',
            'High': '#f0883e',
            'Medium': '#d29922',
            'Low': '#3fb950',
            'Info': '#8b949e'
        }
        
        # Generate pie chart segments
        start_angle = 0
        paths = []
        
        for severity, count in distribution.items():
            if count == 0:
                continue
            
            percentage = count / total
            angle = percentage * 360
            
            # Calculate SVG arc
            end_angle = start_angle + angle
            x1 = 100 + 80 * self._cos(start_angle)
            y1 = 100 + 80 * self._sin(start_angle)
            x2 = 100 + 80 * self._cos(end_angle)
            y2 = 100 + 80 * self._sin(end_angle)
            
            large_arc = 1 if angle > 180 else 0
            
            path = f'M 100 100 L {x1} {y1} A 80 80 0 {large_arc} 1 {x2} {y2} Z'
            paths.append(f'<path d="{path}" fill="{colors.get(severity, "#8b949e")}" />')
            
            start_angle = end_angle
        
        # Build SVG
        svg = f'''<svg width="200" height="200" viewBox="0 0 200 200">
            {''.join(paths)}
            <circle cx="100" cy="100" r="40" fill="var(--bg-primary)" />
        </svg>'''
        
        return svg
    
    async def generate_findings_by_category(self, findings: List[Dict[str, Any]]) -> str:
        """Generate findings by category bar chart."""
        categories = {}
        
        for finding in findings:
            category = finding.get('type', 'Other')
            categories[category] = categories.get(category, 0) + 1
        
        if not categories:
            return ""
        
        # Sort by count
        sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]
        
        max_count = max([c[1] for c in sorted_cats]) if sorted_cats else 1
        
        # Generate bars
        bars = []
        y_position = 20
        
        for category, count in sorted_cats:
            width = (count / max_count) * 150
            bars.append(f'''
                <text x="10" y="{y_position + 5}" fill="var(--text-primary)" font-size="10">{category[:15]}</text>
                <rect x="100" y="{y_position - 5}" width="{width}" height="15" fill="var(--accent)" />
                <text x="{100 + width + 5}" y="{y_position + 5}" fill="var(--text-secondary)" font-size="10">{count}</text>
            ''')
            y_position += 25
        
        svg = f'''<svg width="300" height="{20 + len(sorted_cats) * 25}" viewBox="0 0 300 {20 + len(sorted_cats) * 25}">
            {''.join(bars)}
        </svg>'''
        
        return svg
    
    async def generate_timeline_chart(self, timeline: List[Dict[str, Any]]) -> str:
        """Generate timeline Gantt chart."""
        if not timeline:
            return ""
        
        # Filter to main phases only
        phases = [item for item in timeline if not item.get('phase', '').startswith('  -')]
        
        if not phases:
            return ""
        
        # Generate Gantt chart
        y_position = 20
        bars = []
        
        for phase in phases:
            duration = phase.get('duration', '')
            # Simple representation - in production, parse actual timestamps
            bars.append(f'''
                <text x="10" y="{y_position + 5}" fill="var(--text-primary)" font-size="10">{phase.get('phase', '')}</text>
                <rect x="100" y="{y_position - 5}" width="150" height="15" fill="var(--accent)" opacity="0.7" />
                <text x="260" y="{y_position + 5}" fill="var(--text-secondary)" font-size="10">{duration}</text>
            ''')
            y_position += 25
        
        svg = f'''<svg width="350" height="{20 + len(phases) * 25}" viewBox="0 0 350 {20 + len(phases) * 25}">
            {''.join(bars)}
        </svg>'''
        
        return svg
    
    def _cos(self, degrees: float) -> float:
        """Cosine of angle in degrees."""
        import math
        return math.cos(math.radians(degrees))
    
    def _sin(self, degrees: float) -> float:
        """Sine of angle in degrees."""
        import math
        return math.sin(math.radians(degrees))