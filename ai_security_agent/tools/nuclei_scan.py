"""Nuclei vulnerability scanner module."""
import asyncio
from typing import List, Optional, Dict, Any
from pathlib import Path
import json

async def scan(
    target: str,
    executor: Any,
    output_file: Path,
    params: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Run nuclei scan against target.
    
    Args:
        target: Target URL
        executor: Command executor instance
        output_file: Path to save output
        params: Additional nuclei parameters
    
    Returns:
        Parsed scan results
    """
    params = params or ['-t', 'cves/', '-t', 'vulnerabilities/']
    
    # Build command
    command = ['nuclei']
    command.extend(params)
    command.extend(['-u', target])
    
    # Add JSON output
    json_file = output_file.with_suffix('.json')
    command.extend(['-json', '-o', str(json_file)])
    
    # Execute
    returncode, stdout, stderr = await executor.execute(command)
    
    results = {
        'target': target,
        'command': ' '.join(command),
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'json_file': str(json_file) if json_file.exists() else None,
        'findings': []
    }
    
    # Parse JSON output
    if json_file.exists():
        with open(json_file, 'r') as f:
            for line in f:
                try:
                    finding = json.loads(line)
                    results['findings'].append({
                        'template': finding.get('template-id', ''),
                        'name': finding.get('info', {}).get('name', ''),
                        'severity': finding.get('info', {}).get('severity', 'unknown'),
                        'description': finding.get('info', {}).get('description', ''),
                        'matched': finding.get('matched-at', ''),
                        'type': finding.get('type', '')
                    })
                except json.JSONDecodeError:
                    continue
    
    return results