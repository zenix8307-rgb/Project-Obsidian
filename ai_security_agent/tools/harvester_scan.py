"""theHarvester OSINT gathering module."""
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
    Run theHarvester scan against target.
    
    Args:
        target: Target domain
        executor: Command executor instance
        output_file: Path to save output
        params: Additional theHarvester parameters
    
    Returns:
        Parsed scan results
    """
    params = params or []
    
    # Build command
    command = ['theharvester']
    command.extend(params)
    command.extend(['-d', target, '-b', 'all'])
    
    # Execute
    returncode, stdout, stderr = await executor.execute(command)
    
    results = {
        'target': target,
        'command': ' '.join(command),
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'emails': [],
        'hosts': [],
        'subdomains': []
    }
    
    # Parse results
    if returncode == 0:
        current_section = None
        for line in stdout.split('\n'):
            line = line.strip()
            
            if 'Emails found:' in line:
                current_section = 'emails'
                continue
            elif 'Hosts found:' in line:
                current_section = 'hosts'
                continue
            elif 'Subdomains found:' in line:
                current_section = 'subdomains'
                continue
            
            if current_section == 'emails' and '@' in line:
                results['emails'].append(line)
            elif current_section == 'hosts' and line.startswith('http'):
                results['hosts'].append(line)
            elif current_section == 'subdomains' and line and not line.startswith('---'):
                results['subdomains'].append(line)
    
    return results