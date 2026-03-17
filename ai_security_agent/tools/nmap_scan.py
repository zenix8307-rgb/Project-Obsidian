"""Nmap scanning module."""
import asyncio
from typing import List, Optional, Dict, Any
from pathlib import Path
import re

async def scan(
    target: str,
    executor: Any,
    output_file: Path,
    params: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Run nmap scan against target.
    
    Args:
        target: Target domain or IP
        executor: Command executor instance
        output_file: Path to save output
        params: Additional nmap parameters
    
    Returns:
        Parsed scan results
    """
    params = params or ['-sV', '-sC', '-O', '-T4']
    
    # Build command
    command = ['nmap']
    command.extend(params)
    command.append(target)
    
    # Add XML output for parsing
    xml_file = output_file.with_suffix('.xml')
    command.extend(['-oX', str(xml_file)])
    
    # Execute
    returncode, stdout, stderr = await executor.execute(command)
    
    # Parse results
    results = {
        'target': target,
        'command': ' '.join(command),
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'xml_file': str(xml_file) if xml_file.exists() else None,
        'ports': [],
        'services': [],
        'os': None
    }
    
    # Parse port information
    if returncode == 0:
        # Parse open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)'
        for line in stdout.split('\n'):
            match = re.search(port_pattern, line)
            if match:
                port, service, version = match.groups()
                results['ports'].append({
                    'port': int(port),
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service,
                    'version': version.strip()
                })
            
            # OS detection
            if 'OS:' in line:
                results['os'] = line.replace('OS:', '').strip()
    
    # Save parsed results
    with open(output_file, 'w') as f:
        import json
        json.dump(results, f, indent=2)
    
    return results