"""Gobuster directory enumeration module."""
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
    Run gobuster scan against target.
    
    Args:
        target: Target URL
        executor: Command executor instance
        output_file: Path to save output
        params: Additional gobuster parameters
    
    Returns:
        Parsed scan results
    """
    params = params or ['dir']
    
    # Default wordlist
    wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
    
    # Build command
    command = ['gobuster']
    command.extend(params)
    command.extend(['-u', target, '-w', wordlist])
    
    # Execute
    returncode, stdout, stderr = await executor.execute(command)
    
    results = {
        'target': target,
        'command': ' '.join(command),
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'directories': []
    }
    
    # Parse directories found
    if returncode == 0:
        dir_pattern = r'/(\S+)\s+\(Status:\s*(\d+)\)'
        for line in stdout.split('\n'):
            match = re.search(dir_pattern, line)
            if match:
                directory, status = match.groups()
                results['directories'].append({
                    'path': f"/{directory}",
                    'status': int(status)
                })
    
    return results