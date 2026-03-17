"""Dirsearch directory enumeration module."""
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
    Run dirsearch scan against target.
    
    Args:
        target: Target URL
        executor: Command executor instance
        output_file: Path to save output
        params: Additional dirsearch parameters
    
    Returns:
        Parsed scan results
    """
    params = params or []
    
    # Build command
    command = ['dirsearch']
    command.extend(params)
    command.extend(['-u', target])
    
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
    
    # Parse results
    if returncode == 0:
        dir_pattern = r'(\d+)\s+(\d+\w+)\s+(\S+)$'
        for line in stdout.split('\n'):
            match = re.search(dir_pattern, line)
            if match:
                status, size, path = match.groups()
                results['directories'].append({
                    'path': path,
                    'status': int(status),
                    'size': size
                })
    
    return results