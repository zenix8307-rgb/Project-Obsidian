"""WhatWeb technology detection module."""
import asyncio
from typing import List, Optional, Dict, Any
from pathlib import Path

async def scan(
    target: str,
    executor: Any,
    output_file: Path,
    params: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Run whatweb scan against target.
    
    Args:
        target: Target URL
        executor: Command executor instance
        output_file: Path to save output
        params: Additional whatweb parameters
    
    Returns:
        Parsed scan results
    """
    params = params or ['-a', '3']
    
    # Build command
    command = ['whatweb']
    command.extend(params)
    command.append(target)
    
    # Execute
    returncode, stdout, stderr = await executor.execute(command)
    
    results = {
        'target': target,
        'command': ' '.join(command),
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'technologies': []
    }
    
    # Parse technologies found
    if returncode == 0 and stdout:
        # WhatWeb output format: "http://target.com [status] Title, Technology1, Technology2"
        if '[' in stdout and ']' in stdout:
            tech_part = stdout.split(']')[-1].strip()
            techs = [t.strip() for t in tech_part.split(',') if t.strip()]
            results['technologies'] = techs
    
    return results