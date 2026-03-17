"""Searchsploit exploit lookup module."""
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
    Run searchsploit lookup.
    
    Args:
        target: Search term (service, CVE, etc.)
        executor: Command executor instance
        output_file: Path to save output
        params: Additional searchsploit parameters
    
    Returns:
        Parsed search results
    """
    params = params or []
    
    # Build command
    command = ['searchsploit']
    command.extend(params)
    command.append(target)
    
    # Execute
    returncode, stdout, stderr = await executor.execute(command)
    
    results = {
        'search_term': target,
        'command': ' '.join(command),
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'exploits': []
    }
    
    # Parse exploits found
    if returncode == 0:
        lines = stdout.split('\n')
        start_parsing = False
        
        for line in lines:
            if '----' in line:
                start_parsing = True
                continue
            
            if start_parsing and line.strip():
                # Parse exploit line
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 3:
                    results['exploits'].append({
                        'path': parts[0] if len(parts) > 0 else '',
                        'title': parts[1] if len(parts) > 1 else '',
                        'type': parts[2] if len(parts) > 2 else ''
                    })
    
    return results