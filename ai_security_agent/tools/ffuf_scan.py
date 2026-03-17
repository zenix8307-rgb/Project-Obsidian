"""FFUF fuzzing module."""
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
    Run ffuf scan against target.
    
    Args:
        target: Target URL with FUZZ keyword
        executor: Command executor instance
        output_file: Path to save output
        params: Additional ffuf parameters
    
    Returns:
        Parsed scan results
    """
    params = params or []
    
    # Default wordlist
    wordlist = '/usr/share/wordlists/dirb/common.txt'
    
    # Build command
    command = ['ffuf']
    command.extend(params)
    command.extend(['-u', target, '-w', wordlist])
    
    # Add JSON output
    json_file = output_file.with_suffix('.json')
    command.extend(['-o', str(json_file), '-of', 'json'])
    
    # Execute
    returncode, stdout, stderr = await executor.execute(command)
    
    results = {
        'target': target,
        'command': ' '.join(command),
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'json_file': str(json_file) if json_file.exists() else None,
        'results': []
    }
    
    # Parse JSON output
    if json_file.exists():
        with open(json_file, 'r') as f:
            try:
                data = json.load(f)
                results['results'] = data.get('results', [])
            except json.JSONDecodeError:
                pass
    
    return results