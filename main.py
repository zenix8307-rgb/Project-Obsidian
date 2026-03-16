#!/usr/bin/env python3
"""
AI-Powered Security Auditing Assistant
Main entry point for the application.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from ui.cli_interface import CLIInterface

async def main():
    """Main entry point."""
    cli = CLIInterface()
    await cli.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)