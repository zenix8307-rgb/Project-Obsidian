"""Configuration management for the security agent."""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """Central configuration manager for the security agent."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize configuration with default values."""
        self.base_dir = Path(__file__).parent.parent
        self.data_dir = self.base_dir / 'data'
        self.scans_dir = self.data_dir / 'scans'
        self.reports_dir = self.data_dir / 'reports'
        self.cache_dir = self.data_dir / 'cache'
        self.logs_dir = self.data_dir / 'logs'
        self.models_dir = self.base_dir / 'models'
        
        # Create directories if they don't exist
        for dir_path in [self.scans_dir, self.reports_dir, self.cache_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # LLM Configuration
        self.llm_model_path = self.models_dir / 'Gemma-2b-Uncensored-v1.Q5_K_S.gguf'
        self.llama_cpp_path = self._find_llama_cpp()
        
        # Tool Configuration
        self.tool_timeout = 1800  # 30 minutes default timeout
        self.max_concurrent_tools = 3
        self.scan_retry_count = 2
        
        # Report Configuration
        self.company_name = "AI Security Agent"
        self.report_author = "Automated Security Assistant"
        
        # Load user config if exists
        self._load_user_config()
    
    def _find_llama_cpp(self) -> Optional[Path]:
        """Find llama.cpp executable in common locations."""
        common_paths = [
            '/usr/local/bin/main',
            '/usr/bin/main',
            self.base_dir / 'llama.cpp' / 'main',
            self.base_dir / 'vendor' / 'llama.cpp' / 'main'
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return Path(path)
        
        # If not found, assume it's in PATH
        return Path('main')
    
    def _load_user_config(self):
        """Load user configuration from file if exists."""
        config_file = self.base_dir / 'config.json'
        if config_file.exists():
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                for key, value in user_config.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tool."""
        tool_configs = {
            'nmap': {
                'timeout': 1200,
                'default_options': ['-sV', '-sC', '-O', '--osscan-guess']
            },
            'gobuster': {
                'timeout': 1800,
                'wordlist': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
            },
            'ffuf': {
                'timeout': 1800,
                'wordlist': '/usr/share/wordlists/dirb/common.txt'
            },
            'sqlmap': {
                'timeout': 3600,
                'risk': 3,
                'level': 5
            }
        }
        return tool_configs.get(tool_name, {})
    
    def save(self):
        """Save current configuration to file."""
        config_file = self.base_dir / 'config.json'
        config_data = {
            'tool_timeout': self.tool_timeout,
            'max_concurrent_tools': self.max_concurrent_tools,
            'scan_retry_count': self.scan_retry_count,
            'company_name': self.company_name,
            'report_author': self.report_author
        }
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=4)