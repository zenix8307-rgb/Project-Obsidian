"""Interface for local LLM inference using llama.cpp."""
import asyncio
import subprocess
import json
from typing import Optional, Dict, Any, List
from pathlib import Path
import tempfile
import os

from ..core.logger import LoggerMixin
from ..core.config import Config

class LLMInterface(LoggerMixin):
    """Interface for interacting with local LLM models via llama.cpp."""
    
    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize LLM interface.
        
        Args:
            model_path: Path to the GGUF model file
        """
        self.config = Config()
        self.model_path = model_path or self.config.llm_model_path
        
        if not self.model_path.exists():
            self.log_warning(f"Model not found at {self.model_path}")
        
        self.llama_path = self.config.llama_cpp_path
        self.context_size = 2048
        self.temperature = 0.7
        self.max_tokens = 512
        
        self.log_info(f"LLM Interface initialized with model: {self.model_path.name}")
    
    def ask(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Synchronously ask the LLM a question.
        
        Args:
            prompt: The user prompt to send to the LLM
            system_prompt: Optional system prompt for context
        
        Returns:
            LLM response as string
        """
        try:
            # Build full prompt with system context if provided
            full_prompt = self._build_full_prompt(prompt, system_prompt)
            
            # Create temporary file for prompt
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(full_prompt)
                prompt_file = f.name
            
            # Build command
            cmd = [
                str(self.llama_path),
                '-m', str(self.model_path),
                '-f', prompt_file,
                '-n', str(self.max_tokens),
                '--temp', str(self.temperature),
                '-c', str(self.context_size),
                '--no-display-prompt'
            ]
            
            self.log_debug(f"Running LLM command: {' '.join(cmd)}")
            
            # Run llama.cpp
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Clean up temp file
            os.unlink(prompt_file)
            
            if result.returncode != 0:
                self.log_error(f"LLM error: {result.stderr}")
                return f"Error: {result.stderr}"
            
            response = result.stdout.strip()
            self.log_debug(f"LLM response: {response[:200]}...")
            
            return response
            
        except subprocess.TimeoutExpired:
            self.log_error("LLM request timed out")
            return "Error: Request timed out"
        except Exception as e:
            self.log_error(f"LLM request failed: {e}")
            return f"Error: {str(e)}"
    
    async def ask_async(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Asynchronously ask the LLM a question.
        
        This runs the synchronous method in a thread pool.
        
        Args:
            prompt: The user prompt to send to the LLM
            system_prompt: Optional system prompt for context
        
        Returns:
            LLM response as string
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.ask,
            prompt,
            system_prompt
        )
    
    def _build_full_prompt(self, user_prompt: str, system_prompt: Optional[str]) -> str:
        """Build the full prompt with appropriate formatting."""
        if system_prompt:
            full_prompt = f"<s>[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n\n{user_prompt} [/INST]"
        else:
            full_prompt = f"<s>[INST] {user_prompt} [/INST]"
        
        return full_prompt
    
    def set_parameters(
        self,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        context_size: Optional[int] = None
    ):
        """Update LLM parameters."""
        if temperature is not None:
            self.temperature = max(0.0, min(2.0, temperature))
        if max_tokens is not None:
            self.max_tokens = max_tokens
        if context_size is not None:
            self.context_size = context_size
        
        self.log_info(f"Updated LLM parameters: temp={self.temperature}, max_tokens={self.max_tokens}")
    
    def ask_structured(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        output_format: str = "json"
    ) -> Dict[str, Any]:
        """
        Ask the LLM and parse structured output.
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            output_format: Expected output format (json, yaml, etc.)
        
        Returns:
            Parsed structured response
        """
        # Add format instruction to prompt
        if output_format == "json":
            prompt += "\n\nRespond with valid JSON only. No other text."
        
        response = self.ask(prompt, system_prompt)
        
        if output_format == "json":
            try:
                # Try to extract JSON from response
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    json_str = response[json_start:json_end]
                    return json.loads(json_str)
                else:
                    # Try to parse whole response as JSON
                    return json.loads(response)
                    
            except json.JSONDecodeError as e:
                self.log_error(f"Failed to parse JSON response: {e}")
                return {"error": "Failed to parse response", "raw": response}
        
        return {"response": response}
    
    def analyze_security_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Specialized method for analyzing security findings.
        
        Args:
            findings: List of security findings to analyze
        
        Returns:
            Analysis results with severity, recommendations, etc.
        """
        system_prompt = """
        You are a senior security analyst expert. Analyze the provided security findings 
        and provide:
        1. Overall risk assessment
        2. Prioritized recommendations
        3. Potential impact analysis
        4. Remediation steps
        
        Be concise but thorough.
        """
        
        findings_text = json.dumps(findings, indent=2)
        prompt = f"""
        Analyze these security findings from a penetration test:
        
        {findings_text}
        
        Provide a structured analysis with:
        - Overall risk level (Critical/High/Medium/Low)
        - Top 3 most critical issues
        - Recommended immediate actions
        - Long-term remediation strategy
        """
        
        return self.ask_structured(prompt, system_prompt)
    
    def is_available(self) -> bool:
        """Check if LLM is available and working."""
        if not self.model_path.exists():
            return False
        
        try:
            # Test with a simple prompt
            response = self.ask("Respond with the word 'OK'", "You are a helpful assistant.")
            return response is not None and len(response) > 0
        except Exception:
            return False