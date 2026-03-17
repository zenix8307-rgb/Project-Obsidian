"""Memory system for storing and retrieving scan information."""
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from .logger import LoggerMixin
from .config import Config

class MemorySystem(LoggerMixin):
    """Persistent memory system for storing scan results and context."""
    
    def __init__(self):
        self.config = Config()
        self.memory_file = self.config.cache_dir / 'memory.json'
        self.memory = self._load_memory()
    
    def _load_memory(self) -> Dict[str, Any]:
        """Load memory from disk."""
        if self.memory_file.exists():
            try:
                with open(self.memory_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.log_error(f"Failed to load memory: {e}")
                return {'targets': {}, 'scans': {}, 'knowledge': {}}
        return {'targets': {}, 'scans': {}, 'knowledge': {}}
    
    def _save_memory(self):
        """Save memory to disk."""
        try:
            with open(self.memory_file, 'w') as f:
                json.dump(self.memory, f, indent=2)
        except Exception as e:
            self.log_error(f"Failed to save memory: {e}")
    
    def _generate_target_key(self, target: str) -> str:
        """Generate a consistent key for a target."""
        return hashlib.sha256(target.encode()).hexdigest()[:16]
    
    def store_target_info(self, target: str, info: Dict[str, Any]):
        """Store information about a target."""
        target_key = self._generate_target_key(target)
        
        if target_key not in self.memory['targets']:
            self.memory['targets'][target_key] = {
                'target': target,
                'first_seen': datetime.now().isoformat(),
                'scans': [],
                'info': {}
            }
        
        # Update target info
        self.memory['targets'][target_key]['info'].update(info)
        self.memory['targets'][target_key]['last_seen'] = datetime.now().isoformat()
        
        self._save_memory()
    
    def store_scan_result(self, target: str, scan_type: str, results: Dict[str, Any]):
        """Store scan results in memory."""
        target_key = self._generate_target_key(target)
        scan_id = hashlib.sha256(
            f"{target}{scan_type}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        scan_record = {
            'id': scan_id,
            'type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }
        
        # Add to scans index
        self.memory['scans'][scan_id] = scan_record
        
        # Add to target's scans
        if target_key in self.memory['targets']:
            self.memory['targets'][target_key]['scans'].append(scan_id)
        
        self._save_memory()
        return scan_id
    
    def get_target_history(self, target: str) -> Dict[str, Any]:
        """Get scan history for a target."""
        target_key = self._generate_target_key(target)
        target_data = self.memory['targets'].get(target_key, {})
        
        # Enrich with scan details
        scans = []
        for scan_id in target_data.get('scans', []):
            if scan_id in self.memory['scans']:
                scans.append(self.memory['scans'][scan_id])
        
        return {
            'target': target,
            'info': target_data.get('info', {}),
            'first_seen': target_data.get('first_seen'),
            'last_seen': target_data.get('last_seen'),
            'scans': scans
        }
    
    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific scan by ID."""
        return self.memory['scans'].get(scan_id)
    
    def get_recent_scans(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get scans from the last N days."""
        cutoff = datetime.now() - timedelta(days=days)
        recent = []
        
        for scan_id, scan_data in self.memory['scans'].items():
            scan_time = datetime.fromisoformat(scan_data['timestamp'])
            if scan_time >= cutoff:
                recent.append(scan_data)
        
        return recent
    
    def store_knowledge(self, key: str, value: Any):
        """Store general knowledge in memory."""
        self.memory['knowledge'][key] = {
            'value': value,
            'timestamp': datetime.now().isoformat()
        }
        self._save_memory()
    
    def get_knowledge(self, key: str) -> Optional[Any]:
        """Retrieve stored knowledge."""
        if key in self.memory['knowledge']:
            return self.memory['knowledge'][key]['value']
        return None
    
    def find_similar_targets(self, target: str) -> List[str]:
        """Find targets with similar characteristics."""
        target_key = self._generate_target_key(target)
        current_target = self.memory['targets'].get(target_key, {})
        
        similar = []
        if not current_target:
            return similar
        
        current_info = current_target.get('info', {})
        current_services = set(current_info.get('services', []))
        
        for t_key, t_data in self.memory['targets'].items():
            if t_key == target_key:
                continue
            
            t_info = t_data.get('info', {})
            t_services = set(t_info.get('services', []))
            
            # Calculate similarity based on common services
            if current_services and t_services:
                common = current_services.intersection(t_services)
                if len(common) / max(len(current_services), len(t_services)) > 0.5:
                    similar.append(t_data['target'])
        
        return similar
    
    def clear_old_memory(self, days: int = 30):
        """Clear memory entries older than specified days."""
        cutoff = datetime.now() - timedelta(days=days)
        
        # Clean scans
        to_remove = []
        for scan_id, scan_data in self.memory['scans'].items():
            scan_time = datetime.fromisoformat(scan_data['timestamp'])
            if scan_time < cutoff:
                to_remove.append(scan_id)
        
        for scan_id in to_remove:
            del self.memory['scans'][scan_id]
        
        # Update target references
        for target_data in self.memory['targets'].values():
            target_data['scans'] = [
                s for s in target_data.get('scans', [])
                if s not in to_remove
            ]
        
        self._save_memory()
        self.log_info(f"Cleared {len(to_remove)} old scan records")