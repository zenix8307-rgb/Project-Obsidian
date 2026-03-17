"""Task management system for coordinating security scans."""
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from .logger import LoggerMixin

class TaskStatus(Enum):
    """Task status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

class Task:
    """Represents a single task in the task manager."""
    
    def __init__(
        self,
        task_id: str,
        name: str,
        func: Callable,
        priority: TaskPriority = TaskPriority.MEDIUM,
        dependencies: List[str] = None,
        timeout: int = 1800
    ):
        self.id = task_id
        self.name = name
        self.func = func
        self.priority = priority
        self.dependencies = dependencies or []
        self.timeout = timeout
        self.status = TaskStatus.PENDING
        self.result = None
        self.error = None
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.retry_count = 0
        self.max_retries = 2
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'priority': self.priority.value,
            'status': self.status.value,
            'dependencies': self.dependencies,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'retry_count': self.retry_count
        }

class TaskManager(LoggerMixin):
    """Manages task execution, dependencies, and concurrency."""
    
    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self.tasks: Dict[str, Task] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.completed_tasks: Dict[str, Task] = {}
        self._stop_event = asyncio.Event()
        self._scheduler_task = None
    
    def add_task(self, task: Task) -> str:
        """Add a task to the manager."""
        self.tasks[task.id] = task
        self.log_info(f"Added task: {task.name} (ID: {task.id})")
        return task.id
    
    def create_task(
        self,
        name: str,
        func: Callable,
        priority: TaskPriority = TaskPriority.MEDIUM,
        dependencies: List[str] = None,
        timeout: int = 1800
    ) -> str:
        """Create and add a new task."""
        task_id = f"{name}_{datetime.now().timestamp()}"
        task = Task(task_id, name, func, priority, dependencies, timeout)
        return self.add_task(task)
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID."""
        return self.tasks.get(task_id) or self.completed_tasks.get(task_id)
    
    def get_ready_tasks(self) -> List[Task]:
        """Get tasks that are ready to run (dependencies satisfied)."""
        ready = []
        for task in self.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            
            # Check dependencies
            deps_satisfied = True
            for dep_id in task.dependencies:
                dep_task = self.get_task(dep_id)
                if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                    deps_satisfied = False
                    break
            
            if deps_satisfied:
                ready.append(task)
        
        # Sort by priority
        ready.sort(key=lambda t: t.priority.value, reverse=True)
        return ready
    
    async def execute_task(self, task: Task):
        """Execute a single task."""
        self.log_info(f"Executing task: {task.name}")
        
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now()
        
        try:
            # Execute with timeout
            result = await asyncio.wait_for(
                task.func(),
                timeout=task.timeout
            )
            
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            
            self.log_info(f"Task completed: {task.name}")
            
        except asyncio.TimeoutError:
            task.error = f"Task timed out after {task.timeout} seconds"
            task.status = TaskStatus.FAILED
            self.log_error(f"Task timed out: {task.name}")
            
        except Exception as e:
            task.error = str(e)
            
            # Check if we should retry
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.PENDING
                self.log_warning(f"Retrying task {task.name} ({task.retry_count}/{task.max_retries})")
            else:
                task.status = TaskStatus.FAILED
                self.log_error(f"Task failed: {task.name} - {e}")
        
        finally:
            if task.status == TaskStatus.COMPLETED:
                self.completed_tasks[task.id] = task
            if task.id in self.tasks:
                del self.tasks[task.id]
    
    async def scheduler(self):
        """Main scheduler loop."""
        while not self._stop_event.is_set():
            try:
                # Check for ready tasks
                ready_tasks = self.get_ready_tasks()
                
                # Start new tasks if we have capacity
                while (len(self.running_tasks) < self.max_concurrent and 
                       ready_tasks):
                    task = ready_tasks.pop(0)
                    
                    # Create async task
                    runner = asyncio.create_task(self.execute_task(task))
                    self.running_tasks[task.id] = runner
                
                # Clean up completed tasks
                done = []
                for task_id, runner in self.running_tasks.items():
                    if runner.done():
                        done.append(task_id)
                
                for task_id in done:
                    del self.running_tasks[task_id]
                
                # Wait a bit before next check
                await asyncio.sleep(0.5)
                
            except Exception as e:
                self.log_error(f"Scheduler error: {e}")
                await asyncio.sleep(1)
    
    async def start(self):
        """Start the task manager."""
        self.log_info("Starting task manager")
        self._stop_event.clear()
        self._scheduler_task = asyncio.create_task(self.scheduler())
    
    async def stop(self):
        """Stop the task manager."""
        self.log_info("Stopping task manager")
        self._stop_event.set()
        
        # Cancel running tasks
        for task_id, runner in self.running_tasks.items():
            runner.cancel()
        
        if self._scheduler_task:
            await self._scheduler_task
    
    async def wait_for_completion(self):
        """Wait for all tasks to complete."""
        while self.tasks or self.running_tasks:
            await asyncio.sleep(1)
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the task manager."""
        return {
            'total_tasks': len(self.tasks) + len(self.completed_tasks),
            'pending': len([t for t in self.tasks.values() if t.status == TaskStatus.PENDING]),
            'running': len(self.running_tasks),
            'completed': len([t for t in self.completed_tasks.values()]),
            'failed': len([t for t in self.tasks.values() if t.status == TaskStatus.FAILED])
        }
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task."""
        if task_id in self.running_tasks:
            self.running_tasks[task_id].cancel()
            return True
        elif task_id in self.tasks:
            self.tasks[task_id].status = TaskStatus.CANCELLED
            return True
        return False