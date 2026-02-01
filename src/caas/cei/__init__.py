"""
Compliance Event Interceptor (CEI)

Intercepts compliance-relevant events before state mutation in the object storage control plane.
Ensures completeness by capturing all mutation events.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from queue import Queue, Empty
import json
import hashlib


class EventType(Enum):
    """Types of compliance-relevant events."""
    OBJECT_CREATE = "object.create"
    OBJECT_UPDATE = "object.update"
    OBJECT_DELETE = "object.delete"
    OBJECT_READ = "object.read"
    POLICY_CREATE = "policy.create"
    POLICY_UPDATE = "policy.update"
    POLICY_DELETE = "policy.delete"


@dataclass
class ComplianceEvent:
    """Represents a compliance-relevant event."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    tenant_id: str
    bucket: str
    object_key: Optional[str] = None
    principal: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": self.tenant_id,
            "bucket": self.bucket,
            "object_key": self.object_key,
            "principal": self.principal,
            "metadata": self.metadata,
        }
    
    def compute_hash(self) -> str:
        """Compute cryptographic hash of the event."""
        event_data = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(event_data.encode()).hexdigest()


class EventInterceptor:
    """
    Intercepts and captures compliance-relevant events.
    
    This class provides a hook mechanism to intercept events before they
    cause state mutations in the object storage system.
    """
    
    def __init__(self, max_queue_size: int = 10000):
        """
        Initialize the event interceptor.
        
        Args:
            max_queue_size: Maximum number of events to queue
        """
        self.event_queue: Queue = Queue(maxsize=max_queue_size)
        self.handlers: List[Callable[[ComplianceEvent], None]] = []
        self._event_count = 0
        self._intercepted_events: List[ComplianceEvent] = []
    
    def register_handler(self, handler: Callable[[ComplianceEvent], None]) -> None:
        """
        Register a handler function to be called when events are intercepted.
        
        Args:
            handler: Callback function that receives ComplianceEvent
        """
        self.handlers.append(handler)
    
    def intercept(self, event: ComplianceEvent) -> bool:
        """
        Intercept a compliance event.
        
        Args:
            event: The compliance event to intercept
            
        Returns:
            True if event was successfully intercepted, False otherwise
        """
        try:
            # Add to queue for processing
            self.event_queue.put(event, block=False)
            
            # Keep track for completeness verification
            self._intercepted_events.append(event)
            self._event_count += 1
            
            # Call registered handlers
            for handler in self.handlers:
                try:
                    handler(event)
                except Exception as e:
                    # Log error but continue processing
                    print(f"Handler error: {e}")
            
            return True
            
        except Exception as e:
            print(f"Failed to intercept event: {e}")
            return False
    
    def get_event(self, timeout: Optional[float] = None) -> Optional[ComplianceEvent]:
        """
        Retrieve an event from the queue.
        
        Args:
            timeout: Maximum time to wait for an event (None = non-blocking)
            
        Returns:
            ComplianceEvent if available, None otherwise
        """
        try:
            return self.event_queue.get(block=timeout is not None, timeout=timeout)
        except Empty:
            return None
    
    def get_event_count(self) -> int:
        """Get the total number of intercepted events."""
        return self._event_count
    
    def verify_completeness(self, expected_count: int) -> bool:
        """
        Verify that all expected events were captured.
        
        Args:
            expected_count: Expected number of events
            
        Returns:
            True if actual count matches expected count
        """
        return self._event_count == expected_count
    
    def get_intercepted_events(self) -> List[ComplianceEvent]:
        """Get list of all intercepted events."""
        return self._intercepted_events.copy()


class EventFilter:
    """Filters events based on criteria."""
    
    def __init__(self):
        self.tenant_filters: List[str] = []
        self.bucket_filters: List[str] = []
        self.event_type_filters: List[EventType] = []
    
    def add_tenant_filter(self, tenant_id: str) -> None:
        """Filter events by tenant ID."""
        self.tenant_filters.append(tenant_id)
    
    def add_bucket_filter(self, bucket: str) -> None:
        """Filter events by bucket."""
        self.bucket_filters.append(bucket)
    
    def add_event_type_filter(self, event_type: EventType) -> None:
        """Filter events by type."""
        self.event_type_filters.append(event_type)
    
    def matches(self, event: ComplianceEvent) -> bool:
        """
        Check if event matches filter criteria.
        
        Args:
            event: Event to check
            
        Returns:
            True if event matches all active filters
        """
        if self.tenant_filters and event.tenant_id not in self.tenant_filters:
            return False
        
        if self.bucket_filters and event.bucket not in self.bucket_filters:
            return False
        
        if self.event_type_filters and event.event_type not in self.event_type_filters:
            return False
        
        return True
