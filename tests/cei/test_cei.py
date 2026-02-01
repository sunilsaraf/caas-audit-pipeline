"""
Unit tests for Compliance Event Interceptor (CEI)
"""

import pytest
from datetime import datetime
import uuid

from caas.cei import (
    ComplianceEvent, EventType, EventInterceptor, EventFilter
)


class TestComplianceEvent:
    """Test ComplianceEvent class."""
    
    def test_event_creation(self):
        """Test creating a compliance event."""
        event = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket",
            object_key="test-object.txt",
            principal="user@example.com",
            metadata={"size": 1024}
        )
        
        assert event.event_id is not None
        assert event.event_type == EventType.OBJECT_CREATE
        assert event.tenant_id == "tenant-1"
        assert event.bucket == "test-bucket"
        assert event.object_key == "test-object.txt"
    
    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        event = ComplianceEvent(
            event_id=event_id,
            event_type=EventType.OBJECT_UPDATE,
            timestamp=timestamp,
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["event_id"] == event_id
        assert event_dict["event_type"] == EventType.OBJECT_UPDATE.value
        assert event_dict["timestamp"] == timestamp.isoformat()
        assert event_dict["tenant_id"] == "tenant-1"
    
    def test_event_hash(self):
        """Test computing event hash."""
        event = ComplianceEvent(
            event_id="evt-123",
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        hash1 = event.compute_hash()
        hash2 = event.compute_hash()
        
        # Hash should be deterministic
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex


class TestEventInterceptor:
    """Test EventInterceptor class."""
    
    def test_interceptor_creation(self):
        """Test creating an event interceptor."""
        interceptor = EventInterceptor(max_queue_size=100)
        
        assert interceptor.get_event_count() == 0
        assert len(interceptor.get_intercepted_events()) == 0
    
    def test_intercept_event(self):
        """Test intercepting an event."""
        interceptor = EventInterceptor()
        
        event = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        result = interceptor.intercept(event)
        
        assert result is True
        assert interceptor.get_event_count() == 1
    
    def test_get_event(self):
        """Test retrieving intercepted events."""
        interceptor = EventInterceptor()
        
        event = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        interceptor.intercept(event)
        retrieved = interceptor.get_event()
        
        assert retrieved is not None
        assert retrieved.event_id == event.event_id
    
    def test_verify_completeness(self):
        """Test verifying event completeness."""
        interceptor = EventInterceptor()
        
        # Intercept 3 events
        for i in range(3):
            event = ComplianceEvent(
                event_id=str(uuid.uuid4()),
                event_type=EventType.OBJECT_CREATE,
                timestamp=datetime.utcnow(),
                tenant_id="tenant-1",
                bucket="test-bucket"
            )
            interceptor.intercept(event)
        
        assert interceptor.verify_completeness(3) is True
        assert interceptor.verify_completeness(2) is False
        assert interceptor.verify_completeness(4) is False
    
    def test_handler_registration(self):
        """Test registering event handlers."""
        interceptor = EventInterceptor()
        handled_events = []
        
        def handler(event: ComplianceEvent):
            handled_events.append(event)
        
        interceptor.register_handler(handler)
        
        event = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        interceptor.intercept(event)
        
        assert len(handled_events) == 1
        assert handled_events[0].event_id == event.event_id


class TestEventFilter:
    """Test EventFilter class."""
    
    def test_tenant_filter(self):
        """Test filtering events by tenant."""
        filter = EventFilter()
        filter.add_tenant_filter("tenant-1")
        
        event1 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        event2 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-2",
            bucket="test-bucket"
        )
        
        assert filter.matches(event1) is True
        assert filter.matches(event2) is False
    
    def test_bucket_filter(self):
        """Test filtering events by bucket."""
        filter = EventFilter()
        filter.add_bucket_filter("important-bucket")
        
        event1 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="important-bucket"
        )
        
        event2 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="other-bucket"
        )
        
        assert filter.matches(event1) is True
        assert filter.matches(event2) is False
    
    def test_event_type_filter(self):
        """Test filtering events by type."""
        filter = EventFilter()
        filter.add_event_type_filter(EventType.OBJECT_DELETE)
        
        event1 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_DELETE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        event2 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        assert filter.matches(event1) is True
        assert filter.matches(event2) is False
    
    def test_combined_filters(self):
        """Test combining multiple filters."""
        filter = EventFilter()
        filter.add_tenant_filter("tenant-1")
        filter.add_event_type_filter(EventType.OBJECT_CREATE)
        
        # Matches both filters
        event1 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        # Wrong tenant
        event2 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_CREATE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-2",
            bucket="test-bucket"
        )
        
        # Wrong event type
        event3 = ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.OBJECT_DELETE,
            timestamp=datetime.utcnow(),
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        assert filter.matches(event1) is True
        assert filter.matches(event2) is False
        assert filter.matches(event3) is False
