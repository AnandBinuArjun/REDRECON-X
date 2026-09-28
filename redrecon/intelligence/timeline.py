import time
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    stage: str
    started_at: float
    ended_at: Optional[float] = None
    duration_sec: float = 0.0
    items_processed: int = 0
    metadata: Dict[str, str] = Field(default_factory=dict)


class ScanTimeline:
    """
    Measures per-module execution intervals, scan latency, and efficiency benchmarks.
    Crucial for academic evaluation and research reporting.
    """

    def __init__(self):
        self.start_time = time.perf_counter()
        self.events: Dict[str, TimelineEvent] = {}

    def start_stage(self, stage: str, metadata: Optional[Dict[str, str]] = None) -> None:
        self.events[stage] = TimelineEvent(
            stage=stage,
            started_at=time.perf_counter(),
            metadata=metadata or {},
        )

    def end_stage(self, stage: str, items_processed: int = 0) -> float:
        if stage in self.events:
            event = self.events[stage]
            event.ended_at = time.perf_counter()
            event.duration_sec = round(event.ended_at - event.started_at, 2)
            event.items_processed = items_processed
            return event.duration_sec
        return 0.0

    def total_duration(self) -> float:
        return round(time.perf_counter() - self.start_time, 2)

    def summary(self) -> Dict[str, Dict[str, float]]:
        return {
            stage: {
                "duration_sec": ev.duration_sec,
                "items_processed": ev.items_processed,
            }
            for stage, ev in self.events.items()
        }
