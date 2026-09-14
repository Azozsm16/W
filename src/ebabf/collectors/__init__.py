"""Collectors. One per observation surface, all behind the same interface."""

from ebabf.collectors.base import Collector, CollectorContext, Pseudonymizer
from ebabf.collectors.filesystem import FileMonitorCollector, WatchRoot
from ebabf.collectors.network import NetworkCollector
from ebabf.collectors.process import ProcessCollector
from ebabf.collectors.registry import (
    CollectorRegistry,
    CoverageReport,
    default_registry,
    register_collector,
)
from ebabf.collectors.user_activity import UserActivityCollector

__all__ = [
    "Collector",
    "CollectorContext",
    "Pseudonymizer",
    "ProcessCollector",
    "NetworkCollector",
    "FileMonitorCollector",
    "WatchRoot",
    "UserActivityCollector",
    "CollectorRegistry",
    "CoverageReport",
    "default_registry",
    "register_collector",
]
