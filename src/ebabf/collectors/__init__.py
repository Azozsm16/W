"""Collectors. One per observation surface, all behind the same interface."""

from ebabf.collectors.base import Collector, CollectorContext, Pseudonymizer
from ebabf.collectors.process import ProcessCollector

__all__ = ["Collector", "CollectorContext", "Pseudonymizer", "ProcessCollector"]
