"""Platform abstraction and the coverage report (spec 3, 4, 11.3)."""

from __future__ import annotations

from typing import Iterator

import pytest

from ebabf.collectors.base import Collector, CollectorContext
from ebabf.collectors.registry import CollectorRegistry, CoverageReport, default_registry
from ebabf.schema import Event, EventSource


def _make(name: str, *, supported: bool = True, explodes: bool = False) -> type[Collector]:
    class _Collector(Collector):
        source = EventSource.PROCESS

        def __init__(self, context: CollectorContext) -> None:
            if explodes:
                raise RuntimeError("driver missing")
            super().__init__(context)

        @classmethod
        def is_supported(cls) -> bool:
            return supported

        def collect(self) -> Iterator[Event]:
            return iter(())

    _Collector.name = name
    return _Collector


class TestRegistration:
    def test_register_and_look_up(self, collector_context: CollectorContext) -> None:
        registry = CollectorRegistry()
        registry.register(_make("alpha"))
        assert registry.names() == ("alpha",)
        assert isinstance(registry.build("alpha", collector_context), Collector)

    def test_duplicate_name_refused(self) -> None:
        registry = CollectorRegistry()
        registry.register(_make("alpha"))
        with pytest.raises(ValueError, match="already registered"):
            registry.register(_make("alpha"))

    def test_re_registering_the_same_type_is_harmless(self) -> None:
        registry = CollectorRegistry()
        collector_type = _make("alpha")
        registry.register(collector_type)
        registry.register(collector_type)
        assert registry.names() == ("alpha",)

    def test_unknown_name_raises_with_a_hint(self) -> None:
        registry = CollectorRegistry()
        registry.register(_make("alpha"))
        with pytest.raises(KeyError, match="alpha"):
            registry.get("beta")

    def test_every_sprint_collector_is_registered(self) -> None:
        import ebabf.collectors  # noqa: F401 - import registers them

        assert set(default_registry.names()) == {
            "process",
            "network",
            "file",
            "user_activity",
        }


class TestCoverageIsDeclared:
    """Spec 11.3: a coverage gap is always announced, never silent."""

    def test_unsupported_collectors_are_reported_not_dropped(
        self, collector_context: CollectorContext
    ) -> None:
        registry = CollectorRegistry()
        registry.register(_make("alpha"))
        registry.register(_make("beta", supported=False))

        active, report = registry.build_supported(collector_context)
        assert [c.name for c in active] == ["alpha"]
        assert report.active == ("alpha",)
        assert len(report.unavailable) == 1
        assert report.unavailable[0][0] == "beta"
        assert report.is_complete is False

    def test_a_collector_that_fails_to_build_does_not_stop_the_others(
        self, collector_context: CollectorContext
    ) -> None:
        registry = CollectorRegistry()
        registry.register(_make("alpha"))
        registry.register(_make("broken", explodes=True))

        active, report = registry.build_supported(collector_context)
        assert [c.name for c in active] == ["alpha"]
        assert report.unavailable[0][0] == "broken"
        assert "RuntimeError" in report.unavailable[0][1]

    def test_full_coverage_reports_complete(
        self, collector_context: CollectorContext
    ) -> None:
        registry = CollectorRegistry()
        registry.register(_make("alpha"))
        _, report = registry.build_supported(collector_context)
        assert report.is_complete is True
        assert report.unavailable == ()

    def test_report_serialises_for_the_dashboard(
        self, collector_context: CollectorContext
    ) -> None:
        registry = CollectorRegistry()
        registry.register(_make("beta", supported=False))
        _, report = registry.build_supported(collector_context)
        payload = report.as_dict()
        assert payload["is_complete"] is False
        assert payload["unavailable"][0]["collector"] == "beta"
        assert "reason" in payload["unavailable"][0]

    def test_selection_can_be_narrowed(self, collector_context: CollectorContext) -> None:
        registry = CollectorRegistry()
        registry.register(_make("alpha"))
        registry.register(_make("beta"))
        active, _ = registry.build_supported(collector_context, only=["alpha"])
        assert [c.name for c in active] == ["alpha"]

    def test_narrowing_to_an_unknown_name_raises(
        self, collector_context: CollectorContext
    ) -> None:
        registry = CollectorRegistry()
        registry.register(_make("alpha"))
        with pytest.raises(KeyError, match="gamma"):
            registry.build_supported(collector_context, only=["gamma"])
