"""Network collector - spec 5.2 features, from synthetic packets only.

No test here touches a real interface. The flow logic is pure state, so it can
be driven with packets built in memory, which keeps the suite deterministic and
runnable without CAP_NET_RAW.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP

from ebabf.collectors.base import CollectorContext
from ebabf.collectors.network import (
    HOST_SUBJECT,
    FlowKey,
    FlowTable,
    NetworkCollector,
    PacketSource,
    ScapyPacketSource,
    SocketOwnerResolver,
    domain_entropy,
    shannon_entropy,
)
from ebabf.schema import EventSource

LOCAL = frozenset({"10.0.0.1"})

SPEC_5_2_FIELDS = {
    "dest_ip",
    "dest_port",
    "bytes_out",
    "bytes_in",
    "connection_interval_variance",
    "unique_dest_count",
    "protocol",
    "dns_entropy",
}


def out_tcp(dst: str = "93.184.216.34", dport: int = 443, sport: int = 51000, size: int = 100):
    return IP(src="10.0.0.1", dst=dst) / TCP(sport=sport, dport=dport) / (b"x" * size)


def in_tcp(src: str = "93.184.216.34", sport: int = 443, dport: int = 51000, size: int = 40):
    return IP(src=src, dst="10.0.0.1") / TCP(sport=sport, dport=dport) / (b"y" * size)


def dns_query(qname: str, sport: int = 5353):
    return (
        IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=sport, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )


class StubPacketSource(PacketSource):
    """Hands the collector a fixed list of packets instead of an interface."""

    def __init__(self, packets: list[Any] | None = None) -> None:
        self.packets = packets or []
        self.started = False
        self.stopped = False
        self._handler: Callable[[Any], None] | None = None

    def start(self, handler: Callable[[Any], None]) -> None:
        self.started = True
        self._handler = handler
        for packet in self.packets:
            handler(packet)

    def stop(self) -> None:
        self.stopped = True

    def feed(self, packet: Any) -> None:
        assert self._handler is not None
        self._handler(packet)


class StubOwnerResolver(SocketOwnerResolver):
    def __init__(self, owners: dict[tuple[str, int], str] | None = None) -> None:
        super().__init__()
        self._fixed = owners or {}
        self.refreshed = 0

    def refresh(self) -> None:
        self.refreshed += 1
        self._owners = dict(self._fixed)


class TestEntropy:
    def test_empty_is_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_uniform_string_has_no_entropy(self) -> None:
        assert shannon_entropy("aaaaaa") == 0.0

    def test_generated_names_score_above_human_ones(self) -> None:
        """The whole point of the feature (spec 5.2, DGA detection)."""
        human = max(domain_entropy(d) for d in ("www.google.com", "mail.company.sa", "github.com"))
        generated = min(
            domain_entropy(d)
            for d in ("kq3v9z7xw1p2.com", "x7f3k9zq2m8vn4bt.attacker.com", "zxqwvbnmlkjhgfds.net")
        )
        assert generated > human

    def test_tunnelling_in_a_subdomain_is_caught(self) -> None:
        """Scoring only the registrable label would read this as ordinary."""
        assert domain_entropy("x7f3k9zq2m8vn4bt.attacker.com") > domain_entropy("www.attacker.com")

    def test_tld_is_excluded(self) -> None:
        assert domain_entropy("com") == shannon_entropy("com")

    def test_malformed_names_do_not_raise(self) -> None:
        for name in ("", ".", "...", "a"):
            assert domain_entropy(name) >= 0.0


class TestFlowTable:
    def test_outbound_and_inbound_join_one_flow(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(out_tcp(size=100), now=1000.0)
        table.observe(in_tcp(size=40), now=1000.5)
        flows = table.drain()
        assert len(flows) == 1
        state = next(iter(flows.values()))
        assert state.bytes_out > state.bytes_in > 0
        assert state.packets_out == 1 and state.packets_in == 1

    def test_flow_key_is_oriented_by_the_local_address(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(in_tcp(), now=1000.0)
        key = next(iter(table.drain()))
        assert key.local_ip == "10.0.0.1"
        assert key.remote_ip == "93.184.216.34"
        assert key.remote_port == 443

    def test_distinct_destinations_are_distinct_flows(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(out_tcp(dst="1.1.1.1", sport=40001), now=1000.0)
        table.observe(out_tcp(dst="2.2.2.2", sport=40002), now=1000.0)
        assert len(table.drain()) == 2

    def test_drain_clears_the_table(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(out_tcp(), now=1000.0)
        assert len(table.drain()) == 1
        assert len(table.drain()) == 0

    def test_non_ip_traffic_is_ignored(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(IP(src="10.0.0.1", dst="1.1.1.1") / ICMP(), now=1000.0)
        assert len(table) == 0

    def test_a_malformed_packet_does_not_stop_capture(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(object(), now=1000.0)  # not a packet at all
        table.observe(out_tcp(), now=1000.1)
        assert len(table) == 1


class TestBeaconing:
    """Low interval variance is the C2 signal (spec 5.2)."""

    def test_regular_connections_have_near_zero_variance(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        for index in range(6):
            table.observe(out_tcp(dst="5.5.5.5", sport=40000 + index), now=1000.0 + index * 60.0)
        assert table.interval_variance("5.5.5.5") == pytest.approx(0.0, abs=1e-6)

    def test_irregular_connections_have_high_variance(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        for index, offset in enumerate([0, 3, 190, 200, 900, 905]):
            table.observe(out_tcp(dst="6.6.6.6", sport=40000 + index), now=1000.0 + offset)
        variance = table.interval_variance("6.6.6.6")
        assert variance is not None and variance > 1000

    def test_too_few_samples_report_unknown_not_zero(self) -> None:
        """Two connections give one gap, and one gap is not a rhythm.

        Reporting 0.0 there would manufacture a perfect beacon out of two
        unrelated connections - spec principle 1.
        """
        table = FlowTable(local_addresses=LOCAL)
        assert table.interval_variance("7.7.7.7") is None
        table.observe(out_tcp(dst="7.7.7.7", sport=40001), now=1000.0)
        assert table.interval_variance("7.7.7.7") is None
        table.observe(out_tcp(dst="7.7.7.7", sport=40002), now=1060.0)
        assert table.interval_variance("7.7.7.7") is None
        table.observe(out_tcp(dst="7.7.7.7", sport=40003), now=1120.0)
        assert table.interval_variance("7.7.7.7") is not None

    def test_timing_history_survives_a_drain(self) -> None:
        """Beaconing spans sweeps, so the history must outlive one."""
        table = FlowTable(local_addresses=LOCAL)
        for index in range(3):
            table.observe(out_tcp(dst="8.8.4.4", sport=40000 + index), now=1000.0 + index * 60)
            table.drain()
        table.observe(out_tcp(dst="8.8.4.4", sport=40009), now=1240.0)
        assert table.interval_variance("8.8.4.4") is not None


class TestDns:
    def test_query_entropy_is_recorded(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(dns_query("x7f3k9zq2m8vn4bt.attacker.com"), now=1000.0)
        state = next(iter(table.drain().values()))
        assert state.dns_query_count == 1
        assert state.dns_max_entropy is not None and state.dns_max_entropy > 3.0

    def test_the_highest_entropy_query_wins(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(dns_query("www.google.com"), now=1000.0)
        table.observe(dns_query("zxqwvbnmlkjhgfds.net"), now=1000.1)
        state = next(iter(table.drain().values()))
        assert state.dns_query_count == 2
        assert state.dns_max_entropy > domain_entropy("www.google.com")

    def test_the_queried_name_is_not_stored(self) -> None:
        """Only the number leaves the parser; the name itself does not."""
        table = FlowTable(local_addresses=LOCAL)
        table.observe(dns_query("secret-project.internal.example.com"), now=1000.0)
        state = next(iter(table.drain().values()))
        assert "secret-project" not in repr(state)

    def test_responses_are_not_counted_as_queries(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        response = (
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=5353)
            / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com"))
        )
        table.observe(response, now=1000.0)
        state = next(iter(table.drain().values()))
        assert state.dns_query_count == 0

    def test_non_dns_flows_have_no_entropy(self) -> None:
        table = FlowTable(local_addresses=LOCAL)
        table.observe(out_tcp(), now=1000.0)
        assert next(iter(table.drain().values())).dns_max_entropy is None


class TestCollector:
    def _collector(
        self, context: CollectorContext, packets: list[Any], owners=None
    ) -> tuple[NetworkCollector, StubPacketSource]:
        source = StubPacketSource(packets)
        collector = NetworkCollector(
            context,
            packet_source=source,
            owner_resolver=StubOwnerResolver(owners),
            flow_table=FlowTable(local_addresses=LOCAL),
        )
        return collector, source

    def test_declares_its_source(self) -> None:
        assert NetworkCollector.source is EventSource.NETWORK
        assert NetworkCollector.name == "network"

    def test_every_spec_5_2_field_is_present(self, collector_context: CollectorContext) -> None:
        collector, _ = self._collector(collector_context, [out_tcp(), in_tcp()])
        collector.start()
        events = list(collector.collect())
        assert events
        assert SPEC_5_2_FIELDS <= set(events[0].raw_attributes)

    def test_attributes_a_flow_to_its_socket_owner(
        self, collector_context: CollectorContext
    ) -> None:
        collector, _ = self._collector(
            collector_context, [out_tcp(sport=51000)], owners={("10.0.0.1", 51000): "alice"}
        )
        collector.start()
        event = next(iter(collector.collect()))
        assert event.raw_attributes["subject_attributed"] is True
        assert event.subject_pseudonym.startswith("USR-")

    def test_unattributable_flows_go_to_the_host_subject_not_a_guess(
        self, collector_context: CollectorContext
    ) -> None:
        """A captured packet carries no pid; inventing an owner is forbidden."""
        collector, _ = self._collector(collector_context, [out_tcp(sport=51000)], owners={})
        collector.start()
        event = next(iter(collector.collect()))
        assert event.raw_attributes["subject_attributed"] is False
        expected = collector_context.pseudonymizer.pseudonymize(HOST_SUBJECT)
        assert event.subject_pseudonym == expected

    def test_two_users_get_two_pseudonyms(self, collector_context: CollectorContext) -> None:
        collector, _ = self._collector(
            collector_context,
            [out_tcp(dst="1.1.1.1", sport=51000), out_tcp(dst="2.2.2.2", sport=51001)],
            owners={("10.0.0.1", 51000): "alice", ("10.0.0.1", 51001): "bob"},
        )
        collector.start()
        pseudonyms = {e.subject_pseudonym for e in collector.collect()}
        assert len(pseudonyms) == 2

    def test_unique_dest_count_counts_the_sweep(
        self, collector_context: CollectorContext
    ) -> None:
        packets = [out_tcp(dst=f"9.9.9.{n}", sport=51000 + n) for n in range(1, 5)]
        collector, _ = self._collector(collector_context, packets)
        collector.start()
        events = list(collector.collect())
        assert len(events) == 4
        assert all(e.raw_attributes["unique_dest_count"] == 4 for e in events)

    def test_events_carry_no_score(self, collector_context: CollectorContext) -> None:
        collector, _ = self._collector(collector_context, [out_tcp()])
        collector.start()
        for event in collector.collect():
            assert event.raw_score is None
            assert event.confidence is None
            assert event.decision is None

    def test_no_payload_bytes_reach_the_event(
        self, collector_context: CollectorContext
    ) -> None:
        """Principle 5: the capture reads headers, never content."""
        secret = b"PASSWORD=hunter2-do-not-capture"
        packet = IP(src="10.0.0.1", dst="3.3.3.3") / TCP(sport=51000, dport=80) / secret
        collector, _ = self._collector(collector_context, [packet])
        collector.start()
        event = next(iter(collector.collect()))
        rendered = repr(dict(event.raw_attributes))
        assert b"hunter2" not in rendered.encode()
        assert "PASSWORD" not in rendered

    def test_second_sweep_starts_empty(self, collector_context: CollectorContext) -> None:
        collector, source = self._collector(collector_context, [out_tcp()])
        collector.start()
        assert len(list(collector.collect())) == 1
        assert list(collector.collect()) == []

    def test_lifecycle_drives_the_source(self, collector_context: CollectorContext) -> None:
        collector, source = self._collector(collector_context, [])
        collector.start()
        assert source.started is True
        collector.start()  # idempotent
        collector.close()
        assert source.stopped is True

    def test_owner_table_is_refreshed_each_sweep(
        self, collector_context: CollectorContext
    ) -> None:
        source = StubPacketSource([out_tcp()])
        resolver = StubOwnerResolver({})
        collector = NetworkCollector(
            collector_context,
            packet_source=source,
            owner_resolver=resolver,
            flow_table=FlowTable(local_addresses=LOCAL),
        )
        collector.start()
        list(collector.collect())
        list(collector.collect())
        assert resolver.refreshed == 2


class TestCaptureAvailability:
    def test_reports_why_it_cannot_run(self) -> None:
        available, reason = ScapyPacketSource.is_available()
        assert isinstance(available, bool)
        if not available:
            assert reason, "unavailability must come with a reason (spec 11.3)"
