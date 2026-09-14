"""Pins every third-party interface this agent depends on.

Existing because of a real bug: `record()` classified filesystem events with
string literals typed from memory, and watchdog emits three types that were
not among them. Every one was silently counted as a modification, so reading
a file registered as changing it.

That class of failure is the dangerous one. A wrong attribute name in a
verification line fails immediately and loudly. A wrong attribute name in a
collector produces a field that is quietly empty, or quietly wrong, and the
agent trains on it for two weeks before anyone notices.

So every assumption about psutil, scapy and watchdog is asserted here. If a
library upgrade changes one, this file fails - which is the point. These are
contract tests, not behaviour tests: they check that what we believe about
these libraries is still true.
"""

from __future__ import annotations

import inspect
import os
import warnings

import psutil
import pytest

warnings.filterwarnings("ignore", module="scapy")


class TestPsutilProcessContract:
    """Fields the process collector reads (spec 5.1)."""

    REQUIRED_ATTRS = [
        "pid",
        "ppid",
        "name",
        "exe",
        "username",
        "uids",
        "create_time",
        "cpu_percent",
        "status",
    ]

    def test_every_requested_attr_is_valid(self) -> None:
        """psutil raises on an unknown attr name, so a typo cannot pass silently."""
        from ebabf.collectors.process import _ATTRS

        assert _ATTRS == self.REQUIRED_ATTRS
        next(psutil.process_iter(attrs=_ATTRS, ad_value=None))

    def test_an_invalid_attr_is_rejected_loudly(self) -> None:
        with pytest.raises(ValueError, match="invalid attr name"):
            next(psutil.process_iter(attrs=["pid", "not_a_real_attr"], ad_value=None))

    def test_uids_field_names(self) -> None:
        """`_privilege_level` reads .real and .effective through getattr,
        which would return None rather than raise if either were renamed."""
        uids = psutil.Process(os.getpid()).uids()
        assert uids._fields == ("real", "effective", "saved")
        assert isinstance(uids.real, int) and isinstance(uids.effective, int)

    def test_the_exceptions_we_catch_exist(self) -> None:
        for name in ("NoSuchProcess", "AccessDenied", "ZombieProcess"):
            assert issubclass(getattr(psutil, name), Exception)

    def test_process_info_is_a_dict_with_the_requested_keys(self) -> None:
        from ebabf.collectors.process import _ATTRS

        info = next(psutil.process_iter(attrs=_ATTRS, ad_value=None)).info
        assert isinstance(info, dict)
        assert set(_ATTRS) <= set(info)


class TestPsutilNetworkContract:
    """Fields the network collector reads for attribution (spec 5.2)."""

    def test_connection_row_shape(self) -> None:
        connections = psutil.net_connections(kind="inet")
        if not connections:
            pytest.skip("no inet sockets on this host")
        row = connections[0]
        assert {"laddr", "raddr", "pid", "status"} <= set(row._fields)

    def test_address_has_ip_and_port(self) -> None:
        for row in psutil.net_connections(kind="inet"):
            if row.laddr:
                assert row.laddr._fields == ("ip", "port")
                assert isinstance(row.laddr.port, int)
                return
        pytest.skip("no bound sockets on this host")

    def test_interface_addresses_expose_family_and_address(self) -> None:
        addresses = next(iter(psutil.net_if_addrs().values()))
        assert {"family", "address"} <= set(addresses[0]._fields)
        assert isinstance(addresses[0].family.name, str)

    def test_local_addresses_are_discovered(self) -> None:
        from ebabf.collectors.network import _local_addresses

        assert "127.0.0.1" in _local_addresses()


class TestPsutilUserContract:
    """Fields the user activity collector reads (spec 5.4).

    Accessed as plain attributes rather than through getattr, so a rename
    raises instead of yielding None - but this host may have no sessions, so
    the shape is checked against the namedtuple itself.
    """

    def test_session_field_names(self) -> None:
        """Read from psutil's own namedtuple, so the check holds on a host
        with no logged-in sessions - a container, or CI."""
        from psutil._ntuples import suser

        assert {"name", "terminal", "host", "started"} <= set(suser._fields)

    def test_live_sessions_match_the_namedtuple(self) -> None:
        from psutil._ntuples import suser

        sessions = psutil.users()
        if not sessions:
            pytest.skip("no logged-in sessions on this host")
        assert set(sessions[0]._fields) == set(suser._fields)

    def test_the_collector_reads_them_as_plain_attributes(self) -> None:
        """A rename must raise, not silently produce None."""
        import ebabf.collectors.user_activity as module

        source = inspect.getsource(module)
        for field in ("session.name", "session.terminal", "session.host", "session.started"):
            assert field in source
            assert f'getattr(session, "{field.split(".")[1]}"' not in source


class TestScapyContract:
    """Header fields the flow table reads. Payloads are never parsed."""

    def test_layer_classes_import(self) -> None:
        from scapy.layers.dns import DNS, DNSQR  # noqa: F401
        from scapy.layers.inet import IP, TCP, UDP  # noqa: F401
        from scapy.layers.inet6 import IPv6  # noqa: F401

    def test_ip_and_transport_field_names(self) -> None:
        from scapy.layers.inet import IP, TCP

        packet = IP(src="10.0.0.1", dst="1.1.1.1") / TCP(sport=1234, dport=443)
        assert packet[IP].src == "10.0.0.1"
        assert packet[IP].dst == "1.1.1.1"
        assert int(packet[TCP].sport) == 1234
        assert int(packet[TCP].dport) == 443
        assert len(packet) > 0

    def test_haslayer_distinguishes_protocols(self) -> None:
        from scapy.layers.inet import ICMP, IP, TCP, UDP

        tcp = IP() / TCP()
        assert tcp.haslayer(TCP) and not tcp.haslayer(UDP)
        assert (IP() / ICMP()).haslayer(ICMP)

    def test_dns_query_response_flag(self) -> None:
        """`qr` separates questions from answers; treating a response as a
        query would double every destination's DNS count."""
        from scapy.layers.dns import DNS, DNSQR, DNSRR

        query = DNS(rd=1, qd=DNSQR(qname="a.example.com"))
        response = DNS(qr=1, qd=DNSQR(qname="a.example.com"), an=DNSRR(rrname="a.example.com"))
        assert int(query.qr) == 0
        assert int(response.qr) == 1

    def test_dns_question_name_field(self) -> None:
        from scapy.layers.dns import DNS, DNSQR

        packet = DNS(rd=1, qd=DNSQR(qname="a.example.com"))
        names = list(packet.qd) if hasattr(packet.qd, "__iter__") else [packet.qd]
        assert names and hasattr(names[0], "qname")
        assert b"a.example.com" in names[0].qname

    def test_question_iteration_matches_the_installed_shape(self) -> None:
        from scapy.layers.dns import DNS, DNSQR

        from ebabf.collectors.network import _iter_questions

        packet = DNS(rd=1, qd=[DNSQR(qname="a.example.com"), DNSQR(qname="b.example.com")])
        assert sorted(_iter_questions(packet)) == ["a.example.com.", "b.example.com."]

    def test_async_sniffer_accepts_the_kwargs_we_pass(self) -> None:
        """Its signature is (*args, **kwargs), so the names are checked against
        the documented sniff() parameters instead of by introspection."""
        from scapy.sendrecv import AsyncSniffer, sniff

        documentation = (sniff.__doc__ or "") + (AsyncSniffer.__doc__ or "")
        for keyword in ("iface", "filter", "prn", "store"):
            assert keyword in documentation, f"sniff no longer documents {keyword!r}"
        assert hasattr(AsyncSniffer, "start") and hasattr(AsyncSniffer, "stop")

    def test_store_false_is_what_keeps_frames_off_disk(self) -> None:
        """Principle 5 depends on this: captured frames are never retained."""
        import ebabf.collectors.network as module

        assert "store=False" in inspect.getsource(module)


class TestWatchdogContract:
    """The interface whose wrong assumption caused the read-as-write bug."""

    def test_event_type_constants_exist(self) -> None:
        from watchdog.events import (
            EVENT_TYPE_CREATED,
            EVENT_TYPE_DELETED,
            EVENT_TYPE_MODIFIED,
            EVENT_TYPE_MOVED,
        )

        assert (EVENT_TYPE_CREATED, EVENT_TYPE_DELETED) == ("created", "deleted")
        assert (EVENT_TYPE_MODIFIED, EVENT_TYPE_MOVED) == ("modified", "moved")

    def test_every_emittable_type_is_classified(self) -> None:
        import watchdog.events as events

        from ebabf.collectors.filesystem import (
            _KNOWN_NON_MUTATION_EVENTS,
            MUTATION_EVENTS,
        )

        emitted = {
            getattr(events, name) for name in dir(events) if name.startswith("EVENT_TYPE_")
        }
        assert emitted - set(MUTATION_EVENTS) - _KNOWN_NON_MUTATION_EVENTS == set()

    def test_event_objects_expose_the_fields_the_handler_reads(self) -> None:
        from watchdog.events import FileCreatedEvent, FileMovedEvent

        created = FileCreatedEvent("/tmp/a")
        assert created.event_type == "created"
        assert created.src_path == "/tmp/a"
        assert created.is_directory is False
        assert FileMovedEvent("/tmp/a", "/tmp/b").dest_path == "/tmp/b"

    def test_observer_schedule_signature(self) -> None:
        from watchdog.observers import Observer

        parameters = inspect.signature(Observer.schedule).parameters
        assert {"event_handler", "path", "recursive"} <= set(parameters)

    def test_observer_lifecycle_methods(self) -> None:
        from watchdog.observers import Observer

        for method in ("start", "stop", "join", "schedule"):
            assert callable(getattr(Observer, method))


class TestVersionsAreKnown:
    """The versions these contracts were verified against."""

    def test_installed_versions_meet_the_floor(self) -> None:
        from importlib.metadata import version

        for package, minimum in (
            ("psutil", (5, 9)),
            ("scapy", (2, 5)),
            ("watchdog", (3, 0)),
            ("cryptography", (41, 0)),
        ):
            installed = tuple(int(p) for p in version(package).split(".")[:2])
            assert installed >= minimum, f"{package} {installed} is below {minimum}"
