"""Network collector - the features in spec 5.2, via packet capture.

Headers only. The capture reads IP/TCP/UDP header fields, byte counts, and DNS
question names; it never touches a payload. Principle 5 (metadata only) is not
relaxed by the choice of capture as the collection method - it decides what may
be read out of what is captured.

Three pieces, kept apart so each is testable on its own:

- `FlowTable` - pure state. Accepts packets, accumulates per-flow counters and
  per-destination timing. No sockets, no threads.
- `PacketSource` - where packets come from. `ScapyPacketSource` sniffs a live
  interface; tests feed packets directly.
- `NetworkCollector` - drains the flow table each sweep and attributes flows to
  a subject.

A captured packet carries no pid, so it cannot say who opened the connection.
Attribution comes from a separate snapshot of the socket table. What cannot be
attributed is recorded against a reserved host subject, never guessed at.
"""

from __future__ import annotations

import logging
import math
import statistics
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, ClassVar, Iterator

import psutil

from ebabf.collectors.base import Collector, CollectorContext
from ebabf.collectors.registry import register_collector
from ebabf.schema import Event, EventSource

__all__ = [
    "NetworkCollector",
    "CaptureUnavailable",
    "FlowTable",
    "FlowKey",
    "PacketSource",
    "ScapyPacketSource",
    "HOST_SUBJECT",
    "shannon_entropy",
]

logger = logging.getLogger(__name__)

# Flows that no socket-table entry claims are recorded against this subject.
# It is pseudonymised like any other, so events stay well-formed, and it says
# plainly "the host, not a known user" rather than inventing an owner.
HOST_SUBJECT = "__host__"

# How many flow start times to keep per destination for the beaconing measure.
_MAX_INTERVAL_SAMPLES = 64

# Long enough for a capture thread that cannot start to have died. Without
# this pause `start()` returns before the failure has happened.
_START_SETTLE_SECONDS = 0.5


class CaptureUnavailable(RuntimeError):
    """Packet capture could not be started, or died immediately after starting.

    Raised rather than left to be discovered by the absence of traffic. scapy
    is unhelpful here: AsyncSniffer.start() returns cleanly even when the BPF
    filter cannot be compiled, and `sniffer.running` stays True while the
    capture thread is already dead. Only the thread's liveness and its stored
    exception tell the truth, so both are checked.
    """


def shannon_entropy(text: str) -> float:
    """Character-level Shannon entropy, in bits.

    Spec 5.2 uses this to flag DGA domains: an algorithmically generated name
    spreads its characters far more evenly than a human-chosen one.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def domain_entropy(qname: str) -> float:
    """Highest entropy among the name's labels, excluding the TLD.

    The maximum rather than the registrable label alone, because the
    machine-generated part sits in different places in the two cases this is
    meant to catch: a DGA domain is generated at the registrable label
    (`kq3v9z7xw1p2.com`), while DNS tunnelling hides its payload in a
    subdomain under a fixed one (`<encoded>.attacker.com`). Scoring only the
    registrable label would read the second as ordinary traffic.

    The TLD is excluded because it is drawn from a tiny fixed set and would
    pull every score toward the same middle.
    """
    labels = [label for label in qname.strip(".").split(".") if label]
    if not labels:
        return 0.0
    scored = labels[:-1] if len(labels) > 1 else labels
    return max(shannon_entropy(label) for label in scored)


@dataclass(frozen=True, slots=True)
class FlowKey:
    """One conversation, as seen on the wire."""

    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int


@dataclass(slots=True)
class FlowState:
    """Counters for one flow. Header-derived only."""

    bytes_out: int = 0
    bytes_in: int = 0
    packets_out: int = 0
    packets_in: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    dns_query_count: int = 0
    dns_max_entropy: float | None = None


class FlowTable:
    """Accumulates flows from packets. Pure state; safe to unit-test directly."""

    def __init__(self, local_addresses: frozenset[str] | None = None) -> None:
        self._flows: dict[FlowKey, FlowState] = {}
        self._local = local_addresses if local_addresses is not None else _local_addresses()
        # Flow start times per remote IP, kept across sweeps: beaconing is a
        # pattern between connections, so it cannot be seen inside one sweep.
        self._starts: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=_MAX_INTERVAL_SAMPLES)
        )
        self._lock = threading.Lock()

    def observe(self, packet: Any, *, now: float | None = None) -> None:
        """Record one packet. Unparseable packets are ignored, not raised on."""
        try:
            self._observe(packet, now if now is not None else time.time())
        except Exception:  # noqa: BLE001 - a malformed frame must not stop capture
            logger.debug("undecodable packet ignored", exc_info=True)

    def _observe(self, packet: Any, now: float) -> None:
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        if packet.haslayer(IP):
            network = packet[IP]
        elif packet.haslayer(IPv6):
            network = packet[IPv6]
        else:
            return

        src, dst = network.src, network.dst
        if packet.haslayer(TCP):
            transport, protocol = packet[TCP], "tcp"
        elif packet.haslayer(UDP):
            transport, protocol = packet[UDP], "udp"
        else:
            return

        sport, dport = int(transport.sport), int(transport.dport)
        size = len(packet)
        outbound = src in self._local

        if outbound:
            key = FlowKey(protocol, src, sport, dst, dport)
        else:
            key = FlowKey(protocol, dst, dport, src, sport)

        with self._lock:
            state = self._flows.get(key)
            if state is None:
                state = FlowState(first_seen=now, last_seen=now)
                self._flows[key] = state
                self._starts[key.remote_ip].append(now)
            state.last_seen = now
            if outbound:
                state.bytes_out += size
                state.packets_out += 1
            else:
                state.bytes_in += size
                state.packets_in += 1

            # DNS question names, for the DGA measure. Only the entropy is
            # kept; the name itself is not stored on the event.
            if packet.haslayer(DNS):
                dns = packet[DNS]
                if getattr(dns, "qd", None) and int(getattr(dns, "qr", 0)) == 0:
                    state.dns_query_count += 1
                    for question in _iter_questions(dns):
                        entropy = domain_entropy(question)
                        if state.dns_max_entropy is None or entropy > state.dns_max_entropy:
                            state.dns_max_entropy = entropy

    def interval_variance(self, remote_ip: str) -> float | None:
        """Variance of the gaps between connections to one destination.

        Low variance means a metronome, which is what a C2 beacon looks like.
        Returns None below three samples: two connections give one gap, and a
        single gap has no variance to speak of. Reporting 0.0 there would
        manufacture a perfect beacon out of two unrelated connections.
        """
        with self._lock:
            starts = list(self._starts.get(remote_ip, ()))
        if len(starts) < 3:
            return None
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        return statistics.pvariance(gaps)

    def unique_destination_count(self) -> int:
        with self._lock:
            return len({key.remote_ip for key in self._flows})

    def drain(self) -> dict[FlowKey, FlowState]:
        """Return the accumulated flows and reset. Timing history is kept."""
        with self._lock:
            drained, self._flows = self._flows, {}
        return drained

    def __len__(self) -> int:
        with self._lock:
            return len(self._flows)


def _iter_questions(dns: Any) -> Iterator[str]:
    """Question names in a DNS packet.

    scapy exposes `qd` as a packet list in current versions and as a chained
    payload in older ones; both shapes are handled so the collector does not
    depend on which is installed.
    """
    questions = getattr(dns, "qd", None)
    if questions is None:
        return
    if isinstance(questions, (list, tuple)) or hasattr(questions, "__iter__"):
        candidates = list(questions)
    else:  # pragma: no cover - older scapy chains questions as payloads
        candidates = []
        node = questions
        while node is not None and hasattr(node, "qname"):
            candidates.append(node)
            node = getattr(node, "payload", None) or None

    for question in candidates:
        name = getattr(question, "qname", b"")
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        if name:
            yield name


def _local_addresses() -> frozenset[str]:
    """Addresses belonging to this host, used to tell outbound from inbound."""
    found: set[str] = set()
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family.name in {"AF_INET", "AF_INET6"}:
                found.add(address.address.split("%")[0])
    return frozenset(found)


class PacketSource:
    """Where packets come from. Swappable so capture can be replaced later."""

    def start(self, handler: Callable[[Any], None]) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    @property
    def dropped(self) -> int:
        return 0

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        return True, ""


class ScapyPacketSource(PacketSource):
    """Live capture in a background thread.

    Needs CAP_NET_RAW. Without it the collector reports itself unavailable
    rather than failing at the first packet, so the coverage gap is declared
    up front instead of discovered during an incident.
    """

    def __init__(self, *, interface: str | None = None, bpf_filter: str = "ip or ip6") -> None:
        self._interface = interface
        self._filter = bpf_filter
        self._sniffer: Any = None

    @classmethod
    def is_available(cls, *, bpf_filter: str | None = "ip or ip6") -> tuple[bool, str]:
        """Whether capture can actually run here, and why not if it cannot."""
        import os

        if not sys.platform.startswith("linux"):
            return False, f"packet capture not implemented for {sys.platform}"

        # A BPF filter is compiled by libpcap. Without it scapy raises inside
        # the capture thread, where nobody is listening, so it is checked here
        # instead - before the collector is reported as active.
        if bpf_filter:
            try:
                from scapy.arch.common import compile_filter

                compile_filter(bpf_filter, "lo")
            except ImportError as exc:
                return False, f"libpcap is missing, so no BPF filter can be compiled: {exc}"
            except Exception as exc:  # noqa: BLE001 - any compile failure is unavailability
                return False, f"BPF filter {bpf_filter!r} will not compile: {exc}"

        if os.geteuid() == 0:
            return True, ""
        try:
            import socket

            probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
            probe.close()
            return True, ""
        except PermissionError:
            return False, "packet capture needs CAP_NET_RAW"
        except OSError as exc:
            return False, f"packet capture unavailable: {exc}"

    def start(self, handler: Callable[[Any], None]) -> None:
        from scapy.sendrecv import AsyncSniffer

        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter=self._filter,
            prn=handler,
            store=False,  # never retain frames: counters only, no packet log
        )
        self._sniffer.start()
        time.sleep(_START_SETTLE_SECONDS)
        self._raise_if_capture_died()

    def _raise_if_capture_died(self) -> None:
        """Turn a dead capture thread into an error the caller can see."""
        sniffer = self._sniffer
        if sniffer is None:  # pragma: no cover - start() always sets it
            raise CaptureUnavailable("capture was never started")

        stored = getattr(sniffer, "exception", None)
        if stored is not None:
            raise CaptureUnavailable(f"capture failed to start: {stored}") from stored

        thread = getattr(sniffer, "thread", None)
        if thread is not None and not thread.is_alive():
            # `sniffer.running` is still True at this point, which is why it is
            # not the thing being checked.
            raise CaptureUnavailable(
                "the capture thread stopped immediately after starting; "
                "no packets will be seen"
            )

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001 - shutdown must not raise
                logger.debug("sniffer stop failed", exc_info=True)
            self._sniffer = None


class SocketOwnerResolver:
    """Maps a flow to the user that owns its socket.

    Packet capture sees the wire, which carries no pid. This reads the socket
    table separately and matches on the local endpoint.
    """

    def __init__(self) -> None:
        self._owners: dict[tuple[str, int], str] = {}

    def refresh(self) -> None:
        owners: dict[tuple[str, int], str] = {}
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Without privileges the socket table is partial. Attribution
            # degrades to the host subject; it is never invented.
            logger.debug("socket table not readable; flows will be host-attributed")
            self._owners = {}
            return
        for conn in connections:
            if not conn.laddr or conn.pid is None:
                continue
            try:
                username = psutil.Process(conn.pid).username()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            if username:
                owners[(conn.laddr.ip, int(conn.laddr.port))] = username
        self._owners = owners

    def owner_of(self, key: FlowKey) -> str | None:
        return self._owners.get((key.local_ip, key.local_port))


@register_collector
class NetworkCollector(Collector):
    """Emits one event per flow observed since the previous sweep."""

    source: ClassVar[EventSource] = EventSource.NETWORK
    name: ClassVar[str] = "network"

    def __init__(
        self,
        context: CollectorContext,
        *,
        packet_source: PacketSource | None = None,
        owner_resolver: SocketOwnerResolver | None = None,
        flow_table: FlowTable | None = None,
    ) -> None:
        super().__init__(context)
        # `is None`, not `or`: FlowTable defines __len__, so an empty table is
        # falsy and `or` would silently swap out a caller-supplied one.
        self._source = packet_source if packet_source is not None else ScapyPacketSource()
        self._owners = owner_resolver if owner_resolver is not None else SocketOwnerResolver()
        self._flows = flow_table if flow_table is not None else FlowTable()
        self._started = False

    @classmethod
    def is_supported(cls) -> bool:
        available, reason = ScapyPacketSource.is_available()
        if not available:
            logger.warning("network collector unavailable: %s", reason)
        return available

    @classmethod
    def support_reason(cls) -> str | None:
        available, reason = ScapyPacketSource.is_available()
        return None if available else reason

    @property
    def is_capturing(self) -> bool:
        """Whether the capture is genuinely running, not merely started."""
        return self._started

    def start(self) -> None:
        if not self._started:
            self._source.start(self._flows.observe)
            self._started = True

    def close(self) -> None:
        if self._started:
            self._source.stop()
            self._started = False

    def collect(self) -> Iterator[Event]:
        self._owners.refresh()
        flows = self._flows.drain()
        unique_destinations = len({key.remote_ip for key in flows})

        for key, state in flows.items():
            owner = self._owners.owner_of(key)
            raw_attributes: dict[str, Any] = {
                # spec 5.2
                "dest_ip": key.remote_ip,
                "dest_port": key.remote_port,
                "bytes_out": state.bytes_out,
                "bytes_in": state.bytes_in,
                "connection_interval_variance": self._flows.interval_variance(key.remote_ip),
                "unique_dest_count": unique_destinations,
                "protocol": key.protocol,
                "dns_entropy": state.dns_max_entropy,
                # flow context, all header-derived
                "local_port": key.local_port,
                "packets_out": state.packets_out,
                "packets_in": state.packets_in,
                "flow_duration": round(state.last_seen - state.first_seen, 3),
                "dns_query_count": state.dns_query_count,
                "subject_attributed": owner is not None,
            }
            yield self._build_event(
                subject=owner or HOST_SUBJECT,
                raw_attributes=raw_attributes,
            )
