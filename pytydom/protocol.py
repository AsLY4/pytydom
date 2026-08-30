"""HTTP-over-websocket message catalogue for the Tydom Gateway.

Frame building and parsing, inventory payload parsing, and the
state-application rules (endpoint error must be 0, data element validity
must be "upToDate").
"""

import json
from dataclasses import dataclass, field


@dataclass
class Frame:
    """One complete HTTP message extracted from the websocket stream."""

    kind: str  # "request" or "response"
    path: str
    transac_id: str | None
    body: str
    method: str | None = None
    status: int | None = None

    @property
    def json(self):
        return json.loads(self.body) if self.body.strip() else None


def build_request(method: str, path: str, transac_id: str, body: str = "") -> bytes:
    """Serialize an outbound request frame."""
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Content-Length: {len(body.encode())}\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        f"Transac-Id: {transac_id}\r\n\r\n{body}"
    ).encode()


def _consume_chunked(payload: bytes) -> tuple[bytes, int] | None:
    """Extract one chunked body: (body, bytes consumed), or None while
    incomplete. Raises ValueError on malformed chunk sizes."""
    out = bytearray()
    offset = 0
    while True:
        line_end = payload.find(b"\r\n", offset)
        if line_end == -1:
            return None
        size = int(payload[offset:line_end].strip(), 16)
        data_start = line_end + 2
        if size == 0:
            if len(payload) < data_start + 2:
                return None
            return bytes(out), data_start + 2
        if len(payload) < data_start + size + 2:
            return None
        out += payload[data_start : data_start + size]
        offset = data_start + size + 2


def next_frame(buffer: bytes) -> tuple[Frame | None, bytes]:
    """Extract the first complete message from the websocket byte stream.

    The stream is continuous HTTP/1.1: one websocket frame may carry
    several messages and one message may span frames. Returns
    (frame, remainder); frame is None when nothing was parsed —
    remainder == b"" means non-HTTP bytes were dropped, an unchanged
    remainder means the message is still incomplete. Message bodies end
    at the chunked terminal zero chunk, after Content-Length bytes, or
    immediately when neither marker is present (headers-only
    acknowledgements). Raises ValueError on malformed framing.
    """
    head, sep, rest = buffer.partition(b"\r\n\r\n")
    lines = head.decode(errors="ignore").split("\r\n")
    first = lines[0].split(" ")
    is_response = first[0].startswith("HTTP/") and len(first) >= 2
    is_request = len(first) >= 3 and first[2].startswith("HTTP/")
    if not is_response and not is_request:
        return None, b""
    if not sep:
        return None, buffer
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    if headers.get("transfer-encoding", "").lower().startswith("chunk"):
        consumed = _consume_chunked(rest)
        if consumed is None:
            return None, buffer
        body_bytes, used = consumed
        remainder = rest[used:]
    elif "content-length" in headers:
        length = int(headers["content-length"])
        if len(rest) < length:
            return None, buffer
        body_bytes, remainder = rest[:length], rest[length:]
    else:
        body_bytes, remainder = b"", rest

    frame = Frame(
        kind="response" if is_response else "request",
        status=int(first[1]) if is_response else None,
        method=None if is_response else first[0],
        path=headers.get("uri-origin", "") if is_response else first[1],
        transac_id=headers.get("transac-id"),
        body=body_bytes.decode(errors="ignore"),
    )
    return frame, remainder


@dataclass
class TydomDevice:
    """One gateway endpoint, identified by "{id_endpoint}_{id_device}"."""

    key: str
    device_id: int
    endpoint_id: int
    name: str
    usage: str
    data: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    energy_dests: list = field(default_factory=list)
    energy_srcs: list = field(default_factory=list)
    energy_units: list = field(default_factory=list)
    area_name: str | None = None
    _listeners: list = field(default_factory=list)

    def add_listener(self, listener):
        """Register a state-change callback; returns its remover."""
        self._listeners.append(listener)

        def _remove():
            self._listeners.remove(listener)

        return _remove

    def apply(self, data: dict) -> None:
        """Apply confirmed state values and notify listeners."""
        self.data.update(data)
        for listener in list(self._listeners):
            listener()


def has_pod_position(device: TydomDevice) -> bool:
    """Motorized doors carry podPosition; they map to lock, not contact."""
    return "podPosition" in device.data or "podPosition" in device.metadata


def parse_configs(payload) -> dict[str, dict]:
    """Endpoint directory from /configs/file, keyed by device key."""
    entries = {}
    for endpoint in (payload or {}).get("endpoints", []):
        key = f"{endpoint['id_endpoint']}_{endpoint['id_device']}"
        entries[key] = {
            "device_id": endpoint["id_device"],
            "endpoint_id": endpoint["id_endpoint"],
            "name": endpoint["name"],
            "usage": endpoint["last_usage"] or "unknown",
        }
    return entries


def parse_meta(payload) -> dict[str, dict]:
    """Attribute metadata from /devices/meta, keyed by device key."""
    entries = {}
    for device in payload or []:
        for endpoint in device.get("endpoints", []):
            key = f"{endpoint['id']}_{device['id']}"
            entries[key] = {meta["name"]: meta for meta in endpoint.get("metadata", [])}
    return entries


def parse_scenarios(payload) -> list[dict]:
    """Scenario definitions from the /configs/file `scenarios` array."""
    return [
        {"id": scenario["id"], "name": scenario["name"]}
        for scenario in (payload or {}).get("scenarios", [])
    ]


def parse_area_names(payload) -> dict[int, str]:
    """Thermal-zone names from the /configs/file `areas` array."""
    return {
        area["id"]: area["name"]
        for area in (payload or {}).get("areas", [])
        if "id" in area and "name" in area
    }


def parse_area_links(payload) -> dict[str, int]:
    """Device-key → area id from the /devices/meta endpoint `link`."""
    links: dict[str, int] = {}
    for device in payload or []:
        for endpoint in device.get("endpoints", []):
            link = endpoint.get("link") or {}
            if link.get("type") == "area" and link.get("id") is not None:
                links[f"{endpoint['id']}_{device['id']}"] = link["id"]
    return links


def parse_areas_meta(payload) -> dict[int, dict]:
    """Zone attribute metadata from /areas/meta, keyed by area id."""
    entries: dict[int, dict] = {}
    for area in payload or []:
        entries[area["id"]] = {meta["name"]: meta for meta in area.get("metadata", [])}
    return entries


def parse_areas_data(payload) -> dict[int, dict]:
    """Confirmed zone state from an /areas/data body, keyed by area id.

    Same shape as a flat /devices/data element but the top-level `id`
    is an area id and there is no `endpoints` key.
    """
    entries: dict[int, dict] = {}
    for area in payload or []:
        if area.get("error", 0) != 0:
            continue
        entries[area["id"]] = {
            element["name"]: element["value"]
            for element in area.get("data", [])
            if element.get("validity") == "upToDate"
        }
    return entries


def parse_cmeta(payload) -> dict[str, dict]:
    """Energy capabilities advertised by /devices/cmeta, per key:
    energyIndex destinations, energyDistrib sources, and energyInstant
    units."""
    entries: dict[str, dict] = {}
    for device in payload or []:
        for endpoint in device.get("endpoints", []):
            key = f"{endpoint['id']}_{device['id']}"
            dests: list = []
            srcs: list = []
            units: list = []
            for cmeta in endpoint.get("cmetadata", []):
                name = cmeta.get("name")
                if name == "energyIndex":
                    for parameter in cmeta.get("parameters", []):
                        if parameter.get("name") == "dest":
                            dests.extend(parameter.get("enum_values", []))
                elif name == "energyDistrib":
                    for parameter in cmeta.get("parameters", []):
                        if parameter.get("name") == "src":
                            srcs.extend(parameter.get("enum_values", []))
                elif name == "energyInstant":
                    for parameter in cmeta.get("parameters", []):
                        if parameter.get("name") == "unit":
                            units.extend(parameter.get("enum_values", []))
            if dests or srcs or units:
                entries[key] = {"dests": dests, "srcs": srcs, "units": units}
    return entries


def parse_energy_cdata(payload) -> dict[str, dict]:
    """Energy counters from a cdata response, keyed by device key."""
    entries: dict[str, dict] = {}
    for device in payload or []:
        for endpoint in device.get("endpoints", []):
            if endpoint.get("error", 0) != 0:
                continue
            key = f"{endpoint['id']}_{device['id']}"
            values = {}
            for element in endpoint.get("cdata", []):
                name = element.get("name")
                if name == "energyIndex":
                    dest = element.get("parameters", {}).get("dest")
                    counter = element.get("values", {}).get("counter")
                    if dest is not None and counter is not None:
                        values[f"energyIndex_{dest}"] = counter
                elif name == "energyDistrib":
                    # The distribution echo carries a date plus one
                    # counter per breakdown slot, keyed by slot name.
                    for slot, counter in element.get("values", {}).items():
                        if slot != "date" and isinstance(counter, (int, float)):
                            values[f"energyIndex_{slot}"] = counter
                elif name == "energyInstant":
                    unit = element.get("parameters", {}).get("unit")
                    measure = element.get("values", {}).get("measure")
                    if unit is not None and isinstance(measure, (int, float)):
                        # Hundredths of the physical unit (trace truth).
                        values[f"energyInstant_{unit}"] = measure / 100
            if values:
                entries[key] = values
    return entries


def parse_devices_data(payload) -> dict[str, dict]:
    """Confirmed state values from a /devices/data body, keyed by device key.

    Application rules: endpoints with a non-zero error are skipped; data
    elements are kept only when their validity is "upToDate".
    """
    if isinstance(payload, dict):
        payload = [payload]
    entries: dict[str, dict] = {}
    for device in payload or []:
        for endpoint in device.get("endpoints", []):
            if endpoint.get("error", 0) != 0:
                continue
            key = f"{endpoint['id']}_{device['id']}"
            values = {
                element["name"]: element["value"]
                for element in endpoint.get("data", [])
                if element.get("validity") == "upToDate"
            }
            if values:
                entries[key] = values
    return entries
