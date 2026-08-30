"""pytydom — a Home-Assistant-independent client for Delta Dore Tydom gateways.

Groups the wire protocol (HTTP-over-websocket framing and payload parsing),
the authenticated gateway session handshake, and the cloud credential
lookup used to retrieve a gateway's password from a Delta Dore account.
"""

from . import cloud, gateway, protocol
from .cloud import async_get_gateway_password
from .exceptions import (
    TydomAuthenticationError,
    TydomCommunicationError,
    TydomConnectionError,
    TydomError,
)
from .gateway import async_open_session, async_validate_connection
from .protocol import (
    Frame,
    TydomDevice,
    build_request,
    has_pod_position,
    next_frame,
    parse_area_links,
    parse_area_names,
    parse_areas_data,
    parse_areas_meta,
    parse_cmeta,
    parse_configs,
    parse_devices_data,
    parse_energy_cdata,
    parse_meta,
    parse_scenarios,
)

__all__ = [
    "Frame",
    "TydomAuthenticationError",
    "TydomCommunicationError",
    "TydomConnectionError",
    "TydomDevice",
    "TydomError",
    "async_get_gateway_password",
    "async_open_session",
    "async_validate_connection",
    "build_request",
    "cloud",
    "gateway",
    "has_pod_position",
    "next_frame",
    "parse_area_links",
    "parse_area_names",
    "parse_areas_data",
    "parse_areas_meta",
    "parse_cmeta",
    "parse_configs",
    "parse_devices_data",
    "parse_energy_cdata",
    "parse_meta",
    "parse_scenarios",
    "protocol",
]
