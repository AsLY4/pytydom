"""Delta Dore cloud client — gateway credential retrieval.

OpenID discovery, ROPC token grant, then
sites lookup to obtain the Tydom Gateway password for a MAC address.
"""

import asyncio
import logging

import aiohttp

from .exceptions import TydomAuthenticationError, TydomCommunicationError

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 60


async def async_get_gateway_password(
    session: aiohttp.ClientSession,
    email: str,
    password: str,
    mac: str,
    *,
    discovery_url: str,
    sites_url: str,
    client_id: str,
    scope: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Return the gateway password registered for `mac` on the account.

    The OpenID discovery URL, sites URL, client id and scope are passed in
    by the caller (the integration holds Delta Dore's endpoints), so the
    library embeds no vendor configuration.
    """
    try:
        async with asyncio.timeout(timeout):
            async with session.get(discovery_url) as resp:
                token_endpoint = (await resp.json())["token_endpoint"]

            form = aiohttp.FormData()
            for name, value in (
                ("username", email),
                ("password", password),
                ("grant_type", "password"),
                ("client_id", client_id),
                ("scope", scope),
            ):
                # content_type forces multipart/form-data, as the endpoint expects
                form.add_field(name, value, content_type="text/plain")
            async with session.post(token_endpoint, data=form) as resp:
                if resp.status != 200:
                    _LOGGER.debug("Account token rejected: HTTP %s", resp.status)
                    raise TydomAuthenticationError("Account credentials rejected")
                access_token = (await resp.json())["access_token"]

            async with session.get(
                sites_url,
                params={"gateway_mac": mac},
                headers={"Authorization": f"Bearer {access_token}"},
            ) as resp:
                if resp.status != 200:
                    _LOGGER.debug("Sites lookup rejected: HTTP %s", resp.status)
                    raise TydomAuthenticationError("Sites lookup rejected")
                sites = (await resp.json()).get("sites", [])
    except (TimeoutError, aiohttp.ClientError, OSError) as err:
        _LOGGER.debug(
            "Cloud credential retrieval failed (%s): %s", type(err).__name__, err
        )
        raise TydomCommunicationError("Delta Dore cloud unreachable") from err

    for site in sites:
        gateway = site.get("gateway", {})
        if gateway.get("mac", "").upper() == mac.upper() and gateway.get("password"):
            _LOGGER.debug("Gateway password retrieved from the cloud for %s", mac)
            return gateway["password"]
    _LOGGER.debug("No gateway %s among the %d account site(s)", mac, len(sites))
    raise TydomAuthenticationError("No matching gateway on this account")
