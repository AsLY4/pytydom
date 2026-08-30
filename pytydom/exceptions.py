"""Exception hierarchy for the Tydom gateway client.

Home-Assistant-independent on purpose: the integration maps these to its
own Home Assistant errors at the boundary.
"""


class TydomError(Exception):
    """Base class for every error raised by this library."""


class TydomAuthenticationError(TydomError):
    """Credentials were rejected (gateway digest or cloud account)."""


class TydomConnectionError(TydomError):
    """The gateway could not be reached."""


class TydomCommunicationError(TydomError):
    """The Delta Dore cloud could not be reached."""
