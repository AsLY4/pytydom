# pytydom

A Home-Assistant-independent Python client for **Delta Dore Tydom**
gateways. It provides:

- the wire **protocol** — HTTP-over-websocket framing and payload parsing;
- the authenticated **gateway** session handshake (HTTP Digest → websocket);
- the **cloud** credential lookup that retrieves a gateway's password from
  a Delta Dore account.

It raises its own exception hierarchy (`TydomError` and subclasses) and
takes all endpoints and timeouts as parameters, so it carries no
dependency on Home Assistant.

This package is developed alongside the `deltadore` Home Assistant
integration and is intended to be published to PyPI as the integration's
transport dependency (quality-scale `dependency-transparency`).
