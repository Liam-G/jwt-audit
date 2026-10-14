"""Built-in scan profiles and endpoint dictionaries."""

from __future__ import annotations

from dataclasses import dataclass

COMMON_ENDPOINTS = (
    "/admin",
    "/protected",
    "/dashboard",
    "/admin/dashboard",
    "/admin/panel",
    "/admin-panel/",
    "/users",
    "/user",
    "/profile",
    "/me",
    "/account",
    "/settings",
    "/api/admin",
    "/api/admins",
    "/api/login",
    "/api/auth",
    "/api/admin/auth/login",
    "/auth",
    "/api/user",
    "/api/users",
    "/api/users/me",
    "/api/me",
    "/api/account",
    "/api/profile",
    "/api/protected",
    "/api/dashboard",
    "/api/admin/dashboard",
    "/api/admin/users",
    "/api/admin/admins",
    "/api/admin/me",
    "/api/admin/profile",
    "/api/admin/settings",
    "/api/admin/stats",
    "/api/admin/data",
    "/api/admin/accounts",
    "/api/admin/clients",
    "/v1/admin",
    "/v1/admins",
    "/v1/users",
    "/v1/users/me",
    "/v2/admin",
    "/graphql",
)

DEEP_ENDPOINTS = COMMON_ENDPOINTS + (
    "/api/admin/activities",
    "/api/admin/appointments",
    "/api/admin/invoices",
    "/api/admin/subscriptions",
    "/api/admin/overview",
    "/api/admin/meal-plans",
    "/api/admin/weight-entries",
    "/internal",
    "/api/internal",
    "/api/v1/admin",
    "/api/v1/users/me",
    "/rest/admin",
    "/management",
)

ENDPOINT_PACKS = {
    "account": (
        "/account",
        "/accounts",
        "/me",
        "/profile",
        "/settings",
        "/user",
        "/users",
        "/api/account",
        "/api/me",
        "/api/profile",
        "/api/user",
        "/api/users/me",
    ),
    "admin": (
        "/admin",
        "/admin/dashboard",
        "/admin/panel",
        "/api/admin",
        "/api/admin/dashboard",
        "/api/admin/settings",
        "/api/admin/users",
        "/v1/admin",
        "/v2/admin",
    ),
    "api": (
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/rest",
        "/v1",
        "/v2",
    ),
    "management": (
        "/actuator",
        "/actuator/health",
        "/internal",
        "/management",
        "/metrics",
        "/api/internal",
        "/api/management",
    ),
}


@dataclass(frozen=True)
class ScanProfile:
    name: str
    endpoints: tuple[str, ...]
    methods: tuple[str, ...]
    algorithms: tuple[str, ...]
    header_variants: tuple[str, ...]
    deep_payloads: bool
    include_unsigned: bool
    follow_same_origin_redirects: bool
    workers: int


PROFILES = {
    "safe": ScanProfile("safe", (), ("GET",), ("HS256",), ("library",), False, False, False, 1),
    "standard": ScanProfile(
        "standard",
        COMMON_ENDPOINTS,
        ("GET", "POST"),
        ("HS256",),
        ("alg-first", "typ-first"),
        False,
        False,
        True,
        4,
    ),
    "deep": ScanProfile(
        "deep",
        DEEP_ENDPOINTS,
        ("GET", "POST"),
        ("HS256", "HS384", "HS512"),
        ("alg-first", "typ-first"),
        True,
        True,
        True,
        8,
    ),
}
