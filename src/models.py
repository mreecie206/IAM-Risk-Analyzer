from dataclasses import dataclass
from typing import List


@dataclass
class RoleAssignment:
    """
    Represents a single RBAC role assignment.
    """
    role_name: str
    user_id: str
    is_external: bool
    is_high_privilege: bool


@dataclass
class ConditionalAccessPolicy:
    """
    Represents a Conditional Access policy configuration.
    """
    name: str
    requires_mfa: bool
    applies_to_admins: bool
    allows_legacy_auth: bool
    has_location_condition: bool
    has_device_condition: bool


@dataclass
class IdentityConfig:
    """
    Root configuration object containing RBAC roles and CA policies.
    """
    roles: List[RoleAssignment]
    policies: List[ConditionalAccessPolicy]



