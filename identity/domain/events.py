from dataclasses import dataclass


@dataclass(frozen=True)
class UserRegistered:
    user_id: str


@dataclass(frozen=True)
class UserUpdated:
    user_id: str


@dataclass(frozen=True)
class ProfileInformationUpdated:
    user_id: str


@dataclass(frozen=True)
class ProfileInformationDeleted:
    user_id: str


@dataclass(frozen=True)
class GroupCreated:
    group_id: str


@dataclass(frozen=True)
class GroupMembershipChanged:
    group_id: str


@dataclass(frozen=True)
class GroupDeleted:
    group_id: str
