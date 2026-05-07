class DomainRuleViolation(Exception):
    """Raised when a domain invariant or permission rule is violated."""


class DomainPermissionDenied(DomainRuleViolation):
    pass


class DomainValidationError(DomainRuleViolation):
    pass
