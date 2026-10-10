from app.core.target import Target


class ScopeGuard:
    def __init__(self, require_explicit_consent: bool = True):
        self.require_explicit_consent = require_explicit_consent

    def confirm_permission(self, target: Target, user_confirmed: bool) -> bool:
        """
        Ensures the user has confirmed ownership or authorization before proceeding.
        Raises PermissionError if consent is missing.
        """
        if self.require_explicit_consent and not user_confirmed:
            raise PermissionError(
                f"Scan refused for target '{target.normalized_value}'. "
                "You must explicitly confirm authorization before scanning[cite: 4, 7]."
            )
        return True