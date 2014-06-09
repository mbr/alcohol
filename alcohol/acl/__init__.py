class FlatRBAC(object):
    """Basic interface for the simplest possible role-based access control
    implementation."""

    # user:role
    def assign(self, user, role):
        raise NotImplementedError()

    def unassign(self, user, role):
        raise NotImplementedError()

    # role:permission
    def permit(self, role, permission):
        raise NotImplementedError()

    def revoke(self, role, permission):
        raise NotImplementedError()

    # checking
    def allows(self, role, permission):
        raise NotImplementedError()

    def allowed(self, user, permission):
        for role in self.get_assigned_roles(user):
            if self.allows(role, permission):
                return True

        return False

    # reflection
    def get_assigned_roles(self, user):
        raise NotImplementedError()


class SessionMixin(object):
    def create_session(self, user):
        raise NotImplementedError()

    # modification of session
    def activate(self, session, permissions=None):
        raise NotImplementedError()

    def deactivate(self, session, permissions=None):
        raise NotImplementedError()

    # checking
    def authorized(self, session, permissions):
        raise NotImplementedError()


class DictRBAC(FlatRBAC):
    def __init__(self):
        self._role_map = {}
        self._permission_map = {}

    def assign(self, user, role):
        self._role_map.setdefault(user, set()).add(role)

    def unassign(self, user, role):
        self._role_map.get(user, set()).discard(role)

    def permit(self, role, permission):
        self._permission_map.setdefault(role, set()).add(permission)

    def revoke(self, role, permission):
        self._permission_map.get(role, set()).discard(permission)

    def allows(self, role, permission):
        return permission in self._permission_map.get(role, set())

    def get_assigned_roles(self, user):
        return self._role_map.get(user, set())
