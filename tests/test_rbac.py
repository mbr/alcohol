from sqlalchemy import create_engine, Column, Integer
from sqlalchemy.ext.declarative import declarative_base

from alcohol.rbac import DictRBAC
from alcohol.rbac.sqlalchemy import SQLAlchemyRBAC

import pytest

hashables = ('val', 0, -1, -2, 1234, '+@#$@', ('some', 'tuple', 'val'), True,
             False, None)
alt_vals = 'val2', '0'


class FlatAclTests(object):
    def test_assigning_roles(self, flat_acl, user_a, role_x):
        flat_acl.assign(user_a, role_x)
        assert role_x in flat_acl.get_assigned_roles(user_a)

    def test_unassignin_roles(self, flat_acl, user_a, role_x):
        flat_acl.assign(user_a, role_x)
        assert role_x in flat_acl.get_assigned_roles(user_a)
        flat_acl.unassign(user_a, role_x)
        assert role_x not in flat_acl.get_assigned_roles(user_a)

    def test_unassigning_unassigned_roles(self, flat_acl, user_a, role_x):
        assert role_x not in flat_acl.get_assigned_roles(user_a)
        flat_acl.unassign(user_a, role_x)
        assert role_x not in flat_acl.get_assigned_roles(user_a)

    def test_unassigning_does_not_erase_all(
        self, flat_acl, user_a, role_x, role_y
    ):
        flat_acl.assign(user_a, role_x)
        flat_acl.assign(user_a, role_y)

        assert role_x in flat_acl.get_assigned_roles(user_a)
        assert role_y in flat_acl.get_assigned_roles(user_a)

        flat_acl.unassign(user_a, role_x)

        assert not role_x in flat_acl.get_assigned_roles(user_a)
        assert role_y in flat_acl.get_assigned_roles(user_a)

    def test_user_starts_with_no_roles(self, flat_acl, user_a):
        assert not flat_acl.get_assigned_roles(user_a)

    def test_permitting(self, flat_acl, role_x, perm_p):
        assert not flat_acl.allows(role_x, perm_p)
        flat_acl.permit(role_x, perm_p)
        assert flat_acl.allows(role_x, perm_p)

    def test_revoking(self, flat_acl, role_x, perm_p):
        flat_acl.permit(role_x, perm_p)
        assert flat_acl.allows(role_x, perm_p)
        flat_acl.revoke(role_x, perm_p)
        assert not flat_acl.allows(role_x, perm_p)

    def test_no_default_permissions(self, flat_acl, role_x, perm_p, perm_q):
        assert not flat_acl.allows(role_x, perm_p)
        assert not flat_acl.allows(role_x, perm_q)

    def test_permissions_are_per_role_xnd_permission(
        self, flat_acl, role_x, role_y, perm_p, perm_q
    ):
        flat_acl.permit(role_x, perm_p)
        flat_acl.permit(role_y, perm_q)

        assert flat_acl.allows(role_x, perm_p)
        assert not flat_acl.allows(role_y, perm_p)
        assert not flat_acl.allows(role_x, perm_q)
        assert flat_acl.allows(role_y, perm_q)

    def test_user_role_permissions(self, flat_acl, user_a, role_x, perm_p):
        assert not flat_acl.allowed(user_a, perm_p)
        flat_acl.permit(role_x, perm_p)
        assert not flat_acl.allowed(user_a, perm_p)
        flat_acl.assign(user_a, role_x)
        assert flat_acl.allowed(user_a, perm_p)


class TestDictRbac(FlatAclTests):
    @pytest.fixture
    def flat_acl(self):
        return DictRBAC()

    @pytest.fixture(params=hashables)
    def user_a(self, request):
        return request.param

    @pytest.fixture(params=alt_vals)
    def user_b(self, request):
        return request.param

    @pytest.fixture(params=hashables)
    def role_x(self, request):
        return request.param

    @pytest.fixture(params=alt_vals)
    def role_y(self, request):
        return request.param

    @pytest.fixture(params=hashables)
    def perm_p(self, request):
        return request.param

    @pytest.fixture(params=alt_vals)
    def perm_q(self, request):
        return request.param


class TestSqlaRbac(FlatAclTests):
    @pytest.fixture
    def flat_acl(self):
        Base = declarative_base()
        self.engine = create_engine('sqlite:///:memory:', echo=True)

        class User(Base):
            __tablename__ = 'users'
            id = Column(Integer, primary_key=True)

        self.user_class = User

        class Role(Base):
            __tablename__ = 'roles'
            id = Column(Integer, primary_key=True)

        self.role_class = Role

        class Permission(Base):
            __tablename__ = 'permissions'
            id = Column(Integer, primary_key=True)

        self.permission_class = Permission

        return SQLAlchemyRBAC(User, Role, Permission)

    @pytest.fixture(params=range(3))
    def user_a(self, request):
        return self.user_class(id=request.param)

    @pytest.fixture(params=range(3, 6))
    def user_b(self, request):
        return self.user_class(id=request.param)

    @pytest.fixture(params=range(3))
    def role_x(self, request):
        return self.role_class(id=request.param)

    @pytest.fixture(params=range(3, 6))
    def role_y(self, request):
        return self.role_class(id=request.param)

    @pytest.fixture(params=range(3))
    def perm_p(self, request):
        return self.permission_class(id=request.param)

    @pytest.fixture(params=range(3, 6))
    def perm_q(self, request):
        return self.permission_class(id=request.param)
