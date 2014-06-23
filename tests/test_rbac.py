import pytest
from alcohol.rbac import DictRBAC


@pytest.fixture
def flat_acl():
    return DictRBAC()


hashables = ('val', 0, -1, -2, 1234, '+@#$@', ('some', 'tuple', 'val'), True,
             False, None)
alt_vals = 'val2', '0'


@pytest.fixture(params=hashables)
def user_a(request):
    return request.param


@pytest.fixture(params=alt_vals)
def user_b(request):
    return request.param


@pytest.fixture(params=hashables)
def role_x(request):
    return request.param


@pytest.fixture(params=alt_vals)
def role_y(request):
    return request.param


@pytest.fixture(params=hashables)
def perm_p(request):
    return request.param


@pytest.fixture(params=alt_vals)
def perm_q(request):
    return request.param


def test_assigning_roles(flat_acl, user_a, role_x):
    flat_acl.assign(user_a, role_x)
    assert role_x in flat_acl.get_assigned_roles(user_a)


def test_unassignin_roles(flat_acl, user_a, role_x):
    flat_acl.assign(user_a, role_x)
    assert role_x in flat_acl.get_assigned_roles(user_a)
    flat_acl.unassign(user_a, role_x)
    assert role_x not in flat_acl.get_assigned_roles(user_a)


def test_unassigning_unassigned_roles(flat_acl, user_a, role_x):
    assert role_x not in flat_acl.get_assigned_roles(user_a)
    flat_acl.unassign(user_a, role_x)
    assert role_x not in flat_acl.get_assigned_roles(user_a)


def test_unassigning_does_not_erase_all(flat_acl, user_a, role_x, role_y):
    flat_acl.assign(user_a, role_x)
    flat_acl.assign(user_a, role_y)

    assert role_x in flat_acl.get_assigned_roles(user_a)
    assert role_y in flat_acl.get_assigned_roles(user_a)

    flat_acl.unassign(user_a, role_x)

    assert not role_x in flat_acl.get_assigned_roles(user_a)
    assert role_y in flat_acl.get_assigned_roles(user_a)


def test_user_starts_with_no_roles(flat_acl, user_a):
    assert not flat_acl.get_assigned_roles(user_a)


def test_permitting(flat_acl, role_x, perm_p):
    assert not flat_acl.allows(role_x, perm_p)
    flat_acl.permit(role_x, perm_p)
    assert flat_acl.allows(role_x, perm_p)


def test_revoking(flat_acl, role_x, perm_p):
    flat_acl.permit(role_x, perm_p)
    assert flat_acl.allows(role_x, perm_p)
    flat_acl.revoke(role_x, perm_p)
    assert not flat_acl.allows(role_x, perm_p)


def test_no_default_permissions(flat_acl, role_x, perm_p, perm_q):
    assert not flat_acl.allows(role_x, perm_p)
    assert not flat_acl.allows(role_x, perm_q)


def test_permissions_are_per_role_xnd_permission(
    flat_acl, role_x, role_y, perm_p, perm_q
):
    flat_acl.permit(role_x, perm_p)
    flat_acl.permit(role_y, perm_q)

    assert flat_acl.allows(role_x, perm_p)
    assert not flat_acl.allows(role_y, perm_p)
    assert not flat_acl.allows(role_x, perm_q)
    assert flat_acl.allows(role_y, perm_q)


def test_user_role_permissions(flat_acl, user_a, role_x, perm_p):
    assert not flat_acl.allowed(user_a, perm_p)
    flat_acl.permit(role_x, perm_p)
    assert not flat_acl.allowed(user_a, perm_p)
    flat_acl.assign(user_a, role_x)
    assert flat_acl.allowed(user_a, perm_p)
