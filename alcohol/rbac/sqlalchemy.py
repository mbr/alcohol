from __future__ import absolute_import

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.orm import relationship

from . import FlatRBAC


def _pkey_cols(decl_type):
    return decl_type.__table__.primary_key.columns.values()


def _pkey_1col(decl_type):
    cols = _pkey_cols(decl_type)

    if len(cols) != 1:
        raise TypeError('SQLAlchemyRBAC only supports models with a single '
                        'primary key column.')

    return cols[0]


class SQLAlchemyRBAC(FlatRBAC):
    def __init__(self,
                 user_type,
                 role_type,
                 permission_type,
                 prefix='rbac_',
                 ):

        metadata = user_type.metadata
        self.prefix = prefix
        self._roles_rel = '_' + self.prefix + 'roles'
        self._perms_rel = '_' + self.prefix + 'permissions'

        user_key_col = _pkey_1col(user_type)
        role_key_col = _pkey_1col(role_type)
        permission_key_col = _pkey_1col(permission_type)

        user_role_map = Table(
            self.prefix + 'user_role_map',
            metadata,

            Column('user_pkey',
                   user_key_col.type,
                   ForeignKey(user_key_col)),
            Column('role_pkey',
                   role_key_col.type,
                   ForeignKey(role_key_col)),
        )

        role_permissions_map = Table(
            self.prefix + 'role_permission_map',
            metadata,

            Column('role_pkey',
                   role_key_col.type,
                   ForeignKey(role_key_col)),
            Column('permission_pkey',
                   permission_key_col.type,
                   ForeignKey(permission_key_col)),
        )

        # add orm relationships
        setattr(user_type, self._roles_rel, relationship(
            role_type, secondary=user_role_map,
        ))
        setattr(role_type, self._perms_rel, relationship(
            permission_type, secondary=role_permissions_map,
        ))

    # RBAC api:
    def assign(self, user, role):
        getattr(user, self._roles_rel).append(role)

    def unassign(self, user, role):
        try:
            getattr(user, self._roles_rel).remove(role)
        except ValueError:
            pass  # not in list, ignore

    def permit(self, role, permission):
        getattr(role, self._perms_rel).append(permission)

    def revoke(self, role, permission):
        try:
            getattr(role, self._perms_rel).remove(permission)
        except ValueError:
            pass  # not in list, ignore

    def allows(self, role, permission):
        return permission in getattr(role, self._perms_rel)

    def get_assigned_roles(self, user):
        return list(getattr(user, self._roles_rel))
