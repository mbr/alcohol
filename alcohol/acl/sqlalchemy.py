from sqlalchemy import Column, ForeignKey, Integer, Table
from sqlalchemy.orm import relationship

from .. import FlatRBAC


class SQLAlchemyRBAC(FlatRBAC):
    def __init__(self,
                 Base,
                 user_id_type=Integer,
                 role_id_type=Integer,
                 permission_id_type=Integer,
                 prefix='rbac_',
                 ):

        user_table_name = prefix + 'users',
        role_table_name = prefix + 'roles',
        permission_table_name = prefix + 'permissions'

        user_role = Table(
            prefix + 'user_role_map',
            Base.metadata,
            Column('user_id',
                   user_id_type,
                   ForeignKey(user_table_name + '.id')),
            Column('role_id',
                   role_id_type,
                   ForeignKey(role_table_name + '.id')),
        )

        role_permission = Table(
            prefix + 'role_permission_map',
            Base.metadata,
            Column('role_id',
                   role_id_type,
                   ForeignKey(role_table_name + '.id')),
            Column('permission_id',
                   permission_id_type,
                   ForeignKey(permission_table_name + '.id')),
        )

        class RBACUser(Base):
            __tablename__ = user_table_name
            id = Column(user_id_type, primary_key=True)

        self.user_class = RBACUser

        class RBACRole(Base):
            __tablename__ = prefix + 'roles'
            id = Column(role_id_type, primary_key=True)
            users = relationship(RBACUser, secondary=user_role,
                                 backref='roles')

        self.role_class = RBACRole

        class RBACPermission(Base):
            __tablename__ = prefix + 'permissions'
            id = Column(permission_id_type, primary_key=True)
            roles = relationship(RBACRole, secondary=role_permission,
                                 backref='permissions')

        self.permission_class = RBACPermission

    # RBAC api:
    def assign(self, user, role):
        user.roles.append(role)

    def unassign(self, user, role):
        user.roles.remove(role)

    def permit(self, role, permission):
        role.permissions.add(permission)

    def revoke(self, role, permission):
        role.permissions.delete(permission)

    def allows(self, role, permission):
        return permission in role.permissions

    def get_assigned_roles(self, user):
        return user.roles.all()
