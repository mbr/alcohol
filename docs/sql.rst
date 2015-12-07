Example using SQL backends
==========================


Authorization
-------------

The following example is a walk-through for a simple web application that uses
`SQLAlchemy <http://sqlalchemy.org>`_ for its backend.

First, we start with a simple model::

  from alcohol.rbac.sqlalchemy import SQLAlchemyRBAC
  from alcohol.mixins.sqlalchemy import SQLAlchemyEmailMixin,SQLAlchemyPasswordMixin
  from sqlalchemy import Column, Integer, Unicode, String
  from sqlalchemy.ext.declarative import declarative_base

  Base = declarative_base()


  class User(Base, SQLAlchemyEmailMixin, SQLAlchemyPasswordMixin):
      __tablename__ = 'users'
      id = Column(Integer, primary_key=True)
      name = Column(Unicode, unique=True)


  class Role(Base):
      __tablename__ = 'roles'
      id = Column(Integer, primary_key=True)
      name = Column(String, unique=True)


  class Permission(Base):
      __tablename__ = 'permissions'
      id = Column(Integer, primary_key=True)
      name = Column(String, unique=True)

  acl = SQLAlchemyRBAC(User, Role, Permission)


Note that alcohol supports non-``Integer`` primary keys just fine and will
create the appropriate columns.

A script to create our database is required; for simplicity, we will use a
very simple version::

  from sqlalchemy import create_engine
  from sqlalchemy.orm import sessionmaker

  engine = create_engine('sqlite:///dev.db', echo=True)
  Base.metadata.create_all(engine)

  # we need a session
  Session = sessionmaker(bind=engine)
  s = Session()

  # create a few users
  alice = User(name='Alice')
  bob = User(name='Bob')
  cecille = User(name='Cecille')

  # and a few roles
  admin = Role(name='admin')
  user = Role(name='user')

  # now we can create permissions as well
  view_article = Permission(name='view_article')
  publish_article = Permission(name='publish_article')

  s.add_all([alice, bob, cecille, admin, user, view_article, publish_article])
  s.commit()


  # later on , we can assign permissions to roles (and users to permissions):
  acl.assign(alice, admin)
  acl.assign(bob, user)

  acl.permit(admin, publish_article)
  acl.permit(admin, view_article)
  acl.permit(user, view_article)

  s.add_all([alice, bob, admin, user])
  s.commit()


Note that in a more real-world situation, it would depend on the application
whether or not users, roles and permissions are created upfront upon DB
initialization or while the app is running. For example, users are usually
created by having them sign up, but smaller applications may have a fixed set
of roles and permissions. Larger, more configurable applications may
customize these as well.

Of course, we will want to check these later on::

  alice = s.query(User).filter_by(name='Alice').one()
  bob = s.query(User).filter_by(name='Bob').one()
  read_article = s.query(Permission).filter_by(name='publish_article').one()

  print acl.allowed(alice, publish_article)
  print acl.allowed(bob, publish_article)

It is somewhat cumbersome to look up the ``Permissions`` object each time, how
to alleviate this is up to the application. A simple-yet-effective way is
caching the Permissions known to the application.


Passwords and emails
--------------------

Notice that due to the fact that we added
:class:`~alcohol.mixins.sqlalchemy.SQLAlchemyPasswordMixin` and
:class:`~alcohol.mixins.sqlalchemy.SQLAlchemyEmailMixin`, we have additional
functionality on users unrelated to authoziation::

  SECRET_KEY='my-apps-secret-key'

  pw_reset_token = alice.create_password_reset_token(SECRET_KEY)

  # later on, we can validate this token
  if alice.check_password_reset_token(SECRET_KEY, pw_reset_token):
      alice.password = 'new-pw'

  # to activate emails, a similar functionality exists:
  mail_token = alice.create_email_activation_token(SECRET_KEY, 'new@mail.com')

  alice.activate_email(SECRET_KEY, mail_token)

Calling ``alcohol.mixins.sqlalchemy.SQLAlchemyEmailMixin.activate_email``
will automatically update the email address of Alice here, provided the token
has not been tampered with and is not older than a day.
