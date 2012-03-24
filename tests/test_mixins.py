#!/usr/bin/env python
# coding=utf8

from datetime import datetime, timedelta
import sys
import time

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from sqlalchemy import create_engine, Column, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy.exc import IntegrityError

from alcohol.mixins import password_mixin, email_mixin, timestamp_mixin
from alcohol.tokengen import TokenGenerator


class TestPasswordMixin(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite:///:memory:', echo=False)
        self.session = sessionmaker(bind=self.engine)()
        self.Base = declarative_base(
            bind=self.engine
        )

        class UserClass(self.Base, password_mixin()):
            __tablename__ = 'users'
            token_gen = TokenGenerator('s3cr3tk3y')

            id = Column(Integer, primary_key=True)

        self.Base.metadata.drop_all()
        self.Base.metadata.create_all()

        self.User = UserClass

    def tearDown(self):
        self.Base.metadata.drop_all()

    def test_stores_password(self):
        valid_password = 's0m3p4$$w0rd'
        invalid_password = valid_password + 'x'
        user = self.User(password=valid_password)
        self.session.add(user)
        self.session.commit()
        user_id = user.id
        del user

        # retrieve
        user = self.session.query(self.User).get(user_id)

        self.assertTrue(user.check_password(valid_password))
        self.assertFalse(user.check_password(invalid_password))

    def test_creates_new_salt_each_time(self):
        user = self.User(password='a')
        salt1 = user._pw_salt
        user.password = 'b'
        salt2 = user._pw_salt

        self.assertNotEqual(salt1, salt2)

    def test_salt_password_indenpendant(self):
        user = self.User(password='a')
        salt1 = user._pw_salt
        user2 = self.User(password='a')
        salt2 = user2._pw_salt

        self.assertNotEqual(salt1, salt2)

    def test_password_reset_token_different(self):
        user = self.User(password='foo')
        token1 = user.create_reset_password_token()
        token2 = user.create_reset_password_token()

        self.assertNotEqual(token1, token2)

    def test_password_reset_token_works(self):
        user = self.User(password='foo')
        token = user.create_reset_password_token()
        self.assertTrue(user.check_password_reset_token(token))

    def test_password_reset_is_secure(self):
        user = self.User(password='foo')
        token = user.create_reset_password_token()

        for i in xrange(0, len(token)):
            orig_byte = token[i]
            new_byte = '0' if orig_byte != '0' else '1'
            bad_token = token[:i] + new_byte + token[i + 1:]
            very_bad_token = token[:i] + 'g' + token[i + 1:]

            self.assertFalse(user.check_password_reset_token(bad_token))
            self.assertFalse(user.check_password_reset_token(very_bad_token))

    def test_password_reset_expires(self):
        user = self.User(password='foo')

        start = time.time()
        token = user.create_reset_password_token(valid_for=1)
        check = user.check_password_reset_token(token)
        end = time.time()

        if end - start >= 1.0:
            unittest.skip('Skipping one password check, took too long')
        else:
            self.assertTrue(check)

        time.sleep(1.1)
        self.assertFalse(user.check_password_reset_token(token))

    def test_two_tokens_work_both(self):
        user = self.User(password='foo')
        token1 = user.create_reset_password_token()
        token2 = user.create_reset_password_token()

        self.assertTrue(user.check_password_reset_token(token2))
        self.assertTrue(user.check_password_reset_token(token1))
        self.assertTrue(user.check_password_reset_token(token2))

    def test_tokens_stops_working_after_pw_change(self):
        user = self.User(password='foo')
        token1 = user.create_reset_password_token()
        token2 = user.create_reset_password_token()

        user.password = 'new_password'

        self.assertFalse(user.check_password_reset_token(token2))
        self.assertFalse(user.check_password_reset_token(token1))
        self.assertFalse(user.check_password_reset_token(token2))
        self.assertFalse(user.check_password_reset_token(token1))

    def test_password_cannot_be_read(self):
        user = self.User()

        with self.assertRaises(TypeError):
            x = user.password


class TestEmailMixin(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite:///:memory:', echo=False)
        self.session = sessionmaker(bind=self.engine)()
        self.Base = declarative_base(
            bind=self.engine
        )

        class UserClass(self.Base, email_mixin()):
            __tablename__ = 'users'
            token_gen = TokenGenerator('mylittlesecretkey')

            id = Column(Integer, primary_key=True)

        class UserClassUniqueEmail(self.Base, email_mixin(email_unique=True)):
            __tablename__ = 'users_with_unique_emails'
            token_gen = TokenGenerator('mylittlesecretkey2')

            id = Column(Integer, primary_key=True)

        self.Base.metadata.drop_all()
        self.Base.metadata.create_all()

        self.User = UserClass
        self.UserUniqueEmail = UserClassUniqueEmail

    def tearDown(self):
        self.Base.metadata.drop_all()

    def test_email_stored(self):
        email = 'some@email.invalid'
        user = self.User(email=email)

        self.session.add(user)
        self.session.commit()

        user_id = user.id
        del user

        user = self.session.query(self.User).get(user_id)
        self.assertEqual(user.email, email)

    def test_unverified_email_stored(self):
        unverified_email = 'another@email.invalid'
        user = self.User(unverified_email=unverified_email)

        self.session.add(user)
        self.session.commit()

        user_id = user.id
        del user

        user = self.session.query(self.User).get(user_id)
        self.assertEqual(user.unverified_email, unverified_email)

    def test_email_verification_token_works(self):
        unverified_email = 'another@email.invalid'
        user = self.User(unverified_email=unverified_email)

        token = user.create_email_activation_token

    def test_email_verification_token_altered_fails(self):
        user = self.User(unverified_email='my@email.invalid')
        token = user.create_email_activation_token()

        for i in xrange(0, len(token)):
            orig_byte = token[i]
            new_byte = '0' if orig_byte != '0' else '1'
            bad_token = token[:i] + new_byte + token[i + 1:]
            very_bad_token = token[:i] + 'g' + token[i + 1:]

            self.assertFalse(user.activate_email(bad_token))
            self.assertFalse(user.activate_email(very_bad_token))

    def test_email_verification_token_usable_once(self):
        user = self.User(unverified_email='my@email.invalid')
        token = user.create_email_activation_token()

        self.assertTrue(user.activate_email(token))
        self.assertFalse(user.activate_email(token))

    def test_email_activation_unsets_and_sets(self):
        old_email = 'old@email.invalid'
        new_email = 'new@email.invalid'

        user = self.User(email=old_email, unverified_email=new_email)

        self.assertEqual(old_email, user.email)
        self.assertEqual(new_email, user.unverified_email)

        token = user.create_email_activation_token()

        user.activate_email(token)

        self.assertEqual(new_email, user.email)
        self.assertIsNone(user.unverified_email)

    def test_cannot_get_email_token_without_email(self):
        user = self.User()

        with self.assertRaises(TypeError):
            user.create_email_activation_token()

    def test_can_use_any_email_token(self):
        user = self.User(unverified_email='unverified@email.invalid')

        token1 = user.create_email_activation_token()
        token2 = user.create_email_activation_token()
        token3 = user.create_email_activation_token()
        token4 = user.create_email_activation_token()
        token5 = user.create_email_activation_token()

        self.assertTrue(user.activate_email(token4))

    def test_email_not_unique(self):
        email = 'foo@bar.invalid'
        user = self.User(email=email)

        self.session.add(user)
        self.session.commit()

        user2 = self.User(email=email)

        self.session.add(user2)
        self.session.commit()

    def test_email_unique(self):
        email = 'foo@bar.invalid'
        user = self.UserUniqueEmail(email=email)

        self.session.add(user)
        self.session.commit()

        with self.assertRaises(IntegrityError):
            user2 = self.UserUniqueEmail(email=email)

            self.session.add(user2)
            self.session.commit()


class TestTimestampMixin(unittest.TestCase):
    server_side = True

    def setUp(self):
        self.engine = create_engine('sqlite:///:memory:', echo=False)
        self.session = sessionmaker(bind=self.engine)()
        self.Base = declarative_base(
            bind=self.engine
        )

        class GizmoClass(self.Base, timestamp_mixin(self.server_side)):
            __tablename__ = 'gizmos'

            id = Column(Integer, primary_key=True)

        self.Base.metadata.drop_all()
        self.Base.metadata.create_all()

        self.Gizmo = GizmoClass

    def test_timestamp_set_at_creation(self):
        g = self.Gizmo()

        self.session.add(g)
        t = datetime.utcnow()
        self.session.commit()
        self.assertLess(t - g.created, timedelta(seconds=1))

        self.assertIsNone(g.modified)

    def test_timestamp_updated_on_update(self):
        g = self.Gizmo()

        self.session.add(g)
        self.session.commit()

        time.sleep(1.1)

        created_before = g.created

        g.id = 99
        self.session.add(g)
        self.session.commit()

        t = datetime.utcnow()
        self.assertLess(t - g.modified, timedelta(seconds=1))

        self.assertEqual(g.created, created_before)


class TestServerSideTimestampMixin(TestTimestampMixin):
    server_side = False
