import logging
import os
import unittest
from unittest.mock import patch

from flask import Flask
import jinja2
import ldap
from mockldap import MockLdap

from flask_appbuilder import AppBuilder, SQLA
from flask_appbuilder.security.manager import AUTH_LDAP

logging.basicConfig(format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
logging.getLogger().setLevel(logging.DEBUG)
log = logging.getLogger(__name__)


class LDAPSearchTestCase(unittest.TestCase):
    top = ("o=test", {"o": ["test"]})
    example = ("ou=example,o=test", {"ou": ["example"]})
    manager = (
        "cn=manager,ou=example,o=test",
        {"cn": ["manager"], "userPassword": ["ldaptest"]},
    )
    alice = (
        "cn=alice,ou=example,o=test",
        {
            "cn": ["alice"],
            "givenName": [b"Alice"],
            "sn": [b"Doe"],
            "email": [b"alice@example.com"],
            "memberOf": [b"cn=group,ou=groups,o=test"],
            "userPassword": ["alicepw"],
        },
    )
    group = (
        "cn=group,ou=groups,o=test",
        {"cn": ["group"], "member": ["cn=alice,ou=example,o=test"]},
    )
    admins = ("cn=admins,ou=groups,o=test", {"cn": ["admins"], "member": []})

    directory = dict([top, example, group, admins, manager, alice])

    initialize_call = ("initialize", ("ldap://localhost/",), {})
    opt_referrals_call = ("set_option", (ldap.OPT_REFERRALS, 0), {})
    manager_simple_bind_s_call = (
        "simple_bind_s",
        ("cn=manager,ou=example,o=test", "ldaptest"),
        {},
    )
    alice_simple_bind_s_call = (
        "simple_bind_s",
        ("cn=alice,ou=example,o=test", "alicepw"),
        {},
    )
    search_s_call = (
        "search_s",
        ("ou=example,o=test", 2, "(cn=alice)", ["givenName", "sn", "email"]),
        {},
    )
    search_s_with_memberof_call = (
        "search_s",
        (
            "ou=example,o=test",
            2,
            "(cn=alice)",
            ["givenName", "sn", "email", "memberOf"],
        ),
        {},
    )

    @classmethod
    def setUpClass(cls):
        # We only need to create the MockLdap instance once. The content we
        # pass in will be used for all LDAP connections.
        cls.mockldap = MockLdap(cls.directory)

    @classmethod
    def tearDownClass(cls):
        del cls.mockldap

    def setUp(self):

        self.mockldap.start()
        self.ldapobj = self.mockldap["ldap://localhost/"]

        self.app = Flask(__name__)
        self.app.jinja_env.undefined = jinja2.StrictUndefined
        self.app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI")
        self.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        self.app.config["AUTH_TYPE"] = AUTH_LDAP
        self.app.config["AUTH_LDAP_UID_FIELD"] = "cn"
        self.app.config["AUTH_LDAP_ALLOW_SELF_SIGNED"] = False
        self.app.config["AUTH_LDAP_USE_TLS"] = False
        self.app.config["AUTH_LDAP_SERVER"] = "ldap://localhost/"
        self.app.config["AUTH_LDAP_SEARCH"] = "ou=example,o=test"
        self.app.config["AUTH_LDAP_BIND_USER"] = "cn=manager,ou=example,o=test"
        self.app.config["AUTH_LDAP_BIND_PASSWORD"] = "ldaptest"
        self.app.config["AUTH_LDAP_APPEND_DOMAIN"] = False
        self.app.config["AUTH_LDAP_FIRSTNAME_FIELD"] = "givenName"
        self.app.config["AUTH_LDAP_LASTNAME_FIELD"] = "sn"
        self.app.config["AUTH_LDAP_EMAIL_FIELD"] = "email"

        self.db = SQLA(self.app)

    def tearDown(self):
        self.mockldap.stop()
        del self.ldapobj
        log.debug("TEAR DOWN")

        self.db.session.remove()
        self.db.drop_all()

        self.appbuilder = None
        self.app = None
        self.db = None

    def test_ldapsearch(self):
        con = ldap.initialize("ldap://localhost/")

        self.app.config["AUTH_LDAP_SEARCH_FILTER"] = ""
        self.appbuilder = AppBuilder(self.app, self.db.session)

        user = self.appbuilder.sm._search_ldap(ldap, con, "alice")
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [self.initialize_call, self.manager_simple_bind_s_call, self.search_s_call],
        )
        self.assertEqual(user[0][0], self.alice[0])

    def test_ldapsearchfilter(self):
        # mockldap has an issue with bytes in attrs
        # search doesn't work with bytes, but to get the proper return you need bytes...
        with patch.dict(
            self.directory[self.alice[0]],
            {
                "memberOf": [
                    i.decode() for i in self.directory[self.alice[0]]["memberOf"]
                ]
            },
        ):
            mockldap = MockLdap(self.directory)
            mockldap.start()
            self.ldapobj = mockldap["ldap://localhost/"]
            con = ldap.initialize("ldap://localhost/")

            self.app.config[
                "AUTH_LDAP_SEARCH_FILTER"
            ] = "(memberOf=cn=group,ou=groups,o=test)"
            self.appbuilder = AppBuilder(self.app, self.db.session)

            search_s_call = (
                "search_s",
                (
                    "ou=example,o=test",
                    2,
                    "(&(memberOf=cn=group,ou=groups,o=test)(cn=alice))",
                    ["givenName", "sn", "email"],
                ),
                {},
            )

            user = self.appbuilder.sm._search_ldap(ldap, con, "alice")
            self.assertEqual(
                self.ldapobj.methods_called(with_args=True),
                [self.initialize_call, self.manager_simple_bind_s_call, search_s_call],
            )
            self.assertEqual(user[0][0], self.alice[0])

    # missing username
    def test_ldapauth_missing_username(self):
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm

        self.assertIsNone(sm.auth_user_ldap(None, None))
        self.assertIsNone(sm.auth_user_ldap("", None))

        self.assertEquals(self.ldapobj.methods_called(with_args=True), [])
        self.assertEqual(sm.get_all_users(), [])

    # inactive user
    def test_ldapauth_inactive_user(self):
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        user = sm.add_user(
            username="testuser",
            first_name="test",
            last_name="user",
            email="testuser@example.com",
            role=[],
        )
        user.active = False

        self.assertIsNone(sm.auth_user_ldap("testuser", "somepassword"))

        self.assertEquals(self.ldapobj.methods_called(with_args=True), [])
        self.assertEqual(len(sm.get_all_users()), 1)

    # direct bind new
    def test_ldapauth_direct_new(self):
        self.app.config["AUTH_USER_REGISTRATION"] = True
        self.app.config["AUTH_LDAP_BIND_USER"] = None
        self.app.config["AUTH_LDAP_BIND_PASSWORD"] = None
        self.app.config["AUTH_LDAP_USERNAME_FORMAT"] = "cn=%s,ou=example,o=test"
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        self.assertEqual(sm.get_all_users(), [])

        user = sm.auth_user_ldap("alice", "alicepw")

        self.assertIsInstance(user, sm.user_model)
        self.assertEqual(len(sm.get_all_users()), 1)
        self.assertEqual(user.first_name, "Alice")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "alice@example.com")
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [
                self.initialize_call,
                self.opt_referrals_call,
                self.alice_simple_bind_s_call,
                self.search_s_call,
            ],
        )

    # direct bind existing
    def test_ldapauth_direct_existing(self):
        self.app.config["AUTH_LDAP_BIND_USER"] = None
        self.app.config["AUTH_LDAP_BIND_PASSWORD"] = None
        self.app.config["AUTH_LDAP_USERNAME_FORMAT"] = "cn=%s,ou=example,o=test"
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        user = sm.add_user(
            username="alice",
            first_name="Alice",
            last_name="Doe",
            email="alice@example.com",
            role=[],
        )
        self.assertEqual(len(sm.get_all_users()), 1)

        user = sm.auth_user_ldap("alice", "alicepw")

        self.assertIsInstance(user, sm.user_model)
        self.assertEqual(len(sm.get_all_users()), 1)
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [
                self.initialize_call,
                self.opt_referrals_call,
                self.alice_simple_bind_s_call,
            ],
        )

    # bind user new self-registration off
    def test_ldapauth_bind_new(self):
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        self.assertEqual(sm.get_all_users(), [])

        self.assertIsNone(sm.auth_user_ldap("alice", "alicepw"))

        self.assertEqual(sm.get_all_users(), [])
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [
                self.initialize_call,
                self.opt_referrals_call,
                self.manager_simple_bind_s_call,
                self.search_s_call,
                self.alice_simple_bind_s_call,
            ],
        )

    # bind user existing
    def test_ldapauth_bind_existing(self):
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        user = sm.add_user(
            username="alice",
            first_name="Alice",
            last_name="Doe",
            email="alice@example.com",
            role=[],
        )
        self.assertEqual(len(sm.get_all_users()), 1)

        user = sm.auth_user_ldap("alice", "alicepw")

        self.assertIsInstance(user, sm.user_model)
        self.assertEqual(len(sm.get_all_users()), 1)
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [
                self.initialize_call,
                self.opt_referrals_call,
                self.manager_simple_bind_s_call,
                self.search_s_call,
                self.alice_simple_bind_s_call,
            ],
        )

    # role mapping new user self register
    def test_ldapauth_bind_mapping(self):
        self.app.config["AUTH_USER_REGISTRATION"] = True
        self.app.config["AUTH_USER_REGISTRATION_ROLE"] = "Public"
        self.app.config["AUTH_ROLES_MAPPING"] = {
            "cn=group,ou=groups,o=test": "User",
            "cn=admins,ou=groups,o=test": "Admin",
        }
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        sm.add_role("User")
        self.assertEqual(sm.get_all_users(), [])

        log.warn(sm.get_all_roles())

        user = sm.auth_user_ldap("alice", "alicepw")

        self.assertEqual(len(sm.get_all_users()), 1)
        self.assertIsInstance(user, sm.user_model)
        self.assertEqual(user.roles, [sm.find_role("Public"), sm.find_role("User")])
        self.assertEqual(user.first_name, "Alice")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "alice@example.com")
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [
                self.initialize_call,
                self.opt_referrals_call,
                self.manager_simple_bind_s_call,
                self.search_s_with_memberof_call,
                self.alice_simple_bind_s_call,
                self.manager_simple_bind_s_call,
                self.search_s_with_memberof_call,
            ],
        )

    # role mapping login no sync
    def test_ldapauth_login_no_sync(self):
        self.app.config["AUTH_ROLES_MAPPING"] = {
            "cn=group,ou=groups,o=test": "User",
            "cn=admins,ou=groups,o=test": "Admin",
        }
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        sm.add_role("User")
        user = sm.add_user(
            username="alice",
            first_name="Alice",
            last_name="Doe",
            email="alice@example.com",
            role=[],
        )
        self.assertEqual(len(sm.get_all_users()), 1)

        user = sm.auth_user_ldap("alice", "alicepw")

        self.assertIsInstance(user, sm.user_model)
        self.assertEqual(len(sm.get_all_users()), 1)
        self.assertEqual(user.roles, [])
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [
                self.initialize_call,
                self.opt_referrals_call,
                self.manager_simple_bind_s_call,
                self.search_s_with_memberof_call,
                self.alice_simple_bind_s_call,
            ],
        )

    # role mapping login sync
    def test_ldapauth_login_sync(self):
        self.app.config["AUTH_ROLES_SYNC_AT_LOGIN"] = True
        self.app.config["AUTH_ROLES_MAPPING"] = {
            "cn=group,ou=groups,o=test": "User",
            "cn=admins,ou=groups,o=test": "Admin",
        }
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        sm.add_role("User")
        user = sm.add_user(
            username="alice",
            first_name="Alice",
            last_name="Doe",
            email="alice@example.com",
            role=[],
        )
        self.assertEqual(len(sm.get_all_users()), 1)

        user = sm.auth_user_ldap("alice", "alicepw")

        self.assertIsInstance(user, sm.user_model)
        self.assertEqual(len(sm.get_all_users()), 1)
        self.assertEqual(user.roles, [sm.find_role("User")])
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [
                self.initialize_call,
                self.opt_referrals_call,
                self.manager_simple_bind_s_call,
                self.search_s_with_memberof_call,
                self.alice_simple_bind_s_call,
                self.manager_simple_bind_s_call,
                self.search_s_with_memberof_call,
            ],
        )

    # role mapping login sync no changes
    def test_ldapauth_login_sync_no_change(self):
        self.app.config["AUTH_ROLES_SYNC_AT_LOGIN"] = True
        self.app.config["AUTH_ROLES_MAPPING"] = {
            "cn=group,ou=groups,o=test": "User",
            "cn=admins,ou=groups,o=test": "Admin",
        }
        self.appbuilder = AppBuilder(self.app, self.db.session)
        sm = self.appbuilder.sm
        sm.add_role("User")
        user = sm.add_user(
            username="alice",
            first_name="Alice",
            last_name="Doe",
            email="alice@example.com",
            role=[sm.find_role("User")],
        )
        self.assertEqual(len(sm.get_all_users()), 1)

        user = sm.auth_user_ldap("alice", "alicepw")

        self.assertIsInstance(user, sm.user_model)
        self.assertEqual(len(sm.get_all_users()), 1)
        self.assertEqual(user.roles, [sm.find_role("User")])
        self.assertEqual(
            self.ldapobj.methods_called(with_args=True),
            [
                self.initialize_call,
                self.opt_referrals_call,
                self.manager_simple_bind_s_call,
                self.search_s_with_memberof_call,
                self.alice_simple_bind_s_call,
                self.manager_simple_bind_s_call,
                self.search_s_with_memberof_call,
            ],
        )
