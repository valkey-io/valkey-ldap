from unittest import TestCase

import valkey
from valkey.exceptions import ResponseError


class LdapModuleTest(TestCase):
    def setUp(self):
        vk = valkey.Valkey(host="localhost", port=6379, db=0)

        vk.execute_command("CONFIG", "SET", "ldap.auth_enabled", "yes")

        # LDAP server location
        vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap")

        # TLS configuration
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_ca_cert_path", "/valkey-ldap/valkey-ldap-ca.crt"
        )
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_cert_path", "/valkey-ldap/valkey-ldap-client.crt"
        )
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_key_path", "/valkey-ldap/valkey-ldap-client.key"
        )
        vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "no")

        vk.execute_command(
            "CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io"
        )

        self.vk = vk

    def tearDown(self):
        self.vk.close()
        self.vk = None

    def test_ldap_no_server_error(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "")
        with self.assertRaises(ResponseError) as ctx:
            self.vk.execute_command("AUTH", "user1", "user1@123")
        self.assertTrue("no server set in configuration" in str(ctx.exception))

    def test_ldap_auth(self):
        self.vk.execute_command("ACL", "SETUSER", "user1", "ON", ">pass", "allcommands")
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_ssl_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        self.vk.execute_command("ACL", "SETUSER", "user1", "ON", ">pass", "allcommands")
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_tls_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "yes")
        self.vk.execute_command("ACL", "SETUSER", "user1", "ON", ">pass", "allcommands")
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_disabled(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_enabled", "no")
        self.vk.execute_command("ACL", "SETUSER", "user1", "ON", ">pass", "allcommands")
        self.vk.execute_command("AUTH", "user1", "pass")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")


class LdapModuleBindAndSearchTest(TestCase):
    def setUp(self):
        vk = valkey.Valkey(host="localhost", port=6379, db=0)

        vk.execute_command("CONFIG", "SET", "ldap.auth_enabled", "yes")
        vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "SearchAndBind")

        # LDAP server location
        vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap")

        # TLS configuration
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_ca_cert_path", "/valkey-ldap/valkey-ldap-ca.crt"
        )
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_cert_path", "/valkey-ldap/valkey-ldap-client.crt"
        )
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_key_path", "/valkey-ldap/valkey-ldap-client.key"
        )
        vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "no")

        vk.execute_command("CONFIG", "SET", "ldap.search_base", "dc=valkey,dc=io")
        vk.execute_command(
            "CONFIG", "SET", "ldap.search_bind_dn", "cn=admin,dc=valkey,dc=io"
        )
        vk.execute_command("CONFIG", "SET", "ldap.search_bind_passwd", "admin123!")

        self.vk = vk

    def tearDown(self):
        self.vk.close()
        self.vk = None

    def test_ldap_auth(self):
        self.vk.execute_command("ACL", "SETUSER", "u2", "ON", ">pass", "allcommands")
        self.vk.execute_command("AUTH", "u2", "user2@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "u2")

    def test_ldap_ssl_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        self.vk.execute_command("ACL", "SETUSER", "u2", "ON", ">pass", "allcommands")
        self.vk.execute_command("AUTH", "u2", "user2@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "u2")

    def test_ldap_auth_no_user(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        self.vk.execute_command("ACL", "SETUSER", "u2", "ON", ">pass", "allcommands")
        with self.assertRaises(ResponseError) as ctx:
            self.vk.execute_command("AUTH", "user2", "user2@123")
        print(ctx.exception)
        self.assertTrue("query did not return any entry" in str(ctx.exception))
