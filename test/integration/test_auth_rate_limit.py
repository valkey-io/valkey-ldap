import time

import valkey
from valkey.exceptions import AuthenticationError, ResponseError

from util import LdapTestCase


RATE_LIMIT_ERROR = "Too many failed authentication attempts"


class AuthRateLimitTest(LdapTestCase):
    def setUp(self):
        super(AuthRateLimitTest, self).setUp()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "bind")
        self.vk.execute_command("CONFIG", "SET", "ldap.bind_dn_prefix", "cn=")
        self.vk.execute_command(
            "CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io"
        )
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "0")
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_window", "60")
        self.vk.execute_command(
            "CONFIG", "SET", "ldap.auth_rate_limit_block_duration", "300"
        )

        # Separate connection that performs the authentication attempts, so the
        # admin connection (self.vk) keeps its default user.
        self.client = valkey.Valkey(host="localhost", port=6379, db=0)

    def tearDown(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap ldap://ldap-2")
        self.vk.execute_command("CONFIG", "SET", "ldap.acl_fallback_enabled", "no")
        self.vk.execute_command("ACL", "DELUSER", "fallbackuser")
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "0")
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_window", "60")
        self.vk.execute_command(
            "CONFIG", "SET", "ldap.auth_rate_limit_block_duration", "300"
        )
        self.client.close()
        super(AuthRateLimitTest, self).tearDown()

    def _auth(self, password):
        self.client.execute_command("AUTH", "user1", password)

    def _fail_auth(self, times):
        for _ in range(times):
            with self.assertRaises((AuthenticationError, ResponseError)) as ctx:
                self._auth("wrongpass")
            self.assertNotIn(RATE_LIMIT_ERROR, str(ctx.exception))

    def _assert_rate_limited(self):
        with self.assertRaises((AuthenticationError, ResponseError)) as ctx:
            self._auth("user1@123")
        self.assertIn(RATE_LIMIT_ERROR, str(ctx.exception))

    def _info(self):
        # valkey-py parses the INFO reply into a dict
        info = self.vk.execute_command("INFO", "ldap")
        return {k: str(v) for k, v in info.items()}

    def test_disabled_by_default(self):
        self._fail_auth(10)
        self._auth("user1@123")
        self.assertEqual(self.client.execute_command("ACL", "WHOAMI").decode(), "user1")
        self.assertEqual(self._info()["ldap_auth_rate_limit_enabled"], "no")

    def test_blocks_after_max_failures(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "3")

        self._fail_auth(3)

        # Even the right password is rejected while the IP is blocked
        self._assert_rate_limited()

        info = self._info()
        self.assertEqual(info["ldap_auth_rate_limit_enabled"], "yes")
        self.assertEqual(info["ldap_auth_rate_limit_blocked_ips"], "1")

        # Changing the rate limit settings clears the tracked state
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "5")
        self._auth("user1@123")
        self.assertEqual(self.client.execute_command("ACL", "WHOAMI").decode(), "user1")

    def test_successes_are_not_counted(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "2")

        for _ in range(5):
            self._auth("user1@123")
        self.assertEqual(self.client.execute_command("ACL", "WHOAMI").decode(), "user1")

    def test_success_does_not_reset_failures(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "3")

        self._fail_auth(2)
        self._auth("user1@123")
        self._fail_auth(1)
        self._assert_rate_limited()

    def test_block_expires(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "2")
        self.vk.execute_command(
            "CONFIG", "SET", "ldap.auth_rate_limit_block_duration", "2"
        )
        # A block also lasts until the window ends
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_window", "2")

        self._fail_auth(2)
        self._assert_rate_limited()

        time.sleep(2.5)

        self._auth("user1@123")
        self.assertEqual(self.client.execute_command("ACL", "WHOAMI").decode(), "user1")

    def test_exempted_users_not_rate_limited(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.exempted_users_regex", "^default$")
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "1")

        self._fail_auth(1)
        self._assert_rate_limited()

        # The exempted default user keeps authenticating through the local ACL
        self.client.execute_command("AUTH", "default", "anything")

    def test_acl_fallback_attempts_are_counted(self):
        # With LDAP unreachable and ACL fallback enabled, attempts fall through
        # to Valkey's own password check, so they must still be counted.
        self.vk.execute_command("ACL", "SETUSER", "fallbackuser", "on", ">secret", "+@all", "~*")
        self.vk.execute_command("CONFIG", "SET", "ldap.acl_fallback_enabled", "yes")
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://127.0.0.1:1")

        # Make sure attempts really fall back to the ACL password check
        self.client.execute_command("AUTH", "fallbackuser", "secret")
        self.assertEqual(
            self.client.execute_command("ACL", "WHOAMI").decode(), "fallbackuser"
        )

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_rate_limit_max_failures", "3")

        for _ in range(3):
            with self.assertRaises((AuthenticationError, ResponseError)) as ctx:
                self.client.execute_command("AUTH", "fallbackuser", "wrong")
            self.assertNotIn(RATE_LIMIT_ERROR, str(ctx.exception))

        with self.assertRaises((AuthenticationError, ResponseError)) as ctx:
            self.client.execute_command("AUTH", "fallbackuser", "secret")
        self.assertIn(RATE_LIMIT_ERROR, str(ctx.exception))
