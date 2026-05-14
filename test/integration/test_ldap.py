import time
from unittest import TestCase
from threading import Thread
from urllib.parse import urlparse

from valkey.exceptions import AuthenticationError, ConnectionError
import valkey

from util import DOCKER_SERVICES, LdapTestCase, parse_valkey_info_section


class LdapModuleTest(TestCase):
    def test_config_load_from_file(self):
        srv = DOCKER_SERVICES.stop_service("valkey")
        DOCKER_SERVICES.restart_service(srv)
        res = None
        while res is None:
            try:
                vk = valkey.Valkey(host="localhost", port=6379, db=0, socket_timeout=30)
                res = vk.execute_command("CONFIG", "GET", "ldap.servers")
            except ConnectionError:
                time.sleep(1)

        self.assertEqual(res[1].decode("utf-8"), "ldap://ldap ldap://ldap-2")

    def test_configs_after_reload(self):
        vk = valkey.Valkey(host="localhost", port=6379, db=0, socket_timeout=30)

        vk.execute_command("MODULE", "UNLOAD", "ldap")
        vk.execute_command("MODULE", "LOAD", "./libvalkey_ldap.so")

        res = vk.execute_command("CONFIG", "GET", "ldap.servers")
        # The default behavior of Valkey is that configurations set in valkey.conf
        # are only loaded in the first time the module is loaded. If we reload the
        # module without restarting valkey-server, then the configuration options
        # will have their default values.
        #
        self.assertEqual(res[1].decode("utf-8"), "")


class LdapModuleBindTest(LdapTestCase):
    def setUp(self):
        super(LdapModuleBindTest, self).setUp()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "bind")

        self.vk.execute_command(
            "CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io"
        )

    def test_ldap_module_unload_load(self):
        self.test_ldap_auth()
        self.vk.execute_command("MODULE", "UNLOAD", "ldap")
        self.vk.execute_command("MODULE", "LOAD", "./libvalkey_ldap.so")
        self.setUp()
        self.test_ldap_auth()

    def test_ldap_no_server_error(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "")
        with self.assertRaises(AuthenticationError) as ctx:
            self.vk.execute_command("AUTH", "user1", "user1@123")

    def test_ldap_auth(self):
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_wrong_pass(self):
        with self.assertRaises(AuthenticationError) as ctx:
            self.vk.execute_command("AUTH", "user1", "wrongpass")

    def test_ldap_ssl_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_tls_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "yes")
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_disabled(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "")
        self.vk.execute_command("AUTH", "user1", "pass")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_failed_auth_but_locally_successfull(self):
        self.vk.execute_command("AUTH", "user1", "pass")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")


class LdapModuleBindAndSearchTest(LdapTestCase):
    def setUp(self):
        super(LdapModuleBindAndSearchTest, self).setUp()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "search+bind")

        self.vk.execute_command(
            "CONFIG", "SET", "ldap.search_bind_dn", "cn=admin,dc=valkey,dc=io"
        )
        self.vk.execute_command("CONFIG", "SET", "ldap.search_bind_passwd", "admin123!")

        self.vk.execute_command("CONFIG", "SET", "ldap.search_base", "dc=valkey,dc=io")

    def test_ldap_auth(self):
        self.vk.execute_command("AUTH", "u2", "user2@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "u2")

    def test_ldap_ssl_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        self.vk.execute_command("AUTH", "u2", "user2@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "u2")

    def test_ldap_auth_no_user(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        with self.assertRaises(AuthenticationError) as ctx:
            self.vk.execute_command("AUTH", "user2", "user2@123")

    def test_ldap_bind_password_hidden(self):
        res = self.vk.execute_command("CONFIG", "GET", "ldap.search_bind_passwd")
        self.assertEqual(res[1].decode("utf-8"), "admin123!")

        res = self.vk.execute_command("CONFIG", "GET", "ldap.*")
        for i in range(0, len(res), 2):
            self.assertNotEqual(res[i].decode("utf-8"), "ldap.search_bind_passwd")


class LdapModuleFailoverTest(LdapTestCase):
    def setUp(self):
        super(LdapModuleFailoverTest, self).setUp()

        DOCKER_SERVICES.assert_all_services_running()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "bind")

        self.vk.execute_command(
            "CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io"
        )

    def test_ldap_auth(self):
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def _wait_for_ldap_server_status(self, server_name, status_desc):
        while True:
            result = self.vk.execute_command("INFO LDAP")
            status = parse_valkey_info_section(result.decode("utf-8"))

            for server in status.values():
                if server["host"] == server_name:
                    if server["status"] == status_desc:
                        return

            time.sleep(2)

    def test_single_auth_with_failover(self):
        service = DOCKER_SERVICES.stop_service("ldap")
        self._wait_for_ldap_server_status("ldap", "unhealthy")

        self.test_ldap_auth()

        DOCKER_SERVICES.restart_service(service)
        self._wait_for_ldap_server_status("ldap", "healthy")

    def test_single_auth_failure_and_recovery(self):
        service = DOCKER_SERVICES.stop_service("ldap")
        service2 = DOCKER_SERVICES.stop_service("ldap-2")
        self._wait_for_ldap_server_status("ldap", "unhealthy")
        self._wait_for_ldap_server_status("ldap-2", "unhealthy")

        with self.assertRaises(AuthenticationError) as ctx:
            self.vk.execute_command("AUTH", "user1", "user1@123")

        DOCKER_SERVICES.restart_service(service)
        self._wait_for_ldap_server_status("ldap", "healthy")

        self.test_ldap_auth()

        DOCKER_SERVICES.restart_service(service2)
        self._wait_for_ldap_server_status("ldap-2", "healthy")

    def test_unhealthy_error_includes_server_details(self):
        service = DOCKER_SERVICES.stop_service("ldap")
        service2 = DOCKER_SERVICES.stop_service("ldap-2")
        self._wait_for_ldap_server_status("ldap", "unhealthy")
        self._wait_for_ldap_server_status("ldap-2", "unhealthy")

        with self.assertRaises(AuthenticationError):
            self.vk.execute_command("AUTH", "user1", "user1@123")

        # Valkey always returns a generic auth error to the client. The per-server
        # error detail is exposed via INFO LDAP so operators can diagnose without
        # digging through server logs.
        info = parse_valkey_info_section(
            self.vk.execute_command("INFO LDAP").decode("utf-8")
        )
        for server in info.values():
            if server.get("host") in ("ldap", "ldap-2"):
                self.assertEqual(server.get("status"), "unhealthy")
                self.assertTrue(
                    server.get("error", ""),
                    f"server {server['host']} should expose a non-empty error reason",
                )

        DOCKER_SERVICES.restart_service(service)
        DOCKER_SERVICES.restart_service(service2)
        self._wait_for_ldap_server_status("ldap", "healthy")
        self._wait_for_ldap_server_status("ldap-2", "healthy")

    def test_multi_auth_with_failover(self):
        stop_worker = False
        worker_result = {"success": True, "error": None}

        def auth_worker():
            try:
                while not stop_worker:
                    self.test_ldap_auth()
            except Exception as ex:
                worker_result["success"] = False
                worker_result["error"] = ex

        worker_thread = Thread(target=auth_worker)
        worker_thread.start()
        time.sleep(1)

        service = DOCKER_SERVICES.stop_service("ldap")
        try:
            self._wait_for_ldap_server_status("ldap", "unhealthy")
            time.sleep(1)

            stop_worker = True
            worker_thread.join()
            self.assertIsNone(worker_result["error"])
        finally:
            if service is not None:
                DOCKER_SERVICES.restart_service(service)
                self._wait_for_ldap_server_status("ldap", "healthy")

        self.test_ldap_auth()

    def test_hard_drop_no_recovery(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.connection_pool_size", "5")
        # Kill both servers hard
        service = DOCKER_SERVICES.stop_service("ldap")
        service2 = DOCKER_SERVICES.stop_service("ldap-2")
        self._wait_for_ldap_server_status("ldap", "unhealthy")
        # Restart immediately - server comes up slowly
        DOCKER_SERVICES.restart_service(service)
        # Don't wait for healthy - fire auth attempts right away to stress pool reconstruction
        time.sleep(1)
        self._wait_for_ldap_server_status("ldap", "healthy")  # assert this eventually passes
        self.test_ldap_auth()
        DOCKER_SERVICES.restart_service(service2)
        self._wait_for_ldap_server_status("ldap-2", "healthy")


class LdapPoolReconstructionTest(LdapTestCase):
    """
    Reproduces the all-or-nothing reset_connections bug:
    when the LDAP server is degraded enough to accept the FD probe connection
    but rejects subsequent pool connections, the pool is left empty and the
    server never transitions back to HEALTHY.

    Uses iptables inside the ldap container (requires NET_ADMIN cap) to
    rate-limit new TCP SYN packets (--syn) on port 389. The FD probe's SYN
    consumes one burst slot; pool construction SYNs consume the rest or are
    rejected. Established connections are unaffected so the LDAP protocol
    can complete normally on allowed connections.
    """

    _IPTABLES_DROP_RULE = "iptables -I INPUT -p tcp --syn --dport 389 -j REJECT"

    def setUp(self):
        super().setUp()
        DOCKER_SERVICES.assert_all_services_running()
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "bind")
        self.vk.execute_command(
            "CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io"
        )
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap")
        self.vk.execute_command("CONFIG", "SET", "ldap.connection_pool_size", "5")
        self._iptables_active = False
        self._iptables_burst = 1

    def tearDown(self):
        if self._iptables_active:
            self._remove_connection_limit()
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap ldap://ldap-2")
        super().tearDown()

    def _wait_for_ldap_server_status(self, server_name, status_desc):
        while True:
            result = self.vk.execute_command("INFO LDAP")
            status = parse_valkey_info_section(result.decode("utf-8"))
            for server in status.values():
                if server["host"] == server_name:
                    if server["status"] == status_desc:
                        return
            time.sleep(2)

    def _rate_rule(self, burst):
        return (
            f"iptables -I INPUT -p tcp --syn --dport 389 "
            f"-m limit --limit 1/sec --limit-burst {burst} -j ACCEPT"
        )

    def _apply_connection_limit(self, burst=1):
        self._iptables_burst = burst
        # Insert REJECT first so it lands at position 1, then insert ACCEPT
        # which pushes REJECT to position 2. Final chain: [ACCEPT(rate), REJECT].
        DOCKER_SERVICES.exec_in("ldap", self._IPTABLES_DROP_RULE)
        DOCKER_SERVICES.exec_in("ldap", self._rate_rule(burst))
        self._iptables_active = True

    def _remove_connection_limit(self):
        DOCKER_SERVICES.exec_in("ldap", self._rate_rule(self._iptables_burst).replace("-I", "-D"))
        DOCKER_SERVICES.exec_in("ldap", self._IPTABLES_DROP_RULE.replace("-I", "-D"))
        self._iptables_active = False

    def _get_ldap_server_status(self):
        result = self.vk.execute_command("INFO LDAP")
        status = parse_valkey_info_section(result.decode("utf-8"))
        for server in status.values():
            if server.get("host") == "ldap":
                return server.get("status")
        return None

    def test_pool_reconstruction_failure_blocks_recovery(self):
        code, _ = DOCKER_SERVICES.exec_in("ldap", "which iptables")
        if code != 0:
            self.skipTest("iptables not available in ldap container")

        self.vk.execute_command("AUTH", "user1", "user1@123")

        service = DOCKER_SERVICES.stop_service("ldap")
        self._wait_for_ldap_server_status("ldap", "unhealthy")

        DOCKER_SERVICES.restart_service(service)

        # Apply the limit before the port is open so no FD tick can slip
        # through before the iptables rules are in place.
        # Allow only 1 new TCP SYN (burst=1) on port 389.
        # The FD probe's SYN uses the sole burst slot; every pool
        # construction SYN is rejected, leaving the pool empty.
        self._apply_connection_limit()

        DOCKER_SERVICES.wait_for_port("ldap", 389)

        # Give the FD several ticks to attempt recovery (interval=1s)
        time.sleep(6)

        self.assertEqual(
            self._get_ldap_server_status(), "unhealthy",
            "server should remain UNHEALTHY when all pool connections fail (0 connections rebuilt)",
        )

        # Remove the limit — ldap is now fully accessible
        self._remove_connection_limit()

        # The next successful FD tick should complete pool construction and recover
        self._wait_for_ldap_server_status("ldap", "healthy")
        self.vk.execute_command("AUTH", "user1", "user1@123")

    def test_partial_pool_reconstruction_recovers(self):
        # burst=2: the FD probe uses slot 1, one pool connection uses slot 2,
        # then connections 3-5 are rejected. reset_connections should accept the
        # partial pool (1 connection) and mark the server HEALTHY rather than
        # discarding everything and staying UNHEALTHY.
        code, _ = DOCKER_SERVICES.exec_in("ldap", "which iptables")
        if code != 0:
            self.skipTest("iptables not available in ldap container")

        self.vk.execute_command("AUTH", "user1", "user1@123")

        service = DOCKER_SERVICES.stop_service("ldap")
        self._wait_for_ldap_server_status("ldap", "unhealthy")

        DOCKER_SERVICES.restart_service(service)
        DOCKER_SERVICES.wait_for_port("ldap", 389)

        self._apply_connection_limit(burst=2)

        # With the partial-pool fix the server should recover even though only
        # 1 of the 5 pool connections could be established.
        self._wait_for_ldap_server_status("ldap", "healthy")
        self.vk.execute_command("AUTH", "user1", "user1@123")

        self._remove_connection_limit()


class LdapModuleSearchAndBindFailoverTest(LdapModuleFailoverTest):
    def setUp(self):
        super(LdapModuleSearchAndBindFailoverTest, self).setUp()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "search+bind")

        self.vk.execute_command("CONFIG", "SET", "ldap.search_base", "dc=valkey,dc=io")
        self.vk.execute_command(
            "CONFIG", "SET", "ldap.search_bind_dn", "cn=admin,dc=valkey,dc=io"
        )
        self.vk.execute_command("CONFIG", "SET", "ldap.search_bind_passwd", "admin123!")

    def test_ldap_auth(self):
        self.vk.execute_command("AUTH", "u2", "user2@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "u2")
