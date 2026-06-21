import time
from unittest import TestCase
import docker
import valkey


class DockerServices:

    def __init__(self):
        self.client = docker.from_env()

    def assert_all_services_running(self):
        for ct in self.client.containers.list():
            assert ct.status == "running"

    def _find_container(self, name: str):
        for ct in self.client.containers.list(all=True):
            if ct.name == name:
                return ct
        return None

    def stop_service(self, name: str):
        ct = self._find_container(name)
        if ct is None:
            return None
        ct.reload()
        if ct.status != "running":
            return ct
        ct.kill()
        return ct

    def restart_service(self, serv):
        if serv is None:
            raise RuntimeError("Cannot restart an unknown container")
        serv.restart()

    def exec_in(self, name: str, cmd: str):
        ct = self._find_container(name)
        if ct is None:
            raise RuntimeError(f"Container '{name}' not found")
        result = ct.exec_run(["bash", "-c", cmd], user="root")
        return result.exit_code, result.output

    def wait_for_port(self, name: str, port: int):
        while True:
            code, _ = self.exec_in(name, f"bash -c 'echo > /dev/tcp/localhost/{port}' 2>/dev/null")
            if code == 0:
                return
            time.sleep(0.5)


DOCKER_SERVICES = DockerServices()


class LdapTestCase(TestCase):
    def setUp(self):
        vk = valkey.Valkey(host="localhost", port=6379, db=0)

        # LDAP server location
        vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap ldap://ldap-2")

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
        vk.execute_command("CONFIG", "SET", "ldap.return_auth_errors", "no")

        # Set search base for group rules search (needed even in bind mode)
        vk.execute_command("CONFIG", "SET", "ldap.search_base", "dc=valkey,dc=io")
        vk.execute_command("CONFIG", "SET", "ldap.search_bind_dn", "cn=admin,dc=valkey,dc=io")
        vk.execute_command("CONFIG", "SET", "ldap.search_bind_passwd", "admin123!")
        
        # Configure to use 'description' attribute for ACL rules (for testing)
        vk.execute_command("CONFIG", "SET", "ldap.groups_rules_attribute", "description")

        # Add users in Valkey
        vk.execute_command("ACL", "SETUSER", "user1", "ON", ">pass", "+@all", "~*")
        vk.execute_command("ACL", "SETUSER", "u2", "ON", ">pass", "+@all", "~*")

        self.vk = vk

    def tearDown(self):
        assert self.vk is not None, "Valkey instance should not be None"
        self.vk.close()
        self.vk = None


def parse_valkey_info_section(section: str) -> dict:
    result = {}
    lines = section.split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
        else:
            dict_key, dict_values = line.split(":", 1)
            nested_dict = {}
            for key_value_pair in dict_values.split(","):
                key, value = key_value_pair.strip().split("=", 1)
                nested_dict[key.strip()] = value.strip()
            result[dict_key.strip()] = nested_dict
    return result


def clean_acl(client):
    """Remove all users except default and pre-configured LDAP users from ACL"""
    acl_list = client.execute_command("ACL", "LIST")
    # Preserve default and the LDAP users defined in valkey.conf (user1, u2)
    preserve_users = {"default", "user1", "u2"}
    for user_line in acl_list:
        # Parse username from ACL LIST output (format: "user <username> ...")
        parts = user_line.split()
        if len(parts) >= 2 and parts[0] == "user":
            username = parts[1]
            # Don't delete preserved users
            if username not in preserve_users:
                try:
                    client.execute_command("ACL", "DELUSER", username)
                except Exception:
                    # Ignore errors if user doesn't exist or can't be deleted
                    pass


def setup_ldap_users(client):
    """Setup LDAP configuration for testing"""
    # Configure LDAP settings for testing (switch to search+bind mode)
    client.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap ldap://ldap-2")
    client.execute_command("CONFIG", "SET", "ldap.auth_mode", "search+bind")
    
    # Clear bind mode settings to avoid conflicts
    client.execute_command("CONFIG", "SET", "ldap.bind_dn_prefix", "")
    client.execute_command("CONFIG", "SET", "ldap.bind_dn_suffix", "")
    
    # Set search+bind mode settings
    # The search_filter and search_attribute work together: filter is applied, then attribute is checked
    # For user1 (has cn but no uid), we need to search by cn
    client.execute_command("CONFIG", "SET", "ldap.search_base", "dc=valkey,dc=io")
    client.execute_command("CONFIG", "SET", "ldap.search_filter", "objectClass=*")
    client.execute_command("CONFIG", "SET", "ldap.search_attribute", "cn")
    client.execute_command("CONFIG", "SET", "ldap.search_bind_dn", "cn=admin,dc=valkey,dc=io")
    client.execute_command("CONFIG", "SET", "ldap.search_bind_passwd", "admin123!")
    
    # TLS configuration
    client.execute_command("CONFIG", "SET", "ldap.tls_ca_cert_path", "/valkey-ldap/valkey-ldap-ca.crt")
    client.execute_command("CONFIG", "SET", "ldap.tls_cert_path", "/valkey-ldap/valkey-ldap-client.crt")
    client.execute_command("CONFIG", "SET", "ldap.tls_key_path", "/valkey-ldap/valkey-ldap-client.key")
    client.execute_command("CONFIG", "SET", "ldap.use_starttls", "no")
    
    # Users user1 and u2 are already defined in valkey.conf
    # No need to recreate them
