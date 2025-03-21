#include <gtest/gtest.h>

extern "C" {
    #include "vk_ldap.h"
}

TEST(VkLdapTest, TestConnectionToLDAPServer) {
    char *err = NULL;
    LDAPConn *lpconn = vk_ldap_init("ldap://ldap", &err);
    EXPECT_FALSE(err);
    EXPECT_TRUE(lpconn);
    vk_ldap_destroy(lpconn);
}

TEST(VkLdapTest, TestLDAPBindAuth) {
    char *err = NULL;
    LDAPConn *lpconn = vk_ldap_init("ldap://localhost", &err);
    EXPECT_FALSE(err);
    EXPECT_TRUE(lpconn);

    err = NULL;
    int ret = vk_ldap_auth(lpconn, "CN=user1,OU=devops,DC=valkey,DC=io", "user1@123", &err);
    EXPECT_EQ(ret, 0);
    EXPECT_FALSE(err);

    vk_ldap_destroy(lpconn);
}
