find_path(OPENLDAP_INCLUDE_DIR NAMES ldap.h PATHS /usr/include $ENV{LDAP_DIR}/include /usr/local/include)

find_library(LDAP_LIBRARY NAMES ldap HINTS $ENV{LDAP_DIR}/lib)
find_library(LBER_LIBRARY NAMES lber HINTS $ENV{LDAP_DIR}/lib)

set(OPENLDAP_LIBRARIES ${LDAP_LIBRARY} ${LBER_LIBRARY})

# handle the QUIETLY and REQUIRED arguments and set OPENLDAP_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenLdap DEFAULT_MSG OPENLDAP_INCLUDE_DIR LDAP_LIBRARY LBER_LIBRARY)

mark_as_advanced(OPENLDAP_FOUND OPENLDAP_INCLUDE_DIR LDAP_LIBRARY LBER_LIBRARY)
