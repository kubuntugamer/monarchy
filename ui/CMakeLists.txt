# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.16)

option(MONARCHY_WITH_LDAP "Build with OpenLDAP backend support" OFF)
option(MONARCHY_WITH_SAMBA "Build with Samba backend support" OFF)
project(monarchy-ui VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Core Gui PrintSupport Concurrent Network)

add_library(monarchy-ui-core STATIC
    src/objecticons.h
    src/objecticons.cpp
    src/resultsmodel.h
    src/resultsmodel.cpp
    src/consoleview.h
    src/consoleview.cpp
    src/propertysheet.h
    src/propertysheet.cpp
    ../backend/SampleData.h
    ../backend/SampleData.cpp
    ../backend/ConnectionService.h
    ../backend/ConnectionService.cpp
    ../backend/DirectoryService.h
    ../backend/DirectoryService.cpp
    ../backend/LdapClient.h
    ../backend/LdapClient.cpp
    ../backend/AdminService.h
    ../backend/AdminService.cpp
    ../engine/LdapServer.h
    ../engine/LdapServer.cpp
    ../engine/DnsServer.h
    ../engine/DnsServer.cpp
    ../engine/Provisioner.h
    ../engine/Provisioner.cpp
    ../engine/Ntlm.h
    ../engine/Ntlm.cpp
    ../engine/Aes.h
    ../engine/Aes.cpp
    ../engine/Des.h
    ../engine/Des.cpp
    ../engine/Asn1.h
    ../engine/Asn1.cpp
    ../engine/Gss.h
    ../engine/Gss.cpp
    ../engine/Krb5.h
    ../engine/Krb5.cpp
    ../engine/Pac.h
    ../engine/Pac.cpp
    ../engine/Kdc.h
    ../engine/Kdc.cpp
    ../engine/Ndr.h
    ../engine/Ndr.cpp
    ../engine/Rpc.h
    ../engine/Rpc.cpp
    ../engine/Samr.h
    ../engine/Samr.cpp
    ../engine/Lsad.h
    ../engine/Lsad.cpp
    ../engine/Netlogon.h
    ../engine/Netlogon.cpp
    ../engine/Epm.h
    ../engine/Epm.cpp
    ../engine/Smb2.h
    ../engine/Smb2.cpp
    ../engine/Drs.h
    ../engine/Drs.cpp
)

target_include_directories(monarchy-ui-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../backend
    ${CMAKE_CURRENT_SOURCE_DIR}/../engine
)

target_compile_definitions(monarchy-ui-core PUBLIC
    $<$<BOOL:${MONARCHY_WITH_LDAP}>:MONARCHY_WITH_LDAP>
    $<$<BOOL:${MONARCHY_WITH_SAMBA}>:MONARCHY_WITH_SAMBA>
)

if(MONARCHY_WITH_LDAP)
    find_library(LDAP_LIBRARY ldap REQUIRED)
    find_library(LBER_LIBRARY lber REQUIRED)
    find_library(SASL2_LIBRARY sasl2)
    target_link_libraries(monarchy-ui-core PUBLIC ${LDAP_LIBRARY} ${LBER_LIBRARY})
    if(SASL2_LIBRARY)
        target_link_libraries(monarchy-ui-core PUBLIC ${SASL2_LIBRARY})
    endif()
endif()

target_link_libraries(monarchy-ui-core PUBLIC
    Qt6::Widgets
    Qt6::Core
    Qt6::Gui
    Qt6::PrintSupport
    Qt6::Concurrent
    Qt6::Network
)

add_executable(monarchy-ui
    src/main.cpp
    src/mainwindow.h
    src/mainwindow.cpp
    resources/resources.qrc
)

target_link_libraries(monarchy-ui PRIVATE monarchy-ui-core)

# Development probe for the RPC interface (SAMR); not shipped.
add_executable(monarchy-rpc-probe ../engine/samr_probe_main.cpp)
target_link_libraries(monarchy-rpc-probe PRIVATE monarchy-ui-core)

# Development probe for the Netlogon endpoint (MS-NRPC); not shipped.
add_executable(monarchy-netlogon-probe ../engine/netlogon_probe_main.cpp)
target_link_libraries(monarchy-netlogon-probe PRIVATE monarchy-ui-core)

# Development probe for the replication endpoint (MS-DRSR); not shipped.
add_executable(monarchy-drs-probe ../engine/drs_probe_main.cpp)
target_link_libraries(monarchy-drs-probe PRIVATE monarchy-ui-core)

# Throwaway diagnostics for the cross-process RPC stall; not shipped. They
# live in /tmp on the developer machine, so they only exist conditionally.
if(EXISTS /tmp/rpcinline_test.cpp)
    add_executable(monarchy-rpc-inline-test /tmp/rpcinline_test.cpp)
    target_link_libraries(monarchy-rpc-inline-test PRIVATE monarchy-ui-core)
endif()
if(EXISTS /tmp/rpcserve_only.cpp)
    add_executable(monarchy-rpc-serve-only /tmp/rpcserve_only.cpp)
    target_link_libraries(monarchy-rpc-serve-only PRIVATE monarchy-ui-core)
endif()

# Provisions a domain from Monarchy's own code; no Samba or external server.
add_executable(monarchy-provision ../engine/provision_main.cpp)
target_link_libraries(monarchy-provision PRIVATE monarchy-ui-core)

include(CTest)
if(BUILD_TESTING)
    find_package(Qt6 6.5 REQUIRED COMPONENTS Test)

    add_executable(monarchy-ui-tests
        tests/test_consoleview.cpp
    )

    target_link_libraries(monarchy-ui-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-ui-tests COMMAND monarchy-ui-tests)
    set_tests_properties(monarchy-ui-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    add_executable(monarchy-backend-tests
        tests/test_backend.cpp
    )

    target_link_libraries(monarchy-backend-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-backend-tests COMMAND monarchy-backend-tests)
    set_tests_properties(monarchy-backend-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    add_executable(monarchy-dns-tests
        tests/test_dns.cpp
    )

    target_link_libraries(monarchy-dns-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-dns-tests COMMAND monarchy-dns-tests)
    set_tests_properties(monarchy-dns-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    add_executable(monarchy-ntlm-tests
        tests/test_ntlm.cpp
    )

    target_link_libraries(monarchy-ntlm-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-ntlm-tests COMMAND monarchy-ntlm-tests)
    set_tests_properties(monarchy-ntlm-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # Kerberos: the KDC is exercised directly, and — when MIT krb5 is available
    # on the build machine — with a real kinit/GSSAPI client over LDAP.
    find_path(KRB5_INCLUDE_DIR krb5.h)
    find_library(KRB5_LIBRARY krb5)
    find_library(K5CRYPTO_LIBRARY k5crypto)
    find_library(GSSAPI_KRB5_LIBRARY gssapi_krb5)

    add_executable(monarchy-kerberos-tests
        tests/test_kerberos.cpp
    )

    target_link_libraries(monarchy-kerberos-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    if(KRB5_INCLUDE_DIR AND KRB5_LIBRARY AND GSSAPI_KRB5_LIBRARY)
        target_include_directories(monarchy-kerberos-tests PRIVATE ${KRB5_INCLUDE_DIR})
        target_link_libraries(monarchy-kerberos-tests PRIVATE ${KRB5_LIBRARY} ${GSSAPI_KRB5_LIBRARY})
        if(K5CRYPTO_LIBRARY)
            target_link_libraries(monarchy-kerberos-tests PRIVATE ${K5CRYPTO_LIBRARY})
        endif()
        target_compile_definitions(monarchy-kerberos-tests PRIVATE MONARCHY_WITH_KRB5)
        message(STATUS "Kerberos interop test enabled (MIT krb5 found)")
    else()
        message(STATUS "Kerberos interop test runs without a third-party client (MIT krb5 not found)")
    endif()

    add_test(NAME monarchy-kerberos-tests COMMAND monarchy-kerberos-tests)
    set_tests_properties(monarchy-kerberos-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # Netlogon secure-channel negotiation against independent crypto vectors.
    add_executable(monarchy-netlogon-tests
        tests/test_netlogon.cpp
    )

    target_link_libraries(monarchy-netlogon-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-netlogon-tests COMMAND monarchy-netlogon-tests)
    set_tests_properties(monarchy-netlogon-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # DRSR marshalling and the replication interface over DCE/RPC.
    add_executable(monarchy-drs-tests
        tests/test_drs.cpp
    )

    target_link_libraries(monarchy-drs-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-drs-tests COMMAND monarchy-drs-tests)
    set_tests_properties(monarchy-drs-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # NDR marshalling and the SAMR interface over DCE/RPC.
    add_executable(monarchy-samr-tests
        tests/test_samr.cpp
    )

    target_link_libraries(monarchy-samr-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-samr-tests COMMAND monarchy-samr-tests)
    set_tests_properties(monarchy-samr-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # LSAD: the policy response encoding, byte for byte.
    add_executable(monarchy-lsad-tests
        tests/test_lsad.cpp
    )

    target_link_libraries(monarchy-lsad-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-lsad-tests COMMAND monarchy-lsad-tests)
    set_tests_properties(monarchy-lsad-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # The endpoint mapper: the tower encoding C706 appendix L defines and the
    # reply layout ept_lookup returns.
    add_executable(monarchy-epm-tests
        tests/test_epm.cpp
    )

    target_link_libraries(monarchy-epm-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-epm-tests COMMAND monarchy-epm-tests)
    set_tests_properties(monarchy-epm-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # SMB2 session setup and named-pipe I/O.
    add_executable(monarchy-smb-tests
        tests/test_smb2.cpp
    )

    target_link_libraries(monarchy-smb-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-smb-tests COMMAND monarchy-smb-tests)
    set_tests_properties(monarchy-smb-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # LDAP request controls: paged results (RFC 2696) and critical-extension
    # handling, exercised over a real socket.
    add_executable(monarchy-ldap-tests
        tests/test_ldap.cpp
        tests/ldap_wire_helpers.h
    )

    target_link_libraries(monarchy-ldap-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-ldap-tests COMMAND monarchy-ldap-tests)
    set_tests_properties(monarchy-ldap-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    # StartTLS: the LDAP server's TLS upgrade, with a provisioned certificate and
    # openssl's own client as an independent checker.
    add_executable(monarchy-tls-tests
        tests/test_tls.cpp
    )

    target_link_libraries(monarchy-tls-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-tls-tests COMMAND monarchy-tls-tests)
    set_tests_properties(monarchy-tls-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    add_executable(monarchy-provision-tests
        tests/test_provisioner.cpp
    )

    target_link_libraries(monarchy-provision-tests PRIVATE
        monarchy-ui-core
        Qt6::Test
    )

    add_test(NAME monarchy-provision-tests COMMAND monarchy-provision-tests)
    set_tests_properties(monarchy-provision-tests PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )
endif()

install(TARGETS monarchy-ui monarchy-provision DESTINATION bin)
