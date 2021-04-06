cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/spdm_dump
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
)

SET(src_spdm_dump
    spdm_dump.c
    spdm_dump_pcap.c
    support.c
    spdm/spdm_dump_spdm.c
    spdm/spdm_dump_secured_spdm.c
    spdm/spdm_dump_session.c
    mctp/mctp_dump.c
    mctp/pldm/mctp_dump_pldm.c
    pci/pci_doe_dump.c
    pci/spdm_dump_vendor_pci.c
    pci/pci_doe/pci_doe_dump_doe.c
    pci/pci_ide_km/spdm_dump_pci_ide_km.c
)

SET(spdm_dump_LIBRARY
    memlib
    debuglib_null
    spdm_common_lib
    ${CRYPTO}lib
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_transport_pcidoe_lib
    spdm_device_secret_lib_null
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(spdm_dump
                   ${src_spdm_dump}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib_null>
                   $<TARGET_OBJECTS:spdm_common_lib>
                   $<TARGET_OBJECTS:${CRYPTO}lib>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:spdm_secured_message_lib>
                   $<TARGET_OBJECTS:spdm_transport_mctp_lib>
                   $<TARGET_OBJECTS:spdm_transport_pcidoe_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_null>
    )
else()
    ADD_EXECUTABLE(spdm_dump ${src_spdm_dump})
    TARGET_LINK_LIBRARIES(spdm_dump ${spdm_dump_LIBRARY})
endif()
