## @file
#  SPDM library.
#
#  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

#
# Platform Macro Definition
#

!INCLUDE $(WORKSPACE)\MakeFile.Flags

#
# Module Macro Definition
#
MODULE_NAME = TestSpdmRequester
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\UnitTest\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\UnitTest\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\TestSpdmRequester.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterGetVersion.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterGetCapability.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterNegotiateAlgorithm.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterGetDigest.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterGetCertificate.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterChallenge.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterGetMeasurement.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterKeyExchange.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterFinish.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterPskExchange.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterPskFinish.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterHeartbeat.obj \
    $(OUTPUT_DIR)\TestSpdmRequesterEndSession.obj \
    $(OUTPUT_DIR)\SpdmUnitTestCommon.obj \
    $(OUTPUT_DIR)\SpdmTestKey.obj \
    $(OUTPUT_DIR)\SpdmTestSupport.obj \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)\OsStub\BaseMemoryLib\BaseMemoryLib.lib \
    $(BIN_DIR)\OsStub\DebugLib\DebugLib.lib \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\BaseCryptLib$(CRYPTO).lib \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\$(CRYPTO)Lib.lib \
    $(BIN_DIR)\OsStub\RngLib\RngLib.lib \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\MemoryAllocationLib.lib \
    $(BIN_DIR)\Library\SpdmCommonLib\SpdmCommonLib.lib \
    $(BIN_DIR)\Library\SpdmRequesterLib\SpdmRequesterLib.lib \
    $(BIN_DIR)\Library\SpdmCryptLib\SpdmCryptLib.lib \
    $(BIN_DIR)\Library\SpdmSecuredMessageLib\SpdmSecuredMessageLib.lib \
    $(BIN_DIR)\SpdmEmu\SpdmDeviceSecretLib\SpdmDeviceSecretLib.lib \
    $(BIN_DIR)\UnitTest\SpdmTransportTestLib\SpdmTransportTestLib.lib \
    $(BIN_DIR)\UnitTest\CmockaLib\CmockaLib.lib \
    $(OUTPUT_DIR)\$(MODULE_NAME).lib \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(OBJECT_FILES) \
    $(BIN_DIR)\OsStub\BaseMemoryLib\*.obj \
    $(BIN_DIR)\OsStub\DebugLib\*.obj \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\*.obj \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\*.obj \
    $(BIN_DIR)\OsStub\RngLib\*.obj \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\*.obj \
    $(BIN_DIR)\Library\SpdmCommonLib\*.obj \
    $(BIN_DIR)\Library\SpdmRequesterLib\*.obj \
    $(BIN_DIR)\Library\SpdmCryptLib\*.obj \
    $(BIN_DIR)\Library\SpdmSecuredMessageLib\*.obj \
    $(BIN_DIR)\SpdmEmu\SpdmDeviceSecretLib\*.obj \
    $(BIN_DIR)\UnitTest\SpdmTransportTestLib\*.obj \
    $(BIN_DIR)\UnitTest\CmockaLib\*.obj \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\UnitTest\Include \
    -I$(WORKSPACE)\Library\SpdmCommonLib \
    -I$(WORKSPACE)\Library\SpdmRequesterLib \
    -I$(WORKSPACE)\Library\SpdmSecuredMessageLib \
    -I$(WORKSPACE)\SpdmEmu\SpdmDeviceSecretLib \
    -I$(WORKSPACE)\UnitTest\CmockaLib\cmocka\include \
    -I$(WORKSPACE)\UnitTest\CmockaLib\cmocka\include\cmockery \
    -I$(WORKSPACE)\UnitTest\SpdmUnitTestCommon \

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)\$(MODULE_NAME)

#
# Default target, which will build dependent libraries in addition to source files
#

all: mbuild

#
# ModuleTarget
#

mbuild: $(INIT_TARGET) gen_libs $(CODA_TARGET)

#
# Initialization target: print build information and create necessary directories
#
init:
	-@if not exist $(OUTPUT_DIR) $(MD) $(OUTPUT_DIR)

#
# GenLibsTarget
#
gen_libs:
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseMemoryLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\DebugLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseCryptLib$(CRYPTO)\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\$(CRYPTO)Lib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\RngLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\MemoryAllocationLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmCommonLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmRequesterLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmCryptLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmSecuredMessageLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\SpdmEmu\SpdmDeviceSecretLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\UnitTest\SpdmTransportTestLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\UnitTest\CmockaLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\TestSpdmRequester.obj : $(SOURCE_DIR)\TestSpdmRequester.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequester.c

$(OUTPUT_DIR)\TestSpdmRequesterGetVersion.obj : $(SOURCE_DIR)\TestSpdmRequesterGetVersion.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterGetVersion.c

$(OUTPUT_DIR)\TestSpdmRequesterGetCapability.obj : $(SOURCE_DIR)\TestSpdmRequesterGetCapability.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterGetCapability.c

$(OUTPUT_DIR)\TestSpdmRequesterNegotiateAlgorithm.obj : $(SOURCE_DIR)\TestSpdmRequesterNegotiateAlgorithm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterNegotiateAlgorithm.c

$(OUTPUT_DIR)\TestSpdmRequesterGetDigest.obj : $(SOURCE_DIR)\TestSpdmRequesterGetDigest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterGetDigest.c

$(OUTPUT_DIR)\TestSpdmRequesterGetCertificate.obj : $(SOURCE_DIR)\TestSpdmRequesterGetCertificate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterGetCertificate.c

$(OUTPUT_DIR)\TestSpdmRequesterChallenge.obj : $(SOURCE_DIR)\TestSpdmRequesterChallenge.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterChallenge.c

$(OUTPUT_DIR)\TestSpdmRequesterGetMeasurement.obj : $(SOURCE_DIR)\TestSpdmRequesterGetMeasurement.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterGetMeasurement.c

$(OUTPUT_DIR)\TestSpdmRequesterKeyExchange.obj : $(SOURCE_DIR)\TestSpdmRequesterKeyExchange.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterKeyExchange.c

$(OUTPUT_DIR)\TestSpdmRequesterFinish.obj : $(SOURCE_DIR)\TestSpdmRequesterFinish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterFinish.c

$(OUTPUT_DIR)\TestSpdmRequesterPskExchange.obj : $(SOURCE_DIR)\TestSpdmRequesterPskExchange.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterPskExchange.c

$(OUTPUT_DIR)\TestSpdmRequesterPskFinish.obj : $(SOURCE_DIR)\TestSpdmRequesterPskFinish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterPskFinish.c

$(OUTPUT_DIR)\TestSpdmRequesterHeartbeat.obj : $(SOURCE_DIR)\TestSpdmRequesterHeartbeat.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterHeartbeat.c

$(OUTPUT_DIR)\TestSpdmRequesterEndSession.obj : $(SOURCE_DIR)\TestSpdmRequesterEndSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmRequesterEndSession.c

$(OUTPUT_DIR)\SpdmUnitTestCommon.obj : $(SOURCE_DIR)\..\SpdmUnitTestCommon\SpdmUnitTestCommon.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\..\SpdmUnitTestCommon\SpdmUnitTestCommon.c

$(OUTPUT_DIR)\SpdmTestKey.obj : $(SOURCE_DIR)\..\SpdmUnitTestCommon\SpdmTestKey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\..\SpdmUnitTestCommon\SpdmTestKey.c

$(OUTPUT_DIR)\SpdmTestSupport.obj : $(SOURCE_DIR)\..\SpdmUnitTestCommon\SpdmTestSupport.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\..\SpdmUnitTestCommon\SpdmTestSupport.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

$(OUTPUT_DIR)\$(MODULE_NAME) : $(STATIC_LIBRARY_FILES)
	$(DLINK) $(DLINK_FLAGS) $(DLINK_SPATH) $(DLINK_OBJECT_FILES)

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


