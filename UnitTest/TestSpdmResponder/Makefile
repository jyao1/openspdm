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
MODULE_NAME = TestSpdmResponder
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
    $(OUTPUT_DIR)\TestSpdmResponder.obj \
    $(OUTPUT_DIR)\TestSpdmResponderVersion.obj \
    $(OUTPUT_DIR)\TestSpdmResponderCapability.obj \
    $(OUTPUT_DIR)\TestSpdmResponderAlgorithm.obj \
    $(OUTPUT_DIR)\TestSpdmResponderDigest.obj \
    $(OUTPUT_DIR)\TestSpdmResponderCertificate.obj \
    $(OUTPUT_DIR)\TestSpdmResponderChallengeAuth.obj \
    $(OUTPUT_DIR)\TestSpdmResponderMeasurement.obj \
    $(OUTPUT_DIR)\TestSpdmResponderKeyExchange.obj \
    $(OUTPUT_DIR)\TestSpdmResponderFinish.obj \
    $(OUTPUT_DIR)\TestSpdmResponderPskExchange.obj \
    $(OUTPUT_DIR)\TestSpdmResponderPskFinish.obj \
    $(OUTPUT_DIR)\TestSpdmResponderHeartbeat.obj \
    $(OUTPUT_DIR)\TestSpdmResponderEndSession.obj \
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
    $(BIN_DIR)\Library\SpdmResponderLib\SpdmResponderLib.lib \
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
    $(BIN_DIR)\Library\SpdmResponderLib\*.obj \
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
    -I$(WORKSPACE)\Library\SpdmResponderLib \
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
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmResponderLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmCryptLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmSecuredMessageLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\SpdmEmu\SpdmDeviceSecretLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\UnitTest\SpdmTransportTestLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\UnitTest\CmockaLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\TestSpdmResponder.obj : $(SOURCE_DIR)\TestSpdmResponder.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponder.c

$(OUTPUT_DIR)\TestSpdmResponderVersion.obj : $(SOURCE_DIR)\TestSpdmResponderVersion.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderVersion.c

$(OUTPUT_DIR)\TestSpdmResponderCapability.obj : $(SOURCE_DIR)\TestSpdmResponderCapability.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderCapability.c

$(OUTPUT_DIR)\TestSpdmResponderAlgorithm.obj : $(SOURCE_DIR)\TestSpdmResponderAlgorithm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderAlgorithm.c

$(OUTPUT_DIR)\TestSpdmResponderDigest.obj : $(SOURCE_DIR)\TestSpdmResponderDigest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderDigest.c

$(OUTPUT_DIR)\TestSpdmResponderCertificate.obj : $(SOURCE_DIR)\TestSpdmResponderCertificate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderCertificate.c

$(OUTPUT_DIR)\TestSpdmResponderChallengeAuth.obj : $(SOURCE_DIR)\TestSpdmResponderChallengeAuth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderChallengeAuth.c

$(OUTPUT_DIR)\TestSpdmResponderMeasurement.obj : $(SOURCE_DIR)\TestSpdmResponderMeasurement.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderMeasurement.c

$(OUTPUT_DIR)\TestSpdmResponderKeyExchange.obj : $(SOURCE_DIR)\TestSpdmResponderKeyExchange.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderKeyExchange.c

$(OUTPUT_DIR)\TestSpdmResponderFinish.obj : $(SOURCE_DIR)\TestSpdmResponderFinish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderFinish.c

$(OUTPUT_DIR)\TestSpdmResponderPskExchange.obj : $(SOURCE_DIR)\TestSpdmResponderPskExchange.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderPskExchange.c

$(OUTPUT_DIR)\TestSpdmResponderPskFinish.obj : $(SOURCE_DIR)\TestSpdmResponderPskFinish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderPskFinish.c

$(OUTPUT_DIR)\TestSpdmResponderHeartbeat.obj : $(SOURCE_DIR)\TestSpdmResponderHeartbeat.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderHeartbeat.c

$(OUTPUT_DIR)\TestSpdmResponderEndSession.obj : $(SOURCE_DIR)\TestSpdmResponderEndSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TestSpdmResponderEndSession.c

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


