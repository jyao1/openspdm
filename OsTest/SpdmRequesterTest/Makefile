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
MODULE_NAME = SpdmRequesterTest
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\OsTest\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\OsTest\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmRequester.obj \
    $(OUTPUT_DIR)\SpdmRequesterAuthentication.obj \
    $(OUTPUT_DIR)\SpdmRequesterMeasurement.obj \
    $(OUTPUT_DIR)\SpdmRequesterSession.obj \
    $(OUTPUT_DIR)\SpdmRequesterTest.obj \
    $(OUTPUT_DIR)\SpdmTestCommand.obj \
    $(OUTPUT_DIR)\SpdmTestKey.obj \
    $(OUTPUT_DIR)\SpdmTestSupport.obj \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)\OsStub\BaseMemoryLib\BaseMemoryLib.lib \
    $(BIN_DIR)\OsStub\DebugLib\DebugLib.lib \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\BaseCryptLib$(CRYPTO).lib \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\$(CRYPTO)Lib.lib \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\MemoryAllocationLib.lib \
    $(BIN_DIR)\Library\SpdmLib\SpdmCommonLib\SpdmCommonLib.lib \
    $(BIN_DIR)\Library\SpdmLib\SpdmRequesterLib\SpdmRequesterLib.lib \
    $(OUTPUT_DIR)\$(MODULE_NAME).lib \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(OBJECT_FILES) \
    $(BIN_DIR)\OsStub\BaseMemoryLib\*.obj \
    $(BIN_DIR)\OsStub\DebugLib\*.obj \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\*.obj \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\*.obj \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\*.obj \
    $(BIN_DIR)\Library\SpdmLib\SpdmCommonLib\*.obj \
    $(BIN_DIR)\Library\SpdmLib\SpdmRequesterLib\*.obj \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\OsTest\SpdmTestCommon \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH)

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
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\MemoryAllocationLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmCommonLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmRequesterLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\SpdmRequester.obj : $(SOURCE_DIR)\SpdmRequester.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequester.c

$(OUTPUT_DIR)\SpdmRequesterAuthentication.obj : $(SOURCE_DIR)\SpdmRequesterAuthentication.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterAuthentication.c

$(OUTPUT_DIR)\SpdmRequesterMeasurement.obj : $(SOURCE_DIR)\SpdmRequesterMeasurement.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterMeasurement.c

$(OUTPUT_DIR)\SpdmRequesterSession.obj : $(SOURCE_DIR)\SpdmRequesterSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterSession.c

$(OUTPUT_DIR)\SpdmRequesterTest.obj : $(SOURCE_DIR)\SpdmRequesterTest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterTest.c

$(OUTPUT_DIR)\SpdmTestCommand.obj : $(SOURCE_DIR)\../SpdmTestCommon/SpdmTestCommand.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\../SpdmTestCommon/SpdmTestCommand.c

$(OUTPUT_DIR)\SpdmTestKey.obj : $(SOURCE_DIR)\../SpdmTestCommon/SpdmTestKey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\../SpdmTestCommon/SpdmTestKey.c

$(OUTPUT_DIR)\SpdmTestSupport.obj : $(SOURCE_DIR)\../SpdmTestCommon/SpdmTestSupport.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\../SpdmTestCommon/SpdmTestSupport.c

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


