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
BIN_DIR = $(BUILD_DIR)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\OsTest\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\OsTest\$(MODULE_NAME)

#
# Build Macro
#
SOURCE_FILES =  \
	$(SOURCE_DIR)\SpdmRequester.c \
	$(SOURCE_DIR)\SpdmRequesterAuthentication.c \
	$(SOURCE_DIR)\SpdmRequesterMeasurement.c \
	$(SOURCE_DIR)\SpdmRequesterSession.c \
	$(SOURCE_DIR)\SpdmRequesterTest.c \
	$(SOURCE_DIR)\..\SpdmTestCommon\SpdmTestCommand.c \
	$(SOURCE_DIR)\..\SpdmTestCommon\SpdmTestKey.c \
	$(SOURCE_DIR)\..\SpdmTestCommon\SpdmTestSupport.c \


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
    $(BIN_DIR)\OsStub\BaseCryptLib\BaseCryptLib.lib \
    $(BIN_DIR)\OsStub\OpensslLib\OpensslLib.lib \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\MemoryAllocationLib.lib \
    $(BIN_DIR)\Library\SpdmLib\SpdmCommonLib\SpdmCommonLib.lib \
    $(BIN_DIR)\Library\SpdmLib\SpdmRequesterLib\SpdmRequesterLib.lib \
    $(OUTPUT_DIR)\$(MODULE_NAME).lib \


INC =  \
    /I$(WORKSPACE)\OsTest\SpdmRequesterTest \
    /I$(WORKSPACE)\OsTest\SpdmTestCommon \
    /I$(WORKSPACE)\Include \
    /I$(WORKSPACE)\Include\Hal \
    /I$(WORKSPACE)\Include\Hal\$(ARCH)

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
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseMemoryLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\DebugLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseCryptLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\OpensslLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\MemoryAllocationLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmCommonLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmRequesterLib\Makefile

#
# Individual Object Build Targets
#
$(OBJECT_FILES):  $(SOURCE_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_FILES)

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_FILES) /OUT:$@

$(OUTPUT_DIR)\$(MODULE_NAME) : $(STATIC_LIBRARY_FILES)
	"$(DLINK)" $(DLINK_FLAGS) $(DLINK_SPATH) $(STATIC_LIBRARY_FILES)

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


