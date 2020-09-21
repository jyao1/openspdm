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
MODULE_NAME = TestSizeOfSpdmRequester
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\UnitTest\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\UnitTest\$(MODULE_NAME)

DLINK_FLAGS = /out:"$(BIN_DIR)\$(BASE_NAME).dll" /DLL /ENTRY:ModuleEntryPoint /base:0 /pdb:"$(BIN_DIR)\$(BASE_NAME).pdb" /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /MAP /OPT:REF
!IF "$(TARGET)" == "DEBUG"
DLINK_FLAGS = $(DLINK_FLAGS) /DEBUG
!ELSEIF "$(TARGET)" == "RELEASE"
DLINK_FLAGS = $(DLINK_FLAGS) /LTCG
!ENDIF

!IF "$(ARCH)" == "X64"
DLINK_FLAGS = $(DLINK_FLAGS) /MACHINE:AMD64
!ELSEIF "$(ARCH)" == "Ia32"
DLINK_FLAGS = $(DLINK_FLAGS) /MACHINE:I386
!ENDIF

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmRequesterMain.obj \
    $(OUTPUT_DIR)\SpdmRequesterAuthentication.obj \
    $(OUTPUT_DIR)\SpdmRequesterInit.obj \
    $(OUTPUT_DIR)\SpdmRequesterMain.obj \
    $(OUTPUT_DIR)\SpdmRequesterSession.obj \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)\OsStub\BaseMemoryLib\BaseMemoryLib.lib \
    $(BIN_DIR)\OsStub\DebugLibNull\DebugLibNull.lib \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\BaseCryptLib$(CRYPTO).lib \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\$(CRYPTO)Lib.lib \
    $(BIN_DIR)\OsStub\MemoryAllocationLibNull\MemoryAllocationLibNull.lib \
    $(BIN_DIR)\OsStub\IntrinsicLib\IntrinsicLib.lib \
    $(BIN_DIR)\OsStub\BaseCryptStubLibDummy\BaseCryptStubLibDummy.lib \
    $(BIN_DIR)\Library\SpdmLib\SpdmCommonLib\SpdmCommonLib.lib \
    $(BIN_DIR)\Library\SpdmLib\SpdmRequesterLib\SpdmRequesterLib.lib \
    $(BIN_DIR)\Library\SpdmLib\SpdmEncodingLib\SpdmEncodingLib.lib \
    $(OUTPUT_DIR)\$(MODULE_NAME).lib \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(OBJECT_FILES) \
    $(BIN_DIR)\OsStub\BaseMemoryLib\*.obj \
    $(BIN_DIR)\OsStub\DebugLibNull\*.obj \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\*.obj \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\*.obj \
    $(BIN_DIR)\OsStub\MemoryAllocationLibNull\*.obj \
    $(BIN_DIR)\OsStub\IntrinsicLib\*.obj \
    $(BIN_DIR)\OsStub\BaseCryptStubLibDummy\*.obj \
    $(BIN_DIR)\Library\SpdmLib\SpdmCommonLib\*.obj \
    $(BIN_DIR)\Library\SpdmLib\SpdmRequesterLib\*.obj \
    $(BIN_DIR)\Library\SpdmLib\SpdmEncodingLib\*.obj \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\OsStub\Include \

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
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\DebugLibNull\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseCryptLib$(CRYPTO)\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\$(CRYPTO)Lib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\MemoryAllocationLibNull\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\IntrinsicLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseCryptStubLibDummy\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmCommonLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmRequesterLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmEncodingLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\SpdmRequesterAuthentication.obj : $(SOURCE_DIR)\SpdmRequesterAuthentication.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterAuthentication.c

$(OUTPUT_DIR)\SpdmRequesterInit.obj : $(SOURCE_DIR)\SpdmRequesterInit.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterInit.c

$(OUTPUT_DIR)\SpdmRequesterMain.obj : $(SOURCE_DIR)\SpdmRequesterMain.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterMain.c

$(OUTPUT_DIR)\SpdmRequesterSession.obj : $(SOURCE_DIR)\SpdmRequesterSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterSession.c

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


