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
MODULE_NAME = SpdmDump
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\Tool\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\Tool\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmDump.obj \
    $(OUTPUT_DIR)\SpdmDumpMessage.obj \
    $(OUTPUT_DIR)\SpdmDumpPcap.obj \
    $(OUTPUT_DIR)\SpdmDumpSession.obj \
    $(OUTPUT_DIR)\SpdmDumpSupport.obj \
    $(OUTPUT_DIR)\MctpDump.obj \
    $(OUTPUT_DIR)\PciDoeDump.obj \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)\OsStub\BaseMemoryLib\BaseMemoryLib.lib \
    $(BIN_DIR)\OsStub\DebugLibNull\DebugLibNull.lib \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\BaseCryptLib$(CRYPTO).lib \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\$(CRYPTO)Lib.lib \
    $(BIN_DIR)\OsStub\RngLib\RngLib.lib \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\MemoryAllocationLib.lib \
    $(BIN_DIR)\Library\SpdmCommonLib\SpdmCommonLib.lib \
    $(BIN_DIR)\Library\SpdmSecuredMessageLib\SpdmSecuredMessageLib.lib \
    $(BIN_DIR)\Library\SpdmTransportMctpLib\SpdmTransportMctpLib.lib \
    $(BIN_DIR)\Library\SpdmTransportPciDoeLib\SpdmTransportPciDoeLib.lib \
    $(OUTPUT_DIR)\$(MODULE_NAME).lib \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(OBJECT_FILES) \
    $(BIN_DIR)\OsStub\BaseMemoryLib\*.obj \
    $(BIN_DIR)\OsStub\DebugLibNull\*.obj \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\*.obj \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\*.obj \
    $(BIN_DIR)\OsStub\RngLib\*.obj \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\*.obj \
    $(BIN_DIR)\Library\SpdmCommonLib\*.obj \
    $(BIN_DIR)\Library\SpdmSecuredMessageLib\*.obj \
    $(BIN_DIR)\Library\SpdmTransportMctpLib\*.obj \
    $(BIN_DIR)\Library\SpdmTransportPciDoeLib\*.obj \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Library\SpdmCommonLib \
    -I$(WORKSPACE)\Tool\SpdmTestCommon \
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
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\RngLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\MemoryAllocationLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmCommonLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmSecuredMessageLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmTransportMctpLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmTransportPciDoeLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\SpdmDump.obj : $(SOURCE_DIR)\SpdmDump.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmDump.c

$(OUTPUT_DIR)\SpdmDumpMessage.obj : $(SOURCE_DIR)\SpdmDumpMessage.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmDumpMessage.c

$(OUTPUT_DIR)\SpdmDumpPcap.obj : $(SOURCE_DIR)\SpdmDumpPcap.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmDumpPcap.c

$(OUTPUT_DIR)\SpdmDumpSession.obj : $(SOURCE_DIR)\SpdmDumpSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmDumpSession.c

$(OUTPUT_DIR)\SpdmDumpSupport.obj : $(SOURCE_DIR)\SpdmDumpSupport.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmDumpSupport.c

$(OUTPUT_DIR)\MctpDump.obj : $(SOURCE_DIR)\MctpDump.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\MctpDump.c

$(OUTPUT_DIR)\PciDoeDump.obj : $(SOURCE_DIR)\PciDoeDump.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\PciDoeDump.c

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


