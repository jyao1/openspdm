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
OUTPUT_DIR = $(BIN_DIR)\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmDump.obj \
    $(OUTPUT_DIR)\SpdmDumpPcap.obj \
    $(OUTPUT_DIR)\SpdmDumpSession.obj \
    $(OUTPUT_DIR)\SpdmDumpSupport.obj \
    $(OUTPUT_DIR)\SpdmDumpSpdm.obj \
    $(OUTPUT_DIR)\SpdmDumpSecuredSpdm.obj \
    $(OUTPUT_DIR)\MctpDump.obj \
    $(OUTPUT_DIR)\MctpDumpPldm.obj \
    $(OUTPUT_DIR)\PciDoeDump.obj \
    $(OUTPUT_DIR)\SpdmDumpVendorPci.obj \
    $(OUTPUT_DIR)\PciDoeDumpDoe.obj \
    $(OUTPUT_DIR)\SpdmDumpPciIdeKm.obj \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)\OsStub\BaseMemoryLib\BaseMemoryLib.lib \
    $(BIN_DIR)\OsStub\DebugLibNull\DebugLibNull.lib \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\BaseCryptLib$(CRYPTO).lib \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\$(CRYPTO)Lib.lib \
    $(BIN_DIR)\OsStub\RngLib\RngLib.lib \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\MemoryAllocationLib.lib \
    $(BIN_DIR)\Library\SpdmCommonLib\SpdmCommonLib.lib \
    $(BIN_DIR)\Library\SpdmCryptLib\SpdmCryptLib.lib \
    $(BIN_DIR)\Library\SpdmSecuredMessageLib\SpdmSecuredMessageLib.lib \
    $(BIN_DIR)\Library\SpdmTransportMctpLib\SpdmTransportMctpLib.lib \
    $(BIN_DIR)\Library\SpdmTransportPciDoeLib\SpdmTransportPciDoeLib.lib \
    $(BIN_DIR)\OsStub\SpdmDeviceSecretLibNull\SpdmDeviceSecretLibNull.lib \
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
    $(BIN_DIR)\Library\SpdmCryptLib\*.obj \
    $(BIN_DIR)\Library\SpdmSecuredMessageLib\*.obj \
    $(BIN_DIR)\Library\SpdmTransportMctpLib\*.obj \
    $(BIN_DIR)\Library\SpdmTransportPciDoeLib\*.obj \
    $(BIN_DIR)\OsStub\SpdmDeviceSecretLibNull\*.obj \


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
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\RngLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\MemoryAllocationLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmCommonLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmCryptLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmSecuredMessageLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmTransportPciDoeLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmTransportMctpLib\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\SpdmDeviceSecretLibNull\$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\SpdmDump.obj : $(SOURCE_DIR)\SpdmDump.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmDump.c

$(OUTPUT_DIR)\SpdmDumpPcap.obj : $(SOURCE_DIR)\SpdmDumpPcap.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmDumpPcap.c

$(OUTPUT_DIR)\SpdmDumpSupport.obj : $(SOURCE_DIR)\SpdmDumpSupport.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmDumpSupport.c

$(OUTPUT_DIR)\SpdmDumpSpdm.obj : $(SOURCE_DIR)\Spdm\SpdmDumpSpdm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Spdm\SpdmDumpSpdm.c

$(OUTPUT_DIR)\SpdmDumpSecuredSpdm.obj : $(SOURCE_DIR)\Spdm\SpdmDumpSecuredSpdm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Spdm\SpdmDumpSecuredSpdm.c

$(OUTPUT_DIR)\SpdmDumpSession.obj : $(SOURCE_DIR)\Spdm\SpdmDumpSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Spdm\SpdmDumpSession.c

$(OUTPUT_DIR)\MctpDump.obj : $(SOURCE_DIR)\Mctp\MctpDump.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Mctp\MctpDump.c

$(OUTPUT_DIR)\MctpDumpPldm.obj : $(SOURCE_DIR)\Mctp\Pldm\MctpDumpPldm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Mctp\Pldm\MctpDumpPldm.c

$(OUTPUT_DIR)\PciDoeDump.obj : $(SOURCE_DIR)\Pci\PciDoeDump.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pci\PciDoeDump.c

$(OUTPUT_DIR)\SpdmDumpVendorPci.obj : $(SOURCE_DIR)\Pci\SpdmDumpVendorPci.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pci\SpdmDumpVendorPci.c

$(OUTPUT_DIR)\PciDoeDumpDoe.obj : $(SOURCE_DIR)\Pci\PciDoe\PciDoeDumpDoe.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pci\PciDoe\PciDoeDumpDoe.c

$(OUTPUT_DIR)\SpdmDumpPciIdeKm.obj : $(SOURCE_DIR)\Pci\PciIdeKm\SpdmDumpPciIdeKm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pci\PciIdeKm\SpdmDumpPciIdeKm.c

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


