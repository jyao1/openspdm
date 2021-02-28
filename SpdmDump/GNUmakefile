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

include $(WORKSPACE)/GNUmakefile.Flags

#
# Module Macro Definition
#
MODULE_NAME = SpdmDump
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/$(MODULE_NAME)Dir

SOURCE_DIR = $(WORKSPACE)/$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/SpdmDump.o \
    $(OUTPUT_DIR)/SpdmDumpPcap.o \
    $(OUTPUT_DIR)/SpdmDumpSession.o \
    $(OUTPUT_DIR)/SpdmDumpSupport.o \
    $(OUTPUT_DIR)/SpdmDumpSpdm.o \
    $(OUTPUT_DIR)/SpdmDumpSecuredSpdm.o \
    $(OUTPUT_DIR)/MctpDump.o \
    $(OUTPUT_DIR)/MctpDumpPldm.o \
    $(OUTPUT_DIR)/PciDoeDump.o \
    $(OUTPUT_DIR)/SpdmDumpVendorPci.o \
    $(OUTPUT_DIR)/PciDoeDumpDoe.o \
    $(OUTPUT_DIR)/SpdmDumpPciIdeKm.o \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)/OsStub/BaseMemoryLib/BaseMemoryLib.a \
    $(BIN_DIR)/OsStub/DebugLibNull/DebugLibNull.a \
    $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/BaseCryptLib$(CRYPTO).a \
    $(BIN_DIR)/OsStub/$(CRYPTO)Lib/$(CRYPTO)Lib.a \
    $(BIN_DIR)/OsStub/RngLib/RngLib.a \
    $(BIN_DIR)/OsStub/MemoryAllocationLib/MemoryAllocationLib.a \
    $(BIN_DIR)/Library/SpdmCommonLib/SpdmCommonLib.a \
    $(BIN_DIR)/Library/SpdmCryptLib/SpdmCryptLib.a \
    $(BIN_DIR)/Library/SpdmSecuredMessageLib/SpdmSecuredMessageLib.a \
    $(BIN_DIR)/Library/SpdmTransportMctpLib/SpdmTransportMctpLib.a \
    $(BIN_DIR)/Library/SpdmTransportPciDoeLib/SpdmTransportPciDoeLib.a \
    $(BIN_DIR)/OsStub/SpdmDeviceSecretLibNull/SpdmDeviceSecretLibNull.a \
    $(OUTPUT_DIR)/$(MODULE_NAME).a \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(BIN_DIR)/OsStub/BaseMemoryLib/*.o \
    $(BIN_DIR)/OsStub/DebugLibNull/*.o \
    $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/*.o \
    $(BIN_DIR)/OsStub/$(CRYPTO)Lib/*.o \
    $(BIN_DIR)/OsStub/RngLib/*.o \
    $(BIN_DIR)/OsStub/MemoryAllocationLib/*.o \
    $(BIN_DIR)/Library/SpdmCommonLib/*.o \
    $(BIN_DIR)/Library/SpdmCryptLib/*.o \
    $(BIN_DIR)/Library/SpdmSecuredMessageLib/*.o \
    $(BIN_DIR)/Library/SpdmTransportMctpLib/*.o \
    $(BIN_DIR)/Library/SpdmTransportPciDoeLib/*.o \
    $(BIN_DIR)/OsStub/SpdmDeviceSecretLibNull/*.o \
    $(OUTPUT_DIR)/*.o \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH) \
    -I$(WORKSPACE)/OsStub/Include \

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)/$(MODULE_NAME)

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
	-@$(MD) $(OUTPUT_DIR)

#
# GenLibsTarget
#
gen_libs:
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/BaseMemoryLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/DebugLibNull/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/BaseCryptLib$(CRYPTO)/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/$(CRYPTO)Lib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/RngLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/MemoryAllocationLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmCommonLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmCryptLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmSecuredMessageLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmTransportMctpLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmTransportPciDoeLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/SpdmDeviceSecretLibNull/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)/SpdmDump.o : $(SOURCE_DIR)/SpdmDump.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmDumpPcap.o : $(SOURCE_DIR)/SpdmDumpPcap.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmDumpSupport.o : $(SOURCE_DIR)/SpdmDumpSupport.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmDumpSpdm.o : $(SOURCE_DIR)/Spdm/SpdmDumpSpdm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmDumpSecuredSpdm.o : $(SOURCE_DIR)/Spdm/SpdmDumpSecuredSpdm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmDumpSession.o : $(SOURCE_DIR)/Spdm/SpdmDumpSession.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/MctpDump.o : $(SOURCE_DIR)/Mctp/MctpDump.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/MctpDumpPldm.o : $(SOURCE_DIR)/Mctp/Pldm/MctpDumpPldm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/PciDoeDump.o : $(SOURCE_DIR)/Pci/PciDoeDump.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmDumpVendorPci.o : $(SOURCE_DIR)/Pci/SpdmDumpVendorPci.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/PciDoeDumpDoe.o : $(SOURCE_DIR)/Pci/PciDoe/PciDoeDumpDoe.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmDumpPciIdeKm.o : $(SOURCE_DIR)/Pci/PciIdeKm/SpdmDumpPciIdeKm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

$(OUTPUT_DIR)/$(MODULE_NAME) : $(STATIC_LIBRARY_FILES)
	@echo $(BIN_DIR)/OsStub/BaseMemoryLib/BaseMemoryLib.a > $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/DebugLibNull/DebugLibNull.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/BaseCryptLib$(CRYPTO).a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/$(CRYPTO)Lib/$(CRYPTO)Lib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/RngLib/RngLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/MemoryAllocationLib/MemoryAllocationLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmCommonLib/SpdmCommonLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmCryptLib/SpdmCryptLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmSecuredMessageLib/SpdmSecuredMessageLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmTransportMctpLib/SpdmTransportMctpLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmTransportPciDoeLib/SpdmTransportPciDoeLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/SpdmDeviceSecretLibNull/SpdmDeviceSecretLibNull.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(OUTPUT_DIR)/$(MODULE_NAME).a >> $(OUTPUT_DIR)/tmp.list
	$(DLINK) $(DLINK_FLAGS) $(DLINK_SPATH) $(DLINK_OBJECT_FILES) $(DLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


