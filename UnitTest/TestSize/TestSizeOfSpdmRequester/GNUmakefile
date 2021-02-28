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
MODULE_NAME = TestSizeOfSpdmRequester
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/UnitTest/TestSize/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/UnitTest/TestSize/$(MODULE_NAME)

DLINK_FLAGS = -nostdlib -Wl,-n,-q,--gc-sections -Wl,--entry,ModuleEntryPoint 

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/SpdmRequesterMain.o \
    $(OUTPUT_DIR)/SpdmRequesterAuthentication.o \
    $(OUTPUT_DIR)/SpdmRequesterInit.o \
    $(OUTPUT_DIR)/SpdmRequesterMain.o \
    $(OUTPUT_DIR)/SpdmRequesterSession.o \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)/OsStub/BaseMemoryLib/BaseMemoryLib.a \
    $(BIN_DIR)/OsStub/DebugLibNull/DebugLibNull.a \
    $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/BaseCryptLib$(CRYPTO).a \
    $(BIN_DIR)/OsStub/$(CRYPTO)Lib/$(CRYPTO)Lib.a \
    $(BIN_DIR)/UnitTest/TestSize/RngLibNull/RngLibNull.a \
    $(BIN_DIR)/UnitTest/TestSize/MemoryAllocationLibNull/MemoryAllocationLibNull.a \
    $(BIN_DIR)/UnitTest/TestSize/IntrinsicLib/IntrinsicLib.a \
    $(BIN_DIR)/UnitTest/TestSize/BaseCryptStubLibDummy/BaseCryptStubLibDummy.a \
    $(BIN_DIR)/Library/SpdmCommonLib/SpdmCommonLib.a \
    $(BIN_DIR)/Library/SpdmRequesterLib/SpdmRequesterLib.a \
    $(BIN_DIR)/Library/SpdmCryptLib/SpdmCryptLib.a \
    $(BIN_DIR)/Library/SpdmSecuredMessageLib/SpdmSecuredMessageLib.a \
    $(BIN_DIR)/Library/SpdmTransportMctpLib/SpdmTransportMctpLib.a \
    $(BIN_DIR)/OsStub/SpdmDeviceSecretLibNull/SpdmDeviceSecretLibNull.a \
    $(OUTPUT_DIR)/$(MODULE_NAME).a \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(BIN_DIR)/OsStub/BaseMemoryLib/*.o \
    $(BIN_DIR)/OsStub/DebugLibNull/*.o \
    $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/*.o \
    $(BIN_DIR)/OsStub/$(CRYPTO)Lib/*.o \
    $(BIN_DIR)/UnitTest/TestSize/RngLibNull/*.o \
    $(BIN_DIR)/UnitTest/TestSize/MemoryAllocationLibNull/*.o \
    $(BIN_DIR)/UnitTest/TestSize/IntrinsicLib/*.o \
    $(BIN_DIR)/UnitTest/TestSize/BaseCryptStubLibDummy/*.o \
    $(BIN_DIR)/Library/SpdmCommonLib/*.o \
    $(BIN_DIR)/Library/SpdmRequesterLib/*.o \
    $(BIN_DIR)/Library/SpdmCryptLib/*.o \
    $(BIN_DIR)/Library/SpdmSecuredMessageLib/*.o \
    $(BIN_DIR)/Library/SpdmTransportMctpLib/*.o \
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
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/UnitTest/TestSize/RngLibNull/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/UnitTest/TestSize/MemoryAllocationLibNull/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/UnitTest/TestSize/IntrinsicLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/UnitTest/TestSize/BaseCryptStubLibDummy/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmCommonLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmRequesterLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmCryptLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmSecuredMessageLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/Library/SpdmTransportMctpLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/SpdmDeviceSecretLibNull/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)/SpdmRequesterAuthentication.o : $(SOURCE_DIR)/SpdmRequesterAuthentication.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterInit.o : $(SOURCE_DIR)/SpdmRequesterInit.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterMain.o : $(SOURCE_DIR)/SpdmRequesterMain.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterSession.o : $(SOURCE_DIR)/SpdmRequesterSession.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

$(OUTPUT_DIR)/$(MODULE_NAME) : $(STATIC_LIBRARY_FILES)
	@echo $(BIN_DIR)/OsStub/BaseMemoryLib/BaseMemoryLib.a > $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/DebugLibNull/DebugLibNull.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/BaseCryptLib$(CRYPTO).a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/$(CRYPTO)Lib/$(CRYPTO)Lib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/UnitTest/TestSize/RngLibNull/RngLibNull.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/UnitTest/TestSize/MemoryAllocationLibNull/MemoryAllocationLibNull.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/UnitTest/TestSize/IntrinsicLib/IntrinsicLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/UnitTest/TestSize/BaseCryptStubLibDummy/BaseCryptStubLibDummy.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmCommonLib/SpdmCommonLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmRequesterLib/SpdmRequesterLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmCryptLib/SpdmCryptLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmSecuredMessageLib/SpdmSecuredMessageLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/Library/SpdmTransportMctpLib/SpdmTransportMctpLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/SpdmDeviceSecretLibNull/SpdmDeviceSecretLibNull.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(OUTPUT_DIR)/$(MODULE_NAME).a >> $(OUTPUT_DIR)/tmp.list
	$(DLINK) $(DLINK_FLAGS) $(DLINK_SPATH) $(DLINK_OBJECT_FILES) $(DLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


