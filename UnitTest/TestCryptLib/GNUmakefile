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
MODULE_NAME = TestCryptLib
BASE_NAME = $(MODULE_NAME)

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/UnitTest/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/UnitTest/$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/Cryptest.o \
    $(OUTPUT_DIR)/HashVerify.o \
    $(OUTPUT_DIR)/HmacVerify.o \
    $(OUTPUT_DIR)/MacVerify.o \
    $(OUTPUT_DIR)/AeadVerify.o \
    $(OUTPUT_DIR)/RsaVerify.o \
    $(OUTPUT_DIR)/RsaVerify2.o \
    $(OUTPUT_DIR)/DhVerify.o \
    $(OUTPUT_DIR)/EcVerify.o \
    $(OUTPUT_DIR)/EcVerify2.o \
    $(OUTPUT_DIR)/EdVerify.o \
    $(OUTPUT_DIR)/EdVerify2.o \
    $(OUTPUT_DIR)/Sm2Verify.o \
    $(OUTPUT_DIR)/Sm2Verify2.o \
    $(OUTPUT_DIR)/RandVerify.o \
    $(OUTPUT_DIR)/X509Verify.o \
    $(OUTPUT_DIR)/OsSupport.o \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)/OsStub/BaseMemoryLib/BaseMemoryLib.a \
    $(BIN_DIR)/OsStub/DebugLib/DebugLib.a \
    $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/BaseCryptLib$(CRYPTO).a \
    $(BIN_DIR)/OsStub/$(CRYPTO)Lib/$(CRYPTO)Lib.a \
    $(BIN_DIR)/OsStub/RngLib/RngLib.a \
    $(BIN_DIR)/OsStub/MemoryAllocationLib/MemoryAllocationLib.a \
    $(OUTPUT_DIR)/$(MODULE_NAME).a \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(BIN_DIR)/OsStub/BaseMemoryLib/*.o \
    $(BIN_DIR)/OsStub/DebugLib/*.o \
    $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/*.o \
    $(BIN_DIR)/OsStub/$(CRYPTO)Lib/*.o \
    $(BIN_DIR)/OsStub/RngLib/*.o \
    $(BIN_DIR)/OsStub/MemoryAllocationLib/*.o \
    $(OUTPUT_DIR)/*.o \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH) \
    -I$(WORKSPACE)/OsStub/Include

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
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/DebugLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/BaseCryptLib$(CRYPTO)/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/$(CRYPTO)Lib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/RngLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)/OsStub/MemoryAllocationLib/$(MAKEFILE) ARCH=$(ARCH) TARGET=$(TARGET) TOOLCHAIN=$(TOOLCHAIN) CRYPTO=$(CRYPTO)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)/Cryptest.o : $(SOURCE_DIR)/Cryptest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/HashVerify.o : $(SOURCE_DIR)/HashVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/HmacVerify.o : $(SOURCE_DIR)/HmacVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/MacVerify.o : $(SOURCE_DIR)/MacVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/AeadVerify.o : $(SOURCE_DIR)/AeadVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/RsaVerify.o : $(SOURCE_DIR)/RsaVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/RsaVerify2.o : $(SOURCE_DIR)/RsaVerify2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/DhVerify.o : $(SOURCE_DIR)/DhVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/EcVerify.o : $(SOURCE_DIR)/EcVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/EcVerify2.o : $(SOURCE_DIR)/EcVerify2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/EdVerify.o : $(SOURCE_DIR)/EdVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/EdVerify2.o : $(SOURCE_DIR)/EdVerify2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Sm2Verify.o : $(SOURCE_DIR)/Sm2Verify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Sm2Verify2.o : $(SOURCE_DIR)/Sm2Verify2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/RandVerify.o : $(SOURCE_DIR)/RandVerify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/X509Verify.o : $(SOURCE_DIR)/X509Verify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/OsSupport.o : $(SOURCE_DIR)/OsSupport.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

$(OUTPUT_DIR)/$(MODULE_NAME) : $(STATIC_LIBRARY_FILES)
	@echo $(BIN_DIR)/OsStub/BaseMemoryLib/BaseMemoryLib.a > $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/DebugLib/DebugLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/BaseCryptLib$(CRYPTO)/BaseCryptLib$(CRYPTO).a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/$(CRYPTO)Lib/$(CRYPTO)Lib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/RngLib/RngLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(BIN_DIR)/OsStub/MemoryAllocationLib/MemoryAllocationLib.a >> $(OUTPUT_DIR)/tmp.list
	@echo $(OUTPUT_DIR)/$(MODULE_NAME).a >> $(OUTPUT_DIR)/tmp.list
	$(DLINK) $(DLINK_FLAGS) $(DLINK_SPATH) $(DLINK_OBJECT_FILES) $(DLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


