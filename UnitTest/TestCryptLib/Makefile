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
MODULE_NAME = TestCryptLib
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
    $(OUTPUT_DIR)\Cryptest.obj \
    $(OUTPUT_DIR)\HashVerify.obj \
    $(OUTPUT_DIR)\HmacVerify.obj \
    $(OUTPUT_DIR)\MacVerify.obj \
    $(OUTPUT_DIR)\AeadVerify.obj \
    $(OUTPUT_DIR)\RsaVerify.obj \
    $(OUTPUT_DIR)\RsaVerify2.obj \
    $(OUTPUT_DIR)\DhVerify.obj \
    $(OUTPUT_DIR)\EcVerify.obj \
    $(OUTPUT_DIR)\EcVerify2.obj \
    $(OUTPUT_DIR)\EdVerify.obj \
    $(OUTPUT_DIR)\EdVerify2.obj \
    $(OUTPUT_DIR)\Sm2Verify.obj \
    $(OUTPUT_DIR)\Sm2Verify2.obj \
    $(OUTPUT_DIR)\RandVerify.obj \
    $(OUTPUT_DIR)\X509Verify.obj \
    $(OUTPUT_DIR)\OsSupport.obj \


STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)\OsStub\BaseMemoryLib\BaseMemoryLib.lib \
    $(BIN_DIR)\OsStub\DebugLib\DebugLib.lib \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\BaseCryptLib$(CRYPTO).lib \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\$(CRYPTO)Lib.lib \
    $(BIN_DIR)\OsStub\RngLib\RngLib.lib \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\MemoryAllocationLib.lib \
    $(OUTPUT_DIR)\$(MODULE_NAME).lib \


STATIC_LIBRARY_OBJECT_FILES =  \
    $(OBJECT_FILES) \
    $(BIN_DIR)\OsStub\BaseMemoryLib\*.obj \
    $(BIN_DIR)\OsStub\DebugLib\*.obj \
    $(BIN_DIR)\OsStub\BaseCryptLib$(CRYPTO)\*.obj \
    $(BIN_DIR)\OsStub\$(CRYPTO)Lib\*.obj \
    $(BIN_DIR)\OsStub\RngLib\*.obj \
    $(BIN_DIR)\OsStub\MemoryAllocationLib\*.obj \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\OsStub\Include

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

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\Cryptest.obj : $(SOURCE_DIR)\Cryptest.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cryptest.c

$(OUTPUT_DIR)\HashVerify.obj : $(SOURCE_DIR)\HashVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\HashVerify.c

$(OUTPUT_DIR)\HmacVerify.obj : $(SOURCE_DIR)\HmacVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\HmacVerify.c

$(OUTPUT_DIR)\MacVerify.obj : $(SOURCE_DIR)\MacVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\MacVerify.c

$(OUTPUT_DIR)\AeadVerify.obj : $(SOURCE_DIR)\AeadVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\AeadVerify.c

$(OUTPUT_DIR)\RsaVerify.obj : $(SOURCE_DIR)\RsaVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\RsaVerify.c

$(OUTPUT_DIR)\RsaVerify2.obj : $(SOURCE_DIR)\RsaVerify2.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\RsaVerify2.c

$(OUTPUT_DIR)\DhVerify.obj : $(SOURCE_DIR)\DhVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\DhVerify.c

$(OUTPUT_DIR)\EcVerify.obj : $(SOURCE_DIR)\EcVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\EcVerify.c

$(OUTPUT_DIR)\EcVerify2.obj : $(SOURCE_DIR)\EcVerify2.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\EcVerify2.c

$(OUTPUT_DIR)\EdVerify.obj : $(SOURCE_DIR)\EdVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\EdVerify.c

$(OUTPUT_DIR)\EdVerify2.obj : $(SOURCE_DIR)\EdVerify2.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\EdVerify2.c

$(OUTPUT_DIR)\Sm2Verify.obj : $(SOURCE_DIR)\Sm2Verify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Sm2Verify.c

$(OUTPUT_DIR)\Sm2Verify2.obj : $(SOURCE_DIR)\Sm2Verify2.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Sm2Verify2.c

$(OUTPUT_DIR)\RandVerify.obj : $(SOURCE_DIR)\RandVerify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\RandVerify.c

$(OUTPUT_DIR)\X509Verify.obj : $(SOURCE_DIR)\X509Verify.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\X509Verify.c

$(OUTPUT_DIR)\OsSupport.obj : $(SOURCE_DIR)\OsSupport.c
    $(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\OsSupport.c

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


