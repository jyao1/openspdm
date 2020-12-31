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
MODULE_NAME = SpdmCommonLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\Library\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\Library\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmCommonLibContextData.obj \
    $(OUTPUT_DIR)\SpdmCommonLibContextDataSession.obj \
    $(OUTPUT_DIR)\SpdmCommonLibCryptoService.obj \
    $(OUTPUT_DIR)\SpdmCommonLibCryptoServiceSession.obj \
    $(OUTPUT_DIR)\SpdmCommonLibOpaqueData.obj \
    $(OUTPUT_DIR)\SpdmCommonLibSupport.obj \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH)

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)\$(MODULE_NAME).lib

#
# Default target, which will build dependent libraries in addition to source files
#

all: mbuild

#
# ModuleTarget
#

mbuild: $(INIT_TARGET) $(CODA_TARGET)

#
# Initialization target: print build information and create necessary directories
#
init:
	-@if not exist $(OUTPUT_DIR) $(MD) $(OUTPUT_DIR)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\SpdmCommonLibContextData.obj : $(SOURCE_DIR)\SpdmCommonLibContextData.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmCommonLibContextData.c

$(OUTPUT_DIR)\SpdmCommonLibContextDataSession.obj : $(SOURCE_DIR)\SpdmCommonLibContextDataSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmCommonLibContextDataSession.c

$(OUTPUT_DIR)\SpdmCommonLibCryptoService.obj : $(SOURCE_DIR)\SpdmCommonLibCryptoService.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmCommonLibCryptoService.c

$(OUTPUT_DIR)\SpdmCommonLibCryptoServiceSession.obj : $(SOURCE_DIR)\SpdmCommonLibCryptoServiceSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmCommonLibCryptoServiceSession.c

$(OUTPUT_DIR)\SpdmCommonLibOpaqueData.obj : $(SOURCE_DIR)\SpdmCommonLibOpaqueData.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmCommonLibOpaqueData.c

$(OUTPUT_DIR)\SpdmCommonLibSupport.obj : $(SOURCE_DIR)\SpdmCommonLibSupport.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmCommonLibSupport.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


