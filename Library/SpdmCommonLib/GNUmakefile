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
MODULE_NAME = SpdmCommonLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/Library/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/Library/$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/SpdmCommonLibContextData.o \
    $(OUTPUT_DIR)/SpdmCommonLibContextDataSession.o \
    $(OUTPUT_DIR)/SpdmCommonLibCryptoService.o \
    $(OUTPUT_DIR)/SpdmCommonLibCryptoServiceSession.o \
    $(OUTPUT_DIR)/SpdmCommonLibOpaqueData.o \
    $(OUTPUT_DIR)/SpdmCommonLibSupport.o \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH)

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)/$(MODULE_NAME).a

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
	-@$(MD) $(OUTPUT_DIR)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)/SpdmCommonLibContextData.o : $(SOURCE_DIR)/SpdmCommonLibContextData.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmCommonLibContextDataSession.o : $(SOURCE_DIR)/SpdmCommonLibContextDataSession.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmCommonLibCryptoService.o : $(SOURCE_DIR)/SpdmCommonLibCryptoService.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmCommonLibCryptoServiceSession.o : $(SOURCE_DIR)/SpdmCommonLibCryptoServiceSession.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmCommonLibOpaqueData.o : $(SOURCE_DIR)/SpdmCommonLibOpaqueData.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmCommonLibSupport.o : $(SOURCE_DIR)/SpdmCommonLibSupport.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


