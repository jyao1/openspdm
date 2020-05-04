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
OUTPUT_DIR = $(BIN_DIR)\Library\SpdmLib\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\Library\SpdmLib\$(MODULE_NAME)

#
# Build Macro
#
SOURCE_FILES =  \
	$(SOURCE_DIR)\SpdmCommonLibContextData.c \
	$(SOURCE_DIR)\SpdmCommonLibCrypto.c \
	$(SOURCE_DIR)\SpdmCommonLibSessionKeys.c \
	$(SOURCE_DIR)\SpdmCommonLibSupport.c \


OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmCommonLibContextData.obj \
    $(OUTPUT_DIR)\SpdmCommonLibCrypto.obj \
    $(OUTPUT_DIR)\SpdmCommonLibSessionKeys.obj \
    $(OUTPUT_DIR)\SpdmCommonLibSupport.obj \


INC =  \
    /I$(SOURCE_DIR) \
    /I$(WORKSPACE)\Include \
    /I$(WORKSPACE)\Include\Hal \
    /I$(WORKSPACE)\Include\Hal\$(ARCH)

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
$(OBJECT_FILES):  $(SOURCE_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_FILES)

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_FILES) /OUT:$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


