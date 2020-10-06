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
MODULE_NAME = BaseCryptStubLibDummy

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\UnitTest\TestSize\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\UnitTest\TestSize\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\RandDummy.obj \
    $(OUTPUT_DIR)\TimeClockDummy.obj \



INC =  \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\OsStub\Include \

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
$(OUTPUT_DIR)\RandDummy.obj : $(SOURCE_DIR)\RandDummy.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\RandDummy.c

$(OUTPUT_DIR)\TimeClockDummy.obj : $(SOURCE_DIR)\TimeClockDummy.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\TimeClockDummy.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


