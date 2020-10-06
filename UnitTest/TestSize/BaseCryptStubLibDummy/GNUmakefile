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
MODULE_NAME = BaseCryptStubLibDummy

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/UnitTest/TestSize/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/UnitTest/TestSize/$(MODULE_NAME)

CC_FLAGS += -Wno-incompatible-pointer-types -Wno-pointer-sign

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/RandDummy.o \
    $(OUTPUT_DIR)/TimeClockDummy.o \


INC =  \
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH) \
    -I$(WORKSPACE)/OsStub/Include \

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
$(OUTPUT_DIR)/RandDummy.o : $(SOURCE_DIR)/RandDummy.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/TimeClockDummy.o : $(SOURCE_DIR)/TimeClockDummy.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


