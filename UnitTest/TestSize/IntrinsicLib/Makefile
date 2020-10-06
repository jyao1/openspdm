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
MODULE_NAME = IntrinsicLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\UnitTest\TestSize\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\UnitTest\TestSize\$(MODULE_NAME)

CC_FLAGS = $(CC_FLAGS) /GL-

#
# Build Macro
#

!IF "$(ARCH)" == "X64"
OBJECT_FILES =  \
    $(OUTPUT_DIR)\CopyMem.obj \
    $(OUTPUT_DIR)\MemoryIntrinsics.obj \

!ELSEIF "$(ARCH)" == "Ia32"
OBJECT_FILES =  \
    $(OUTPUT_DIR)\CopyMem.obj \
    $(OUTPUT_DIR)\MemoryIntrinsics.obj \
    $(OUTPUT_DIR)\MathDivS64x64.obj \
    $(OUTPUT_DIR)\MathDivS64x64Remainder.obj \
    $(OUTPUT_DIR)\MathDivU64x64.obj \
    $(OUTPUT_DIR)\MathDivU64x64Remainder.obj \
    $(OUTPUT_DIR)\MathFtol.obj \
    $(OUTPUT_DIR)\MathLShiftS64.obj \
    $(OUTPUT_DIR)\MathMultS64x64.obj \
    $(OUTPUT_DIR)\MathRemainderS64x64.obj \
    $(OUTPUT_DIR)\MathRemainderU64x64.obj \
    $(OUTPUT_DIR)\MathRShiftS64.obj \
    $(OUTPUT_DIR)\MathRShiftU64.obj \

!ENDIF

INC =  \
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
$(OUTPUT_DIR)\CopyMem.obj : $(SOURCE_DIR)\CopyMem.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\CopyMem.c

$(OUTPUT_DIR)\MemoryIntrinsics.obj : $(SOURCE_DIR)\MemoryIntrinsics.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\MemoryIntrinsics.c

$(OUTPUT_DIR)\MathDivS64x64.obj : $(SOURCE_DIR)\Ia32\MathDivS64x64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathDivS64x64.c

$(OUTPUT_DIR)\MathDivS64x64Remainder.obj : $(SOURCE_DIR)\Ia32\MathDivS64x64Remainder.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathDivS64x64Remainder.c

$(OUTPUT_DIR)\MathDivU64x64.obj : $(SOURCE_DIR)\Ia32\MathDivU64x64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathDivU64x64.c

$(OUTPUT_DIR)\MathDivU64x64Remainder.obj : $(SOURCE_DIR)\Ia32\MathDivU64x64Remainder.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathDivU64x64Remainder.c

$(OUTPUT_DIR)\MathFtol.obj : $(SOURCE_DIR)\Ia32\MathFtol.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathFtol.c

$(OUTPUT_DIR)\MathLShiftS64.obj : $(SOURCE_DIR)\Ia32\MathLShiftS64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathLShiftS64.c

$(OUTPUT_DIR)\MathMultS64x64.obj : $(SOURCE_DIR)\Ia32\MathMultS64x64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathMultS64x64.c

$(OUTPUT_DIR)\MathRemainderS64x64.obj : $(SOURCE_DIR)\Ia32\MathRemainderS64x64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathRemainderS64x64.c

$(OUTPUT_DIR)\MathRemainderU64x64.obj : $(SOURCE_DIR)\Ia32\MathRemainderU64x64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathRemainderU64x64.c

$(OUTPUT_DIR)\MathRShiftS64.obj : $(SOURCE_DIR)\Ia32\MathRShiftS64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathRShiftS64.c

$(OUTPUT_DIR)\MathRShiftU64.obj : $(SOURCE_DIR)\Ia32\MathRShiftU64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Ia32\MathRShiftU64.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


