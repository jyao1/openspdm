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
MODULE_NAME = SpdmRequesterLib

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
	$(SOURCE_DIR)\SpdmRequesterLibChallenge.c \
	$(SOURCE_DIR)\SpdmRequesterLibCommunication.c \
	$(SOURCE_DIR)\SpdmRequesterLibEndSession.c \
	$(SOURCE_DIR)\SpdmRequesterLibFinish.c \
	$(SOURCE_DIR)\SpdmRequesterLibGetCapability.c \
	$(SOURCE_DIR)\SpdmRequesterLibGetCertificate.c \
	$(SOURCE_DIR)\SpdmRequesterLibGetDigest.c \
	$(SOURCE_DIR)\SpdmRequesterLibGetMeasurement.c \
	$(SOURCE_DIR)\SpdmRequesterLibGetVersion.c \
	$(SOURCE_DIR)\SpdmRequesterLibKeyExchange.c \
	$(SOURCE_DIR)\SpdmRequesterLibNegotiateAlgorithm.c \
	$(SOURCE_DIR)\SpdmRequesterLibPskExchange.c \
	$(SOURCE_DIR)\SpdmRequesterLibPskFinish.c \
	$(SOURCE_DIR)\SpdmRequesterLibSendReceive.c \


OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmRequesterLibChallenge.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibCommunication.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibEndSession.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibFinish.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetCapability.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetCertificate.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetDigest.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetMeasurement.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetVersion.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibKeyExchange.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibNegotiateAlgorithm.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibPskExchange.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibPskFinish.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibSendReceive.obj \


INC =  \
    /I$(SOURCE_DIR) \
    /I$(WORKSPACE)\Library\SpdmLib\SpdmCommonLib \
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


