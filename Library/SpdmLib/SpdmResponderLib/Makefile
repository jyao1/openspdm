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
MODULE_NAME = SpdmResponderLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\Library\SpdmLib\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\Library\SpdmLib\$(MODULE_NAME)

#
# Build Macro
#
SOURCE_FILES =  \
	$(SOURCE_DIR)\SpdmResponderLibAlgorithm.c \
	$(SOURCE_DIR)\SpdmResponderLibCapability.c \
	$(SOURCE_DIR)\SpdmResponderLibCertificate.c \
	$(SOURCE_DIR)\SpdmResponderLibChallengeAuth.c \
	$(SOURCE_DIR)\SpdmResponderLibCommunication.c \
	$(SOURCE_DIR)\SpdmResponderLibDigest.c \
	$(SOURCE_DIR)\SpdmResponderLibEndSession.c \
	$(SOURCE_DIR)\SpdmResponderLibError.c \
	$(SOURCE_DIR)\SpdmResponderLibFinish.c \
	$(SOURCE_DIR)\SpdmResponderLibMeasurement.c \
	$(SOURCE_DIR)\SpdmResponderLibPskExchange.c \
	$(SOURCE_DIR)\SpdmResponderLibPskFinish.c \
	$(SOURCE_DIR)\SpdmResponderLibReceiveSend.c \
	$(SOURCE_DIR)\SpdmResponderLibKeyExchange.c \
	$(SOURCE_DIR)\SpdmResponderLibVersion.c \


OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmResponderLibAlgorithm.obj \
    $(OUTPUT_DIR)\SpdmResponderLibCapability.obj \
    $(OUTPUT_DIR)\SpdmResponderLibCertificate.obj \
    $(OUTPUT_DIR)\SpdmResponderLibChallengeAuth.obj \
    $(OUTPUT_DIR)\SpdmResponderLibCommunication.obj \
    $(OUTPUT_DIR)\SpdmResponderLibDigest.obj \
    $(OUTPUT_DIR)\SpdmResponderLibEndSession.obj \
    $(OUTPUT_DIR)\SpdmResponderLibError.obj \
    $(OUTPUT_DIR)\SpdmResponderLibFinish.obj \
    $(OUTPUT_DIR)\SpdmResponderLibKeyExchange.obj \
    $(OUTPUT_DIR)\SpdmResponderLibMeasurement.obj \
    $(OUTPUT_DIR)\SpdmResponderLibPskExchange.obj \
    $(OUTPUT_DIR)\SpdmResponderLibPskFinish.obj \
    $(OUTPUT_DIR)\SpdmResponderLibReceiveSend.obj \
    $(OUTPUT_DIR)\SpdmResponderLibVersion.obj \


INC =  \
    /I$(WORKSPACE)\Library\SpdmLib\SpdmResponderLib \
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


