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
MODULE_NAME = SpdmResponderLib

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
    $(OUTPUT_DIR)/SpdmResponderLibAlgorithm.o \
    $(OUTPUT_DIR)/SpdmResponderLibCapability.o \
    $(OUTPUT_DIR)/SpdmResponderLibCertificate.o \
    $(OUTPUT_DIR)/SpdmResponderLibChallengeAuth.o \
    $(OUTPUT_DIR)/SpdmResponderLibCommunication.o \
    $(OUTPUT_DIR)/SpdmResponderLibDigest.o \
    $(OUTPUT_DIR)/SpdmResponderLibEncapChallenge.o \
    $(OUTPUT_DIR)/SpdmResponderLibEncapGetCertificate.o \
    $(OUTPUT_DIR)/SpdmResponderLibEncapGetDigest.o \
    $(OUTPUT_DIR)/SpdmResponderLibEncapKeyUpdate.o \
    $(OUTPUT_DIR)/SpdmResponderLibEncapResponse.o \
    $(OUTPUT_DIR)/SpdmResponderLibEndSession.o \
    $(OUTPUT_DIR)/SpdmResponderLibError.o \
    $(OUTPUT_DIR)/SpdmResponderLibFinish.o \
    $(OUTPUT_DIR)/SpdmResponderLibHeartbeat.o \
    $(OUTPUT_DIR)/SpdmResponderLibKeyExchange.o \
    $(OUTPUT_DIR)/SpdmResponderLibKeyUpdate.o \
    $(OUTPUT_DIR)/SpdmResponderLibMeasurement.o \
    $(OUTPUT_DIR)/SpdmResponderLibPskExchange.o \
    $(OUTPUT_DIR)/SpdmResponderLibPskFinish.o \
    $(OUTPUT_DIR)/SpdmResponderLibReceiveSend.o \
    $(OUTPUT_DIR)/SpdmResponderLibVersion.o \
    $(OUTPUT_DIR)/SpdmResponderLibHandleResponseState.o \
    $(OUTPUT_DIR)/SpdmResponderLibRespondIfReady.o \

INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)/Library/SpdmCommonLib \
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
$(OUTPUT_DIR)/SpdmResponderLibAlgorithm.o : $(SOURCE_DIR)/SpdmResponderLibAlgorithm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibCapability.o : $(SOURCE_DIR)/SpdmResponderLibCapability.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibCertificate.o : $(SOURCE_DIR)/SpdmResponderLibCertificate.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibChallengeAuth.o : $(SOURCE_DIR)/SpdmResponderLibChallengeAuth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibCommunication.o : $(SOURCE_DIR)/SpdmResponderLibCommunication.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibDigest.o : $(SOURCE_DIR)/SpdmResponderLibDigest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibEncapChallenge.o : $(SOURCE_DIR)/SpdmResponderLibEncapChallenge.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibEncapGetCertificate.o : $(SOURCE_DIR)/SpdmResponderLibEncapGetCertificate.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibEncapGetDigest.o : $(SOURCE_DIR)/SpdmResponderLibEncapGetDigest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibEncapKeyUpdate.o : $(SOURCE_DIR)/SpdmResponderLibEncapKeyUpdate.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibEncapResponse.o : $(SOURCE_DIR)/SpdmResponderLibEncapResponse.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibEndSession.o : $(SOURCE_DIR)/SpdmResponderLibEndSession.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibError.o : $(SOURCE_DIR)/SpdmResponderLibError.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibFinish.o : $(SOURCE_DIR)/SpdmResponderLibFinish.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibHeartbeat.o : $(SOURCE_DIR)/SpdmResponderLibHeartbeat.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibKeyExchange.o : $(SOURCE_DIR)/SpdmResponderLibKeyExchange.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibKeyUpdate.o : $(SOURCE_DIR)/SpdmResponderLibKeyUpdate.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibMeasurement.o : $(SOURCE_DIR)/SpdmResponderLibMeasurement.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibPskExchange.o : $(SOURCE_DIR)/SpdmResponderLibPskExchange.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibPskFinish.o : $(SOURCE_DIR)/SpdmResponderLibPskFinish.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibReceiveSend.o : $(SOURCE_DIR)/SpdmResponderLibReceiveSend.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibVersion.o : $(SOURCE_DIR)/SpdmResponderLibVersion.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibHandleResponseState.o : $(SOURCE_DIR)/SpdmResponderLibHandleResponseState.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmResponderLibRespondIfReady.o : $(SOURCE_DIR)/SpdmResponderLibRespondIfReady.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


