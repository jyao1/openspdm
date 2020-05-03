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
WORKSPACE = .

!INCLUDE $(WORKSPACE)\MakeFile.Flags

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(ARCH)

#
# Default target, which will build dependent libraries in addition to source files
#

all:
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmCommonLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmRequesterLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\Library\SpdmLib\SpdmResponderLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseMemoryLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\DebugLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\BaseCryptLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\OpensslLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsStub\MemoryAllocationLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsTest\SpdmRequesterTest\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(WORKSPACE)\OsTest\SpdmResponderTest\Makefile
	@$(CP) $(WORKSPACE)\OsTest\TestKey\* $(WORKSPACE)\Build\$(ARCH)

#
# clean all generated files
#
clean:
	-@if exist $(BIN_DIR) $(RD) $(BIN_DIR)

