/** @file
  Provides services to print debug and assert messages to a debug output device.

  The Debug library supports debug print and asserts based on a combination of macros and code.
  The debug library can be turned on and off so that the debug code does not increase the size of an image.

  Note that a reserved macro named MDEPKG_NDEBUG is introduced for the intention
  of size reduction when compiler optimization is disabled. If MDEPKG_NDEBUG is
  defined, then debug and assert related macros wrapped by it are the NULL implementations.

Copyright (c) 2006 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __DEBUG_LIB_H__
#define __DEBUG_LIB_H__

//
// Declare bits for PcdDebugPrintErrorLevel and the ErrorLevel parameter of DebugPrint()
//
#define DEBUG_INFO      0x00000040  // Informational debug messages
#define DEBUG_VERBOSE   0x00400000  // Detailed debug messages that may
                                    // significantly impact boot performance
#define DEBUG_ERROR     0x80000000  // Error

/**
  Prints a debug message to the debug output device if the specified error level is enabled.

  If any bit in ErrorLevel is also set in DebugPrintErrorLevelLib function
  GetDebugPrintErrorLevel (), then print the message specified by Format and the
  associated variable argument list to the debug output device.

  If Format is NULL, then ASSERT().

  @param  ErrorLevel  The error level of the debug message.
  @param  Format      The format string for the debug message to print.
  @param  ...         The variable argument list whose contents are accessed
                      based on the format string specified by Format.

**/
VOID
EFIAPI
DebugPrint (
  IN  UINTN        ErrorLevel,
  IN  CONST CHAR8  *Format,
  ...
  );

/**
  Prints an assert message containing a filename, line number, and description.
  This may be followed by a breakpoint or a dead loop.

  Print a message of the form "ASSERT <FileName>(<LineNumber>): <Description>\n"
  to the debug output device.  If DEBUG_PROPERTY_ASSERT_BREAKPOINT_ENABLED bit of
  PcdDebugProperyMask is set then CpuBreakpoint() is called. Otherwise, if
  DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED bit of PcdDebugProperyMask is set then
  CpuDeadLoop() is called.  If neither of these bits are set, then this function
  returns immediately after the message is printed to the debug output device.
  DebugAssert() must actively prevent recursion.  If DebugAssert() is called while
  processing another DebugAssert(), then DebugAssert() must return immediately.

  If FileName is NULL, then a <FileName> string of "(NULL) Filename" is printed.
  If Description is NULL, then a <Description> string of "(NULL) Description" is printed.

  @param  FileName     The pointer to the name of the source file that generated the assert condition.
  @param  LineNumber   The line number in the source file that generated the assert condition
  @param  Description  The pointer to the description of the assert condition.

**/
VOID
EFIAPI
DebugAssert (
  IN CONST CHAR8  *FileName,
  IN UINTN        LineNumber,
  IN CONST CHAR8  *Description
  );

/**
  Internal worker macro that calls DebugAssert().

  This macro calls DebugAssert(), passing in the filename, line number, and an
  expression that evaluated to FALSE.

  @param  Expression  Boolean expression that evaluated to FALSE

**/
#define _ASSERT(Expression)  DebugAssert (__FILE__, __LINE__, #Expression)

/**
  Internal worker macro that calls DebugPrint().

  This macro calls DebugPrint() passing in the debug error level, a format
  string, and a variable argument list.
  __VA_ARGS__ is not supported by EBC compiler, Microsoft Visual Studio .NET 2003
  and Microsoft Windows Server 2003 Driver Development Kit (Microsoft WINDDK) version 3790.1830.

  @param  Expression  Expression containing an error level, a format string,
                      and a variable argument list based on the format string.

**/

#define _DEBUG_PRINT(PrintLevel, ...)              \
  do {                                             \
    DebugPrint (PrintLevel, ##__VA_ARGS__);        \
  } while (FALSE)
#define _DEBUG(Expression)   _DEBUG_PRINT Expression

/**
  Macro that calls DebugAssert() if an expression evaluates to FALSE.

  If MDEPKG_NDEBUG is not defined and the DEBUG_PROPERTY_DEBUG_ASSERT_ENABLED
  bit of PcdDebugProperyMask is set, then this macro evaluates the Boolean
  expression specified by Expression.  If Expression evaluates to FALSE, then
  DebugAssert() is called passing in the source filename, source line number,
  and Expression.

  @param  Expression  Boolean expression.

**/
#if !defined(MDEPKG_NDEBUG)
  #define ASSERT(Expression)        \
    do {                            \
      if (!(Expression)) {          \
        _ASSERT (Expression);       \
        ANALYZER_UNREACHABLE ();    \
      }                             \
    } while (FALSE)
#else
  #define ASSERT(Expression)
#endif

/**
  Macro that calls DebugPrint().

  If MDEPKG_NDEBUG is not defined and the DEBUG_PROPERTY_DEBUG_PRINT_ENABLED
  bit of PcdDebugProperyMask is set, then this macro passes Expression to
  DebugPrint().

  @param  Expression  Expression containing an error level, a format string,
                      and a variable argument list based on the format string.


**/
#if !defined(MDEPKG_NDEBUG)
  #define DEBUG(Expression)        \
    do {                           \
      _DEBUG (Expression);         \
    } while (FALSE)
#else
  #define DEBUG(Expression)
#endif

/**
  Macro that calls DebugAssert() if a RETURN_STATUS evaluates to an error code.

  If MDEPKG_NDEBUG is not defined and the DEBUG_PROPERTY_DEBUG_ASSERT_ENABLED
  bit of PcdDebugProperyMask is set, then this macro evaluates the
  RETURN_STATUS value specified by StatusParameter.  If StatusParameter is an
  error code, then DebugAssert() is called passing in the source filename,
  source line number, and StatusParameter.

  @param  StatusParameter  RETURN_STATUS value to evaluate.

**/
#if !defined(MDEPKG_NDEBUG)
  #define ASSERT_RETURN_ERROR(StatusParameter)                          \
    do {                                                                \
      if (RETURN_ERROR (StatusParameter)) {                             \
        DEBUG ((DEBUG_ERROR, "\nASSERT_RETURN_ERROR (Status = %p)\n",   \
          StatusParameter));                                            \
        _ASSERT (!RETURN_ERROR (StatusParameter));                      \
      }                                                                 \
    } while (FALSE)
#else
  #define ASSERT_RETURN_ERROR(StatusParameter)
#endif

/**
  Macro that marks the beginning of debug source code.

  If the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set,
  then this macro marks the beginning of source code that is included in a module.
  Otherwise, the source lines between DEBUG_CODE_BEGIN() and DEBUG_CODE_END()
  are not included in a module.

**/
#define DEBUG_CODE_BEGIN()  do { UINT8  __DebugCodeLocal


/**
  The macro that marks the end of debug source code.

  If the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set,
  then this macro marks the end of source code that is included in a module.
  Otherwise, the source lines between DEBUG_CODE_BEGIN() and DEBUG_CODE_END()
  are not included in a module.

**/
#define DEBUG_CODE_END()    __DebugCodeLocal = 0; __DebugCodeLocal++; } while (FALSE)

/**
  The macro that declares a section of debug source code.

  If the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set,
  then the source code specified by Expression is included in a module.
  Otherwise, the source specified by Expression is not included in a module.

**/

#if !defined(MDEPKG_NDEBUG)
  #define DEBUG_CODE(Expression)  \
    DEBUG_CODE_BEGIN ();          \
    Expression                    \
    DEBUG_CODE_END ()
#else
  #define DEBUG_CODE(Expression)
#endif

#endif
