cmake_minimum_required(VERSION 2.6)

if(TOOLCHAIN MATCHES "VS")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Gl-")
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(src_IntrinsicLib
        CopyMem.c
        MemoryIntrinsics.c        
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(ARCH STREQUAL "X64")
        SET(src_IntrinsicLib
            CopyMem.c
            MemoryIntrinsics.c        
        )
    elseif(ARCH STREQUAL "Ia32")
        SET(src_IntrinsicLib
            CopyMem.c
            MemoryIntrinsics.c
            Ia32/MathDivS64x64.c
            Ia32/MathDivS64x64Remainder.c
            Ia32/MathDivU64x64.c
            Ia32/MathDivU64x64Remainder.c
            Ia32/MathFtol.c
            Ia32/MathLShiftS64.c
            Ia32/MathMultS64x64.c
            Ia32/MathRemainderS64x64.c
            Ia32/MathRemainderS64x64.c
            Ia32/MathRemainderU64x64.c
            Ia32/MathRShiftS64.c
            Ia32/MathRShiftU64.c
        )
    endif()
endif()

ADD_LIBRARY(IntrinsicLib STATIC ${src_IntrinsicLib})
