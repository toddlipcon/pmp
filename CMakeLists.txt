cmake_minimum_required(VERSION 2.6)
project (pmp)

if(NOT ELF_BITS)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  SET(ELF_BITS 64)  
endif(CMAKE_SIZEOF_VOID_P EQUAL 8)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  SET(ELF_BITS 32)  
endif(CMAKE_SIZEOF_VOID_P EQUAL 4)
endif(NOT ELF_BITS)

SET(CMAKE_CXX_FLAGS "-g -Wall  -DELF_BITS=64 -Ithirdparty/include")

add_executable(pmp pmp.cc status.cc stringprintf.cc)
target_link_libraries(pmp "-Lthirdparty/lib -lunwind-ptrace -lunwind-generic")
