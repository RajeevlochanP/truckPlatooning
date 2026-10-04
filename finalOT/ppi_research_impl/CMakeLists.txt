cmake_minimum_required(VERSION 3.20)
project(PPIResearch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(libOTe CONFIG REQUIRED)

if(NOT TARGET oc::libOTe)
    message(FATAL_ERROR "libOTe package was found, but target oc::libOTe is unavailable. Use a libOTe installation that exports the oc::libOTe target.")
endif()

# Resolve libOTe's public include roots. The project has used both source-tree
# and installed include layouts, so support both layouts.
get_target_property(PPI_LIBOTE_INCLUDE_DIRS oc::libOTe INTERFACE_INCLUDE_DIRECTORIES)
if(NOT PPI_LIBOTE_INCLUDE_DIRS AND DEFINED libOTe_INC)
    set(PPI_LIBOTE_INCLUDE_DIRS "${libOTe_INC}")
endif()

set(PPI_OOS_SENDER_CLASS "" CACHE STRING
    "Override the libOTe concrete malicious OOS NCO sender class name")
set(PPI_OOS_RECEIVER_CLASS "" CACHE STRING
    "Override the libOTe concrete malicious OOS NCO receiver class name")
set(PPI_OOS_SENDER_HEADER "" CACHE STRING
    "Override the libOTe OOS sender header path relative to a libOTe include root")
set(PPI_OOS_RECEIVER_HEADER "" CACHE STRING
    "Override the libOTe OOS receiver header path relative to a libOTe include root")

# Auto-discover the concrete OOS implementation shipped by the installed/source
# libOTe package. This avoids hard-coding a class name that can differ across
# libOTe revisions while still binding directly to the actual OOS implementation.
if(NOT PPI_OOS_SENDER_CLASS OR NOT PPI_OOS_RECEIVER_CLASS)
    set(_ppi_oos_sender_classes "")
    set(_ppi_oos_receiver_classes "")
    set(_ppi_oos_sender_headers "")
    set(_ppi_oos_receiver_headers "")

    foreach(_inc IN LISTS PPI_LIBOTE_INCLUDE_DIRS)
        if(EXISTS "${_inc}/NChooseOne")
            file(GLOB_RECURSE _headers CONFIGURE_DEPENDS
                "${_inc}/NChooseOne/*.h"
                "${_inc}/NChooseOne/*.hpp")
        elseif(EXISTS "${_inc}/libOTe/NChooseOne")
            file(GLOB_RECURSE _headers CONFIGURE_DEPENDS
                "${_inc}/libOTe/NChooseOne/*.h"
                "${_inc}/libOTe/NChooseOne/*.hpp")
        else()
            continue()
        endif()

        foreach(_header IN LISTS _headers)
            get_filename_component(_name "${_header}" NAME)
            string(TOLOWER "${_name}" _lower_name)
            if(NOT _lower_name MATCHES "oos")
                continue()
            endif()

            file(READ "${_header}" _contents)

            string(REGEX MATCH
                "class[ \t\r\n]+([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]*:[^\{;]*NcoOtExtSender"
                _sender_match "${_contents}")
            if(_sender_match)
                list(APPEND _ppi_oos_sender_classes "${CMAKE_MATCH_1}")
                foreach(_inc IN LISTS PPI_LIBOTE_INCLUDE_DIRS)
                    if(_inc MATCHES "^\$<")
                        continue()
                    endif()
                    file(RELATIVE_PATH _rel "${_inc}" "${_header}")
                    if(NOT _rel MATCHES "^\.\.")
                        list(APPEND _ppi_oos_sender_headers "${_rel}")
                    endif()
                endforeach()
            endif()

            string(REGEX MATCH
                "class[ \t\r\n]+([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]*:[^\{;]*NcoOtExtReceiver"
                _receiver_match "${_contents}")
            if(_receiver_match)
                list(APPEND _ppi_oos_receiver_classes "${CMAKE_MATCH_1}")
                foreach(_inc IN LISTS PPI_LIBOTE_INCLUDE_DIRS)
                    if(_inc MATCHES "^\$<")
                        continue()
                    endif()
                    file(RELATIVE_PATH _rel "${_inc}" "${_header}")
                    if(NOT _rel MATCHES "^\.\.")
                        list(APPEND _ppi_oos_receiver_headers "${_rel}")
                    endif()
                endforeach()
            endif()
        endforeach()
    endforeach()

    list(REMOVE_DUPLICATES _ppi_oos_sender_classes)
    list(REMOVE_DUPLICATES _ppi_oos_receiver_classes)
    list(REMOVE_DUPLICATES _ppi_oos_sender_headers)
    list(REMOVE_DUPLICATES _ppi_oos_receiver_headers)

    if(NOT PPI_OOS_SENDER_CLASS AND _ppi_oos_sender_classes)
        list(GET _ppi_oos_sender_classes 0 PPI_OOS_SENDER_CLASS)
    endif()
    if(NOT PPI_OOS_RECEIVER_CLASS AND _ppi_oos_receiver_classes)
        list(GET _ppi_oos_receiver_classes 0 PPI_OOS_RECEIVER_CLASS)
    endif()
    if(NOT PPI_OOS_SENDER_HEADER AND _ppi_oos_sender_headers)
        list(GET _ppi_oos_sender_headers 0 PPI_OOS_SENDER_HEADER)
    endif()
    if(NOT PPI_OOS_RECEIVER_HEADER AND _ppi_oos_receiver_headers)
        list(GET _ppi_oos_receiver_headers 0 PPI_OOS_RECEIVER_HEADER)
    endif()
endif()

if(NOT PPI_OOS_SENDER_CLASS OR NOT PPI_OOS_RECEIVER_CLASS OR
   NOT PPI_OOS_SENDER_HEADER OR NOT PPI_OOS_RECEIVER_HEADER)
    message(FATAL_ERROR
        "Could not auto-detect the concrete OOS NCO sender/receiver classes in libOTe. "
        "Set PPI_OOS_SENDER_CLASS, PPI_OOS_RECEIVER_CLASS, "
        "PPI_OOS_SENDER_HEADER, and PPI_OOS_RECEIVER_HEADER explicitly.")
endif()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/generated/ppi_oos_adapter.hpp"
    CONTENT
"#pragma once\n"
"#include <${PPI_OOS_SENDER_HEADER}>\n"
"#include <${PPI_OOS_RECEIVER_HEADER}>\n"
"namespace ppi_oos {\n"
"using Sender = osuCrypto::${PPI_OOS_SENDER_CLASS};\n"
"using Receiver = osuCrypto::${PPI_OOS_RECEIVER_CLASS};\n"
"}\n")

add_executable(ppi_platoon ppi_platoon.cpp)

target_include_directories(ppi_platoon PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/generated")

target_link_libraries(ppi_platoon PRIVATE
    oc::libOTe
    OpenSSL::Crypto)

if(UNIX)
    target_link_libraries(ppi_platoon PRIVATE pthread)
endif()

# Strong warnings are useful for a research implementation.
target_compile_options(ppi_platoon PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion -Wshadow>)

message(STATUS "PPI OOS sender class   : ${PPI_OOS_SENDER_CLASS}")
message(STATUS "PPI OOS sender header  : ${PPI_OOS_SENDER_HEADER}")
message(STATUS "PPI OOS receiver class : ${PPI_OOS_RECEIVER_CLASS}")
message(STATUS "PPI OOS receiver hdr   : ${PPI_OOS_RECEIVER_HEADER}")
