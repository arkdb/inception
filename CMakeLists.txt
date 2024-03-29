# Copyright (c) 2006, 2012, Oracle and/or its affiliates. All rights reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
# Avoid warnings in higher versions
if("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" GREATER 2.6)
 CMAKE_POLICY(VERSION 2.8)
endif()

MESSAGE(STATUS "Running cmake version ${CMAKE_VERSION}")

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

# First, decide about build type (debug or release)
# If custom compiler flags are set or cmake is invoked with -DCMAKE_BUILD_TYPE, 
# respect user wishes and do not (re)define CMAKE_BUILD_TYPE. If WITH_DEBUG{_FULL} 
# is given, set CMAKE_BUILD_TYPE = Debug. Otherwise, use Relwithdebinfo.


IF(DEFINED CMAKE_BUILD_TYPE)
  SET(HAVE_CMAKE_BUILD_TYPE TRUE)
ENDIF()
SET(CUSTOM_C_FLAGS $ENV{CFLAGS})

OPTION(WITH_DEBUG "Use dbug/safemutex" OFF)

# Use a default manufacturer if no manufacturer was identified.
SET(MANUFACTURER_DOCSTRING
  "Set the entity that appears as the manufacturer of packages that support a manufacturer field.")
IF(NOT DEFINED MANUFACTURER) 
  SET(MANUFACTURER "Built from Source" CACHE  STRING ${MANUFACTURER_DOCSTRING})
  MARK_AS_ADVANCED(MANUFACTURER)
ENDIF()

# We choose to provide WITH_DEBUG as alias to standard CMAKE_BUILD_TYPE=Debug
# which turns out to be not trivial, as this involves synchronization 
# between CMAKE_BUILD_TYPE and WITH_DEBUG. Besides, we have to deal with cases
# where WITH_DEBUG is  reset from ON to OFF  and here we need to reset 
# CMAKE_BUILD_TYPE to either none or default RelWithDebInfo

SET(BUILDTYPE_DOCSTRING
 "Choose the type of build, options are: None(CMAKE_CXX_FLAGS or
 CMAKE_C_FLAGS used) Debug Release RelWithDebInfo MinSizeRel")

# Possibly temporary fix: Clang on 32 bit causes non-debug server to crash
IF(CMAKE_OSX_ARCHITECTURES MATCHES "i386")
  SET(CMAKE_CXX_COMPILER g++)
ENDIF()

IF(WITH_DEBUG)
  SET(CMAKE_BUILD_TYPE "Debug" CACHE STRING ${BUILDTYPE_DOCSTRING} FORCE)
  SET(MYSQL_MAINTAINER_MODE ON CACHE BOOL
      "MySQL maintainer-specific development environment")
  IF(UNIX AND NOT APPLE)
    # Compiling with PIC speeds up embedded build, on PIC sensitive systems 
    # Predefine it to ON, in case user chooses to build embedded. 
    SET(WITH_PIC ON CACHE BOOL "Compile with PIC")
  ENDIF()
  SET(OLD_WITH_DEBUG 1 CACHE INTERNAL "" FORCE)
ELSEIF(NOT HAVE_CMAKE_BUILD_TYPE OR OLD_WITH_DEBUG)
  IF(CUSTOM_C_FLAGS)
    SET(CMAKE_BUILD_TYPE "" CACHE STRING ${BUILDTYPE_DOCSTRING} FORCE)
  ELSE(CMAKE_BUILD_TYPE MATCHES "Debug" OR NOT HAVE_CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING 
       ${BUILDTYPE_DOCSTRING} FORCE)
  ENDIF()
  SET(OLD_WITH_DEBUG 0 CACHE INTERNAL "" FORCE)
ENDIF()

# Optionally set project name, e.g.
# foo.xcodeproj (mac) or foo.sln (windows)
SET(MYSQL_PROJECT_NAME_DOCSTRING "MySQL project name")
IF(DEFINED MYSQL_PROJECT_NAME)
  SET(MYSQL_PROJECT_NAME ${MYSQL_PROJECT_NAME} CACHE STRING
      ${MYSQL_PROJECT_NAME_DOCSTRING} FORCE)
ELSE()
  SET(MYSQL_PROJECT_NAME "Inception" CACHE STRING
      ${MYSQL_PROJECT_NAME_DOCSTRING} FORCE)
  MARK_AS_ADVANCED(MYSQL_PROJECT_NAME)
ENDIF()
PROJECT(${MYSQL_PROJECT_NAME})

OPTION(WITH_DEFAULT_COMPILER_OPTIONS
  "Use flags from cmake/build_configurations/compiler_options.cmake"
  ON)
IF(BUILD_CONFIG)
  INCLUDE(
  ${CMAKE_SOURCE_DIR}/cmake/build_configurations/${BUILD_CONFIG}.cmake)
ENDIF()

#cmake on 64bit windows/mac/solaris doesn't set CMAKE_SYSTEM_PROCESSOR correctly
SET(MYSQL_MACHINE_TYPE ${CMAKE_SYSTEM_PROCESSOR})


# Include the platform-specific file. To allow exceptions, this code
# looks for files in order of how specific they are. If there is, for
# example, a generic Linux.cmake and a version-specific
# Linux-2.6.28-11-generic, it will pick Linux-2.6.28-11-generic and
# include it. It is then up to the file writer to include the generic
# version if necessary.
FOREACH(_base
    ${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_VERSION}-${CMAKE_SYSTEM_PROCESSOR}
    ${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_VERSION}
    ${CMAKE_SYSTEM_NAME})
  SET(_file ${CMAKE_SOURCE_DIR}/cmake/os/${_base}.cmake)
  IF(EXISTS ${_file})
    INCLUDE(${_file})
    BREAK()
  ENDIF()
ENDFOREACH()
 
# Following autotools tradition, add preprocessor definitions
# specified in environment variable CPPFLAGS
IF(DEFINED ENV{CPPFLAGS})
  ADD_DEFINITIONS($ENV{CPPFLAGS})
ENDIF()

INCLUDE(CheckTypeSize)
CHECK_TYPE_SIZE("void *" SIZEOF_VOIDP)
IF(WITH_DEFAULT_COMPILER_OPTIONS)
  INCLUDE(${CMAKE_SOURCE_DIR}/cmake/build_configurations/compiler_options.cmake)
ENDIF()

# Add macros
INCLUDE(character_sets)
INCLUDE(cpu_info)
INCLUDE(zlib)
INCLUDE(libevent)
INCLUDE(ssl)
INCLUDE(readline)
INCLUDE(mysql_version)
INCLUDE(libutils)
INCLUDE(dtrace)
INCLUDE(plugin)
INCLUDE(install_macros)
INCLUDE(install_layout)
INCLUDE(mysql_add_executable)

OPTION(WITH_FAST_MUTEXES "Compile with fast mutexes" OFF)
MARK_AS_ADVANCED(WITH_FAST_MUTEXES)

# Set DBUG_OFF and other optional release-only flags for non-debug project types
FOREACH(BUILD_TYPE RELEASE RELWITHDEBINFO MINSIZEREL)
  FOREACH(LANG C CXX)
    SET(CMAKE_${LANG}_FLAGS_${BUILD_TYPE} 
     "${CMAKE_${LANG}_FLAGS_${BUILD_TYPE}} -DDBUG_OFF")
    IF(WITH_FAST_MUTEXES)
      SET(CMAKE_${LANG}_FLAGS_${BUILD_TYPE} 
        "${CMAKE_${LANG}_FLAGS_${BUILD_TYPE}} -DMY_PTHREAD_FASTMUTEX=1")
    ENDIF()
  ENDFOREACH()
ENDFOREACH()

IF(NOT CMAKE_BUILD_TYPE
    AND NOT CMAKE_GENERATOR MATCHES "Visual Studio" 
    AND NOT CMAKE_GENERATOR MATCHES "Xcode") 
    # This is the case of no CMAKE_BUILD_TYPE choosen, typical for VS and Xcode
    # or if custom C flags are set. In VS and Xcode for non-Debug configurations 
    # DBUG_OFF is already correctly set. Use DBUG_OFF for Makefile based projects 
    # without build type too, unless user specifically requests DBUG. 
    IF(NOT CMAKE_C_FLAGS MATCHES "-DDBUG_ON")
      ADD_DEFINITIONS(-DDBUG_OFF)
    ENDIF()
ENDIF()

# Add safemutex for debug configurations, except on Windows
# (safemutex has never worked on Windows)
IF(WITH_DEBUG AND NOT WIN32 AND NOT WITH_INNODB_MEMCACHED)
  FOREACH(LANG C CXX)
      SET(CMAKE_${LANG}_FLAGS_DEBUG
          "${CMAKE_${LANG}_FLAGS_DEBUG} -DSAFE_MUTEX")
  ENDFOREACH()
ENDIF()

# Run platform tests
INCLUDE(configure.cmake)

# Common defines and includes
ADD_DEFINITIONS(-DHAVE_CONFIG_H)
INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/extra/rapidjson/include)


# Add bundled or system zlib.
MYSQL_CHECK_ZLIB_WITH_COMPRESS()
# Add bundled yassl/taocrypt or system openssl.
# Add readline or libedit.
MYSQL_CHECK_SSL()
MYSQL_CHECK_READLINE()
# Add libevent

#
# Setup maintainer mode options by the end. Platform checks are
# not run with the warning options as to not perturb fragile checks
# (i.e. do not make warnings into errors).
#
# Why doesn't these flags affect the entire build?
# Because things may already have been included with ADD_SUBDIRECTORY
#
IF(MYSQL_MAINTAINER_MODE)
  # Set compiler flags required under maintainer mode.
  MESSAGE(STATUS "C warning options: ${MY_MAINTAINER_C_WARNINGS}")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MY_MAINTAINER_C_WARNINGS}")
  MESSAGE(STATUS "C++ warning options: ${MY_MAINTAINER_CXX_WARNINGS}")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${MY_MAINTAINER_CXX_WARNINGS}")
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCXX)
  STRING(REGEX MATCH "-Werror"
    BUILD_WITH_WERROR ${CMAKE_CXX_FLAGS})
  IF(BUILD_WITH_WERROR)
    SET("COMPILE_FLAG_WERROR" 1)
  ENDIF()
ENDIF()

IF(WITH_UNIT_TESTS)
 ENABLE_TESTING()
ENDIF()

IF(NOT WITHOUT_SERVER)
SET (MYSQLD_STATIC_PLUGIN_LIBS "" CACHE INTERNAL "")
 # Add storage engines and plugins.
 CONFIGURE_PLUGINS()
ENDIF()

ADD_SUBDIRECTORY(include)
ADD_SUBDIRECTORY(dbug)
ADD_SUBDIRECTORY(strings)
ADD_SUBDIRECTORY(vio)
ADD_SUBDIRECTORY(regex)
ADD_SUBDIRECTORY(mysys)
ADD_SUBDIRECTORY(mysys_ssl)
ADD_SUBDIRECTORY(libmysql)

IF(NOT WITHOUT_SERVER)
  ADD_SUBDIRECTORY(client)
  ADD_SUBDIRECTORY(sql)
  ADD_SUBDIRECTORY(sql/share)
  ADD_SUBDIRECTORY(support-files)
  ADD_SUBDIRECTORY(sql-bench)
  IF(UNIX)
    ADD_SUBDIRECTORY(man)
  ENDIF()
  IF(EXISTS ${CMAKE_SOURCE_DIR}/internal/CMakeLists.txt)
    ADD_SUBDIRECTORY(internal)
  ENDIF()
  ADD_SUBDIRECTORY(packaging/rpm-uln)
ENDIF()

INCLUDE(cmake/abi_check.cmake)
INCLUDE(cmake/tags.cmake)

CONFIGURE_FILE(config.h.cmake   ${CMAKE_BINARY_DIR}/include/my_config.h)
CONFIGURE_FILE(config.h.cmake   ${CMAKE_BINARY_DIR}/include/config.h)
CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/include/mysql_version.h.in
               ${CMAKE_BINARY_DIR}/include/mysql_version.h )
CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/sql/sql_builtin.cc.in
    ${CMAKE_BINARY_DIR}/sql/sql_builtin.cc)
CONFIGURE_FILE(
    ${CMAKE_SOURCE_DIR}/cmake/info_macros.cmake.in ${CMAKE_BINARY_DIR}/info_macros.cmake @ONLY)

# Handle the "INFO_*" files.
INCLUDE(${CMAKE_BINARY_DIR}/info_macros.cmake)
# Source: This can be done during the cmake phase, all information is
# available, but should be repeated on each "make" just in case someone
# does "cmake ; make ; bzr pull ; make".
# Build flags: This must be postponed to the make phase.

# Packaging
IF(WIN32)
  SET(CPACK_GENERATOR "ZIP")
ELSE()
  SET(CPACK_GENERATOR "TGZ")
ENDIF() 
ADD_SUBDIRECTORY(packaging/WiX)
ADD_SUBDIRECTORY(packaging/solaris)

# Create a single package with "make package"
# (see http://public.kitware.com/Bug/view.php?id=11452)
SET(CPACK_MONOLITHIC_INSTALL 1 CACHE INTERNAL "")

LINK_LIBRARIES(jemalloc)
#SET(CMAKE_EXE_LINK_DIRECTORIES)
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}
-fprofile-arcs -ftest-coverage -lgcov -ljemalloc -L/usr/lib64/libjemalloc.so")
