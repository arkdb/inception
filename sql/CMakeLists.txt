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

INCLUDE_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/include 
  ${CMAKE_SOURCE_DIR}/sql 
  ${CMAKE_SOURCE_DIR}/regex 
  ${ZLIB_INCLUDE_DIR}
  ${SSL_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}/sql
)

SET(GEN_SOURCES
  ${CMAKE_CURRENT_BINARY_DIR}/sql_yacc.h 
  ${CMAKE_CURRENT_BINARY_DIR}/sql_yacc.cc
  ${CMAKE_CURRENT_BINARY_DIR}/sql_builtin.cc
  ${CMAKE_CURRENT_BINARY_DIR}/lex_hash.h 
)

SET_SOURCE_FILES_PROPERTIES(${GEN_SOURCES} PROPERTIES GENERATED 1)

ADD_DEFINITIONS(-DMYSQL_SERVER) 
IF(SSL_DEFINES)
 ADD_DEFINITIONS(${SSL_DEFINES})
ENDIF()

SET(SQL_SHARED_SOURCES
  datadict.cc
  debug_sync.cc
  derror.cc
  des_key_file.cc
  discover.cc
  field.cc
  field_conv.cc 
  filesort.cc
  filesort_utils.cc
  handler.cc
  hostname.cc
  init.cc
  item.cc
  item_buff.cc
  item_cmpfunc.cc 
  item_create.cc
  item_func.cc
  item_row.cc 
  item_strfunc.cc
  item_subselect.cc
  item_sum.cc
  item_timefunc.cc 
  item_xmlfunc.cc 
  item_inetfunc.cc
  json_dom.cc
  json_binary.cc
  json_path.cc
  key.cc
  lock.cc
  log.cc
  mdl.cc
  mf_iocache.cc
  my_decimal.cc
  my_default.cc
  my_getopt.cc
  net_serv.cc
  opt_sum.cc 
  parse_file.cc
  partition_info.cc
  password.c
  procedure.cc 
  protocol.cc
  records.cc
  scheduler.cc 
  set_var.cc 
  signal_handler.cc
  sp.cc
  sp_cache.cc
  sp_head.cc
  sp_instr.cc
  sp_pcontext.cc 
  sp_rcontext.cc
  string_service.cc
  sql_acl.cc
  sql_alloc_error_handler.cc
  sql_alter.cc
  sql_analyse.cc
  sql_base.cc 
  sql_bootstrap.cc
  sql_cache.cc
  sql_class.cc
  sql_connect.cc
  sql_cursor.cc
  sql_data_change.cc
  sql_db.cc
  sql_delete.cc
  sql_derived.cc
  sql_do.cc 
  sql_error.cc
  sql_executor.cc
  sql_get_diagnostics.cc
  sql_handler.cc
  sql_help.cc
  sql_insert.cc
  sql_lex.cc 
  sql_list.cc
  sql_locale.cc
  sql_parse.cc
  optimize.cc
  sql_format.cc
  sql_collector.cc
  sql_biosc.cc
  sql_plugin.cc
  sql_prepare.cc
  sql_rename.cc
  sql_resolver.cc
  sql_rewrite.cc
  sql_select.cc
  sql_servers.cc
  sql_signal.cc
  sql_state.c
  sql_string.cc 
  sql_table.cc
  sql_tablespace.cc
  sql_time.cc
  sql_tmp_table.cc
  sql_trigger.cc
  sql_truncate.cc
  sql_update.cc
  sql_view.cc
  strfunc.cc
  sys_vars.cc
  table.cc
  thr_malloc.cc 
  tztime.cc
  uniques.cc
  unireg.cc
  sql_yacc.yy
  sql_show.cc
  ptosc.cc
)

SET(SQL_EXPORTED_SOURCES ${SQL_SHARED_SOURCES} PARENT_SCOPE)

SET(SQL_SOURCE
  ${GEN_SOURCES}
  ${MYSYS_LIBWRAP_SOURCE}
  ${SQL_SHARED_SOURCES}
  ../libmysql/errmsg.c
  ../sql-common/client.c
  ../sql-common/client_plugin.c
  ../sql-common/my_time.c
  ../sql-common/my_user.c 
  ../sql-common/pack.c
  ../sql-common/client_authentication.cc
  mysqld.cc
  sql_client.cc
  )

IF (WIN32 AND OPENSSL_APPLINK_C)
  SET_SOURCE_FILES_PROPERTIES(
    ../sql-common/client_authentication.cc
    PROPERTIES COMPILE_FLAGS "-DHAVE_OPENSSL_APPLINK_C"
  )
ENDIF()

ADD_LIBRARY(sql STATIC ${SQL_SOURCE})
DTRACE_INSTRUMENT(sql)
TARGET_LINK_LIBRARIES(sql ${MYSQLD_STATIC_PLUGIN_LIBS} 
  mysys mysys_ssl dbug strings vio regex   
  ${LIBWRAP} ${LIBCRYPT} ${LIBDL}
  ${SSL_LIBRARIES})

#
# On Windows platform we compile in the clinet-side Windows Native Authentication
# plugin which is used by the client connection code included in the server.
#
IF(WIN32)
  ADD_DEFINITIONS(-DAUTHENTICATION_WIN)
  TARGET_LINK_LIBRARIES(sql auth_win_client)
ENDIF()

SET (BINLOG_SOURCE uuid.cc rpl_gtid_misc.cc
                   rpl_gtid_sid_map.cc rpl_gtid_set.cc rpl_gtid_specification.cc
                   rpl_gtid_state.cc rpl_gtid_owned.cc rpl_gtid_cache.cc
                   rpl_gtid_execution.cc rpl_gtid_mutex_cond_array.cc
                   log_event.cc log_event_old.cc binlog.cc sql_binlog.cc
		   rpl_filter.cc rpl_record.cc rpl_record_old.cc rpl_utility.cc
		   rpl_injector.cc)
ADD_LIBRARY(binlog ${BINLOG_SOURCE})
SET (RPL_SOURCE rpl_handler.cc rpl_tblmap.cc)
ADD_DEPENDENCIES(binlog GenError)
ADD_LIBRARY(rpl ${RPL_SOURCE})
SET (MASTER_SOURCE rpl_master.cc)
ADD_DEPENDENCIES(rpl GenError)
ADD_LIBRARY(master ${MASTER_SOURCE})
ADD_DEPENDENCIES(master GenError)
SET (SLAVE_SOURCE rpl_slave.cc rpl_reporting.cc rpl_mi.cc rpl_rli.cc
		  rpl_info_handler.cc rpl_info_file.cc rpl_info_table.cc
		  rpl_info_values.cc rpl_info.cc rpl_info_factory.cc
		  rpl_info_table_access.cc dynamic_ids.cc rpl_rli_pdb.cc
		  rpl_info_dummy.cc)
ADD_LIBRARY(slave ${SLAVE_SOURCE})
ADD_DEPENDENCIES(slave GenError)
ADD_LIBRARY(sqlgunitlib
  filesort_utils.cc mdl.cc sql_list.cc sql_string.cc thr_malloc.cc
  )
ADD_DEPENDENCIES(sqlgunitlib GenError)

# collector
IF(WIN32)
  SET(COLLECTOR_SOURCE main_collector.cc nt_servc.cc nt_servc.h message.rc)
ELSE()
  SET(COLLECTOR_SOURCE main_collector.cc ${DTRACE_PROBES_ALL})
ENDIF()
MYSQL_ADD_EXECUTABLE(inception_collector ${COLLECTOR_SOURCE} DESTINATION ${INSTALL_SBINDIR} COMPONENT Server)


IF(WIN32)
  SET(MYSQLD_SOURCE main.cc nt_servc.cc nt_servc.h message.rc)
ELSE()
  SET(MYSQLD_SOURCE main.cc ${DTRACE_PROBES_ALL})
ENDIF()

MYSQL_ADD_EXECUTABLE(Inception ${MYSQLD_SOURCE} DESTINATION ${INSTALL_SBINDIR} COMPONENT Server)

OPTION(DEBUG_EXTNAME "Build server as mysqld-debug (debug builds only)" OFF)
MARK_AS_ADVANCED(DEBUG_EXTNAME)

IF(DEBUG_EXTNAME)
  SET_TARGET_PROPERTIES(Inception PROPERTIES DEBUG_OUTPUT_NAME "mysqld-debug")
  SET_TARGET_PROPERTIES(inception_collector PROPERTIES DEBUG_OUTPUT_NAME "mysqld-debug")
ENDIF()

IF(APPLE) 
  # Add CoreServices framework since some dloadable plugins may need it 
  FIND_LIBRARY(CORESERVICES NAMES CoreServices) 
  IF(CORESERVICES) 
    TARGET_LINK_LIBRARIES(Inception ${CORESERVICES}) 
    TARGET_LINK_LIBRARIES(inception_collector ${CORESERVICES}) 
  ENDIF() 
ENDIF() 

IF(NOT WITHOUT_DYNAMIC_PLUGINS)
  SET_TARGET_PROPERTIES(Inception PROPERTIES ENABLE_EXPORTS TRUE)
  GET_TARGET_PROPERTY(mysqld_link_flags Inception LINK_FLAGS)
  SET_TARGET_PROPERTIES(inception_collector PROPERTIES ENABLE_EXPORTS TRUE)
  GET_TARGET_PROPERTY(mysqld_link_flags inception_collector LINK_FLAGS)
  IF(NOT mysqld_link_flags)
    SET(mysqld_link_flags)
  ENDIF()
  IF (MINGW OR CYGWIN)
    SET_TARGET_PROPERTIES(Inception PROPERTIES LINK_FLAGS "${mysqld_link_flags} -Wl,--export-all-symbols")
    SET_TARGET_PROPERTIES(inception_collector PROPERTIES LINK_FLAGS "${mysqld_link_flags} -Wl,--export-all-symbols")
  ENDIF()
  IF(MSVC)
    # Set module definition file. Also use non-incremental linker, 
    # incremental appears to crash from time to time,if used with /DEF option
    SET_TARGET_PROPERTIES(Inception PROPERTIES LINK_FLAGS "${mysqld_link_flags} /DEF:mysqld.def /INCREMENTAL:NO")
    SET_TARGET_PROPERTIES(inception_collector PROPERTIES LINK_FLAGS "${mysqld_link_flags} /DEF:mysqld.def /INCREMENTAL:NO")

    FOREACH (CORELIB sql mysys mysys_ssl dbug strings)
      GET_TARGET_PROPERTY(LOC ${CORELIB} LOCATION)
      FILE(TO_NATIVE_PATH ${LOC} LOC)
      SET (LIB_LOCATIONS ${LIB_LOCATIONS} ${LOC}) 
    ENDFOREACH (CORELIB ${MYSQLD_CORE_LIBS})
    SET(_PLATFORM x86)
    IF(CMAKE_SIZEOF_VOID_P EQUAL 8)
      SET(_PLATFORM  x64)
    ENDIF()
    ADD_CUSTOM_COMMAND(TARGET Inception PRE_LINK
      COMMAND echo ${_PLATFORM} && cscript ARGS //nologo ${PROJECT_SOURCE_DIR}/win/create_def_file.js
                  ${_PLATFORM}  ${LIB_LOCATIONS} > mysqld.def 
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    ADD_CUSTOM_COMMAND(TARGET inception_collector PRE_LINK
      COMMAND echo ${_PLATFORM} && cscript ARGS //nologo ${PROJECT_SOURCE_DIR}/win/create_def_file.js
                  ${_PLATFORM}  ${LIB_LOCATIONS} > mysqld.def 
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    ADD_DEPENDENCIES(sql GenError)
  ENDIF()
ENDIF()

SET_TARGET_PROPERTIES(Inception PROPERTIES ENABLE_EXPORTS TRUE) 
TARGET_LINK_LIBRARIES(Inception sql binlog rpl master slave sql mysys mysys_ssl)

SET_TARGET_PROPERTIES(inception_collector PROPERTIES ENABLE_EXPORTS TRUE) 
TARGET_LINK_LIBRARIES(inception_collector sql binlog rpl master slave sql mysys mysys_ssl)

# Provide plugins with minimal set of libraries
SET(INTERFACE_LIBS ${LIBRT})
IF(INTERFACE_LIBS)
 SET_TARGET_PROPERTIES(Inception PROPERTIES LINK_INTERFACE_LIBRARIES 
  "${INTERFACE_LIBS}")
 SET_TARGET_PROPERTIES(inception_collector PROPERTIES LINK_INTERFACE_LIBRARIES 
  "${INTERFACE_LIBS}")
ENDIF()

# On Solaris, some extra effort is required in order to get dtrace probes
# from static libraries
DTRACE_INSTRUMENT_STATIC_LIBS(Inception 
 "sql;mysys;mysys_ssl;${MYSQLD_STATIC_PLUGIN_LIBS}")
DTRACE_INSTRUMENT_STATIC_LIBS(inception_collector 
 "sql;mysys;mysys_ssl;${MYSQLD_STATIC_PLUGIN_LIBS}")
 

SET(WITH_MYSQLD_LDFLAGS "" CACHE STRING "Additional linker flags for Inception")
SET(WITH_MYSQLD_LDFLAGS "" CACHE STRING "Additional linker flags for inception_collector")
MARK_AS_ADVANCED(WITH_MYSQLD_LDFLAGS)
IF(WITH_MYSQLD_LDFLAGS)
  GET_TARGET_PROPERTY(Inception LINK_FLAGS MYSQLD_LINK_FLAGS)
  GET_TARGET_PROPERTY(inception_collector LINK_FLAGS MYSQLD_LINK_FLAGS)
  IF(NOT MYSQLD_LINK_FLAGS)
    SET(MYSQLD_LINK_FLAGS) 
  ENDIF() 
  SET_TARGET_PROPERTIES(Inception PROPERTIES LINK_FLAGS 
     "${MYSQLD_LINK_FLAGS} ${WITH_MYSQLD_LDFLAGS}")
  SET_TARGET_PROPERTIES(inception_collector PROPERTIES LINK_FLAGS 
     "${MYSQLD_LINK_FLAGS} ${WITH_MYSQLD_LDFLAGS}")
ENDIF()

IF(DEBUG_EXTNAME)
  INSTALL_DEBUG_TARGET(Inception 
    DESTINATION ${INSTALL_SBINDIR} 
    PDB_DESTINATION ${INSTALL_SBINDIR}
    SUFFIX "-debug")

  INSTALL_DEBUG_TARGET(inception_collector 
    DESTINATION ${INSTALL_SBINDIR} 
    PDB_DESTINATION ${INSTALL_SBINDIR}
    SUFFIX "-debug")
ELSE()
  INSTALL_DEBUG_TARGET(Inception 
    DESTINATION ${INSTALL_SBINDIR} 
    PDB_DESTINATION ${INSTALL_SBINDIR}/debug
    RENAME mysqld-debug)
  INSTALL_DEBUG_TARGET(inception_collector 
    DESTINATION ${INSTALL_SBINDIR} 
    PDB_DESTINATION ${INSTALL_SBINDIR}/debug
    RENAME mysqld-debug)
ENDIF()

# Handle out-of-source build from source package with possibly broken 
# bison. Copy bison output to from source to build directory, if not already 
# there
IF (NOT ${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
  IF(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/sql_yacc.cc)
    IF(NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/sql_yacc.cc)
      CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/sql_yacc.cc 
        ${CMAKE_CURRENT_BINARY_DIR}/sql_yacc.cc COPYONLY)
      CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/sql_yacc.h
        ${CMAKE_CURRENT_BINARY_DIR}/sql_yacc.h COPYONLY)
    ENDIF()
  ENDIF()
ENDIF()


INCLUDE(${CMAKE_SOURCE_DIR}/cmake/bison.cmake)
RUN_BISON(
  ${CMAKE_CURRENT_SOURCE_DIR}/sql_yacc.yy 
  ${CMAKE_CURRENT_BINARY_DIR}/sql_yacc.cc
  ${CMAKE_CURRENT_BINARY_DIR}/sql_yacc.h
)

# Gen_lex_hash
ADD_EXECUTABLE(gen_lex_hash gen_lex_hash.cc)

ADD_CUSTOM_COMMAND(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lex_hash.h
  COMMAND gen_lex_hash > lex_hash.h
  DEPENDS gen_lex_hash
)

#Need this only for embedded

FOREACH(tool glibtoolize libtoolize aclocal autoconf autoheader automake gtar 
 tar bzr)
 STRING(TOUPPER ${tool}  TOOL)
 FIND_PROGRAM(${TOOL}_EXECUTABLE ${tool} DOC "path to the executable")
 MARK_AS_ADVANCED(${TOOL}_EXECUTABLE)
ENDFOREACH()

CONFIGURE_FILE(
  ${CMAKE_SOURCE_DIR}/cmake/make_dist.cmake.in ${CMAKE_BINARY_DIR}/make_dist.cmake @ONLY)

ADD_CUSTOM_TARGET(dist 
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/make_dist.cmake
  DEPENDS ${CMAKE_BINARY_DIR}/sql/sql_yacc.cc ${CMAKE_BINARY_DIR}/sql/sql_yacc.h
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

ADD_CUSTOM_TARGET(distclean
  COMMAND ${CMAKE_COMMAND} -E echo  WARNING: distclean target is not functional
  COMMAND ${CMAKE_COMMAND} -E echo  Use 'bzr clean-tree' with --unknown and/or
    --ignored parameter instead
  VERBATIM
  )

IF(INSTALL_LAYOUT STREQUAL "STANDALONE")

# We need to create empty directories (data/test) the installation.  
# This does not work with current CPack due to http://www.cmake.org/Bug/view.php?id=8767
# Avoid completely empty directories and install dummy file instead.
# Use a file extension so that it will be deleted in case someone does
#   'drop database test'
# See deletable_extentions.
SET(DUMMY_FILE ${CMAKE_CURRENT_BINARY_DIR}/dummy.bak ) 
FILE(WRITE ${DUMMY_FILE} "")
INSTALL(FILES ${DUMMY_FILE} DESTINATION data/test COMPONENT DataFiles)

# Install initial database on windows
IF(NOT CMAKE_CROSSCOMPILING)
  IF(DEBUG_EXTNAME)
    GET_TARGET_PROPERTY(MYSQLD_EXECUTABLE Inception LOCATION_DEBUG)
    GET_TARGET_PROPERTY(MYSQLD_EXECUTABLE inception_collector LOCATION_DEBUG)
  ELSE()
    GET_TARGET_PROPERTY(MYSQLD_EXECUTABLE Inception LOCATION)
    GET_TARGET_PROPERTY(MYSQLD_EXECUTABLE inception_collector LOCATION)
  ENDIF()
ENDIF()
ENDIF()
