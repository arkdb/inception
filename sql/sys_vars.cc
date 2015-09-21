/* Copyright (c) 2009, 2011, 2012 Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  @file
  Definitions of all server's session or global variables.

  How to add new variables:

  1. copy one of the existing variables, and edit the declaration.
  2. if you need special behavior on assignment or additional checks
     use ON_CHECK and ON_UPDATE callbacks.
  3. *Don't* add new Sys_var classes or uncle Occam will come
     with his razor to haunt you at nights

  Note - all storage engine variables (for example myisam_whatever)
  should go into the corresponding storage engine sources
  (for example in storage/myisam/ha_myisam.cc) !
*/

#include <stdio.h>
#include <string.h>
#include "my_global.h"                          /* NO_EMBEDDED_ACCESS_CHECKS */
#include "sql_priv.h"
#include "sql_class.h"                          // set_var.h: THD
#include "sys_vars.h"
#include "mysql_com.h"

#include "events.h"
#include <thr_alarm.h>
#include "transaction.h"
#include "opt_trace.h"
#include "mysqld.h"
#include "lock.h"
#include "sql_time.h"                       // known_date_time_formats
#include "sql_acl.h" // SUPER_ACL,
                     // mysql_user_table_is_in_short_password_format
                     // disconnect_on_expired_password
#include "derror.h"  // read_texts
#include "sql_base.h"                           // close_cached_tables
#include "debug_sync.h"                         // DEBUG_SYNC
#include "hostname.h"                           // host_cache_size
#include "sql_show.h"                           // opt_ignore_db_dirs

TYPELIB bool_typelib={ array_elements(bool_values)-1, "", bool_values, 0 };

/*
  This forward declaration is needed because including sql_base.h
  causes further includes.  [TODO] Eliminate this forward declaration
  and include a file with the prototype instead.
*/
extern void close_thread_tables(THD *thd);

/*
  The rule for this file: everything should be 'static'. When a sys_var
  variable or a function from this file is - in very rare cases - needed
  elsewhere it should be explicitly declared 'export' here to show that it's
  not a mistakenly forgotten 'static' keyword.
*/
#define export /* not static */

static Sys_var_charptr Sys_my_bind_addr(
       "bind_address", "IP address to bind to.",
       READ_ONLY GLOBAL_VAR(my_bind_addr_str), CMD_LINE(REQUIRED_ARG),
       IN_FS_CHARSET, DEFAULT(MY_BIND_ALL_ADDRESSES));

/*################*/
static Sys_var_charptr Sys_character_sets_dir(
       "character_sets_dir", "Directory where character sets are",
       READ_ONLY GLOBAL_VAR(charsets_dir), CMD_LINE(REQUIRED_ARG),
       IN_FS_CHARSET, DEFAULT(0));

/*################*/
static Sys_var_struct Sys_character_set_system(
       "character_set_system", "The character set used by the server "
       "for storing identifiers",
       READ_ONLY GLOBAL_VAR(system_charset_info), NO_CMD_LINE,
       offsetof(CHARSET_INFO, csname), DEFAULT(0));

static Sys_var_ulong Sys_connect_timeout(
       "connect_timeout",
       "The number of seconds the mysqld server is waiting for a connect "
       "packet before responding with 'Bad handshake'",
       GLOBAL_VAR(connect_timeout), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(2, LONG_TIMEOUT), DEFAULT(CONNECT_TIMEOUT), BLOCK_SIZE(1));

static Sys_var_ulong Sys_interactive_timeout(
       "interactive_timeout",
       "The number of seconds the server waits for activity on an interactive "
       "connection before closing it",
       SESSION_VAR(net_interactive_timeout),
       CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1, LONG_TIMEOUT), DEFAULT(NET_WAIT_TIMEOUT), BLOCK_SIZE(1));

static bool
check_max_allowed_packet(sys_var *self, THD *thd,  set_var *var)
{
  longlong val;
  val= var->save_result.ulonglong_value;
  if (val < (longlong) global_system_variables.net_buffer_length)
  {
    push_warning_printf(thd, Sql_condition::WARN_LEVEL_WARN,
                        WARN_OPTION_BELOW_LIMIT, ER(WARN_OPTION_BELOW_LIMIT),
                        "max_allowed_packet", "net_buffer_length");
  }
  return false;
}

static Sys_var_ulong Sys_max_allowed_packet(
       "max_allowed_packet",
       "Max packet length to send to or receive from the server",
       SESSION_VAR(max_allowed_packet), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1024, 1024 * 1024 * 1024), DEFAULT(1024 * 1024 * 1024),
       BLOCK_SIZE(1024), NO_MUTEX_GUARD, NOT_IN_BINLOG,
       ON_CHECK(check_max_allowed_packet));

static Sys_var_ulong Sys_max_connections(
       "max_connections", "The number of simultaneous clients allowed",
       GLOBAL_VAR(max_connections), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1, 100000),
       DEFAULT(MAX_CONNECTIONS_DEFAULT),
       BLOCK_SIZE(1),
       NO_MUTEX_GUARD,
       NOT_IN_BINLOG,
       ON_CHECK(0),
       NULL,
       NULL,
       /* max_connections is used as a sizing hint by the performance schema. */
       sys_var::PARSE_EARLY);

// static Sys_var_harows Sys_select_limit(
//        "sql_select_limit",
//        "The maximum number of rows to return from SELECT statements",
//        SESSION_VAR(select_limit), NO_CMD_LINE,
//        VALID_RANGE(0, HA_POS_ERROR), DEFAULT(HA_POS_ERROR), BLOCK_SIZE(1));

static Sys_var_ulong Sys_max_connect_errors(
       "max_connect_errors",
       "If there is more than this number of interrupted connections from "
       "a host this host will be blocked from further connections",
       GLOBAL_VAR(max_connect_errors), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1, ULONG_MAX), DEFAULT(100),
       BLOCK_SIZE(1));

static bool 
check_net_buffer_length(sys_var *self, THD *thd,  set_var *var)
{
  longlong val;
  val= var->save_result.ulonglong_value;
  if (val > (longlong) global_system_variables.max_allowed_packet)
  {
    push_warning_printf(thd, Sql_condition::WARN_LEVEL_WARN,
                        WARN_OPTION_BELOW_LIMIT, ER(WARN_OPTION_BELOW_LIMIT),
                        "max_allowed_packet", "net_buffer_length");
  }
  return false;
}

static Sys_var_ulong Sys_net_buffer_length(
       "net_buffer_length",
       "Buffer length for TCP/IP and socket communication",
       SESSION_VAR(net_buffer_length), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1024, 1024*1024), DEFAULT(16384), BLOCK_SIZE(1024),
       NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(check_net_buffer_length));

static bool fix_net_read_timeout(sys_var *self, THD *thd, enum_var_type type)
{
  if (type != OPT_GLOBAL)
    my_net_set_read_timeout(&thd->net, thd->variables.net_read_timeout);
  return false;
}
static Sys_var_ulong Sys_net_read_timeout(
       "net_read_timeout",
       "Number of seconds to wait for more data from a connection before "
       "aborting the read",
       SESSION_VAR(net_read_timeout), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1, LONG_TIMEOUT), DEFAULT(NET_READ_TIMEOUT), BLOCK_SIZE(1),
       NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0),
       ON_UPDATE(fix_net_read_timeout));

static bool fix_net_write_timeout(sys_var *self, THD *thd, enum_var_type type)
{
  if (type != OPT_GLOBAL)
    my_net_set_write_timeout(&thd->net, thd->variables.net_write_timeout);
  return false;
}
static Sys_var_ulong Sys_net_write_timeout(
       "net_write_timeout",
       "Number of seconds to wait for a block to be written to a connection "
       "before aborting the write",
       SESSION_VAR(net_write_timeout), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1, LONG_TIMEOUT), DEFAULT(NET_WRITE_TIMEOUT), BLOCK_SIZE(1),
       NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0),
       ON_UPDATE(fix_net_write_timeout));

// static bool fix_net_retry_count(sys_var *self, THD *thd, enum_var_type type)
// {
//   if (type != OPT_GLOBAL)
//     thd->net.retry_count=thd->variables.net_retry_count;
//   return false;
// }
// static Sys_var_ulong Sys_net_retry_count(
//        "net_retry_count",
//        "If a read on a communication port is interrupted, retry this "
//        "many times before giving up",
//        SESSION_VAR(net_retry_count), CMD_LINE(REQUIRED_ARG),
//        VALID_RANGE(1, ULONG_MAX), DEFAULT(MYSQLD_NET_RETRY_COUNT),
//        BLOCK_SIZE(1), NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0),
//        ON_UPDATE(fix_net_retry_count));

// static Sys_var_mybool Sys_var_end_markers_in_json(
//        "end_markers_in_json",
//        "In JSON output (\"EXPLAIN FORMAT=JSON\" and optimizer trace), "
//        "if variable is set to 1, repeats the structure's key (if it has one) "
//        "near the closing bracket",
//        SESSION_VAR(end_markers_in_json), CMD_LINE(OPT_ARG),
//        DEFAULT(FALSE));

static Sys_var_uint Sys_port(
       "port",
       "Port number to use for connection or 0 to default to, "
       "my.cnf, $MYSQL_TCP_PORT, "
#if MYSQL_PORT_DEFAULT == 0
       "/etc/services, "
#endif
       "built-in default (" STRINGIFY_ARG(MYSQL_PORT) "), whatever comes first",
       READ_ONLY GLOBAL_VAR(mysqld_port), CMD_LINE(REQUIRED_ARG, 'P'),
       VALID_RANGE(0, UINT_MAX32), DEFAULT(0), BLOCK_SIZE(1));

static bool fix_thd_mem_root(sys_var *self, THD *thd, enum_var_type type)
{
  if (type != OPT_GLOBAL)
    reset_root_defaults(thd->mem_root,
                        thd->variables.query_alloc_block_size,
                        thd->variables.query_prealloc_size);
  return false;
}
static Sys_var_ulong Sys_query_alloc_block_size(
       "query_alloc_block_size",
       "Allocation block size for query parsing and execution",
       SESSION_VAR(query_alloc_block_size), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1024, ULONG_MAX), DEFAULT(QUERY_ALLOC_BLOCK_SIZE),
       BLOCK_SIZE(1024), NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0),
       ON_UPDATE(fix_thd_mem_root));

static Sys_var_ulong Sys_query_prealloc_size(
       "query_prealloc_size",
       "Persistent buffer for query parsing and execution",
       SESSION_VAR(query_prealloc_size), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(QUERY_ALLOC_PREALLOC_SIZE, ULONG_MAX),
       DEFAULT(QUERY_ALLOC_PREALLOC_SIZE),
       BLOCK_SIZE(1024), NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0),
       ON_UPDATE(fix_thd_mem_root));

static Sys_var_charptr Sys_socket(
       "socket", "Socket file to use for connection",
       READ_ONLY GLOBAL_VAR(mysqld_unix_port), CMD_LINE(REQUIRED_ARG),
       IN_FS_CHARSET, DEFAULT(0));

static Sys_var_ulong Sys_thread_stack(
       "thread_stack", "The stack size for each thread",
       READ_ONLY GLOBAL_VAR(my_thread_stack_size), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(128*1024, ULONG_MAX), DEFAULT(DEFAULT_THREAD_STACK),
       BLOCK_SIZE(1024));

static const char *thread_handling_names[]=
{
  "one-thread-per-connection", "no-threads", "loaded-dynamically",
  0
};
static Sys_var_enum Sys_thread_handling(
       "thread_handling",
       "Define threads usage for handling queries, one of "
       "one-thread-per-connection, no-threads, loaded-dynamically"
       , READ_ONLY GLOBAL_VAR(thread_handling), CMD_LINE(REQUIRED_ARG),
       thread_handling_names, DEFAULT(0));

#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
#define SSL_OPT(X) CMD_LINE(REQUIRED_ARG,X)
#else
#define SSL_OPT(X) NO_CMD_LINE
#endif

static bool check_log_path(sys_var *self, THD *thd, set_var *var)
{
    if (!var->value)
        return false; // DEFAULT is ok

    if (!var->save_result.string_value.str)
        return true;

    if (var->save_result.string_value.length > FN_REFLEN)
    { // path is too long
        my_error(ER_PATH_LENGTH, MYF(0), self->name.str);
        return true;
    }

    char path[FN_REFLEN];
    size_t path_length= unpack_filename(path, var->save_result.string_value.str);

    if (!path_length)
        return true;

    if (!is_filename_allowed(var->save_result.string_value.str, 
        var->save_result.string_value.length, TRUE))
    {
        my_error(ER_WRONG_VALUE_FOR_VAR, MYF(0), 
            self->name.str, var->save_result.string_value.str);
        return true;
    }

    MY_STAT f_stat;

    if (my_stat(path, &f_stat, MYF(0)))
    {
        if (!MY_S_ISREG(f_stat.st_mode) || !(f_stat.st_mode & MY_S_IWRITE))
            return true; // not a regular writable file
        return false;
    }

    (void) dirname_part(path, var->save_result.string_value.str, &path_length);

    if (var->save_result.string_value.length - path_length >= FN_LEN)
    { // filename is too long
        my_error(ER_PATH_LENGTH, MYF(0), self->name.str);
        return true;
    }

    if (!path_length) // no path is good path (remember, relative to datadir)
        return false;

    if (my_access(path, (F_OK|W_OK)))
        return true; // directory is not writable

    return false;
}
static bool fix_log(char** logname, const char* default_logname,
    const char*ext, bool enabled, void (*reopen)(char*))
{
    if (!*logname) // SET ... = DEFAULT
    {
        char buff[FN_REFLEN];
        *logname= my_strdup(make_log_name(buff, default_logname, ext),
            MYF(MY_FAE+MY_WME));
        if (!*logname)
            return true;
    }
    logger.lock_exclusive();
    mysql_mutex_unlock(&LOCK_global_system_variables);
    if (enabled)
        reopen(*logname);
    logger.unlock();
    mysql_mutex_lock(&LOCK_global_system_variables);
    return false;
}
static void reopen_general_log(char* name)
{
    logger.get_log_file_handler()->close(0);
    logger.get_log_file_handler()->open_query_log(name);
}
static bool fix_general_log_file(sys_var *self, THD *thd, enum_var_type type)
{
    return fix_log(&opt_logname, default_logfile_name, ".log", opt_log,
        reopen_general_log);
}
static Sys_var_charptr Sys_general_log_path(
    "general_log_file", "Log connections and queries to given file",
    GLOBAL_VAR(opt_logname), CMD_LINE(REQUIRED_ARG),
    IN_FS_CHARSET, DEFAULT(0), NO_MUTEX_GUARD, NOT_IN_BINLOG,
    ON_CHECK(check_log_path), ON_UPDATE(fix_general_log_file));

static Sys_var_mybool Sys_general_log(
    "general_log", "Log connections and queries to a table or log file. "
    "Defaults logging to a file hostname.log or a table mysql.general_log"
    "if --log-output=TABLE is used",
    GLOBAL_VAR(opt_log), CMD_LINE(OPT_ARG),
    DEFAULT(FALSE), NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0));

// bool Sys_var_tx_read_only::session_update(THD *thd, set_var *var)
// {
//   if (var->type == OPT_SESSION && Sys_var_mybool::session_update(thd, var))
//     return true;
//   if (var->type == OPT_DEFAULT || !thd->in_active_multi_stmt_transaction())
//   {
//     // @see Sys_var_tx_isolation::session_update() above for the rules.
//     thd->tx_read_only= var->save_result.ulonglong_value;
//   }
//   return false;
// }

static char *server_version_ptr;
static Sys_var_charptr Sys_version(
       "version", "Server version",
       READ_ONLY GLOBAL_VAR(server_version_ptr), NO_CMD_LINE,
       IN_SYSTEM_CHARSET, DEFAULT(server_version));

static char *server_version_comment_ptr;
static Sys_var_charptr Sys_version_comment(
       "version_comment", "version_comment",
       READ_ONLY GLOBAL_VAR(server_version_comment_ptr), NO_CMD_LINE,
       IN_SYSTEM_CHARSET, DEFAULT(MYSQL_COMPILATION_COMMENT));

static char *server_version_compile_machine_ptr;
static Sys_var_charptr Sys_version_compile_machine(
       "version_compile_machine", "version_compile_machine",
       READ_ONLY GLOBAL_VAR(server_version_compile_machine_ptr), NO_CMD_LINE,
       IN_SYSTEM_CHARSET, DEFAULT(MACHINE_TYPE));

static char *server_version_compile_os_ptr;
static Sys_var_charptr Sys_version_compile_os(
       "version_compile_os", "version_compile_os",
       READ_ONLY GLOBAL_VAR(server_version_compile_os_ptr), NO_CMD_LINE,
       IN_SYSTEM_CHARSET, DEFAULT(SYSTEM_TYPE));

static Sys_var_ulong Sys_net_wait_timeout(
       "wait_timeout",
       "The number of seconds the server waits for activity on a "
       "connection before closing it",
       SESSION_VAR(net_wait_timeout), CMD_LINE(REQUIRED_ARG),
       VALID_RANGE(1, IF_WIN(INT_MAX32/1000, LONG_TIMEOUT)),
       DEFAULT(NET_WAIT_TIMEOUT), BLOCK_SIZE(1));

static Sys_var_charptr Sys_date_format(
       "date_format", "The DATE format (ignored)",
       READ_ONLY GLOBAL_VAR(global_date_format.format.str),
       CMD_LINE(REQUIRED_ARG), IN_SYSTEM_CHARSET,
       DEFAULT(known_date_time_formats[ISO_FORMAT].date_format),
       NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0), ON_UPDATE(0),
       DEPRECATED(""));

static Sys_var_charptr Sys_datetime_format(
       "datetime_format", "The DATETIME format (ignored)",
       READ_ONLY GLOBAL_VAR(global_datetime_format.format.str),
       CMD_LINE(REQUIRED_ARG), IN_SYSTEM_CHARSET,
       DEFAULT(known_date_time_formats[ISO_FORMAT].datetime_format),
       NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0), ON_UPDATE(0),
       DEPRECATED(""));

static Sys_var_charptr Sys_time_format(
       "time_format", "The TIME format (ignored)",
       READ_ONLY GLOBAL_VAR(global_time_format.format.str),
       CMD_LINE(REQUIRED_ARG), IN_SYSTEM_CHARSET,
       DEFAULT(known_date_time_formats[ISO_FORMAT].time_format),
       NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0), ON_UPDATE(0),
       DEPRECATED(""));

// static Sys_var_bit Sys_big_selects(
//        "sql_big_selects", "sql_big_selects",
//        SESSION_VAR(option_bits), NO_CMD_LINE, OPTION_BIG_SELECTS,
//        DEFAULT(FALSE));

/**
  This function sets the session variable thd->variables.sql_log_bin 
  to reflect changes to @@session.sql_log_bin.

  @param[IN] self   A pointer to the sys_var, i.e. Sys_log_binlog.
  @param[IN] type   The type either session or global.

  @return @c FALSE.
*/
// static bool fix_sql_log_bin_after_update(sys_var *self, THD *thd,
//                                          enum_var_type type)
// {
//   if (type == OPT_SESSION)
//   {
//     if (thd->variables.sql_log_bin)
//       thd->variables.option_bits |= OPTION_BIN_LOG;
//     else
//       thd->variables.option_bits &= ~OPTION_BIN_LOG;
//   }
//   return FALSE;
// }

// static Sys_var_bit Sys_sql_warnings(
//        "sql_warnings", "sql_warnings",
//        SESSION_VAR(option_bits), NO_CMD_LINE, OPTION_WARNINGS,
//        DEFAULT(FALSE));
//
// static Sys_var_bit Sys_sql_notes(
//        "sql_notes", "sql_notes",
//        SESSION_VAR(option_bits), NO_CMD_LINE, OPTION_SQL_NOTES,
//        DEFAULT(TRUE));
//
// static Sys_var_bit Sys_auto_is_null(
//        "sql_auto_is_null", "sql_auto_is_null",
//        SESSION_VAR(option_bits), NO_CMD_LINE, OPTION_AUTO_IS_NULL,
//        DEFAULT(FALSE), NO_MUTEX_GUARD, IN_BINLOG);
//
// static Sys_var_bit Sys_foreign_key_checks(
//        "foreign_key_checks", "foreign_key_checks",
//        SESSION_VAR(option_bits), NO_CMD_LINE,
//        REVERSE(OPTION_NO_FOREIGN_KEY_CHECKS),
//        DEFAULT(TRUE), NO_MUTEX_GUARD, IN_BINLOG);

// static bool update_timestamp(THD *thd, set_var *var)
// {
//   if (var->value)
//   {
//     double fl= floor(var->save_result.double_value); // Truncate integer part
//     struct timeval tmp;
//     tmp.tv_sec= (ulonglong) fl;
//     /* Round nanoseconds to nearest microsecond */
//     tmp.tv_usec= (ulonglong) rint((var->save_result.double_value - fl) * 1000000);
//     thd->set_time(&tmp);
//   }
//   else // SET timestamp=DEFAULT
//   {
//     thd->user_time.tv_sec= 0;
//     thd->user_time.tv_usec= 0;
//   }
//   return false;
// }
// static double read_timestamp(THD *thd)
// {
//   return (double) thd->start_time.tv_sec +
//          (double) thd->start_time.tv_usec / 1000000;
// }
//
//
// static bool check_timestamp(sys_var *self, THD *thd, set_var *var)
// {
//   double val;
//
//   if (!var->value)
//     return FALSE;
//
//   val= var->save_result.double_value;
//   if (val != 0 &&          // this is how you set the default value
//       (val < TIMESTAMP_MIN_VALUE || val > TIMESTAMP_MAX_VALUE))
//   {
//     ErrConvString prm(val);
//     my_error(ER_WRONG_VALUE_FOR_VAR, MYF(0), "timestamp", prm.ptr());
//     return TRUE;
//   }
//   return FALSE;
// }


// static Sys_var_session_special_double Sys_timestamp(
//        "timestamp", "Set the time for this client",
//        sys_var::ONLY_SESSION, NO_CMD_LINE,
//        VALID_RANGE(0, 0), BLOCK_SIZE(1),
//        NO_MUTEX_GUARD, IN_BINLOG, ON_CHECK(check_timestamp), 
//        ON_UPDATE(update_timestamp), ON_READ(read_timestamp));
//
// static ulonglong read_error_count(THD *thd)
// {
//   return thd->get_stmt_da()->error_count();
// }
// this really belongs to the SHOW STATUS
// static Sys_var_session_special Sys_error_count(
//        "error_count", "The number of errors that resulted from the "
//        "last statement that generated messages",
//        READ_ONLY sys_var::ONLY_SESSION, NO_CMD_LINE,
//        VALID_RANGE(0, ULONGLONG_MAX), BLOCK_SIZE(1), NO_MUTEX_GUARD,
//        NOT_IN_BINLOG, ON_CHECK(0), ON_UPDATE(0), ON_READ(read_error_count));

// static ulonglong read_warning_count(THD *thd)
// {
//   return thd->get_stmt_da()->warn_count();
// }
// this really belongs to the SHOW STATUS
// static Sys_var_session_special Sys_warning_count(
//        "warning_count", "The number of errors, warnings, and notes "
//        "that resulted from the last statement that generated messages",
//        READ_ONLY sys_var::ONLY_SESSION, NO_CMD_LINE,
//        VALID_RANGE(0, ULONGLONG_MAX), BLOCK_SIZE(1), NO_MUTEX_GUARD,
//        NOT_IN_BINLOG, ON_CHECK(0), ON_UPDATE(0), ON_READ(read_warning_count));

static Sys_var_charptr Sys_remote_bak_host(
    "inception_remote_backup_host", "the host of remote backup.",
    READ_ONLY GLOBAL_VAR(remote_backup_host), CMD_LINE(REQUIRED_ARG),
    IN_FS_CHARSET, DEFAULT("localhost"));

static Sys_var_uint Sys_remote_bak_port(
    "inception_remote_backup_port",
    "Port number to use for remote backup.",
    READ_ONLY GLOBAL_VAR(remote_backup_port), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(0, UINT_MAX32), DEFAULT(0), BLOCK_SIZE(1));

static Sys_var_charptr Sys_remote_system_user(
    "inception_remote_system_user", "the user name of remote process.",
    READ_ONLY GLOBAL_VAR(remote_system_user), CMD_LINE(REQUIRED_ARG),
    IN_FS_CHARSET, DEFAULT(""));

static Sys_var_charptr Sys_remote_system_password(
    "inception_remote_system_password", "the password of remote process.",
    READ_ONLY GLOBAL_VAR(remote_system_password), CMD_LINE(REQUIRED_ARG),
    IN_FS_CHARSET, DEFAULT(""));

static Sys_var_bit Sys_autocommit(
    "autocommit", "autocommit",
    SESSION_VAR(option_bits), NO_CMD_LINE, OPTION_AUTOCOMMIT, DEFAULT(TRUE),
    NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0));

static Sys_var_charptr Sys_inception_user(
    "inception_user", "the user name of inception.",
    READ_ONLY GLOBAL_VAR(inception_user), CMD_LINE(REQUIRED_ARG),
    IN_FS_CHARSET, DEFAULT(""));

static Sys_var_charptr Sys_inception_password(                       
    "inception_password", "the user password of inception.",
    READ_ONLY GLOBAL_VAR(inception_password), CMD_LINE(REQUIRED_ARG),
    IN_FS_CHARSET, DEFAULT(""));

static Sys_var_mybool Sys_inception_check_insert_field(
    "inception_check_insert_field",
    "check field list when insert.",
    GLOBAL_VAR(inception_check_insert_field),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_check_dml_where(
    "inception_check_dml_where",
    "check where condition when execute dml statement.",
    GLOBAL_VAR(inception_check_dml_where),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_check_dml_limit(
    "inception_check_dml_limit",
    "check limit when execute dml statement.",
    GLOBAL_VAR(inception_check_dml_limit),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_check_dml_orderby(
    "inception_check_dml_orderby",
    "check order by when execute dml statement.",
    GLOBAL_VAR(inception_check_dml_orderby),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_enable_select_star(
    "inception_enable_select_star",
    "check select * when execute dml statement.",
    GLOBAL_VAR(inception_enable_select_star),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_enable_orderby_rand(
    "inception_enable_orderby_rand",
    "check order by rand when execute dml statement.",
    GLOBAL_VAR(inception_enable_orderby_rand),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_enable_nullable(
    "inception_enable_nullable",
    "check column nullable when create table or alter table.",
    GLOBAL_VAR(inception_enable_nullable),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_enable_foreign_key(
    "inception_enable_foreign_key",
    "check foreign key when create table or alter table",
    GLOBAL_VAR(inception_enable_foreign_key),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_ulong Sys_inception_max_key_parts(
    "inception_max_key_parts",
    "set the max key parts when create table or create index.",
    GLOBAL_VAR(inception_max_key_parts), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, 64), DEFAULT(5), BLOCK_SIZE(1));

static Sys_var_ulong Sys_inception_max_update_rows(
    "inception_max_update_rows",
    "set the max estimated rows when execute dml",
    GLOBAL_VAR(inception_max_update_rows), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, UINT_MAX32), DEFAULT(10000), BLOCK_SIZE(1));

static Sys_var_ulong Sys_inception_max_keys(
    "inception_max_keys",
    "set the max keys when create table or alter table",
    GLOBAL_VAR(inception_max_keys), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, 1024), DEFAULT(16), BLOCK_SIZE(1));

static Sys_var_mybool Sys_inception_enable_not_innodb(
    "inception_enable_not_innodb",
    "check innodb engine when create table ",
    GLOBAL_VAR(inception_enable_not_innodb),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static bool check_charset(sys_var *self, THD *thd, set_var *var)
{
    char*   charset;
    char*   strToken;
    int     ret;
    if (!var->value)
        return false; 

    if (var->save_result.string_value.length > 256)
        return true;

    charset = (char*)my_malloc(var->save_result.string_value.length + 1, MY_ZEROFILL);
    strcpy(charset, var->save_result.string_value.str);
    if ((strToken = strtok(charset, ",")) == NULL)
    {
        ret = false;
        goto err;
    }

    while(strToken)
    {
        if (get_charset_number(strToken, MY_CS_COMPILED) == 0)
            return true;
        strToken=strtok(NULL, ",");
    }

err:
    my_free(charset);
    return false;
}

static Sys_var_charptr Sys_inception_support_charset(
    "inception_support_charset",
    "check charset when create table or alter, set multi charset use comma to concat",
    GLOBAL_VAR(inception_support_charset),
    CMD_LINE(REQUIRED_ARG), IN_FS_CHARSET, DEFAULT("utf8mb4"),
    NO_MUTEX_GUARD, NOT_IN_BINLOG,
    ON_CHECK(check_charset));

static Sys_var_mybool Sys_inception_check_table_comment(
    "inception_check_table_comment",
    "check comment when create table",
    GLOBAL_VAR(inception_check_table_comment),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_check_column_comment(
    "inception_check_column_comment",
    "check comment when create table or alter tablhe",
    GLOBAL_VAR(inception_check_column_comment),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_check_primary_key(
    "inception_check_primary_key",
    "check table have one primary key at least/most",
    GLOBAL_VAR(inception_check_primary_key),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_enable_partition_table(
    "inception_enable_partition_table",
    "enable paritiion table ",
    GLOBAL_VAR(inception_enable_partition_table),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_enable_blob_type(
    "inception_enable_blob_type",
    "inception_enable_blob_type",
    GLOBAL_VAR(inception_enable_blob_type),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_enable_enum_set_bit(
    "inception_enable_enum_set_bit",
    "inception_enable_enum_set_bit",
    GLOBAL_VAR(inception_enable_enum_set_bit),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_check_index_prefix(
    "inception_check_index_prefix",
    "check the prefix of index name",
    GLOBAL_VAR(inception_check_index_prefix),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_enable_autoincrement_unsigned(
    "inception_enable_autoincrement_unsigned",
    "check the auto-increment datatype unsigned",
    GLOBAL_VAR(inception_enable_autoincrement_unsigned),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_ulong Sys_inception_max_char_length(
    "inception_max_char_length",
    "when char(len)'s len longer then this variable value, warning to convert to varchar",
    GLOBAL_VAR(inception_max_char_length), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, UINT_MAX32), DEFAULT(16), BLOCK_SIZE(1));

static Sys_var_mybool Sys_inception_check_autoincrement_init_value(
    "inception_check_autoincrement_init_value",
    "check whether the auto-increment init value is 1",
    GLOBAL_VAR(inception_check_autoincrement_init_value),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_check_autoincrement_datatype(
    "inception_check_autoincrement_datatype",
    "check whether the auto-increment column datatype is int or bigint",
    GLOBAL_VAR(inception_check_autoincrement_datatype),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_check_timestamp_default(
    "inception_check_timestamp_default",
    "set the default value for timestamp datatype column",
    GLOBAL_VAR(inception_check_timestamp_default),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_enable_column_charset(
    "inception_enable_column_charset",
    "enable set charset for column itself",
    GLOBAL_VAR(inception_enable_column_charset),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_check_autoincrement_name(
    "inception_check_autoincrement_name",
    "check whether autoincrement column name is id，if not, report the id meanfully",
    GLOBAL_VAR(inception_check_autoincrement_name),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_merge_alter_table(
    "inception_merge_alter_table",
    "merge multi alter table statement for same table to only one",
    GLOBAL_VAR(inception_merge_alter_table),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_check_column_default_value(
    "inception_check_column_default_value",
    "check default value when for column",
    GLOBAL_VAR(inception_check_column_default_value),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_enable_identifer_keyword(
    "inception_enable_identifer_keyword",
    "enable identifer use keyword",
    GLOBAL_VAR(inception_enable_identifer_keyword),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_enable_sql_statistic(
    "inception_enable_sql_statistic",
    "statistic sql command",
    GLOBAL_VAR(inception_enable_sql_statistic),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_ulong Sys_inception_osc_min_table_size(
    "inception_osc_min_table_size",
    "when table is larger then this value, then use osc, size is measure by Mega",
    SESSION_VAR(inception_osc_min_table_size), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(0, 1024*1024), DEFAULT(16), BLOCK_SIZE(1));

static Sys_var_charptr Sys_inception_osc_bin_dir(
     "inception_osc_bin_dir", "home directory for pt-online-schema-change",
     READ_ONLY GLOBAL_VAR(inception_osc_bin_dir), CMD_LINE(REQUIRED_ARG),
     IN_FS_CHARSET, DEFAULT(""),
     NO_MUTEX_GUARD, NOT_IN_BINLOG);

static Sys_var_ulong Sys_inception_osc_critical_connected(
    "inception_osc_critical_thread_connected",
    "Examine SHOW GLOBAL STATUS(Threads_running) after every chunk, "
    "and abort if the load is too high. "
    "The option accepts a comma-separated list of MySQL status variables and thresholds. "
    "An optional =MAX_VALUE (or :MAX_VALUE) can follow each variable. "
    "If not given, the tool determines a threshold by examining the "
    "current value at startup and doubling it",
    SESSION_VAR(inception_osc_critical_connected), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, 1024*1024), DEFAULT(1000), BLOCK_SIZE(1));

static Sys_var_ulong Sys_inception_osc_critical_running(
    "inception_osc_critical_thread_running",
    "Examine SHOW GLOBAL STATUS(Threads_running) after every chunk, "
    "and abort if the load is too high. "
    "The option accepts a comma-separated list of MySQL status variables and thresholds. "
    "An optional =MAX_VALUE (or :MAX_VALUE) can follow each variable. "
    "If not given, the tool determines a threshold by examining the "
    "current value at startup and doubling it",
    SESSION_VAR(inception_osc_critical_running), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, 1024*1024), DEFAULT(80), BLOCK_SIZE(1));

static Sys_var_ulong Sys_inception_osc_max_connected(
    "inception_osc_max_thread_connected",
    "Examine SHOW GLOBAL STATUS after every chunk, and pause if any status "
    "variables are higher than their" "thresholds. The option accepts a comma-separated "
    "list of MySQL status variables. An optional =MAX_VALUE"
    "(or :MAX_VALUE) can follow each variable. If not given, the tool "
    "determines a threshold by examining the current value and increasing it by 20%.",
    SESSION_VAR(inception_osc_max_connected), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, 1024*1024), DEFAULT(1000), BLOCK_SIZE(1));

static Sys_var_ulong Sys_inception_osc_max_running(
    "inception_osc_max_thread_running",
    "Examine SHOW GLOBAL STATUS after every chunk, and pause if any status "
    "variables are higher than their" "thresholds. The option accepts a comma-separated "
    "list of MySQL status variables. An optional =MAX_VALUE"
    "(or :MAX_VALUE) can follow each variable. If not given, the tool "
    "determines a threshold by examining the current value and increasing it by 20%.",
    SESSION_VAR(inception_osc_max_running), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, 1024*1024), DEFAULT(80), BLOCK_SIZE(1));

static Sys_var_double Sys_inception_osc_chunk_time(
    "inception_osc_chunk_time",
    "Adjust the chunk size dynamically so each data-copy query takes this long to execute. "
    "The tool tracks the copy rate (rows per second) and adjusts the chunk size after "
    "each data-copy query, so that the next query takes this amount of time (in seconds) "
    "to execute. It keeps an exponentially decaying moving average of queries per second, "
    "so that if the server’s performance changes due to changes in server load, "
    "the tool adapts quickly.",
    SESSION_VAR(inception_osc_chunk_time),
    CMD_LINE(REQUIRED_ARG), VALID_RANGE(0, 1024), DEFAULT(1),
    NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0));

static Sys_var_double Sys_inception_osc_check_interval(
    "inception_osc_check_interval",
    "Sleep time between checks for --max-lag.",
    SESSION_VAR(inception_osc_check_interval),
    CMD_LINE(REQUIRED_ARG), VALID_RANGE(0, 1024), DEFAULT(5),
    NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0));

static Sys_var_double Sys_inception_osc_max_lag(
    "inception_osc_max_lag",
    "Pause the data copy until all replicas’ lag is less than this value..",
    SESSION_VAR(inception_osc_max_lag),
    CMD_LINE(REQUIRED_ARG), VALID_RANGE(0, 1024*1024), DEFAULT(3),
    NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0));

static Sys_var_ulong Sys_inception_osc_chunk_size(
    "inception_osc_chunk_size",
    "This option can override the default behavior, which is to adjust chunk size "
    "dynamically to try to make chunks run in exactly --chunk-time seconds. When this "
    "option isn’t set explicitly, its default value is used as a starting point, "
    "but after that, the tool ignores this option’s value. If you set this option "
    "explicitly, however, then it disables the dynamic adjustment behavior and tries "
    "to make all chunks exactly the specified number of rows.",
    SESSION_VAR(inception_osc_chunk_size), CMD_LINE(REQUIRED_ARG),
    VALID_RANGE(1, 1024*1024), DEFAULT(1000), BLOCK_SIZE(1));

static Sys_var_double Sys_inception_osc_chunk_size_limit(
    "inception_osc_chunk_size_limit",
    "Do not copy chunks this much larger than the desired chunk size."
    "When a table has no unique indexes, chunk sizes can be inaccurate. "
    "This option specifies a maximum tolerable limit to the inaccuracy. "
    "The tool uses <EXPLAIN> to estimate how many rows are in the chunk. If that estimate"
    "exceeds the desired chunk size times the limit, then the tool skips the chunk.",
    SESSION_VAR(inception_osc_chunk_size_limit),
    CMD_LINE(REQUIRED_ARG), VALID_RANGE(0, 1024*1024), DEFAULT(4),
    NO_MUTEX_GUARD, NOT_IN_BINLOG, ON_CHECK(0));

static Sys_var_mybool Sys_inception_osc_drop_new_table(
    "inception_osc_drop_new_table",
    "Drop the new table if copying the original table fails.",
    SESSION_VAR(inception_osc_drop_new_table),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_osc_print_sql(
    "inception_osc_print_sql",
    "Print SQL statements to STDOUT. Specifying this option allows you to see "
    "most of the statements that the tool executes",
    GLOBAL_VAR(inception_osc_print_sql),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_osc_drop_old_table(
    "inception_osc_drop_old_table",
    "Drop the original table after renaming it. After the original table has been "
    "successfully renamed to let the new table take its place, and if there are no "
    "errors, the tool drops the original table by default. If there are any errors, "
    "the tool leaves the original table in place.",
    SESSION_VAR(inception_osc_drop_old_table),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_ddl_support(
    "inception_ddl_support",
    "for temp use",
    GLOBAL_VAR(inception_ddl_support),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_osc_on(
    "inception_osc_on",
    "switch of osc",
    GLOBAL_VAR(inception_osc_on),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_osc_print_none(
    "inception_osc_print_none",
    "if true, not print any success information",
    GLOBAL_VAR(inception_osc_print_none),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

static Sys_var_mybool Sys_inception_read_only(
    "inception_read_only",
    "if true, inception will not execute the sql on remote MySQL server, although --enable-execute",
    GLOBAL_VAR(inception_read_only),
    CMD_LINE(OPT_ARG), DEFAULT(FALSE));

static Sys_var_mybool Sys_inception_check_identifier(
    "inception_check_identifier",
    "if true, inception will check the identifier, valid option: [a-z|A-Z|0-9|_]",
    GLOBAL_VAR(inception_check_identifier),
    CMD_LINE(OPT_ARG), DEFAULT(TRUE));

const char *osc_recursion_method[]= {"processlist", "hosts", "none", NullS};
static Sys_var_enum Sys_inception_osc_recursion_method(
    "inception_osc_recursion_method",
    "Preferred recursion method used to find slaves.",
    SESSION_VAR(inception_osc_recursion_method), CMD_LINE(REQUIRED_ARG),
    osc_recursion_method, DEFAULT(recursion_method_processlist), 
    NO_MUTEX_GUARD, NOT_IN_BINLOG);

