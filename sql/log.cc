/* Copyright (c) 2000, 2011, 2012 Oracle and/or its affiliates. All rights reserved.

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

  @brief
  logging of commands

  @todo
    Abort logging when we get an error in reading or writing log files
*/

#include "my_global.h"                          /* NO_EMBEDDED_ACCESS_CHECKS */
#include "sql_priv.h"
#include "log.h"
#include "sql_base.h"                           // open_log_table
#include "sql_delete.h"                         // mysql_truncate
#include "sql_parse.h"                          // command_name
#include "sql_time.h"           // calc_time_from_sec, my_time_compare
#include "tztime.h"             // my_tz_OFFSET0, struct Time_zone
#include "sql_acl.h"            // SUPER_ACL
#include "sql_audit.h"
#include "mysql/service_my_plugin_log.h"

#include <my_dir.h>
#include <stdarg.h>
#include <m_ctype.h>				// For test_if_number

#ifdef _WIN32
#include "message.h"
#endif

using std::min;
using std::max;

/* max size of the log message */
#define MAX_LOG_BUFFER_SIZE 1024
#define MAX_TIME_SIZE 32

static
const TABLE_FIELD_TYPE slow_query_log_table_fields[SQLT_FIELD_COUNT] =
{
  {
    { C_STRING_WITH_LEN("start_time") },
    { C_STRING_WITH_LEN("timestamp") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("user_host") },
    { C_STRING_WITH_LEN("mediumtext") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("query_time") },
    { C_STRING_WITH_LEN("time") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("lock_time") },
    { C_STRING_WITH_LEN("time") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("rows_sent") },
    { C_STRING_WITH_LEN("int(11)") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("rows_examined") },
    { C_STRING_WITH_LEN("int(11)") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("db") },
    { C_STRING_WITH_LEN("varchar(512)") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("last_insert_id") },
    { C_STRING_WITH_LEN("int(11)") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("insert_id") },
    { C_STRING_WITH_LEN("int(11)") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("server_id") },
    { C_STRING_WITH_LEN("int(10) unsigned") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("sql_text") },
    { C_STRING_WITH_LEN("mediumtext") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("thread_id") },
    { C_STRING_WITH_LEN("bigint(21) unsigned") },
    { NULL, 0 }
  }
};

static const TABLE_FIELD_DEF
  slow_query_log_table_def= {SQLT_FIELD_COUNT, slow_query_log_table_fields};

class Slow_query_log_table_intact : public Table_check_intact
{
protected:
  void report_error(uint, const char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    error_log_print(ERROR_LEVEL, fmt, args);
    va_end(args);
  }
};

/** In case of an error, a message is printed to the error log. */
static Slow_query_log_table_intact sqlt_intact;

static
const TABLE_FIELD_TYPE general_log_table_fields[GLT_FIELD_COUNT] =
{
  {
    { C_STRING_WITH_LEN("event_time") },
    { C_STRING_WITH_LEN("timestamp") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("user_host") },
    { C_STRING_WITH_LEN("mediumtext") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("thread_id") },
    { C_STRING_WITH_LEN("bigint(21) unsigned") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("server_id") },
    { C_STRING_WITH_LEN("int(10) unsigned") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("command_type") },
    { C_STRING_WITH_LEN("varchar(64)") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("argument") },
    { C_STRING_WITH_LEN("mediumtext") },
    { C_STRING_WITH_LEN("utf8") }
  }
};

static const TABLE_FIELD_DEF
  general_log_table_def= {GLT_FIELD_COUNT, general_log_table_fields};

class General_log_table_intact : public Table_check_intact
{
protected:
  void report_error(uint, const char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    error_log_print(ERROR_LEVEL, fmt, args);
    va_end(args);
  }
};

/** In case of an error, a message is printed to the error log. */
static General_log_table_intact glt_intact;

LOGGER logger;

static bool test_if_number(const char *str,
			   ulong *res, bool allow_wildcards);

/**
   purge logs, master and slave sides both, related error code
   convertor.
   Called from @c purge_error_message(), @c MYSQL_BIN_LOG::reset_logs()

   @param  res  an internal to purging routines error code

   @return the user level error code ER_*
*/
uint purge_log_get_error_code(int res)
{
  uint errcode= 0;

  switch (res)  {
  case 0: break;
  case LOG_INFO_EOF:	errcode= ER_UNKNOWN_TARGET_BINLOG; break;
  case LOG_INFO_IO:	errcode= ER_IO_ERR_LOG_INDEX_READ; break;
  case LOG_INFO_INVALID:errcode= ER_BINLOG_PURGE_PROHIBITED; break;
  case LOG_INFO_SEEK:	errcode= ER_FSEEK_FAIL; break;
  case LOG_INFO_MEM:	errcode= ER_OUT_OF_RESOURCES; break;
  case LOG_INFO_FATAL:	errcode= ER_BINLOG_PURGE_FATAL_ERR; break;
  case LOG_INFO_IN_USE: errcode= ER_LOG_IN_USE; break;
  case LOG_INFO_EMFILE: errcode= ER_BINLOG_PURGE_EMFILE; break;
  default:		errcode= ER_LOG_PURGE_UNKNOWN_ERR; break;
  }

  return errcode;
}

/**
  Silence all errors and warnings reported when performing a write
  to a log table.
  Errors and warnings are not reported to the client or SQL exception
  handlers, so that the presence of logging does not interfere and affect
  the logic of an application.
*/
class Silence_log_table_errors : public Internal_error_handler
{
  char m_message[MYSQL_ERRMSG_SIZE];
public:
  Silence_log_table_errors()
  {
    m_message[0]= '\0';
  }

  virtual ~Silence_log_table_errors() {}

  virtual bool handle_condition(THD *thd,
                                uint sql_errno,
                                const char* sql_state,
                                Sql_condition::enum_warning_level level,
                                const char* msg,
                                Sql_condition ** cond_hdl);
  const char *message() const { return m_message; }
};

bool
Silence_log_table_errors::handle_condition(THD *,
                                           uint,
                                           const char*,
                                           Sql_condition::enum_warning_level,
                                           const char* msg,
                                           Sql_condition ** cond_hdl)
{
  *cond_hdl= NULL;
  strmake(m_message, msg, sizeof(m_message)-1);
  return TRUE;
}

sql_print_message_func sql_print_message_handlers[3] =
{
  sql_print_information,
  sql_print_warning,
  sql_print_error
};

/**
  Create the name of the log specified.

  This method forms a new path + file name for the
  log specified in @c name.

  @param[IN] buff    Location for building new string.
  @param[IN] name    Name of the log file.
  @param[IN] log_ext The extension for the log (e.g. .log).

  @returns Pointer to new string containing the name.
*/
char *make_log_name(char *buff, const char *name, const char* log_ext)
{
  strmake(buff, name, FN_REFLEN-5);
  return fn_format(buff, buff, mysql_real_data_home, log_ext,
                   MYF(MY_UNPACK_FILENAME|MY_REPLACE_EXT));
}

/* Check if a given table is opened log table */
int check_if_log_table(size_t db_len, const char *db, size_t table_name_len,
                       const char *table_name, bool check_if_opened)
{
  if (db_len == 5 &&
      !(lower_case_table_names ?
        my_strcasecmp(system_charset_info, db, "mysql") :
        strcmp(db, "mysql")))
  {
    if (table_name_len == 11 && !(lower_case_table_names ?
                                  my_strcasecmp(system_charset_info,
                                                table_name, "general_log") :
                                  strcmp(table_name, "general_log")))
    {
      if (!check_if_opened/* || logger.is_log_table_enabled(QUERY_LOG_GENERAL)*/)
        return QUERY_LOG_GENERAL;
      return 0;
    }

    if (table_name_len == 8 && !(lower_case_table_names ?
      my_strcasecmp(system_charset_info, table_name, "slow_log") :
      strcmp(table_name, "slow_log")))
    {
      if (!check_if_opened/* || logger.is_log_table_enabled(QUERY_LOG_SLOW)*/)
        return QUERY_LOG_SLOW;
      return 0;
    }
  }
  return 0;
}


Log_to_csv_event_handler::Log_to_csv_event_handler()
{
}


Log_to_csv_event_handler::~Log_to_csv_event_handler()
{
}


void Log_to_csv_event_handler::cleanup()
{
  logger.is_log_tables_initialized= FALSE;
}

/* log event handlers */

/**
  Log command to the general log table

  Log given command to the general log table.

  @param  event_time        command start timestamp
  @param  user_host         the pointer to the string with user@host info
  @param  user_host_len     length of the user_host string. this is computed
                            once and passed to all general log event handlers
  @param  thread_id         Id of the thread, issued a query
  @param  command_type      the type of the command being logged
  @param  command_type_len  the length of the string above
  @param  sql_text          the very text of the query being executed
  @param  sql_text_len      the length of sql_text string


  @return This function attempts to never call my_error(). This is
  necessary, because general logging happens already after a statement
  status has been sent to the client, so the client can not see the
  error anyway. Besides, the error is not related to the statement
  being executed and is internal, and thus should be handled
  internally (@todo: how?).
  If a write to the table has failed, the function attempts to
  write to a short error message to the file. The failure is also
  indicated in the return value.

  @retval  FALSE   OK
  @retval  TRUE    error occured
*/

bool Log_to_csv_event_handler::
  log_general(THD *thd, time_t event_time, const char *user_host,
              uint user_host_len, my_thread_id thread_id,
              const char *command_type, uint command_type_len,
              const char *sql_text, uint sql_text_len,
              const CHARSET_INFO *client_cs)
{
  TABLE_LIST table_list;
  TABLE *table;
  bool result= TRUE;
  bool need_close= FALSE;
  bool need_pop= FALSE;
  bool need_rnd_end= FALSE;
  uint field_index;
  Silence_log_table_errors error_handler;
  Open_tables_backup open_tables_backup;
  ulonglong save_thd_options;
  bool save_time_zone_used;

  /*
    CSV uses TIME_to_timestamp() internally if table needs to be repaired
    which will set thd->time_zone_used
  */
  save_time_zone_used= thd->time_zone_used;

  save_thd_options= thd->variables.option_bits;
  thd->variables.option_bits&= ~OPTION_BIN_LOG;

  table_list.init_one_table(MYSQL_SCHEMA_NAME.str, MYSQL_SCHEMA_NAME.length,
                            GENERAL_LOG_NAME.str, GENERAL_LOG_NAME.length,
                            GENERAL_LOG_NAME.str,
                            TL_WRITE_CONCURRENT_INSERT);

  /*
    1) open_log_table generates an error if the
    table can not be opened or is corrupted.
    2) "INSERT INTO general_log" can generate warning sometimes.

    Suppress these warnings and errors, they can't be dealt with
    properly anyway.

    QQ: this problem needs to be studied in more detail.
    Comment this 2 lines and run "cast.test" to see what's happening.
  */
  thd->push_internal_handler(& error_handler);
  need_pop= TRUE;

  if (!(table= open_log_table(thd, &table_list, &open_tables_backup)))
    goto err;

  need_close= TRUE;

  if (glt_intact.check(table_list.table, &general_log_table_def))
    goto err;

  if (table->file->extra(HA_EXTRA_MARK_AS_LOG_TABLE) ||
      table->file->ha_rnd_init(0))
    goto err;

  need_rnd_end= TRUE;

  /* Honor next number columns if present */
  table->next_number_field= table->found_next_number_field;

  /*
    NOTE: we do not call restore_record() here, as all fields are
    filled by the Logger (=> no need to load default ones).
  */

  /*
    We do not set a value for table->field[0], as it will use
    default value (which is CURRENT_TIMESTAMP).
  */

  /* check that all columns exist */
  if (table->s->fields < 6)
    goto err;

  DBUG_ASSERT(table->field[GLT_FIELD_EVENT_TIME]->type() == MYSQL_TYPE_TIMESTAMP);
  table->field[GLT_FIELD_EVENT_TIME]->store_timestamp(event_time);

  /* do a write */
  if (table->field[GLT_FIELD_USER_HOST]->store(user_host, user_host_len,
                                               client_cs) ||
      table->field[GLT_FIELD_THREAD_ID]->store((longlong) thread_id, TRUE) ||
      table->field[GLT_FIELD_SERVER_ID]->store((longlong) server_id, TRUE) ||
      table->field[GLT_FIELD_COMMAND_TYPE]->store(command_type,
                                                  command_type_len, client_cs))
    goto err;

  /*
    A positive return value in store() means truncation.
    Still logging a message in the log in this case.
  */
  table->field[GLT_FIELD_ARGUMENT]->flags|= FIELDFLAG_HEX_ESCAPE;
  if (table->field[GLT_FIELD_ARGUMENT]->store(sql_text, sql_text_len,
                                              client_cs) < 0)
    goto err;

  /* mark all fields as not null */
  table->field[GLT_FIELD_USER_HOST]->set_notnull();
  table->field[GLT_FIELD_THREAD_ID]->set_notnull();
  table->field[GLT_FIELD_SERVER_ID]->set_notnull();
  table->field[GLT_FIELD_COMMAND_TYPE]->set_notnull();
  table->field[GLT_FIELD_ARGUMENT]->set_notnull();

  /* Set any extra columns to their default values */
  for (field_index= GLT_FIELD_COUNT ;
       field_index < table->s->fields ;
       field_index++)
  {
    table->field[field_index]->set_default();
  }

  /* log table entries are not replicated */
  if (table->file->ha_write_row(table->record[0]))
    goto err;

  result= FALSE;

err:
  if (result && !thd->killed)
    sql_print_error("Failed to write to mysql.general_log: %s",
                    error_handler.message());

  if (need_rnd_end)
  {
    table->file->ha_rnd_end();
    table->file->ha_release_auto_increment();
  }
  if (need_pop)
    thd->pop_internal_handler();
  if (need_close)
    close_log_table(thd, &open_tables_backup);

  thd->variables.option_bits= save_thd_options;
  thd->time_zone_used= save_time_zone_used;
  return result;
}


/*
  Log a query to the slow log table

  SYNOPSIS
    log_slow()
    thd               THD of the query
    current_time      current timestamp
    query_start_arg   command start timestamp
    user_host         the pointer to the string with user@host info
    user_host_len     length of the user_host string. this is computed once
                      and passed to all general log event handlers
    query_time        Amount of time the query took to execute (in microseconds)
    lock_time         Amount of time the query was locked (in microseconds)
    is_command        The flag, which determines, whether the sql_text is a
                      query or an administrator command (these are treated
                      differently by the old logging routines)
    sql_text          the very text of the query or administrator command
                      processed
    sql_text_len      the length of sql_text string

  DESCRIPTION

   Log a query to the slow log table

  RETURN
    FALSE - OK
    TRUE - error occured
*/

bool Log_to_csv_event_handler::
  log_slow(THD *thd, time_t current_time, time_t query_start_arg,
           const char *user_host, uint user_host_len,
           ulonglong query_utime, ulonglong lock_utime, bool is_command,
           const char *sql_text, uint sql_text_len)
{
  TABLE_LIST table_list;
  TABLE *table;
  bool result= TRUE;
  bool need_close= FALSE;
  bool need_rnd_end= FALSE;
  Silence_log_table_errors error_handler;
  Open_tables_backup open_tables_backup;
  const CHARSET_INFO *client_cs= thd->variables.character_set_client;
  bool save_time_zone_used;
  DBUG_ENTER("Log_to_csv_event_handler::log_slow");

  thd->push_internal_handler(& error_handler);
  /*
    CSV uses TIME_to_timestamp() internally if table needs to be repaired
    which will set thd->time_zone_used
  */
  save_time_zone_used= thd->time_zone_used;

  table_list.init_one_table(MYSQL_SCHEMA_NAME.str, MYSQL_SCHEMA_NAME.length,
                            SLOW_LOG_NAME.str, SLOW_LOG_NAME.length,
                            SLOW_LOG_NAME.str,
                            TL_WRITE_CONCURRENT_INSERT);

  if (!(table= open_log_table(thd, &table_list, &open_tables_backup)))
    goto err;

  need_close= TRUE;

  if (sqlt_intact.check(table_list.table, &slow_query_log_table_def))
    goto err;

  if (table->file->extra(HA_EXTRA_MARK_AS_LOG_TABLE) ||
      table->file->ha_rnd_init(0))
    goto err;

  need_rnd_end= TRUE;

  /* Honor next number columns if present */
  table->next_number_field= table->found_next_number_field;

  restore_record(table, s->default_values);    // Get empty record

  /* store the time and user values */
  DBUG_ASSERT(table->field[SQLT_FIELD_START_TIME]->type() == MYSQL_TYPE_TIMESTAMP);
  table->field[SQLT_FIELD_START_TIME]->store_timestamp(current_time);
  if (table->field[SQLT_FIELD_USER_HOST]->store(user_host, user_host_len,
                                                client_cs))
    goto err;

  if (query_start_arg)
  {
    longlong query_time= (longlong) (query_utime/1000000);
    longlong lock_time=  (longlong) (lock_utime/1000000);
    /*
      A TIME field can not hold the full longlong range; query_time or
      lock_time may be truncated without warning here, if greater than
      839 hours (~35 days)
    */
    MYSQL_TIME t;
    t.neg= 0;

    /* fill in query_time field */
    calc_time_from_sec(&t, min<long>(query_time, (longlong) TIME_MAX_VALUE_SECONDS), 0);
    if (table->field[SQLT_FIELD_QUERY_TIME]->store_time(&t))
      goto err;
    /* lock_time */
    calc_time_from_sec(&t, min<long>(lock_time, (longlong) TIME_MAX_VALUE_SECONDS), 0);
    if (table->field[SQLT_FIELD_LOCK_TIME]->store_time(&t))
      goto err;
    /* rows_sent */
    if (table->field[SQLT_FIELD_ROWS_SENT]->store((longlong) thd->get_sent_row_count(), TRUE))
      goto err;
    /* rows_examined */
    if (table->field[SQLT_FIELD_ROWS_EXAMINED]->store((longlong) thd->get_examined_row_count(), TRUE))
      goto err;
  }
  else
  {
    table->field[SQLT_FIELD_QUERY_TIME]->set_null();
    table->field[SQLT_FIELD_LOCK_TIME]->set_null();
    table->field[SQLT_FIELD_ROWS_SENT]->set_null();
    table->field[SQLT_FIELD_ROWS_EXAMINED]->set_null();
  }
  /* fill database field */
  if (thd->db)
  {
    if (table->field[SQLT_FIELD_DATABASE]->store(thd->db, thd->db_length,
                                                 client_cs))
      goto err;
    table->field[SQLT_FIELD_DATABASE]->set_notnull();
  }

  if (thd->stmt_depends_on_first_successful_insert_id_in_prev_stmt)
  {
    if (table->
        field[SQLT_FIELD_LAST_INSERT_ID]->store((longlong)
                        thd->first_successful_insert_id_in_prev_stmt_for_binlog,
                        TRUE))
      goto err;
    table->field[SQLT_FIELD_LAST_INSERT_ID]->set_notnull();
  }

  /*
    Set value if we do an insert on autoincrement column. Note that for
    some engines (those for which get_auto_increment() does not leave a
    table lock until the statement ends), this is just the first value and
    the next ones used may not be contiguous to it.
  */
  if (thd->auto_inc_intervals_in_cur_stmt_for_binlog.nb_elements() > 0)
  {
    if (table->
        field[SQLT_FIELD_INSERT_ID]->store((longlong)
          thd->auto_inc_intervals_in_cur_stmt_for_binlog.minimum(), TRUE))
      goto err;
    table->field[SQLT_FIELD_INSERT_ID]->set_notnull();
  }

  if (table->field[SQLT_FIELD_SERVER_ID]->store((longlong) server_id, TRUE))
    goto err;
  table->field[SQLT_FIELD_SERVER_ID]->set_notnull();

  /*
    Column sql_text.
    A positive return value in store() means truncation.
    Still logging a message in the log in this case.
  */
  if (table->field[SQLT_FIELD_SQL_TEXT]->store(sql_text, sql_text_len,
                                               client_cs) < 0)
    goto err;

  if (table->field[SQLT_FIELD_THREAD_ID]->store((longlong) thd->thread_id,
                                                TRUE))
    goto err;

  /* log table entries are not replicated */
  if (table->file->ha_write_row(table->record[0]))
    goto err;

  result= FALSE;

err:
  thd->pop_internal_handler();

  if (result && !thd->killed)
    sql_print_error("Failed to write to mysql.slow_log: %s",
                    error_handler.message());

  if (need_rnd_end)
  {
    table->file->ha_rnd_end();
    table->file->ha_release_auto_increment();
  }
  if (need_close)
    close_log_table(thd, &open_tables_backup);
  thd->time_zone_used= save_time_zone_used;
  DBUG_RETURN(result);
}

int Log_to_csv_event_handler::
  activate_log(THD *thd, uint log_table_type)
{
  TABLE_LIST table_list;
  TABLE *table;
  LEX_STRING *UNINIT_VAR(log_name);
  int result;
  Open_tables_backup open_tables_backup;

  DBUG_ENTER("Log_to_csv_event_handler::activate_log");

  if (log_table_type == QUERY_LOG_GENERAL)
  {
    log_name= &GENERAL_LOG_NAME;
  }
  else
  {
    DBUG_ASSERT(log_table_type == QUERY_LOG_SLOW);

    log_name= &SLOW_LOG_NAME;
  }
  table_list.init_one_table(MYSQL_SCHEMA_NAME.str, MYSQL_SCHEMA_NAME.length,
                            log_name->str, log_name->length, log_name->str,
                            TL_WRITE_CONCURRENT_INSERT);

  table= open_log_table(thd, &table_list, &open_tables_backup);
  if (table)
  {
    result= 0;
    close_log_table(thd, &open_tables_backup);
  }
  else
    result= 1;

  DBUG_RETURN(result);
}

bool Log_to_csv_event_handler::
  log_error(enum loglevel level, const char *format, va_list args)
{
  /* No log table is implemented */
  DBUG_ASSERT(0);
  return FALSE;
}

bool Log_to_file_event_handler::
  log_error(enum loglevel level, const char *format,
            va_list args)
{
  return vprint_msg_to_log(level, format, args);
}

void Log_to_file_event_handler::init_pthread_objects()
{
  mysql_log.init_pthread_objects();
  mysql_slow_log.init_pthread_objects();
}


/** Wrapper around MYSQL_LOG::write() for slow log. */

bool Log_to_file_event_handler::
  log_slow(THD *thd, time_t current_time, time_t query_start_arg,
           const char *user_host, uint user_host_len,
           ulonglong query_utime, ulonglong lock_utime, bool is_command,
           const char *sql_text, uint sql_text_len)
{
  Silence_log_table_errors error_handler;
  thd->push_internal_handler(&error_handler);
  bool retval= mysql_slow_log.write(thd, current_time, query_start_arg,
                                    user_host, user_host_len,
                                    query_utime, lock_utime, is_command,
                                    sql_text, sql_text_len);
  thd->pop_internal_handler();
  return retval;
}


/**
   Wrapper around MYSQL_LOG::write() for general log. We need it since we
   want all log event handlers to have the same signature.
*/

bool Log_to_file_event_handler::
  log_general(THD *thd, time_t event_time, const char *user_host,
              uint user_host_len, my_thread_id thread_id,
              const char *command_type, uint command_type_len,
              const char *sql_text, uint sql_text_len,
              const CHARSET_INFO *client_cs)
{
  Silence_log_table_errors error_handler;
  thd->push_internal_handler(&error_handler);
  bool retval= mysql_log.write(event_time, user_host, user_host_len,
                               thread_id, command_type, command_type_len,
                               sql_text, sql_text_len);
  thd->pop_internal_handler();
  return retval;
}


bool Log_to_file_event_handler::init()
{
  if (!is_initialized)
  {
    if (opt_log)
      mysql_log.open_query_log(opt_logname);

    is_initialized= TRUE;
  }

  return FALSE;
}


void Log_to_file_event_handler::cleanup()
{
  mysql_log.cleanup();
  mysql_slow_log.cleanup();
}

void Log_to_file_event_handler::flush()
{
  /* reopen log files */
  if (opt_log)
    mysql_log.reopen_file();
  if (opt_slow_log)
    mysql_slow_log.reopen_file();
}

/*
  Log error with all enabled log event handlers

  SYNOPSIS
    error_log_print()

    level             The level of the error significance: NOTE,
                      WARNING or ERROR.
    format            format string for the error message
    args              list of arguments for the format string

  RETURN
    FALSE - OK
    TRUE - error occured
*/

bool LOGGER::error_log_print(enum loglevel level, const char *format,
                             va_list args)
{
  bool error= FALSE;
  Log_event_handler **current_handler;

  /* currently we don't need locking here as there is no error_log table */
  for (current_handler= error_log_handler_list ; *current_handler ;)
    error= (*current_handler++)->log_error(level, format, args) || error;

  return error;
}

/**
  Perform basic log initialization: create file-based log handler and
  init error log.
*/
void LOGGER::init_base()
{
  DBUG_ASSERT(inited == 0);
  inited= 1;

  /*
    Here we create file log handler. We don't do it for the table log handler
    here as it cannot be created so early. The reason is THD initialization,
    which depends on the system variables (parsed later).
  */
  if (!file_log_handler)
    file_log_handler= new Log_to_file_event_handler;

  /* by default we use traditional error log */
  init_error_log(LOG_FILE);

  file_log_handler->init_pthread_objects();
  mysql_rwlock_init(key_rwlock_LOCK_logger, &LOCK_logger);
}



/*
  Log slow query with all enabled log event handlers

  SYNOPSIS
    slow_log_print()

    thd                 THD of the query being logged
    query               The query being logged
    query_length        The length of the query string

  RETURN
    FALSE   OK
    TRUE    error occured
*/

// bool LOGGER::general_log_print(THD *thd, enum enum_server_command command,
//                                const char *format, va_list args)
// {
//   uint message_buff_len= 0;
//   char message_buff[MAX_LOG_BUFFER_SIZE];
//
//   /* prepare message */
//   if (format)
//     message_buff_len= my_vsnprintf(message_buff, sizeof(message_buff),
//                                    format, args);
//   else
//     message_buff[0]= '\0';
//
//   return general_log_write(thd, command, message_buff, message_buff_len);
// }

void LOGGER::init_error_log(uint error_log_printer)
{
	error_log_handler_list[0]= file_log_handler;
	error_log_handler_list[1]= 0;
}

/* the parameters are unused for the log tables */
bool Log_to_csv_event_handler::init()
{
  return 0;
}

#ifdef _WIN32
static int eventSource = 0;

static void setup_windows_event_source()
{
  HKEY    hRegKey= NULL;
  DWORD   dwError= 0;
  TCHAR   szPath[MAX_PATH];
  DWORD dwTypes;

  if (eventSource)               // Ensure that we are only called once
    return;
  eventSource= 1;

  // Create the event source registry key
  dwError= RegCreateKey(HKEY_LOCAL_MACHINE,
                          "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\MySQL",
                          &hRegKey);

  /* Name of the PE module that contains the message resource */
  GetModuleFileName(NULL, szPath, MAX_PATH);

  /* Register EventMessageFile */
  dwError = RegSetValueEx(hRegKey, "EventMessageFile", 0, REG_EXPAND_SZ,
                          (PBYTE) szPath, (DWORD) (strlen(szPath) + 1));

  /* Register supported event types */
  dwTypes= (EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE |
            EVENTLOG_INFORMATION_TYPE);
  dwError= RegSetValueEx(hRegKey, "TypesSupported", 0, REG_DWORD,
                         (LPBYTE) &dwTypes, sizeof dwTypes);

  RegCloseKey(hRegKey);
}

#endif /* _WIN32 */

/**
  Find a unique filename for 'filename.#'.

  Set '#' to the number next to the maximum found in the most
  recent log file extension.

  This function will return nonzero if: (i) the generated name
  exceeds FN_REFLEN; (ii) if the number of extensions is exhausted;
  or (iii) some other error happened while examining the filesystem.

  @return
    nonzero if not possible to get unique filename.
*/

static int find_uniq_filename(char *name)
{
  uint                  i;
  char                  buff[FN_REFLEN], ext_buf[FN_REFLEN];
  struct st_my_dir     *dir_info;
  reg1 struct fileinfo *file_info;
  ulong                 max_found= 0, next= 0, number= 0;
  size_t		buf_length, length;
  char			*start, *end;
  int                   error= 0;
  DBUG_ENTER("find_uniq_filename");

  length= dirname_part(buff, name, &buf_length);
  start=  name + length;
  end=    strend(start);

  *end='.';
  length= (size_t) (end - start + 1);

  if ((DBUG_EVALUATE_IF("error_unique_log_filename", 1,
      !(dir_info= my_dir(buff,MYF(MY_DONT_SORT))))))
  {						// This shouldn't happen
    strmov(end,".1");				// use name+1
    DBUG_RETURN(1);
  }
  file_info= dir_info->dir_entry;
  for (i= dir_info->number_off_files ; i-- ; file_info++)
  {
    if (memcmp(file_info->name, start, length) == 0 &&
	test_if_number(file_info->name+length, &number,0))
    {
      set_if_bigger(max_found,(ulong) number);
    }
  }
  my_dirend(dir_info);

  /* check if reached the maximum possible extension number */
  if (max_found == MAX_LOG_UNIQUE_FN_EXT)
  {
    sql_print_error("Log filename extension number exhausted: %06lu. \
Please fix this by archiving old logs and \
updating the index files.", max_found);
    error= 1;
    goto end;
  }

  next= max_found + 1;
  if (sprintf(ext_buf, "%06lu", next)<0)
  {
    error= 1;
    goto end;
  }
  *end++='.';

  /*
    Check if the generated extension size + the file name exceeds the
    buffer size used. If one did not check this, then the filename might be
    truncated, resulting in error.
   */
  if (((strlen(ext_buf) + (end - name)) >= FN_REFLEN))
  {
    sql_print_error("Log filename too large: %s%s (%zu). \
Please fix this by archiving old logs and updating the \
index files.", name, ext_buf, (strlen(ext_buf) + (end - name)));
    error= 1;
    goto end;
  }

  if (sprintf(end, "%06lu", next)<0)
  {
    error= 1;
    goto end;
  }

  /* print warning if reaching the end of available extensions. */
  if ((next > (MAX_LOG_UNIQUE_FN_EXT - LOG_WARN_UNIQUE_FN_EXT_LEFT)))
    sql_print_warning("Next log extension: %lu. \
Remaining log filename extensions: %lu. \
Please consider archiving some logs.", next, (MAX_LOG_UNIQUE_FN_EXT - next));

end:
  DBUG_RETURN(error);
}


void MYSQL_LOG::init(enum_log_type log_type_arg,
                     enum cache_type io_cache_type_arg)
{
  DBUG_ENTER("MYSQL_LOG::init");
  log_type= log_type_arg;
  io_cache_type= io_cache_type_arg;
  DBUG_PRINT("info",("log_type: %d", log_type));
  DBUG_VOID_RETURN;
}


bool MYSQL_LOG::init_and_set_log_file_name(const char *log_name,
                                           const char *new_name,
                                           enum_log_type log_type_arg,
                                           enum cache_type io_cache_type_arg)
{
  init(log_type_arg, io_cache_type_arg);

  if (new_name && !strmov(log_file_name, new_name))
    return TRUE;
  else if (!new_name && generate_new_name(log_file_name, log_name))
    return TRUE;

  return FALSE;
}


/*
  Open a (new) log file.

  SYNOPSIS
    open()

    log_name            The name of the log to open
    log_type_arg        The type of the log. E.g. LOG_NORMAL
    new_name            The new name for the logfile. This is only needed
                        when the method is used to open the binlog file.
    io_cache_type_arg   The type of the IO_CACHE to use for this log file

  DESCRIPTION
    Open the logfile, init IO_CACHE and write startup messages
    (in case of general and slow query logs).

  RETURN VALUES
    0   ok
    1   error
*/

bool MYSQL_LOG::open(
#ifdef HAVE_PSI_INTERFACE
                     PSI_file_key log_file_key,
#endif
                     const char *log_name, enum_log_type log_type_arg,
                     const char *new_name, enum cache_type io_cache_type_arg)
{
  char buff[FN_REFLEN];
  File file= -1;
  my_off_t pos= 0;
  int open_flags= O_CREAT | O_BINARY;
  DBUG_ENTER("MYSQL_LOG::open");
  DBUG_PRINT("enter", ("log_type: %d", (int) log_type_arg));

  write_error= 0;

  if (!(name= my_strdup(log_name, MYF(MY_WME))))
  {
    name= (char *)log_name; // for the error message
    goto err;
  }

  if (init_and_set_log_file_name(name, new_name,
                                 log_type_arg, io_cache_type_arg))
    goto err;

  if (io_cache_type == SEQ_READ_APPEND)
    open_flags |= O_RDWR | O_APPEND;
  else
    open_flags |= O_WRONLY | (log_type == LOG_BIN ? 0 : O_APPEND);

  db[0]= 0;

#ifdef HAVE_PSI_INTERFACE
  /* Keep the key for reopen */
  m_log_file_key= log_file_key;
#endif

  if ((file= mysql_file_open(log_file_key,
                             log_file_name, open_flags,
                             MYF(MY_WME | ME_WAITTANG))) < 0)
    goto err;

  if ((pos= mysql_file_tell(file, MYF(MY_WME))) == MY_FILEPOS_ERROR)
  {
    if (my_errno == ESPIPE)
      pos= 0;
    else
      goto err;
  }

  if (init_io_cache(&log_file, file, IO_SIZE, io_cache_type, pos, 0,
                    MYF(MY_WME | MY_NABP |
                        ((log_type == LOG_BIN) ? MY_WAIT_IF_FULL : 0))))
    goto err;

  if (log_type == LOG_NORMAL)
  {
    char *end;
    int len=my_snprintf(buff, sizeof(buff), "%s, Version: %s (%s). "
#ifdef EMBEDDED_LIBRARY
                        "embedded library\n",
                        my_progname, server_version, MYSQL_COMPILATION_COMMENT
#elif _WIN32
			"started with:\nTCP Port: %d, Named Pipe: %s\n",
                        my_progname, server_version, MYSQL_COMPILATION_COMMENT,
                        mysqld_port, mysqld_unix_port
#else
			"started with:\nTcp port: %d  Unix socket: %s\n",
                        my_progname, server_version, MYSQL_COMPILATION_COMMENT,
                        mysqld_port, mysqld_unix_port
#endif
                       );
    end= strnmov(buff + len, "Time                 Id Command    Argument\n",
                 sizeof(buff) - len);
    if (my_b_write(&log_file, (uchar*) buff, (uint) (end-buff)) ||
	flush_io_cache(&log_file))
      goto err;
  }

  log_state= LOG_OPENED;
  DBUG_RETURN(0);

err:
  sql_print_error("Could not use %s for logging (error %d). \
Turning logging off for the whole duration of the MySQL server process. \
To turn it on again: fix the cause, \
shutdown the MySQL server and restart it.", name, errno);
  if (file >= 0)
    mysql_file_close(file, MYF(0));
  end_io_cache(&log_file);
  my_free(name);
  name= NULL;
  log_state= LOG_CLOSED;
  DBUG_RETURN(1);
}

MYSQL_LOG::MYSQL_LOG()
  : name(0), write_error(FALSE), inited(FALSE), log_type(LOG_UNKNOWN),
    log_state(LOG_CLOSED)
#ifdef HAVE_PSI_INTERFACE
  , m_key_LOCK_log(key_LOG_LOCK_log)
#endif
{
  /*
    We don't want to initialize LOCK_Log here as such initialization depends on
    safe_mutex (when using safe_mutex) which depends on MY_INIT(), which is
    called only in main(). Doing initialization here would make it happen
    before main().
  */
  memset(&log_file, 0, sizeof(log_file));
}

void MYSQL_LOG::init_pthread_objects()
{
  DBUG_ASSERT(inited == 0);
  inited= 1;
  mysql_mutex_init(m_key_LOCK_log, &LOCK_log, MY_MUTEX_INIT_SLOW);
}

/*
  Close the log file

  SYNOPSIS
    close()
    exiting     Bitmask. For the slow and general logs the only used bit is
                LOG_CLOSE_TO_BE_OPENED. This is used if we intend to call
                open at once after close.

  NOTES
    One can do an open on the object at once after doing a close.
    The internal structures are not freed until cleanup() is called
*/

void MYSQL_LOG::close(uint exiting)
{					// One can't set log_type here!
  DBUG_ENTER("MYSQL_LOG::close");
  DBUG_PRINT("enter",("exiting: %d", (int) exiting));
  if (log_state == LOG_OPENED)
  {
    end_io_cache(&log_file);

    if (mysql_file_sync(log_file.file, MYF(MY_WME)) && ! write_error)
    {
      char errbuf[MYSYS_STRERROR_SIZE];
      write_error= 1;
      sql_print_error(ER_DEFAULT(ER_ERROR_ON_WRITE), name, errno,
                      my_strerror(errbuf, sizeof(errbuf), errno));
    }

    if (mysql_file_close(log_file.file, MYF(MY_WME)) && ! write_error)
    {
      char errbuf[MYSYS_STRERROR_SIZE];
      write_error= 1;
      sql_print_error(ER_DEFAULT(ER_ERROR_ON_WRITE), name, errno,
                      my_strerror(errbuf, sizeof(errbuf), errno));
    }
  }

  log_state= (exiting & LOG_CLOSE_TO_BE_OPENED) ? LOG_TO_BE_OPENED : LOG_CLOSED;
  my_free(name);
  name= NULL;
  DBUG_VOID_RETURN;
}

/** This is called only once. */

void MYSQL_LOG::cleanup()
{
  DBUG_ENTER("cleanup");
  if (inited)
  {
    inited= 0;
    mysql_mutex_destroy(&LOCK_log);
    close(0);
  }
  DBUG_VOID_RETURN;
}


int MYSQL_LOG::generate_new_name(char *new_name, const char *log_name)
{
  fn_format(new_name, log_name, mysql_data_home, "", 4);
  if (log_type == LOG_BIN)
  {
    if (!fn_ext(log_name)[0])
    {
      if (find_uniq_filename(new_name))
      {
        my_printf_error(ER_NO_UNIQUE_LOGFILE, ER(ER_NO_UNIQUE_LOGFILE),
                        MYF(ME_FATALERROR), log_name);
	sql_print_error(ER(ER_NO_UNIQUE_LOGFILE), log_name);
	return 1;
      }
    }
  }
  return 0;
}


/*
  Reopen the log file

  SYNOPSIS
    reopen_file()

  DESCRIPTION
    Reopen the log file. The method is used during FLUSH LOGS
    and locks LOCK_log mutex
*/


void MYSQL_QUERY_LOG::reopen_file()
{
  char *save_name;

  DBUG_ENTER("MYSQL_LOG::reopen_file");
  if (!is_open())
  {
    DBUG_PRINT("info",("log is closed"));
    DBUG_VOID_RETURN;
  }

  mysql_mutex_lock(&LOCK_log);

  save_name= name;
  name= 0;				// Don't free name
  close(LOG_CLOSE_TO_BE_OPENED);

  /*
     Note that at this point, log_state != LOG_CLOSED (important for is_open()).
  */

  open(
#ifdef HAVE_PSI_INTERFACE
       m_log_file_key,
#endif
       save_name, log_type, 0, io_cache_type);
  my_free(save_name);

  mysql_mutex_unlock(&LOCK_log);

  DBUG_VOID_RETURN;
}


/*
  Write a command to traditional general log file

  SYNOPSIS
    write()

    event_time        command start timestamp
    user_host         the pointer to the string with user@host info
    user_host_len     length of the user_host string. this is computed once
                      and passed to all general log  event handlers
    thread_id         Id of the thread, issued a query
    command_type      the type of the command being logged
    command_type_len  the length of the string above
    sql_text          the very text of the query being executed
    sql_text_len      the length of sql_text string

  DESCRIPTION

   Log given command to to normal (not rotable) log file

  RETURN
    FASE - OK
    TRUE - error occured
*/

bool MYSQL_QUERY_LOG::write(time_t event_time, const char *user_host,
                            uint user_host_len, my_thread_id thread_id,
                            const char *command_type, uint command_type_len,
                            const char *sql_text, uint sql_text_len)
{
  char buff[32];
  uint length= 0;
  char local_time_buff[MAX_TIME_SIZE];
  struct tm start;
  uint time_buff_len= 0;

  mysql_mutex_lock(&LOCK_log);

  /* Test if someone closed between the is_open test and lock */
  if (is_open())
  {
    /* for testing output of timestamp and thread id */
    DBUG_EXECUTE_IF("reset_log_last_time", last_time= 0;);

    /* Note that my_b_write() assumes it knows the length for this */
      if (event_time != last_time)
      {
        last_time= event_time;

        localtime_r(&event_time, &start);

        time_buff_len= my_snprintf(local_time_buff, MAX_TIME_SIZE,
                                   "%02d%02d%02d %2d:%02d:%02d\t",
                                   start.tm_year % 100, start.tm_mon + 1,
                                   start.tm_mday, start.tm_hour,
                                   start.tm_min, start.tm_sec);

        if (my_b_write(&log_file, (uchar*) local_time_buff, time_buff_len))
          goto err;
      }
      else
        if (my_b_write(&log_file, (uchar*) "\t\t" ,2) < 0)
          goto err;

    length= my_snprintf(buff, 32, "%5lu ", thread_id);

    if (my_b_write(&log_file, (uchar*) buff, length))
      goto err;

    if (my_b_write(&log_file, (uchar*) command_type, command_type_len))
      goto err;

    if (my_b_write(&log_file, (uchar*) "\t", 1))
      goto err;

    /* sql_text */
    if (my_b_write(&log_file, (uchar*) sql_text, sql_text_len))
      goto err;

    if (my_b_write(&log_file, (uchar*) "\n\n", 2) ||
        flush_io_cache(&log_file))
      goto err;
  }

  mysql_mutex_unlock(&LOCK_log);
  return FALSE;
err:

  if (!write_error)
  {
    char errbuf[MYSYS_STRERROR_SIZE];
    write_error= 1;
    sql_print_error(ER(ER_ERROR_ON_WRITE), name, errno,
                    my_strerror(errbuf, sizeof(errbuf), errno));
  }
  mysql_mutex_unlock(&LOCK_log);
  return TRUE;
}


/*
  Log a query to the traditional slow log file

  SYNOPSIS
    write()

    thd               THD of the query
    current_time      current timestamp
    query_start_arg   command start timestamp
    user_host         the pointer to the string with user@host info
    user_host_len     length of the user_host string. this is computed once
                      and passed to all general log event handlers
    query_utime       Amount of time the query took to execute (in microseconds)
    lock_utime        Amount of time the query was locked (in microseconds)
    is_command        The flag, which determines, whether the sql_text is a
                      query or an administrator command.
    sql_text          the very text of the query or administrator command
                      processed
    sql_text_len      the length of sql_text string

  DESCRIPTION

   Log a query to the slow log file.

  RETURN
    FALSE - OK
    TRUE - error occured
*/

bool MYSQL_QUERY_LOG::write(THD *thd, time_t current_time,
                            time_t query_start_arg, const char *user_host,
                            uint user_host_len, ulonglong query_utime,
                            ulonglong lock_utime, bool is_command,
                            const char *sql_text, uint sql_text_len)
{
  bool error= 0;
  DBUG_ENTER("MYSQL_QUERY_LOG::write");

  mysql_mutex_lock(&LOCK_log);

  if (!is_open())
  {
    mysql_mutex_unlock(&LOCK_log);
    DBUG_RETURN(0);
  }

  if (is_open())
  {						// Safety agains reopen
    int tmp_errno= 0;
    char buff[80], *end;
    char query_time_buff[22+7], lock_time_buff[22+7];
    uint buff_len;
    end= buff;

    if (!(specialflag & SPECIAL_SHORT_LOG_FORMAT))
    {
      if (current_time != last_time)
      {
        last_time= current_time;
        struct tm start;
        localtime_r(&current_time, &start);

        buff_len= my_snprintf(buff, sizeof buff,
                              "# Time: %02d%02d%02d %2d:%02d:%02d\n",
                              start.tm_year % 100, start.tm_mon + 1,
                              start.tm_mday, start.tm_hour,
                              start.tm_min, start.tm_sec);

        /* Note that my_b_write() assumes it knows the length for this */
        if (my_b_write(&log_file, (uchar*) buff, buff_len))
          tmp_errno= errno;
      }
      buff_len= my_snprintf(buff, 32, "%5lu", thd->thread_id);
      if (my_b_printf(&log_file, "# User@Host: %s  Id: %s\n", user_host, buff)
          == (uint) -1)
        tmp_errno= errno;
    }
    /* For slow query log */
    sprintf(query_time_buff, "%.6f", ulonglong2double(query_utime)/1000000.0);
    sprintf(lock_time_buff,  "%.6f", ulonglong2double(lock_utime)/1000000.0);
    if (my_b_printf(&log_file,
                    "# Query_time: %s  Lock_time: %s"
                    " Rows_sent: %lu  Rows_examined: %lu\n",
                    query_time_buff, lock_time_buff,
                    (ulong) thd->get_sent_row_count(),
                    (ulong) thd->get_examined_row_count()) == (uint) -1)
      tmp_errno= errno;
    if (thd->db && strcmp(thd->db, db))
    {						// Database changed
      if (my_b_printf(&log_file,"use %s;\n",thd->db) == (uint) -1)
        tmp_errno= errno;
      strmov(db,thd->db);
    }
    if (thd->stmt_depends_on_first_successful_insert_id_in_prev_stmt)
    {
      end=strmov(end, ",last_insert_id=");
      end=longlong10_to_str((longlong)
                            thd->first_successful_insert_id_in_prev_stmt_for_binlog,
                            end, -10);
    }
    // Save value if we do an insert.
    if (thd->auto_inc_intervals_in_cur_stmt_for_binlog.nb_elements() > 0)
    {
      if (!(specialflag & SPECIAL_SHORT_LOG_FORMAT))
      {
        end=strmov(end,",insert_id=");
        end=longlong10_to_str((longlong)
                              thd->auto_inc_intervals_in_cur_stmt_for_binlog.minimum(),
                              end, -10);
      }
    }

    /*
      This info used to show up randomly, depending on whether the query
      checked the query start time or not. now we always write current
      timestamp to the slow log
    */
    end= strmov(end, ",timestamp=");
    end= int10_to_str((long) current_time, end, 10);

    if (end != buff)
    {
      *end++=';';
      *end='\n';
      if (my_b_write(&log_file, (uchar*) "SET ", 4) ||
          my_b_write(&log_file, (uchar*) buff + 1, (uint) (end-buff)))
        tmp_errno= errno;
    }
    if (is_command)
    {
      end= strxmov(buff, "# administrator command: ", NullS);
      buff_len= (ulong) (end - buff);
      DBUG_EXECUTE_IF("simulate_slow_log_write_error",
                      {DBUG_SET("+d,simulate_file_write_error");});
      if(my_b_write(&log_file, (uchar*) buff, buff_len))
        tmp_errno= errno;
    }
    if (my_b_write(&log_file, (uchar*) sql_text, sql_text_len) ||
        my_b_write(&log_file, (uchar*) ";\n",2) ||
        flush_io_cache(&log_file))
      tmp_errno= errno;
    if (tmp_errno)
    {
      error= 1;
      if (! write_error)
      {
        char errbuf[MYSYS_STRERROR_SIZE];
        write_error= 1;
        sql_print_error(ER(ER_ERROR_ON_WRITE), name, error,
                        my_strerror(errbuf, sizeof(errbuf), errno));
      }
    }
  }
  mysql_mutex_unlock(&LOCK_log);
  DBUG_RETURN(error);
}


/**
  @todo
  The following should be using fn_format();  We just need to
  first change fn_format() to cut the file name if it's too long.
*/
const char *MYSQL_LOG::generate_name(const char *log_name,
                                      const char *suffix,
                                      bool strip_ext, char *buff)
{
  if (!log_name || !log_name[0])
  {
    strmake(buff, pidfile_name, FN_REFLEN - strlen(suffix) - 1);
    return (const char *)
      fn_format(buff, buff, "", suffix, MYF(MY_REPLACE_EXT|MY_REPLACE_DIR));
  }
  // get rid of extension if the log is binary to avoid problems
  if (strip_ext)
  {
    char *p= fn_ext(log_name);
    uint length= (uint) (p - log_name);
    strmake(buff, log_name, min<size_t>(length, FN_REFLEN-1));
    return (const char*)buff;
  }
  return log_name;
}


int error_log_print(enum loglevel level, const char *format,
                    va_list args)
{
  return logger.error_log_print(level, format, args);
}

bool general_log_print(THD *thd, enum enum_server_command command,
                       const char *format, ...)
{
  va_list args;
  uint error= 0;

//   /* Print the message to the buffer if we want to log this king of commands */
//   if (! logger.log_command(thd, command))
//     return FALSE;

//   va_start(args, format);
//   error= logger.general_log_print(thd, command, format, args);
//   va_end(args);

  return error;
}

void LOGGER::init_log_tables()
{
    if (!table_log_handler)
        table_log_handler= new Log_to_csv_event_handler;

    if (!is_log_tables_initialized &&
        !table_log_handler->init() && !file_log_handler->init())
        is_log_tables_initialized= TRUE;
}

void LOGGER::init_general_log(uint general_log_printer)
{
    if (general_log_printer & LOG_NONE)
    {
        general_log_handler_list[0]= 0;
        return;
    }

    switch (general_log_printer) {
    case LOG_FILE:
        general_log_handler_list[0]= file_log_handler;
        general_log_handler_list[1]= 0;
        break;
    case LOG_TABLE:
        general_log_handler_list[0]= table_log_handler;
        general_log_handler_list[1]= 0;
        break;
    case LOG_TABLE|LOG_FILE:
        general_log_handler_list[0]= file_log_handler;
        general_log_handler_list[1]= table_log_handler;
        general_log_handler_list[2]= 0;
        break;
    }
}

int LOGGER::set_handlers(uint error_log_printer,
    uint slow_log_printer,
    uint general_log_printer)
{
    /* error log table is not supported yet */
    DBUG_ASSERT(error_log_printer < LOG_TABLE);

    init_log_tables();

    lock_exclusive();

    init_error_log(error_log_printer);
    init_general_log(general_log_printer);

    unlock();

    return 0;
}

bool LOGGER::general_log_write(THD *thd, enum enum_server_command command,
    const char *query, uint query_length)
{
    bool error= FALSE;
    Log_event_handler **current_handler= general_log_handler_list;
    char user_host_buff[MAX_USER_HOST_SIZE + 1];
    uint user_host_len= 0;
    time_t current_time;

    DBUG_ASSERT(thd);

    //begin及commit不会写日志
    if (thd->lex->sql_command == SQLCOM_INCEPTION_START ||
        thd->lex->sql_command == SQLCOM_INCEPTION_COMMIT)
        return false;

    lock_shared();
    if (!opt_log)
    {
        unlock();
        return 0;
    }
    user_host_len= make_user_name(thd, user_host_buff);

    current_time= my_time(0);

    while (*current_handler)
        error|= (*current_handler++)->
        log_general(thd, current_time, user_host_buff,
        user_host_len, thd->thread_id,
        command_name[(uint) command].str,
        command_name[(uint) command].length,
        query, query_length,
        //sql_with_charset.ptr(), sql_with_charset.length(),
        //thd->variables.character_set_client
        thd->query_charset()) || error;
    unlock();

    return error;
}

bool general_log_write(THD *thd, enum enum_server_command command,
                       const char *query, uint query_length)
{
  /* Write the message to the log if we want to log this king of commands */
    return logger.general_log_write(thd, command, query, query_length);

  return FALSE;
}

/**
  Check if a string is a valid number.

  @param str			String to test
  @param res			Store value here
  @param allow_wildcards	Set to 1 if we should ignore '%' and '_'

  @note
    For the moment the allow_wildcards argument is not used
    Should be move to some other file.

  @retval
    1	String is a number
  @retval
    0	String is not a number
*/

static bool test_if_number(register const char *str,
			   ulong *res, bool allow_wildcards)
{
  reg2 int flag;
  const char *start;
  DBUG_ENTER("test_if_number");

  flag=0; start=str;
  while (*str++ == ' ') ;
  if (*--str == '-' || *str == '+')
    str++;
  while (my_isdigit(files_charset_info,*str) ||
	 (allow_wildcards && (*str == wild_many || *str == wild_one)))
  {
    flag=1;
    str++;
  }
  if (*str == '.')
  {
    for (str++ ;
	 my_isdigit(files_charset_info,*str) ||
	   (allow_wildcards && (*str == wild_many || *str == wild_one)) ;
	 str++, flag=1) ;
  }
  if (*str != 0 || flag == 0)
    DBUG_RETURN(0);
  if (res)
    *res=atol(start);
  DBUG_RETURN(1);			/* Number ok */
} /* test_if_number */


void sql_perror(const char *message)
{
#ifdef HAVE_STRERROR
  sql_print_error("%s: %s",message, strerror(errno));
#else
  perror(message);
#endif
}


/*
  Change the file associated with two output streams. Used to
  redirect stdout and stderr to a file. The streams are reopened
  only for appending (writing at end of file).
*/
extern "C" my_bool reopen_fstreams(const char *filename,
                                   FILE *outstream, FILE *errstream)
{
  if (outstream && !my_freopen(filename, "a", outstream))
    return TRUE;

  if (errstream && !my_freopen(filename, "a", errstream))
    return TRUE;

  /* The error stream must be unbuffered. */
  if (errstream)
    setbuf(errstream, NULL);

  return FALSE;
}


/*
  Unfortunately, there seems to be no good way
  to restore the original streams upon failure.
*/
static bool redirect_std_streams(const char *file)
{
  if (reopen_fstreams(file, stdout, stderr))
    return TRUE;

  setbuf(stderr, NULL);
  return FALSE;
}


#ifdef _WIN32
static void print_buffer_to_nt_eventlog(enum loglevel level, char *buff,
                                        size_t length, size_t buffLen)
{
  HANDLE event;
  char   *buffptr= buff;
  DBUG_ENTER("print_buffer_to_nt_eventlog");

  /* Add ending CR/LF's to string, overwrite last chars if necessary */
  strmov(buffptr+min(length, buffLen-5), "\r\n\r\n");

  setup_windows_event_source();
  if ((event= RegisterEventSource(NULL,"MySQL")))
  {
    switch (level) {
      case ERROR_LEVEL:
        ReportEvent(event, EVENTLOG_ERROR_TYPE, 0, MSG_DEFAULT, NULL, 1, 0,
                    (LPCSTR*)&buffptr, NULL);
        break;
      case WARNING_LEVEL:
        ReportEvent(event, EVENTLOG_WARNING_TYPE, 0, MSG_DEFAULT, NULL, 1, 0,
                    (LPCSTR*) &buffptr, NULL);
        break;
      case INFORMATION_LEVEL:
        ReportEvent(event, EVENTLOG_INFORMATION_TYPE, 0, MSG_DEFAULT, NULL, 1,
                    0, (LPCSTR*) &buffptr, NULL);
        break;
    }
    DeregisterEventSource(event);
  }

  DBUG_VOID_RETURN;
}
#endif /* _WIN32 */


#ifndef EMBEDDED_LIBRARY
static void print_buffer_to_file(enum loglevel level, const char *buffer,
                                 size_t length)
{
  time_t skr;
  struct tm tm_tmp;
  struct tm *start;
  DBUG_ENTER("print_buffer_to_file");
  DBUG_PRINT("enter",("buffer: %s", buffer));

  mysql_mutex_lock(&LOCK_error_log);

  skr= my_time(0);
  localtime_r(&skr, &tm_tmp);
  start=&tm_tmp;

  fprintf(stderr, "%d-%02d-%02d %02d:%02d:%02d %lu [%s] %.*s\n",
          start->tm_year + 1900,
          start->tm_mon + 1,
          start->tm_mday,
          start->tm_hour,
          start->tm_min,
          start->tm_sec,
          current_pid,
          (level == ERROR_LEVEL ? "ERROR" : level == WARNING_LEVEL ?
           "Warning" : "Note"),
          (int) length, buffer);

  fflush(stderr);

  mysql_mutex_unlock(&LOCK_error_log);
  DBUG_VOID_RETURN;
}

/**
  Prints a printf style message to the error log and, under NT, to the
  Windows event log.

  This function prints the message into a buffer and then sends that buffer
  to other functions to write that message to other logging sources.

  @param level          The level of the msg significance
  @param format         Printf style format of message
  @param args           va_list list of arguments for the message

  @returns
    The function always returns 0. The return value is present in the
    signature to be compatible with other logging routines, which could
    return an error (e.g. logging to the log tables)
*/
int vprint_msg_to_log(enum loglevel level, const char *format, va_list args)
{
  char   buff[1024];
  size_t length;
  DBUG_ENTER("vprint_msg_to_log");

  length= my_vsnprintf(buff, sizeof(buff), format, args);
  print_buffer_to_file(level, buff, length);

#ifdef _WIN32
  print_buffer_to_nt_eventlog(level, buff, length, sizeof(buff));
#endif

  DBUG_RETURN(0);
}
#endif /* EMBEDDED_LIBRARY */


void sql_print_error(const char *format, ...)
{
  va_list args;
  DBUG_ENTER("sql_print_error");

  va_start(args, format);
  error_log_print(ERROR_LEVEL, format, args);
  va_end(args);

  DBUG_VOID_RETURN;
}


void sql_print_warning(const char *format, ...)
{
  va_list args;
  DBUG_ENTER("sql_print_warning");

  va_start(args, format);
  error_log_print(WARNING_LEVEL, format, args);
  va_end(args);

  DBUG_VOID_RETURN;
}


void sql_print_information(const char *format, ...)
{
  va_list args;
  DBUG_ENTER("sql_print_information");

  va_start(args, format);
  error_log_print(INFORMATION_LEVEL, format, args);
  va_end(args);

  DBUG_VOID_RETURN;
}


extern "C"
int my_plugin_log_message(MYSQL_PLUGIN *plugin_ptr, plugin_log_level level,
                          const char *format, ...)
{
  char format2[MYSQL_ERRMSG_SIZE];
  int ret;
  loglevel lvl;
  struct st_plugin_int *plugin = static_cast<st_plugin_int *> (*plugin_ptr);
  va_list args;

  DBUG_ASSERT(level >= MY_ERROR_LEVEL || level <= MY_INFORMATION_LEVEL);

  switch (level)
  {
  case MY_ERROR_LEVEL:       lvl= ERROR_LEVEL; break;
  case MY_WARNING_LEVEL:     lvl= WARNING_LEVEL; break;
  case MY_INFORMATION_LEVEL: lvl= INFORMATION_LEVEL; break;
  default:                   return 1;
  }

  va_start(args, format);
  snprintf(format2, sizeof (format2) - 1, "Plugin %.*s reported: '%s'",
           (int) plugin->name.length, plugin->name.str, format);
  ret= error_log_print(lvl, format2, args);
  va_end(args);
  return ret;
}



/**
  Perform heuristic recovery, if --tc-heuristic-recover was used.

  @note
    no matter whether heuristic recovery was successful or not
    mysqld must exit. So, return value is the same in both cases.

  @retval
    0	no heuristic recovery was requested
  @retval
    1   heuristic recovery was performed
*/

