/* Copyright (c) 2010, 2012, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#ifndef MYSQLD_INCLUDED
#define MYSQLD_INCLUDED

#include "my_global.h" /* MYSQL_PLUGIN_IMPORT, FN_REFLEN, FN_EXTLEN */
#include "sql_bitmap.h"                         /* Bitmap */
#include "my_decimal.h"                         /* my_decimal */
#include "mysql_com.h"                     /* SERVER_VERSION_LENGTH */
#include "my_atomic.h"                     /* my_atomic_rwlock_t */
#include "mysql/psi/mysql_file.h"          /* MYSQL_FILE */
#include "sql_list.h"                      /* I_List */
#include "sql_cmd.h"                       /* SQLCOM_END */
#include "sql_const.h"
#include "my_list.h"

class THD;
struct handlerton;
class Time_zone;

struct scheduler_functions;

typedef struct st_mysql_const_lex_string LEX_CSTRING;
typedef struct st_mysql_show_var SHOW_VAR;

/*
  This forward declaration is used from C files where the real
  definition is included before.  Since C does not allow repeated
  typedef declarations, even when identical, the definition may not be
  repeated.
*/
#ifndef CHARSET_INFO_DEFINED
typedef struct charset_info_st CHARSET_INFO;
#endif  /* CHARSET_INFO_DEFINED */

#if MAX_INDEXES <= 64
typedef Bitmap<64>  key_map;          /* Used for finding keys */
#else
typedef Bitmap<((MAX_INDEXES+7)/8*8)> key_map; /* Used for finding keys */
#endif

	/* Bits from testflag */
#define TEST_PRINT_CACHED_TABLES 1
#define TEST_NO_KEY_GROUP	 2
#define TEST_MIT_THREAD		4
#define TEST_BLOCKING		8
#define TEST_KEEP_TMP_TABLES	16
#define TEST_READCHECK		64	/**< Force use of readcheck */
#define TEST_NO_EXTRA		128
#define TEST_CORE_ON_SIGNAL	256	/**< Give core if signal */
#define TEST_NO_STACKTRACE	512
#define TEST_SIGINT		1024	/**< Allow sigint on threads */
#define TEST_SYNCHRONIZATION    2048    /**< get server to do sleep in
                                           some places */
/* Function prototypes */
void kill_mysql(void);
void close_connection(THD *thd, uint sql_errno= 0);
void handle_connection_in_main_thread(THD *thd);
void create_thread_to_handle_connection(THD *thd);
void destroy_thd(THD *thd);
bool one_thread_per_connection_end(THD *thd, bool block_pthread);
void kill_blocked_pthreads();
void refresh_status(THD *thd);
bool is_secure_file_path(char *path);
void dec_connection_count();

// These are needed for unit testing.
void set_remaining_args(int argc, char **argv);
int init_common_variables();
void my_init_signals();
bool gtid_server_init();
void gtid_server_cleanup();

extern "C" MYSQL_PLUGIN_IMPORT CHARSET_INFO *system_charset_info;
extern MYSQL_PLUGIN_IMPORT CHARSET_INFO *files_charset_info ;
extern MYSQL_PLUGIN_IMPORT CHARSET_INFO *national_charset_info;
extern MYSQL_PLUGIN_IMPORT CHARSET_INFO *table_alias_charset;

/**
  Character set of the buildin error messages loaded from errmsg.sys.
*/
extern CHARSET_INFO *error_message_charset_info;

extern CHARSET_INFO *character_set_filesystem;

extern MY_BITMAP temp_pool;
extern bool opt_large_files, server_id_supplied;
extern bool opt_update_log, opt_bin_log, opt_error_log;
extern my_bool opt_log, opt_slow_log, opt_log_raw;
extern my_bool opt_backup_history_log;
extern my_bool opt_backup_progress_log;
extern ulonglong log_output_options;
extern ulong log_backup_output_options;
extern my_bool opt_log_queries_not_using_indexes;
extern ulong opt_log_throttle_queries_not_using_indexes;
extern bool opt_disable_networking, opt_skip_show_db;
extern bool opt_skip_name_resolve;
extern bool opt_ignore_builtin_innodb;
extern my_bool opt_character_set_client_handshake;
extern bool volatile abort_loop;
extern bool in_bootstrap;
extern my_bool opt_bootstrap;
extern uint connection_count;
extern my_bool opt_safe_user_create;
extern my_bool opt_safe_show_db, opt_local_infile, opt_myisam_use_mmap;
extern my_bool opt_slave_compressed_protocol, use_temp_pool;
extern ulong slave_exec_mode_options;
extern ulonglong slave_type_conversions_options;
extern my_bool read_only, opt_readonly;
extern ulonglong slave_rows_search_algorithms_options;
#ifndef DBUG_OFF
extern uint slave_rows_last_search_algorithm_used;
#endif
#ifndef EMBEDDED_LIBRARY
extern "C" int check_enough_stack_size(int);
#endif
extern my_bool opt_enable_named_pipe, opt_sync_frm, opt_allow_suspicious_udfs;
extern my_bool opt_secure_auth;
extern char* opt_secure_file_priv;
extern char* opt_secure_backup_file_priv;
extern size_t opt_secure_backup_file_priv_len;
extern my_bool opt_log_slow_admin_statements, opt_log_slow_slave_statements;
extern my_bool sp_automatic_privileges, opt_noacl;
extern my_bool opt_old_style_user_limits, trust_function_creators;
extern uint opt_crash_binlog_innodb;
extern char *mysqld_unix_port;
extern char *default_tz_name;
extern Time_zone *default_tz;
extern char *default_storage_engine;
extern char *default_tmp_storage_engine;
extern bool opt_endinfo, using_udf_functions;
extern my_bool locked_in_memory;
extern bool opt_using_transactions;
extern ulong max_long_data_size;
extern ulong current_pid;
extern ulong expire_logs_days;
extern char *remote_backup_host;
extern char* inception_user;
extern char* inception_password;
extern char *remote_system_user;
extern char *remote_system_password;
extern bool inception_check_insert_field;
extern bool inception_check_dml_where;
extern bool inception_check_dml_limit;
extern bool inception_check_dml_orderby;
extern bool inception_enable_select_star;
extern bool inception_enable_orderby_rand;
extern bool inception_enable_nullable;
extern bool inception_enable_foreign_key;
extern ulong inception_max_key_parts;
extern ulong inception_max_update_rows;
extern ulong inception_max_keys;
extern bool inception_enable_not_innodb;
extern char* inception_support_charset;
extern bool inception_check_table_comment;
extern bool inception_check_column_comment;
extern bool inception_check_primary_key;
extern bool inception_enable_partition_table;
extern bool inception_enable_blob_type;
extern bool inception_enable_enum_set_bit;
extern bool inception_check_index_prefix;
extern bool inception_enable_autoincrement_unsigned;
extern ulong inception_max_char_length;
extern bool inception_check_autoincrement_init_value;
extern bool inception_check_autoincrement_datatype;
extern bool inception_check_timestamp_default;
extern bool inception_enable_column_charset;
extern bool inception_check_autoincrement_name;
extern bool inception_merge_alter_table;
extern bool inception_check_column_default_value;
extern bool inception_enable_identifer_keyword;
extern bool inception_enable_sql_statistic;
extern char* inception_osc_bin_dir;
extern bool inception_osc_print_sql;
extern bool inception_osc_print_none;
extern bool inception_read_only;
extern bool inception_check_identifier;
extern bool inception_ddl_support;
extern bool inception_osc_on;
extern char* inception_datacenter_host;
extern int inception_datacenter_port;
extern char* inception_datacenter_user;
extern char* inception_datacenter_password;
extern ulong inception_transfer_trx_sequence_sync;
extern ulong inception_transfer_event_sequence_sync;
extern ulong inception_transfer_binlog_expire_days;
extern ulong inception_transfer_slave_sync;
// extern ulong inception_osc_critical_connected;
// extern ulong inception_osc_critical_running;
// extern ulong inception_osc_max_connected;
// extern ulong inception_osc_max_running;
// extern double inception_osc_chunk_time;
// extern double inception_osc_check_interval;
// extern double inception_osc_max_lag;
// extern ulong inception_osc_chunk_size;
// extern double inception_osc_chunk_size_limit;
// extern bool inception_osc_drop_new_table;
// extern bool inception_osc_drop_old_table;

extern uint remote_backup_port;
extern my_bool relay_log_recovery;
extern uint sync_binlog_period, sync_relaylog_period, 
            sync_relayloginfo_period, sync_masterinfo_period,
            opt_mts_checkpoint_period, opt_mts_checkpoint_group;
extern ulong opt_tc_log_size, tc_log_max_pages_used, tc_log_page_size;
extern ulong tc_log_page_waits;
extern my_bool relay_log_purge, opt_innodb_safe_binlog, opt_innodb;
extern my_bool relay_log_recovery;
extern uint test_flags,select_errors,ha_open_options;
extern uint protocol_version, mysqld_port, dropping_tables;
extern ulong delay_key_write_options;
extern char *opt_logname, *opt_bin_logname, 
            *opt_relay_logname;
extern char *opt_backup_history_logname, *opt_backup_progress_logname,
            *opt_backup_settings_name;
extern const char *log_output_str;
extern const char *log_backup_output_str;
extern char *mysql_home_ptr, *pidfile_name_ptr;
extern char *my_bind_addr_str;
extern char mysql_home[FN_REFLEN];
extern char pidfile_name[FN_REFLEN], *opt_init_file;
extern char default_logfile_name[FN_REFLEN];
extern char *opt_tc_log_file;
/*Move UUID_LENGTH from item_strfunc.h*/
#define UUID_LENGTH (8+1+4+1+4+1+4+1+12)
extern char server_uuid[UUID_LENGTH+1];
extern const char *server_uuid_ptr;
extern const double log_10[309];
extern ulonglong keybuff_size;
extern ulonglong thd_startup_options;
extern ulong thread_id;
extern ulong binlog_cache_use, binlog_cache_disk_use;
extern ulong binlog_stmt_cache_use, binlog_stmt_cache_disk_use;
extern ulong aborted_threads,aborted_connects;
extern ulong delayed_insert_timeout;
extern ulong delayed_insert_limit, delayed_queue_size;
extern ulong delayed_insert_threads, delayed_insert_writes;
extern ulong delayed_rows_in_use,delayed_insert_errors;
extern int32 slave_open_temp_tables;
extern ulong query_cache_size, query_cache_min_res_unit;
extern ulong slow_launch_threads, slow_launch_time;
extern ulong table_cache_size, table_def_size;
extern ulong table_cache_size_per_instance, table_cache_instances;
extern MYSQL_PLUGIN_IMPORT ulong max_connections;
extern ulong max_connect_errors, connect_timeout;
extern my_bool opt_slave_allow_batching;
extern my_bool allow_slave_start;
extern LEX_CSTRING reason_slave_blocked;
extern ulong slave_trans_retries;
extern uint  slave_net_timeout;
extern ulong opt_mts_slave_parallel_workers;
extern ulonglong opt_mts_pending_jobs_size_max;
extern my_bool log_bin_use_v1_row_events;
extern ulong what_to_log,flush_time;
extern ulong max_prepared_stmt_count, prepared_stmt_count;
extern ulong open_files_limit;
extern ulong binlog_cache_size, binlog_stmt_cache_size;
extern ulonglong max_binlog_cache_size, max_binlog_stmt_cache_size;
extern int32 opt_binlog_max_flush_queue_time;
extern ulong max_binlog_size, max_relay_log_size;
extern ulong slave_max_allowed_packet;
extern ulong opt_binlog_rows_event_max_size;
extern ulong binlog_checksum_options;
extern const char *binlog_checksum_type_names[];
extern my_bool opt_master_verify_checksum;
extern my_bool opt_slave_sql_verify_checksum;
extern my_bool enforce_gtid_consistency;
enum enum_gtid_mode
{
  /// Support only anonymous groups, not GTIDs.
  GTID_MODE_OFF= 0,
  /// Support both GTIDs and anonymous groups; generate anonymous groups.
  GTID_MODE_UPGRADE_STEP_1= 1,
  /// Support both GTIDs and anonymous groups; generate GTIDs.
  GTID_MODE_UPGRADE_STEP_2= 2,
  /// Support only GTIDs, not anonymous groups.
  GTID_MODE_ON= 3
};
extern ulong gtid_mode;
extern const char *gtid_mode_names[];
extern TYPELIB gtid_mode_typelib;

extern ulong max_blocked_pthreads;
extern ulong stored_program_cache_size;
extern ulong back_log;
extern char language[FN_REFLEN];
extern "C" MYSQL_PLUGIN_IMPORT ulong server_id;
extern ulong concurrency;
extern time_t server_start_time, flush_status_time;
extern char *opt_mysql_tmpdir, mysql_charsets_dir[];
extern int mysql_unpacked_real_data_home_len;
extern MYSQL_PLUGIN_IMPORT MY_TMPDIR mysql_tmpdir_list;
extern const char *first_keyword, *delayed_user, *binary_keyword;
extern MYSQL_PLUGIN_IMPORT const char  *my_localhost;
extern MYSQL_PLUGIN_IMPORT const char **errmesg;			/* Error messages */
extern const char *myisam_recover_options_str;
extern const char *in_left_expr_name, *in_additional_cond, *in_having_cond;
extern SHOW_VAR status_vars[];
extern struct system_variables max_system_variables;
extern struct system_status_var global_status_var;
extern struct rand_struct sql_rand;
extern const char *opt_date_time_formats[];
extern handlerton *partition_hton;
extern handlerton *myisam_hton;
extern handlerton *heap_hton;
extern uint opt_server_id_bits;
extern ulong opt_server_id_mask;
#ifdef WITH_NDBCLUSTER_STORAGE_ENGINE
/* engine specific hook, to be made generic */
extern int(*ndb_wait_setup_func)(ulong);
extern ulong opt_ndb_wait_setup;
#endif
extern const char *load_default_groups[];
extern struct my_option my_long_options[];
extern struct my_option my_long_early_options[];
extern struct my_option my_isql_options[];

int handle_early_options();
void adjust_related_options();
extern int mysqld_server_started;
extern "C" MYSQL_PLUGIN_IMPORT int orig_argc;
extern "C" MYSQL_PLUGIN_IMPORT char **orig_argv;
extern pthread_attr_t connection_attrib;
extern MYSQL_FILE *bootstrap_file;
extern my_bool old_mode;
extern LEX_STRING opt_init_connect, opt_init_slave;
extern int bootstrap_error;
extern char err_shared_dir[];
extern TYPELIB thread_handling_typelib;
extern my_decimal decimal_zero;
extern ulong connection_errors_select;
extern ulong connection_errors_accept;
extern ulong connection_errors_tcpwrap;
extern ulong connection_errors_internal;
extern ulong connection_errors_max_connection;
extern ulong connection_errors_peer_addr;
extern ulong log_warnings;

#define ISQL_OPTION_COUNT 11


/*
  THR_MALLOC is a key which will be used to set/get MEM_ROOT** for a thread,
  using my_pthread_setspecific_ptr()/my_thread_getspecific_ptr().
*/
extern pthread_key(MEM_ROOT**,THR_MALLOC);

#ifdef HAVE_PSI_INTERFACE
#ifdef HAVE_MMAP
extern PSI_mutex_key key_PAGE_lock, key_LOCK_sync, key_LOCK_active,
       key_LOCK_pool;
#endif /* HAVE_MMAP */

#ifdef HAVE_OPENSSL
extern PSI_mutex_key key_LOCK_des_key_file;
#endif

extern PSI_mutex_key key_BINLOG_LOCK_commit;
extern PSI_mutex_key key_BINLOG_LOCK_commit_queue;
extern PSI_mutex_key key_BINLOG_LOCK_done;
extern PSI_mutex_key key_BINLOG_LOCK_flush_queue;
extern PSI_mutex_key key_BINLOG_LOCK_index;
extern PSI_mutex_key key_BINLOG_LOCK_log;
extern PSI_mutex_key key_BINLOG_LOCK_sync;
extern PSI_mutex_key key_BINLOG_LOCK_sync_queue;
extern PSI_mutex_key
  key_delayed_insert_mutex, key_hash_filo_lock, key_LOCK_active_mi,
  key_LOCK_connection_count, key_LOCK_crypt, key_LOCK_delayed_create,
  key_LOCK_delayed_insert, key_LOCK_delayed_status, key_LOCK_error_log,
  key_LOCK_gdl, key_LOCK_global_system_variables,
  key_LOCK_lock_db, key_LOCK_logger, key_LOCK_manager,
  key_LOCK_prepared_stmt_count,
  key_LOCK_sql_slave_skip_counter,
  key_LOCK_slave_net_timeout,
  key_LOCK_server_started, key_LOCK_status,
  key_LOCK_table_share, key_LOCK_thd_data,
  key_LOCK_user_conn, key_LOCK_uuid_generator, key_LOG_LOCK_log,
  key_master_info_data_lock, key_master_info_run_lock,
  key_master_info_sleep_lock,
  key_mutex_slave_reporting_capability_err_lock, key_relay_log_info_data_lock,
  key_relay_log_info_sleep_lock,
  key_relay_log_info_log_space_lock, key_relay_log_info_run_lock,
  key_mutex_slave_parallel_pend_jobs, key_mutex_mts_temp_tables_lock,
  key_mutex_slave_parallel_worker,
  key_structure_guard_mutex, key_TABLE_SHARE_LOCK_ha_data,
  key_LOCK_error_messages, key_LOCK_thread_count,
  key_LOCK_log_throttle_qni;
extern PSI_mutex_key key_RELAYLOG_LOCK_commit;
extern PSI_mutex_key key_RELAYLOG_LOCK_commit_queue;
extern PSI_mutex_key key_RELAYLOG_LOCK_done;
extern PSI_mutex_key key_RELAYLOG_LOCK_flush_queue;
extern PSI_mutex_key key_RELAYLOG_LOCK_index;
extern PSI_mutex_key key_RELAYLOG_LOCK_log;
extern PSI_mutex_key key_RELAYLOG_LOCK_sync;
extern PSI_mutex_key key_RELAYLOG_LOCK_sync_queue;
extern PSI_mutex_key key_LOCK_sql_rand;
extern PSI_mutex_key key_gtid_ensure_index_mutex;
extern PSI_mutex_key key_LOCK_thread_created;

extern PSI_rwlock_key key_rwlock_LOCK_grant, key_rwlock_LOCK_logger,
  key_rwlock_LOCK_sys_init_connect, key_rwlock_LOCK_sys_init_slave,
  key_rwlock_LOCK_system_variables_hash, key_rwlock_query_cache_query_lock,
  key_rwlock_global_sid_lock;

#ifdef HAVE_MMAP
extern PSI_cond_key key_PAGE_cond, key_COND_active, key_COND_pool;
#endif /* HAVE_MMAP */

extern PSI_cond_key key_BINLOG_update_cond,
  key_COND_cache_status_changed, key_COND_manager,
  key_COND_server_started,
  key_delayed_insert_cond, key_delayed_insert_cond_client,
  key_item_func_sleep_cond, key_master_info_data_cond,
  key_master_info_start_cond, key_master_info_stop_cond,
  key_master_info_sleep_cond,
  key_relay_log_info_data_cond, key_relay_log_info_log_space_cond,
  key_relay_log_info_start_cond, key_relay_log_info_stop_cond,
  key_relay_log_info_sleep_cond, key_cond_slave_parallel_pend_jobs,
  key_cond_slave_parallel_worker,
  key_TABLE_SHARE_cond, key_user_level_lock_cond,
  key_COND_thread_count, key_COND_thread_cache, key_COND_flush_thread_cache;
extern PSI_cond_key key_BINLOG_COND_done;
extern PSI_cond_key key_RELAYLOG_COND_done;
extern PSI_cond_key key_RELAYLOG_update_cond;
extern PSI_cond_key key_BINLOG_prep_xids_cond;
extern PSI_cond_key key_RELAYLOG_prep_xids_cond;
extern PSI_cond_key key_gtid_ensure_index_cond;

extern PSI_thread_key key_thread_bootstrap, key_thread_delayed_insert,
  key_thread_handle_manager, key_thread_kill_server, key_thread_main,
  key_thread_one_connection, key_thread_signal_hand;

#ifdef HAVE_MMAP
extern PSI_file_key key_file_map;
#endif /* HAVE_MMAP */

extern PSI_file_key key_file_binlog, key_file_binlog_index, key_file_casetest,
  key_file_dbopt, key_file_des_key_file, key_file_ERRMSG, key_select_to_file,
  key_file_fileparser, key_file_frm, key_file_global_ddl_log, key_file_load,
  key_file_loadfile, key_file_log_event_data, key_file_log_event_info,
  key_file_master_info, key_file_misc, key_file_partition,
  key_file_pid, key_file_relay_log_info, key_file_send_file, key_file_tclog,
  key_file_trg, key_file_trn, key_file_init;
extern PSI_file_key key_file_query_log, key_file_slow_log;
extern PSI_file_key key_file_relaylog, key_file_relaylog_index;
extern PSI_socket_key key_socket_tcpip, key_socket_unix, key_socket_client_connection;

void init_server_psi_keys();
#endif /* HAVE_PSI_INTERFACE */

/*
  MAINTAINER: Please keep this list in order, to limit merge collisions.
  Hint: grep PSI_stage_info | sort -u
*/
#ifdef HAVE_PSI_STATEMENT_INTERFACE
/**
  Statement instrumentation keys (sql).
  The last entry, at [SQLCOM_END], is for parsing errors.
*/
extern PSI_statement_info sql_statement_info[(uint) SQLCOM_END + 1];

/**
  Statement instrumentation keys (com).
  The last entry, at [COM_END], is for packet errors.
*/
extern PSI_statement_info com_statement_info[(uint) COM_END + 1];

void init_sql_statement_info();
void init_com_statement_info();
#endif /* HAVE_PSI_STATEMENT_INTERFACE */

#ifndef __WIN__
extern pthread_t signal_thread;
#define strcmpi strcasecmp
#define strnicmp strncasecmp
#endif

#ifdef HAVE_OPENSSL
extern struct st_VioSSLFd * ssl_acceptor_fd;
#endif /* HAVE_OPENSSL */

/*
  The following variables were under INNODB_COMPABILITY_HOOKS
 */
extern my_bool opt_large_pages;
extern uint opt_large_page_size;
extern char lc_messages_dir[FN_REFLEN];
extern char *lc_messages_dir_ptr, *log_error_file_ptr;
extern MYSQL_PLUGIN_IMPORT char reg_ext[FN_EXTLEN];
extern MYSQL_PLUGIN_IMPORT uint reg_ext_length;
extern MYSQL_PLUGIN_IMPORT uint lower_case_table_names;
extern MYSQL_PLUGIN_IMPORT bool mysqld_embedded;
extern ulong specialflag;
extern uint mysql_data_home_len;
extern uint mysql_real_data_home_len;
extern const char *mysql_real_data_home_ptr;
extern ulong thread_handling;
extern MYSQL_PLUGIN_IMPORT char  *mysql_data_home;
extern "C" MYSQL_PLUGIN_IMPORT char server_version[SERVER_VERSION_LENGTH];
extern MYSQL_PLUGIN_IMPORT char mysql_real_data_home[];
extern char mysql_unpacked_real_data_home[];
extern MYSQL_PLUGIN_IMPORT struct system_variables global_system_variables;
extern char default_logfile_name[FN_REFLEN];

#define mysql_tmpdir (my_tmpdir(&mysql_tmpdir_list))

extern MYSQL_PLUGIN_IMPORT const key_map key_map_empty;
extern MYSQL_PLUGIN_IMPORT key_map key_map_full;          /* Should be threaded as const */

/*
  Server mutex locks and condition variables.
 */
extern mysql_mutex_t
       LOCK_user_locks, LOCK_status,
       LOCK_error_log, LOCK_delayed_insert, LOCK_uuid_generator,
       LOCK_delayed_status, LOCK_delayed_create, LOCK_crypt, LOCK_timezone,
       LOCK_slave_list, LOCK_active_mi, LOCK_manager,
       LOCK_global_system_variables, LOCK_user_conn, LOCK_log_throttle_qni,
       LOCK_prepared_stmt_count, LOCK_error_messages, LOCK_connection_count,
       LOCK_sql_slave_skip_counter, LOCK_slave_net_timeout;
#ifdef HAVE_OPENSSL
extern mysql_mutex_t LOCK_des_key_file;
#endif
extern mysql_mutex_t LOCK_server_started;
extern mysql_cond_t COND_server_started;
extern mysql_rwlock_t LOCK_grant, LOCK_sys_init_connect, LOCK_sys_init_slave;
extern mysql_rwlock_t LOCK_system_variables_hash;
extern int32 thread_running;
extern my_atomic_rwlock_t thread_running_lock;
extern my_atomic_rwlock_t slave_open_temp_tables_lock;
extern my_atomic_rwlock_t opt_binlog_max_flush_queue_time_lock;

extern char *opt_ssl_ca, *opt_ssl_capath, *opt_ssl_cert, *opt_ssl_cipher,
            *opt_ssl_key, *opt_ssl_crl, *opt_ssl_crlpath;

extern MYSQL_PLUGIN_IMPORT pthread_key(THD*, THR_THD);

/**
  only options that need special treatment in get_one_option() deserve
  to be listed below
*/
enum options_mysqld
{
  OPT_to_set_the_start_number=256,
  OPT_BIND_ADDRESS,
  OPT_POOL_OF_THREADS,
  OPT_SERVER_ID,
  OPT_SKIP_HOST_CACHE,
  OPT_SSL_CA,
  OPT_SSL_CAPATH,
  OPT_SSL_CERT,
  OPT_SSL_CIPHER,
  OPT_SSL_KEY,
  OPT_WANT_CORE,
  OPT_LOG_ERROR,
  OPT_SSL_CRL,
  OPT_SSL_CRLPATH,
  OPT_PFS_INSTRUMENT,
  OPT_DEFAULT_AUTH,
  OPT_SECURE_AUTH,
  OPT_THREAD_CACHE_SIZE,
  OPT_HOST_CACHE_SIZE,
  OPT_SKIP_STACK_TRACE,
};


/**
   Query type constants (usable as bitmap flags).
*/
enum enum_query_type
{
  /// Nothing specific, ordinary SQL query.
  QT_ORDINARY= 0,
  /// In utf8.
  QT_TO_SYSTEM_CHARSET= (1 << 0),
  /// Without character set introducers.
  QT_WITHOUT_INTRODUCERS= (1 << 1),
  /// When printing a SELECT, add its number (select_lex->number)
  QT_SHOW_SELECT_NUMBER= (1 << 2),
  /// Don't print a database if it's equal to the connection's database
  QT_NO_DEFAULT_DB= (1 << 3),
  /// When printing a derived table, don't print its expression, only alias
  QT_DERIVED_TABLE_ONLY_ALIAS= (1 << 4)
};

/* query_id */
typedef int64 query_id_t;
extern query_id_t global_query_id;
extern my_atomic_rwlock_t global_query_id_lock;

void unireg_end(void) __attribute__((noreturn));

/* increment query_id and return it.  */
inline __attribute__((warn_unused_result)) query_id_t next_query_id()
{
  query_id_t id;
  my_atomic_rwlock_wrlock(&global_query_id_lock);
  id= my_atomic_add64(&global_query_id, 1);
  my_atomic_rwlock_wrunlock(&global_query_id_lock);
  return (id+1);
}

/*
  TODO: Replace this with an inline function.
 */
#ifndef EMBEDDED_LIBRARY
extern "C" void unireg_abort(int exit_code) __attribute__((noreturn));
#else
extern "C" void unireg_clear(int exit_code);
#define unireg_abort(exit_code) do { unireg_clear(exit_code); DBUG_RETURN(exit_code); } while(0)
#endif

inline void table_case_convert(char * name, uint length)
{
  if (lower_case_table_names)
    files_charset_info->cset->casedn(files_charset_info,
                                     name, length, name, length);
}

ulong sql_rnd_with_mutex();

extern int32 num_thread_running;
inline int32
inc_thread_running()
{
  int32 num_threads;
  my_atomic_rwlock_wrlock(&thread_running_lock);
  num_threads= my_atomic_add32(&num_thread_running, 1);
  my_atomic_rwlock_wrunlock(&thread_running_lock);
  return (num_threads+1);
}

inline int32
dec_thread_running()
{
  int32 num_threads;
  my_atomic_rwlock_wrlock(&thread_running_lock);
  num_threads= my_atomic_add32(&num_thread_running, -1);
  my_atomic_rwlock_wrunlock(&thread_running_lock);
  return (num_threads-1);
}

#if defined(MYSQL_DYNAMIC_PLUGIN) && defined(_WIN32)
extern "C" THD *_current_thd_noinline();
#define _current_thd() _current_thd_noinline()
#else
/*
  THR_THD is a key which will be used to set/get THD* for a thread,
  using my_pthread_setspecific_ptr()/my_thread_getspecific_ptr().
*/
extern pthread_key(THD*, THR_THD);
inline THD *_current_thd(void)
{
  return my_pthread_getspecific_ptr(THD*,THR_THD);
}
#endif
#define current_thd _current_thd()

extern const char *MY_BIND_ALL_ADDRESSES;

#undef ENABLED_DEBUG_SYNC

#endif /* MYSQLD_INCLUDED */
