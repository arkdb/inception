/* Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.

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

#include "my_global.h"                          /* NO_EMBEDDED_ACCESS_CHECKS */

#include <vector>
#include <algorithm>
#include <functional>
#include <list>
#include <set>

#include "sql_priv.h"
#include "unireg.h"
#include <signal.h>
#include "sql_parse.h"    // test_if_data_home_dir
#include "sql_cache.h"    // query_cache, query_cache_*
#include "sql_locale.h"   // MY_LOCALES, my_locales, my_locale_by_name
#include "sql_show.h"     // free_status_vars, add_status_vars,
                          // reset_status_vars
#include "strfunc.h"      // find_set_from_flags
#include "parse_file.h"   // File_parser_dummy_hook
#include "sql_db.h"       // my_dboptions_cache_free
                          // my_dboptions_cache_init
#include "sql_table.h"    // release_ddl_log, execute_ddl_log_recovery
#include "sql_connect.h"  // free_max_user_conn, init_max_user_conn,
                          // handle_one_connection
#include "sql_time.h"     // known_date_time_formats,
                          // get_date_time_format_str,
                          // date_time_format_make
#include "tztime.h"       // my_tz_free, my_tz_init, my_tz_SYSTEM
#include "hostname.h"     // hostname_cache_free, hostname_cache_init
#include "sql_acl.h"      // acl_free, grant_free, acl_init,
                          // grant_init
#include "sql_base.h"     // table_def_free, table_def_init,
                          // Table_cache,
                          // cached_table_definitions
#include "sql_test.h"     // mysql_print_status
#include "item_create.h"  // item_create_cleanup, item_create_init
#include "sql_servers.h"  // servers_free, servers_init
#include "init.h"         // unireg_init
#include "derror.h"       // init_errmessage
#include "derror.h"       // init_errmessage
#include "des_key_file.h" // load_des_key_file
#include "sql_manager.h"  // stop_handle_manager, start_handle_manager
#include <m_ctype.h>
#include <my_dir.h>
#include <my_bit.h>
#include "rpl_gtid.h"
#include "rpl_slave.h"
#include "rpl_master.h"
#include "rpl_mi.h"
#include "rpl_filter.h"
#include <sql_common.h>
#include <my_stacktrace.h>
#include "mysqld_suffix.h"
#include "mysys_err.h"
#include "events.h"
#include "sql_audit.h"
#include "probes_mysql.h"
#include "scheduler.h"
#include "debug_sync.h"
#include "sql_callback.h"
#include "opt_trace_context.h"

#include "global_threads.h"
#include "mysqld.h"
#include "my_default.h"

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
#include "../storage/perfschema/pfs_server.h"
#endif /* WITH_PERFSCHEMA_STORAGE_ENGINE */
#include <mysql/psi/mysql_idle.h>
#include <mysql/psi/mysql_socket.h>
#include <mysql/psi/mysql_statement.h>
#include "mysql_com_server.h"

#include "keycaches.h"
#include "set_var.h"

#include "sys_vars_shared.h"

//#include "rpl_injector.h"

//#include "rpl_handler.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <thr_alarm.h>
#include <ft_global.h>
#include <errmsg.h>
#include "sp_rcontext.h"
#include "sp_cache.h"
#include "sql_reload.h"  // reload_acl_and_cache

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_FESETROUND
#include <fenv.h>
#endif
// #include "table_cache.h" // table_cache_manager

using std::min;
using std::max;
using std::vector;

#define mysqld_charset &my_charset_latin1

/* We have HAVE_purify below as this speeds up the shutdown of MySQL */

#if defined(HAVE_DEC_3_2_THREADS) || defined(SIGNALS_DONT_BREAK_READ) || defined(HAVE_purify) && defined(__linux__)
#define HAVE_CLOSE_SERVER_SOCK 1
#endif

extern "C" {          // Because of SCO 3.2V4.2
#include <errno.h>
#include <sys/stat.h>
#ifndef __GNU_LIBRARY__
#define __GNU_LIBRARY__       // Skip warnings in getopt.h
#endif
#include <my_getopt.h>
#ifdef HAVE_SYSENT_H
#include <sysent.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>        // For getpwent
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <my_net.h>

#if !defined(__WIN__)
#include <sys/resource.h>
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_SELECT_H
#include <select.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/utsname.h>
#endif /* __WIN__ */

#include <my_libwrap.h>

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef __WIN__
#include <crtdbg.h>
#endif

#ifdef HAVE_SOLARIS_LARGE_PAGES
#include <sys/mman.h>
#if defined(__sun__) && defined(__GNUC__) && defined(__cplusplus) \
    && defined(_XOPEN_SOURCE)
extern int getpagesizes(size_t *, int);
extern int getpagesizes2(size_t *, int);
extern int memcntl(caddr_t, size_t, int, caddr_t, int, int);
#endif /* __sun__ ... */
#endif /* HAVE_SOLARIS_LARGE_PAGES */

#ifdef _AIX41
int initgroups(const char *,unsigned int);
#endif

#if defined(__FreeBSD__) && defined(HAVE_IEEEFP_H) && !defined(HAVE_FEDISABLEEXCEPT)
#include <ieeefp.h>
#ifdef HAVE_FP_EXCEPT       // Fix type conflict
typedef fp_except fp_except_t;
#endif
#endif /* __FreeBSD__ && HAVE_IEEEFP_H && !HAVE_FEDISABLEEXCEPT */
#ifdef HAVE_SYS_FPU_H
/* for IRIX to use set_fpc_csr() */
#include <sys/fpu.h>
#endif
#ifdef HAVE_FPU_CONTROL_H
#include <fpu_control.h>
#endif
#if defined(__i386__) && !defined(HAVE_FPU_CONTROL_H)
# define fpu_control_t unsigned int
# define _FPU_EXTENDED 0x300
# define _FPU_DOUBLE 0x200
# if defined(__GNUC__) || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590)
#  define _FPU_GETCW(cw) asm volatile ("fnstcw %0" : "=m" (*&cw))
#  define _FPU_SETCW(cw) asm volatile ("fldcw %0" : : "m" (*&cw))
# else
#  define _FPU_GETCW(cw) (cw= 0)
#  define _FPU_SETCW(cw)
# endif
#endif

extern "C" my_bool reopen_fstreams(const char *filename,
                                   FILE *outstream, FILE *errstream);

inline void setup_fpu()
{
#if defined(__FreeBSD__) && defined(HAVE_IEEEFP_H) && !defined(HAVE_FEDISABLEEXCEPT)
  /* We can't handle floating point exceptions with threads, so disable
     this on freebsd
     Don't fall for overflow, underflow,divide-by-zero or loss of precision.
     fpsetmask() is deprecated in favor of fedisableexcept() in C99.
  */
#if defined(FP_X_DNML)
  fpsetmask(~(FP_X_INV | FP_X_DNML | FP_X_OFL | FP_X_UFL | FP_X_DZ |
        FP_X_IMP));
#else
  fpsetmask(~(FP_X_INV |             FP_X_OFL | FP_X_UFL | FP_X_DZ |
              FP_X_IMP));
#endif /* FP_X_DNML */
#endif /* __FreeBSD__ && HAVE_IEEEFP_H && !HAVE_FEDISABLEEXCEPT */

#ifdef HAVE_FEDISABLEEXCEPT
  fedisableexcept(FE_ALL_EXCEPT);
#endif

#ifdef HAVE_FESETROUND
    /* Set FPU rounding mode to "round-to-nearest" */
  fesetround(FE_TONEAREST);
#endif /* HAVE_FESETROUND */

  /*
    x86 (32-bit) requires FPU precision to be explicitly set to 64 bit
    (double precision) for portable results of floating point operations.
    However, there is no need to do so if compiler is using SSE2 for floating
    point, double values will be stored and processed in 64 bits anyway.
  */
#if defined(__i386__) && !defined(__SSE2_MATH__)
#if defined(_WIN32)
#if !defined(_WIN64)
  _control87(_PC_53, MCW_PC);
#endif /* !_WIN64 */
#else /* !_WIN32 */
  fpu_control_t cw;
  _FPU_GETCW(cw);
  cw= (cw & ~_FPU_EXTENDED) | _FPU_DOUBLE;
  _FPU_SETCW(cw);
#endif /* _WIN32 && */
#endif /* __i386__ */

// #if defined(__sgi) && defined(HAVE_SYS_FPU_H)
//   /* Enable denormalized DOUBLE values support for IRIX */
//   union fpc_csr n;
//   n.fc_word = get_fpc_csr();
//   n.fc_struct.flush = 0;
//   set_fpc_csr(n.fc_word);
// #endif
}

} /* cplusplus */

#define MYSQL_KILL_SIGNAL SIGTERM

#include <my_pthread.h>     // For thr_setconcurency()

#ifdef SOLARIS
extern "C" int gethostname(char *name, int namelen);
#endif

extern "C" sig_handler handle_fatal_signal(int sig);

#if defined(__linux__)
#define ENABLE_TEMP_POOL 1
#else
#define ENABLE_TEMP_POOL 0
#endif

/* Constants */

#include <welcome_copyright_notice.h> // ORACLE_WELCOME_COPYRIGHT_NOTICE

const char *show_comp_option_name[]= {"YES", "NO", "DISABLED"};

const char *first_keyword= "first", *binary_keyword= "BINARY";
const char *my_localhost= "localhost", *delayed_user= "DELAYED";

bool opt_large_files= sizeof(my_off_t) > 4;
static my_bool opt_autocommit; ///< for --autocommit command-line option

/*
  Used with --help for detailed option
*/
static my_bool opt_help= 0, opt_verbose= 0;

arg_cmp_func Arg_comparator::comparator_matrix[5][2] =
{{&Arg_comparator::compare_string,     &Arg_comparator::compare_e_string},
 {&Arg_comparator::compare_real,       &Arg_comparator::compare_e_real},
 {&Arg_comparator::compare_int_signed, &Arg_comparator::compare_e_int},
 {&Arg_comparator::compare_row,        &Arg_comparator::compare_e_row},
 {&Arg_comparator::compare_decimal,    &Arg_comparator::compare_e_decimal}};

/* static variables */

#ifdef HAVE_PSI_INTERFACE
#if (defined(_WIN32) || defined(HAVE_SMEM)) && !defined(EMBEDDED_LIBRARY)
static PSI_thread_key key_thread_handle_con_namedpipes;
static PSI_cond_key key_COND_handler_count;
#endif /* _WIN32 || HAVE_SMEM && !EMBEDDED_LIBRARY */

#if defined(HAVE_SMEM) && !defined(EMBEDDED_LIBRARY)
static PSI_thread_key key_thread_handle_con_sharedmem;
#endif /* HAVE_SMEM && !EMBEDDED_LIBRARY */

#if (defined(_WIN32) || defined(HAVE_SMEM)) && !defined(EMBEDDED_LIBRARY)
static PSI_thread_key key_thread_handle_con_sockets;
#endif /* _WIN32 || HAVE_SMEM && !EMBEDDED_LIBRARY */

#ifdef __WIN__
static PSI_thread_key key_thread_handle_shutdown;
#endif /* __WIN__ */

#if defined (HAVE_OPENSSL) && !defined(HAVE_YASSL)
static PSI_rwlock_key key_rwlock_openssl;
#endif
#endif /* HAVE_PSI_INTERFACE */

#ifdef HAVE_NPTL
volatile sig_atomic_t ld_assume_kernel_is_set= 0;
#endif

/* the default log output is log tables */
static bool lower_case_table_names_used= 0;
static int volatile select_thread_in_use, signal_thread_in_use;
/* See Bug#56666 and Bug#56760 */;
volatile bool ready_to_exit;
static my_bool opt_debugging= 1;
static my_bool opt_short_log_format= 0;
static uint kill_blocked_pthreads_flag, wake_pthread;
static ulong killed_threads;
       ulong max_used_connections;
static char *mysqld_user, *mysqld_chroot;
static char *default_character_set_name;
static char *character_set_filesystem_name;
static char *lc_messages;
static char *lc_time_names_name;
char *my_bind_addr_str;
static char *default_collation_name;
char *default_storage_engine;
char *default_tmp_storage_engine;
static char compiled_default_collation_name[]= MYSQL_DEFAULT_COLLATION_NAME;

LEX_STRING opt_init_connect, opt_init_slave;

static mysql_cond_t COND_thread_cache, COND_flush_thread_cache;

/* Global variables */

bool opt_bin_log, opt_ignore_builtin_innodb= 0;
my_bool opt_log, opt_slow_log, opt_log_raw;
ulonglong log_output_options;
my_bool opt_log_queries_not_using_indexes= 0;
ulong opt_log_throttle_queries_not_using_indexes= 0;
bool opt_error_log= IF_WIN(1,0);
bool opt_disable_networking=0, opt_skip_show_db=0;
bool opt_skip_name_resolve=0;
my_bool opt_character_set_client_handshake= 1;
bool server_id_supplied = 0;
bool opt_endinfo, using_udf_functions;
my_bool locked_in_memory;
bool opt_using_transactions;
bool volatile abort_loop;
bool volatile shutdown_in_progress;
ulong log_warnings;
#if defined(_WIN32) && !defined(EMBEDDED_LIBRARY)
ulong slow_start_timeout;
#endif
/*
  True if the bootstrap thread is running. Protected by LOCK_thread_count.
  Used in bootstrap() function to determine if the bootstrap thread
  has completed. Note, that we can't use 'thread_count' instead,
  since in 5.1, in presence of the Event Scheduler, there may be
  event threads running in parallel, so it's impossible to know
  what value of 'thread_count' is a sign of completion of the
  bootstrap thread.

  At the same time, we can't start the event scheduler after
  bootstrap either, since we want to be able to process event-related
  SQL commands in the init file and in --bootstrap mode.
*/
bool in_bootstrap= FALSE;
my_bool opt_bootstrap= 0;

/**
   @brief 'grant_option' is used to indicate if privileges needs
   to be checked, in which case the lock, LOCK_grant, is used
   to protect access to the grant table.
   @note This flag is dropped in 5.1
   @see grant_init()
 */
bool volatile grant_option;

my_bool opt_skip_slave_start = 0; ///< If set, slave is not autostarted
my_bool opt_reckless_slave = 0;
my_bool opt_enable_named_pipe= 0;
my_bool opt_local_infile, opt_slave_compressed_protocol;
my_bool opt_safe_user_create = 0;
my_bool opt_show_slave_auth_info;
my_bool opt_log_slave_updates= 0;
char *opt_slave_skip_errors;
my_bool opt_slave_allow_batching= 0;

/**
  compatibility option:
    - index usage hints (USE INDEX without a FOR clause) behave as in 5.0
*/
my_bool old_mode;

/*
  Legacy global handlerton. These will be removed (please do not add more).
*/
handlerton *heap_hton;
handlerton *myisam_hton;
handlerton *partition_hton;

uint opt_server_id_bits= 0;
ulong opt_server_id_mask= 0;
my_bool read_only= 0, opt_readonly= 0;
my_bool use_temp_pool, relay_log_purge;
my_bool relay_log_recovery;
my_bool opt_sync_frm, opt_allow_suspicious_udfs;
my_bool opt_secure_auth= 0;
char* opt_secure_file_priv;
my_bool opt_log_slow_admin_statements= 0;
my_bool opt_log_slow_slave_statements= 0;
my_bool lower_case_file_system= 0;
my_bool opt_large_pages= 0;
my_bool opt_super_large_pages= 0;
my_bool opt_myisam_use_mmap= 0;
uint   opt_large_page_size= 0;
// #if defined(ENABLED_DEBUG_SYNC)
// MYSQL_PLUGIN_IMPORT uint    opt_debug_sync_timeout= 0;
// #endif /* defined(ENABLED_DEBUG_SYNC) */
my_bool opt_old_style_user_limits= 0, trust_function_creators= 0;
/*
  True if there is at least one per-hour limit for some user, so we should
  check them before each query (and possibly reset counters when hour is
  changed). False otherwise.
*/
volatile bool mqh_used = 0;
my_bool opt_noacl= 1;
my_bool sp_automatic_privileges= 1;

ulong opt_binlog_rows_event_max_size;
const char *binlog_checksum_default= "NONE";
ulong binlog_checksum_options;
my_bool opt_master_verify_checksum= 0;
my_bool opt_slave_sql_verify_checksum= 1;
const char *binlog_format_names[]= {"MIXED", "STATEMENT", "ROW", NullS};
my_bool enforce_gtid_consistency;
ulong gtid_mode;
const char *gtid_mode_names[]=
{"OFF", "UPGRADE_STEP_1", "UPGRADE_STEP_2", "ON", NullS};
TYPELIB gtid_mode_typelib=
{ array_elements(gtid_mode_names) - 1, "", gtid_mode_names, NULL };

#ifdef HAVE_INITGROUPS
volatile sig_atomic_t calling_initgroups= 0; /**< Used in SIGSEGV handler. */
#endif
uint mysqld_port, test_flags, select_errors, dropping_tables, ha_open_options;
uint mysqld_port_timeout;
ulong delay_key_write_options;
uint protocol_version;
uint lower_case_table_names;
ulong tc_heuristic_recover= 0;
int32 num_thread_running;
ulong thread_created;
ulong back_log, connect_timeout, concurrency, server_id;
ulong table_cache_size, table_def_size;
ulong table_cache_instances;
ulong table_cache_size_per_instance;
ulong what_to_log;
ulong slow_launch_time=2;
int32 slave_open_temp_tables;
ulong max_binlog_size, max_relay_log_size;
ulong slave_trans_retries;
uint  slave_net_timeout;
ulong slave_exec_mode_options;
ulonglong slave_type_conversions_options=0;
ulong opt_mts_slave_parallel_workers;
ulonglong opt_mts_pending_jobs_size_max;
ulonglong slave_rows_search_algorithms_options;
#ifndef DBUG_OFF
uint slave_rows_last_search_algorithm_used;
#endif
ulong binlog_cache_size=0;
ulonglong  max_binlog_cache_size=0;
ulong slave_max_allowed_packet= 0;
ulong binlog_stmt_cache_size=0;
my_atomic_rwlock_t opt_binlog_max_flush_queue_time_lock;
int32 opt_binlog_max_flush_queue_time= 0;
ulonglong  max_binlog_stmt_cache_size=0;
ulong query_cache_size=0;
ulong refresh_version;  /* Increments on each reload */
query_id_t global_query_id;
my_atomic_rwlock_t global_query_id_lock;
my_atomic_rwlock_t thread_running_lock;
my_atomic_rwlock_t slave_open_temp_tables_lock;
ulong aborted_threads, aborted_connects;
ulong delayed_insert_timeout, delayed_insert_limit, delayed_queue_size;
ulong delayed_insert_threads, delayed_insert_writes, delayed_rows_in_use;
ulong delayed_insert_errors,flush_time;
ulong specialflag=0;
ulong binlog_cache_use= 0, binlog_cache_disk_use= 0;
ulong binlog_stmt_cache_use= 0, binlog_stmt_cache_disk_use= 0;
ulong max_connections, max_connect_errors;
my_bool log_bin_use_v1_row_events= 0;
bool host_cache_size_specified= false;
bool table_definition_cache_specified= false;

char *opt_logname;

/**
  Limit of the total number of prepared statements in the server.
  Is necessary to protect the server against out-of-memory attacks.
*/
ulong max_prepared_stmt_count;
/**
  Current total number of prepared statements in the server. This number
  is exact, and therefore may not be equal to the difference between
  `com_stmt_prepare' and `com_stmt_close' (global status variables), as
  the latter ones account for all registered attempts to prepare
  a statement (including unsuccessful ones).  Prepared statements are
  currently connection-local: if the same SQL query text is prepared in
  two different connections, this counts as two distinct prepared
  statements.
*/
ulong prepared_stmt_count=0;
ulong thread_id=1L,current_pid;
ulong slow_launch_threads = 0;
uint sync_binlog_period= 0, sync_relaylog_period= 0,
     sync_relayloginfo_period= 0, sync_masterinfo_period= 0,
     opt_mts_checkpoint_period, opt_mts_checkpoint_group;
ulong expire_logs_days = 0;
char *remote_backup_host = NULL;
char *remote_system_user = NULL;
char *remote_system_password = NULL;
char *inception_user = NULL;
char *inception_password = NULL;
uint remote_backup_port = 0;

bool inception_check_insert_field=0;
bool inception_check_dml_where=0;
bool inception_check_dml_limit=0;
bool inception_check_dml_orderby=0;
bool inception_enable_select_star=0;
bool inception_enable_orderby_rand=0;
bool inception_enable_nullable=0;
bool inception_enable_foreign_key=0;
ulong inception_max_key_parts=0;
ulong inception_max_update_rows=0;
ulong inception_max_keys=0;
bool inception_enable_not_innodb=0;
char* inception_support_charset=0;
bool inception_check_table_comment=0;
bool inception_check_column_comment=0;
bool inception_check_primary_key=0;
bool inception_enable_partition_table=0;
bool inception_enable_blob_type=0;
bool inception_enable_enum_set_bit=0;
bool inception_check_index_prefix=0;
bool inception_enable_autoincrement_unsigned=0;
ulong inception_max_char_length=0;
bool inception_check_autoincrement_init_value=0;
bool inception_check_autoincrement_datatype=0;
bool inception_check_timestamp_default=0;
bool inception_enable_column_charset=0;
bool inception_check_autoincrement_name=0;
bool inception_merge_alter_table=0;
bool inception_check_column_default_value=0;
bool inception_enable_identifer_keyword=0;
bool inception_enable_sql_statistic=0;
char* inception_osc_bin_dir= NULL;
bool inception_osc_print_sql=0;
bool inception_osc_print_none=0;
bool inception_read_only=0;
bool inception_check_identifier=0;
bool inception_ddl_support=0;
bool inception_osc_on=0;
// ulong inception_osc_critical_connected=0;
// ulong inception_osc_critical_running=0;
// ulong inception_osc_max_connected=0;
// ulong inception_osc_max_running=0;
// double inception_osc_chunk_time=0;
// double inception_osc_check_interval=0;
// double inception_osc_max_lag=0;
// ulong inception_osc_chunk_size=0;
// double inception_osc_chunk_size_limit=0;
// bool inception_osc_drop_new_table=0;
// bool inception_osc_drop_old_table=0;

mysql_mutex_t        osc_mutex;
osc_cache_t global_osc_cache;
/**
  Soft upper limit for number of sp_head objects that can be stored
  in the sp_cache for one connection.
*/
ulong stored_program_cache_size= 0;

const double log_10[] = {
  1e000, 1e001, 1e002, 1e003, 1e004, 1e005, 1e006, 1e007, 1e008, 1e009,
  1e010, 1e011, 1e012, 1e013, 1e014, 1e015, 1e016, 1e017, 1e018, 1e019,
  1e020, 1e021, 1e022, 1e023, 1e024, 1e025, 1e026, 1e027, 1e028, 1e029,
  1e030, 1e031, 1e032, 1e033, 1e034, 1e035, 1e036, 1e037, 1e038, 1e039,
  1e040, 1e041, 1e042, 1e043, 1e044, 1e045, 1e046, 1e047, 1e048, 1e049,
  1e050, 1e051, 1e052, 1e053, 1e054, 1e055, 1e056, 1e057, 1e058, 1e059,
  1e060, 1e061, 1e062, 1e063, 1e064, 1e065, 1e066, 1e067, 1e068, 1e069,
  1e070, 1e071, 1e072, 1e073, 1e074, 1e075, 1e076, 1e077, 1e078, 1e079,
  1e080, 1e081, 1e082, 1e083, 1e084, 1e085, 1e086, 1e087, 1e088, 1e089,
  1e090, 1e091, 1e092, 1e093, 1e094, 1e095, 1e096, 1e097, 1e098, 1e099,
  1e100, 1e101, 1e102, 1e103, 1e104, 1e105, 1e106, 1e107, 1e108, 1e109,
  1e110, 1e111, 1e112, 1e113, 1e114, 1e115, 1e116, 1e117, 1e118, 1e119,
  1e120, 1e121, 1e122, 1e123, 1e124, 1e125, 1e126, 1e127, 1e128, 1e129,
  1e130, 1e131, 1e132, 1e133, 1e134, 1e135, 1e136, 1e137, 1e138, 1e139,
  1e140, 1e141, 1e142, 1e143, 1e144, 1e145, 1e146, 1e147, 1e148, 1e149,
  1e150, 1e151, 1e152, 1e153, 1e154, 1e155, 1e156, 1e157, 1e158, 1e159,
  1e160, 1e161, 1e162, 1e163, 1e164, 1e165, 1e166, 1e167, 1e168, 1e169,
  1e170, 1e171, 1e172, 1e173, 1e174, 1e175, 1e176, 1e177, 1e178, 1e179,
  1e180, 1e181, 1e182, 1e183, 1e184, 1e185, 1e186, 1e187, 1e188, 1e189,
  1e190, 1e191, 1e192, 1e193, 1e194, 1e195, 1e196, 1e197, 1e198, 1e199,
  1e200, 1e201, 1e202, 1e203, 1e204, 1e205, 1e206, 1e207, 1e208, 1e209,
  1e210, 1e211, 1e212, 1e213, 1e214, 1e215, 1e216, 1e217, 1e218, 1e219,
  1e220, 1e221, 1e222, 1e223, 1e224, 1e225, 1e226, 1e227, 1e228, 1e229,
  1e230, 1e231, 1e232, 1e233, 1e234, 1e235, 1e236, 1e237, 1e238, 1e239,
  1e240, 1e241, 1e242, 1e243, 1e244, 1e245, 1e246, 1e247, 1e248, 1e249,
  1e250, 1e251, 1e252, 1e253, 1e254, 1e255, 1e256, 1e257, 1e258, 1e259,
  1e260, 1e261, 1e262, 1e263, 1e264, 1e265, 1e266, 1e267, 1e268, 1e269,
  1e270, 1e271, 1e272, 1e273, 1e274, 1e275, 1e276, 1e277, 1e278, 1e279,
  1e280, 1e281, 1e282, 1e283, 1e284, 1e285, 1e286, 1e287, 1e288, 1e289,
  1e290, 1e291, 1e292, 1e293, 1e294, 1e295, 1e296, 1e297, 1e298, 1e299,
  1e300, 1e301, 1e302, 1e303, 1e304, 1e305, 1e306, 1e307, 1e308
};

time_t server_start_time, flush_status_time;

char server_uuid[UUID_LENGTH+1];
const char *server_uuid_ptr;
char mysql_home[FN_REFLEN], pidfile_name[FN_REFLEN], system_time_zone[30];
char default_logfile_name[FN_REFLEN];
char *default_tz_name;
char log_error_file[FN_REFLEN], glob_hostname[FN_REFLEN];
char mysql_real_data_home[FN_REFLEN],
     lc_messages_dir[FN_REFLEN], reg_ext[FN_EXTLEN],
     mysql_charsets_dir[FN_REFLEN],
     *opt_init_file, *opt_tc_log_file;
char *lc_messages_dir_ptr;
char mysql_unpacked_real_data_home[FN_REFLEN];
int mysql_unpacked_real_data_home_len;
uint mysql_real_data_home_len, mysql_data_home_len= 1;
uint reg_ext_length;
const key_map key_map_empty(0);
key_map key_map_full(0);                        // Will be initialized later
char logname_path[FN_REFLEN];
char slow_logname_path[FN_REFLEN];
char secure_file_real_path[FN_REFLEN];

DATE_TIME_FORMAT global_date_format, global_datetime_format, global_time_format;
Time_zone *default_tz;

char *mysql_data_home= const_cast<char*>(".");
const char *mysql_real_data_home_ptr= mysql_real_data_home;
char server_version[SERVER_VERSION_LENGTH];
char *mysqld_unix_port, *opt_mysql_tmpdir;
ulong thread_handling;

/** name of reference on left expression in rewritten IN subquery */
const char *in_left_expr_name= "<left expr>";
/** name of additional condition */
const char *in_additional_cond= "<IN COND>";
const char *in_having_cond= "<IN HAVING>";

my_decimal decimal_zero;
/** Number of connection errors when selecting on the listening port */
ulong connection_errors_select= 0;
/** Number of connection errors when accepting sockets in the listening port. */
ulong connection_errors_accept= 0;
/** Number of connection errors from TCP wrappers. */
ulong connection_errors_tcpwrap= 0;
/** Number of connection errors from internal server errors. */
ulong connection_errors_internal= 0;
/** Number of connection errors from the server max_connection limit. */
ulong connection_errors_max_connection= 0;
/** Number of errors when reading the peer address. */
ulong connection_errors_peer_addr= 0;

/* classes for comparation parsing/processing */
Eq_creator eq_creator;
Ne_creator ne_creator;
Gt_creator gt_creator;
Lt_creator lt_creator;
Ge_creator ge_creator;
Le_creator le_creator;

MYSQL_FILE *bootstrap_file;
int bootstrap_error;

Rpl_filter* rpl_filter;
Rpl_filter* binlog_filter;

struct system_variables global_system_variables;
struct system_variables max_system_variables;
struct system_status_var global_status_var;

MY_TMPDIR mysql_tmpdir_list;
MY_BITMAP temp_pool;

CHARSET_INFO *system_charset_info, *files_charset_info ;
CHARSET_INFO *national_charset_info, *table_alias_charset;
CHARSET_INFO *character_set_filesystem;
CHARSET_INFO *error_message_charset_info;

MY_LOCALE *my_default_lc_messages;
MY_LOCALE *my_default_lc_time_names;

SHOW_COMP_OPTION have_ssl, have_symlink, have_dlopen, have_query_cache;
SHOW_COMP_OPTION have_geometry, have_rtree_keys;
SHOW_COMP_OPTION have_crypt, have_compress;
SHOW_COMP_OPTION have_profiling;

/* Thread specific variables */

pthread_key(MEM_ROOT**,THR_MALLOC);
pthread_key(THD*, THR_THD);
mysql_mutex_t LOCK_thread_created;
mysql_mutex_t LOCK_thread_count;
mysql_mutex_t
  LOCK_status, LOCK_error_log, LOCK_uuid_generator,
  LOCK_delayed_insert, LOCK_delayed_status, LOCK_delayed_create,
  LOCK_crypt,
  LOCK_global_system_variables,
  LOCK_user_conn, LOCK_slave_list, LOCK_active_mi,
  LOCK_connection_count, LOCK_error_messages;
mysql_mutex_t LOCK_sql_rand;

/**
  The below lock protects access to two global server variables:
  max_prepared_stmt_count and prepared_stmt_count. These variables
  set the limit and hold the current total number of prepared statements
  in the server, respectively. As PREPARE/DEALLOCATE rate in a loaded
  server may be fairly high, we need a dedicated lock.
*/
mysql_mutex_t LOCK_prepared_stmt_count;

/*
 The below two locks are introudced as guards (second mutex) for
  the global variables sql_slave_skip_counter and slave_net_timeout
  respectively. See fix_slave_skip_counter/fix_slave_net_timeout
  for more details
*/
mysql_mutex_t LOCK_sql_slave_skip_counter;
mysql_mutex_t LOCK_slave_net_timeout;
mysql_mutex_t LOCK_log_throttle_qni;
#ifdef HAVE_OPENSSL
mysql_mutex_t LOCK_des_key_file;
#endif
mysql_rwlock_t LOCK_grant, LOCK_sys_init_connect, LOCK_sys_init_slave;
mysql_rwlock_t LOCK_system_variables_hash;
mysql_cond_t COND_thread_count;
pthread_t signal_thread;
pthread_attr_t connection_attrib;
mysql_mutex_t LOCK_server_started;
mysql_cond_t COND_server_started;

int mysqld_server_started= 0;

File_parser_dummy_hook file_parser_dummy_hook;

/* replication parameters, if master_host is not NULL, we are a slave */
uint report_port= 0;
ulong master_retry_count=0;
char *master_info_file;
char *relay_log_info_file, *report_user, *report_password, *report_host;
char *opt_relay_logname = 0, *opt_relaylog_index_name=0;
char *opt_bin_logname;

/* Static variables */

static volatile sig_atomic_t kill_in_progress;


static my_bool opt_myisam_log;
static volatile int cleanup_done;
static ulong opt_specialflag;
static char *opt_update_logname;
char *opt_binlog_index_name;
char *mysql_home_ptr, *pidfile_name_ptr;
/** Initial command line arguments (count), after load_defaults().*/
static int defaults_argc;
/**
  Initial command line arguments (arguments), after load_defaults().
  This memory is allocated by @c load_defaults() and should be freed
  using @c free_defaults().
  Do not modify defaults_argc / defaults_argv,
  use remaining_argc / remaining_argv instead to parse the command
  line arguments in multiple steps.
*/
static char **defaults_argv;
/** Remaining command line arguments (count), filtered by handle_options().*/
static int remaining_argc;
/** Remaining command line arguments (arguments), filtered by handle_options().*/
static char **remaining_argv;

int orig_argc;
char **orig_argv;

#if defined(HAVE_OPENSSL) && !defined(HAVE_YASSL)
int init_rsa_keys(void);
void deinit_rsa_keys(void);
int show_rsa_public_key(THD *thd, SHOW_VAR *var, char *buff);
#endif

static volatile sig_atomic_t global_thread_count= 0;
static std::set<THD*> *global_thread_list= NULL;

ulong max_blocked_pthreads= 0;
static ulong blocked_pthread_count= 0;
static std::list<THD*> *waiting_thd_list= NULL;
Checkable_rwlock *global_sid_lock= NULL;
Sid_map *global_sid_map= NULL;
Gtid_state *gtid_state= NULL;

/*
  global_thread_list and waiting_thd_list are both pointers to objects
  on the heap, to avoid potential problems with running destructors atexit().
 */
static void delete_global_thread_list()
{
  delete global_thread_list;
  delete waiting_thd_list;
  global_thread_list= NULL;
  waiting_thd_list= NULL;
}

Thread_iterator global_thread_list_begin()
{
  mysql_mutex_assert_owner(&LOCK_thread_count);
  return global_thread_list->begin();
}

Thread_iterator global_thread_list_end()
{
  mysql_mutex_assert_owner(&LOCK_thread_count);
  return global_thread_list->end();
}

void add_global_thread(THD *thd)
{
  DBUG_PRINT("info", ("add_global_thread %p", thd));
  mysql_mutex_assert_owner(&LOCK_thread_count);
  const bool have_thread=
    global_thread_list->find(thd) != global_thread_list->end();
  if (!have_thread)
  {
    ++global_thread_count;
    global_thread_list->insert(thd);
  }
  // Adding the same THD twice is an error.
  DBUG_ASSERT(!have_thread);
}

void remove_global_thread(THD *thd)
{
  DBUG_PRINT("info", ("remove_global_thread %p current_linfo %p",
                      thd, thd->current_linfo));
  mysql_mutex_assert_owner(&LOCK_thread_count);
  DBUG_ASSERT(thd->release_resources_done());

  const size_t num_erased= global_thread_list->erase(thd);
  if (num_erased == 1)
    --global_thread_count;
  // Removing a THD that was never added is an error.
  DBUG_ASSERT(1 == num_erased);

  mysql_cond_broadcast(&COND_thread_count);
}

uint get_thread_count()
{
  return (uint) global_thread_count;
}


void set_remaining_args(int argc, char **argv)
{
  remaining_argc= argc;
  remaining_argv= argv;
}
/* 
  Multiple threads of execution use the random state maintained in global
  sql_rand to generate random numbers. sql_rnd_with_mutex use mutex
  LOCK_sql_rand to protect sql_rand across multiple instantiations that use
  sql_rand to generate random numbers.
 */
ulong sql_rnd_with_mutex()
{
  mysql_mutex_lock(&LOCK_sql_rand);
  ulong tmp=(ulong) (my_rnd(&sql_rand) * 0xffffffff); /* make all bits random */
  mysql_mutex_unlock(&LOCK_sql_rand);
  return tmp;
}

#ifdef HAVE_PSI_STATEMENT_INTERFACE
PSI_statement_info stmt_info_new_packet;
#endif

#ifndef EMBEDDED_LIBRARY
void net_before_header_psi(struct st_net *net, void *user_data, size_t /* unused: count */)
{
  THD *thd;
  thd= static_cast<THD*> (user_data);
  DBUG_ASSERT(thd != NULL);

  if (thd->m_server_idle)
  {
    /*
      The server is IDLE, waiting for the next command.
      Technically, it is a wait on a socket, which may take a long time,
      because the call is blocking.
      Disable the socket instrumentation, to avoid recording a SOCKET event.
      Instead, start explicitly an IDLE event.
    */
    MYSQL_SOCKET_SET_STATE(net->vio->mysql_socket, PSI_SOCKET_STATE_IDLE);
    MYSQL_START_IDLE_WAIT(thd->m_idle_psi, &thd->m_idle_state);
  }
}

void net_after_header_psi(struct st_net *net, void *user_data, size_t /* unused: count */, my_bool rc)
{
  THD *thd;
  thd= static_cast<THD*> (user_data);
  DBUG_ASSERT(thd != NULL);

  if (thd->m_server_idle)
  {
    /*
      The server just got data for a network packet header,
      from the network layer.
      The IDLE event is now complete, since we now have a message to process.
      We need to:
      - start a new STATEMENT event
      - start a new STAGE event, within this statement,
      - start recording SOCKET WAITS events, within this stage.
      The proper order is critical to get events numbered correctly,
      and nested in the proper parent.
    */
    MYSQL_END_IDLE_WAIT(thd->m_idle_psi);

    if (! rc)
    {
      thd->m_statement_psi= MYSQL_START_STATEMENT(&thd->m_statement_state,
                                                  stmt_info_new_packet.m_key,
                                                  thd->db, thd->db_length,
                                                  thd->charset());

    }

    /*
      TODO: consider recording a SOCKET event for the bytes just read,
      by also passing count here.
    */
    MYSQL_SOCKET_SET_STATE(net->vio->mysql_socket, PSI_SOCKET_STATE_ACTIVE);
  }
}

void init_net_server_extension(THD *thd)
{
#ifdef HAVE_PSI_INTERFACE
  /* Start with a clean state for connection events. */
  thd->m_idle_psi= NULL;
  thd->m_statement_psi= NULL;
  thd->m_server_idle= false;
  /* Hook up the NET_SERVER callback in the net layer. */
  thd->m_net_server_extension.m_user_data= thd;
  thd->m_net_server_extension.m_before_header= net_before_header_psi;
  thd->m_net_server_extension.m_after_header= net_after_header_psi;
  /* Activate this private extension for the mysqld server. */
  thd->net.extension= & thd->m_net_server_extension;
#else
  thd->net.extension= NULL;
#endif
}
#endif /* EMBEDDED_LIBRARY */

/**
  A log message for the error log, buffered in memory.
  Log messages are temporarily buffered when generated before the error log
  is initialized, and then printed once the error log is ready.
*/
class Buffered_log : public Sql_alloc
{
public:
  Buffered_log(enum loglevel level, const char *message);

  ~Buffered_log()
  {}

  void print(void);

private:
  /** Log message level. */
  enum loglevel m_level;
  /** Log message text. */
  String m_message;
};

/**
  Constructor.
  @param level          the message log level
  @param message        the message text
*/
Buffered_log::Buffered_log(enum loglevel level, const char *message)
  : m_level(level), m_message()
{
  m_message.copy(message, strlen(message), &my_charset_latin1);
}

/**
  Print a buffered log to the real log file.
*/
void Buffered_log::print()
{
  /*
    Since messages are buffered, they can be printed out
    of order with other entries in the log.
    Add "Buffered xxx" to the message text to prevent confusion.
  */
  switch(m_level)
  {
  case ERROR_LEVEL:
    sql_print_error("Buffered error: %s\n", m_message.c_ptr_safe());
    break;
  case WARNING_LEVEL:
    sql_print_warning("Buffered warning: %s\n", m_message.c_ptr_safe());
    break;
  case INFORMATION_LEVEL:
    /*
      Messages printed as "information" still end up in the mysqld *error* log,
      but with a [Note] tag instead of an [ERROR] tag.
      While this is probably fine for a human reading the log,
      it is upsetting existing automated scripts used to parse logs,
      because such scripts are likely to not already handle [Note] properly.
      INFORMATION_LEVEL messages are simply silenced, on purpose,
      to avoid un needed verbosity.
    */
    break;
  }
}

/**
  Collection of all the buffered log messages.
*/
class Buffered_logs
{
public:
  Buffered_logs()
  {}

  ~Buffered_logs()
  {}

  void init();
  void cleanup();

  void buffer(enum loglevel m_level, const char *msg);
  void print();
private:
  /**
    Memory root to use to store buffered logs.
    This memory root lifespan is between init and cleanup.
    Once the buffered logs are printed, they are not needed anymore,
    and all the memory used is reclaimed.
  */
  MEM_ROOT m_root;
  /** List of buffered log messages. */
  List<Buffered_log> m_list;
};

void Buffered_logs::init()
{
  init_alloc_root(&m_root, 1024, 0);
}

void Buffered_logs::cleanup()
{
  m_list.delete_elements();
  free_root(&m_root, MYF(0));
}

/**
  Add a log message to the buffer.
*/
void Buffered_logs::buffer(enum loglevel level, const char *msg)
{
  /*
    Do not let Sql_alloc::operator new(size_t) allocate memory,
    there is no memory root associated with the main() thread.
    Give explicitly the proper memory root to use to
    Sql_alloc::operator new(size_t, MEM_ROOT *) instead.
  */
  Buffered_log *log= new (&m_root) Buffered_log(level, msg);
  if (log)
    m_list.push_back(log, &m_root);
}

/**
  Print buffered log messages.
*/
void Buffered_logs::print()
{
  Buffered_log *log;
  List_iterator_fast<Buffered_log> it(m_list);
  while ((log= it++))
    log->print();
}

/** Logs reported before a logger is available. */
static Buffered_logs buffered_logs;

/**
  Error reporter that buffer log messages.
  @param level          log message level
  @param format         log message format string
*/
C_MODE_START
static void buffered_option_error_reporter(enum loglevel level,
                                           const char *format, ...)
{
  va_list args;
  char buffer[1024];

  va_start(args, format);
  my_vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  buffered_logs.buffer(level, buffer);
}


/**
  Character set and collation error reporter that prints to sql error log.
  @param level          log message level
  @param format         log message format string

  This routine is used to print character set and collation
  warnings and errors inside an already running mysqld server,
  e.g. when a character set or collation is requested for the very first time
  and its initialization does not go well for some reasons.

  Note: At early mysqld initialization stage,
  when error log is not yet available,
  we use buffered_option_error_reporter() instead,
  to print general character set subsystem initialization errors,
  such as Index.xml syntax problems, bad XML tag hierarchy, etc.
*/
static void charset_error_reporter(enum loglevel level,
                                   const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vprint_msg_to_log(level, format, args);
  va_end(args);                      
}
C_MODE_END

static MYSQL_SOCKET unix_sock, ip_sock;
struct rand_struct sql_rand; ///< used by sql_class.cc:THD::THD()

#ifndef EMBEDDED_LIBRARY
struct passwd *user_info;
static pthread_t select_thread;
static uint thr_kill_signal;
#endif

/* OS specific variables */

#ifdef __WIN__
#undef   getpid
#include <process.h>

static mysql_cond_t COND_handler_count;
static uint handler_count;
static bool start_mode=0, use_opt_args;
static int opt_argc;
static char **opt_argv;

#if !defined(EMBEDDED_LIBRARY)
static HANDLE hEventShutdown;
static char shutdown_event_name[40];
#include "nt_servc.h"
static   NTService  Service;        ///< Service object for WinNT
#endif /* EMBEDDED_LIBRARY */
#endif /* __WIN__ */

#ifdef _WIN32
static char pipe_name[512];
static SECURITY_ATTRIBUTES saPipeSecurity;
static SECURITY_DESCRIPTOR sdPipeDescriptor;
static HANDLE hPipe = INVALID_HANDLE_VALUE;
#endif

#ifndef EMBEDDED_LIBRARY
bool mysqld_embedded=0;
#else
bool mysqld_embedded=1;
#endif

static my_bool plugins_are_initialized= FALSE;

#ifndef DBUG_OFF
static const char* default_dbug_option;
#endif
#ifdef HAVE_LIBWRAP
const char *libwrapName= NULL;
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif
#ifdef HAVE_QUERY_CACHE
ulong query_cache_min_res_unit= QUERY_CACHE_MIN_RESULT_DATA_SIZE;
Query_cache query_cache;
#endif

my_bool opt_use_ssl  = 0;
char *opt_ssl_ca= NULL, *opt_ssl_capath= NULL, *opt_ssl_cert= NULL,
     *opt_ssl_cipher= NULL, *opt_ssl_key= NULL, *opt_ssl_crl= NULL,
     *opt_ssl_crlpath= NULL;

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#ifndef HAVE_YASSL
typedef struct CRYPTO_dynlock_value
{
  mysql_rwlock_t lock;
} openssl_lock_t;

static openssl_lock_t *openssl_stdlocks;
static openssl_lock_t *openssl_dynlock_create(const char *, int);
static void openssl_dynlock_destroy(openssl_lock_t *, const char *, int);
static void openssl_lock_function(int, int, const char *, int);
static void openssl_lock(int, openssl_lock_t *, const char *, int);
static unsigned long openssl_id_function();
#endif
char *des_key_file;
#ifndef EMBEDDED_LIBRARY
struct st_VioSSLFd *ssl_acceptor_fd;
#endif
#endif /* HAVE_OPENSSL */

/**
  Number of currently active user connections. The variable is protected by
  LOCK_connection_count.
*/
uint connection_count= 0;

/* Function declarations */

pthread_handler_t signal_hand(void *arg);
static int mysql_init_variables(void);
static int get_options(int *argc_ptr, char ***argv_ptr);
static void add_terminator(vector<my_option> *options);
extern "C" my_bool mysqld_get_one_option(int, const struct my_option *, char *);
static void set_server_version(void);
static int init_thread_environment();
static char *get_relative_path(const char *path);
static int fix_paths(void);
void handle_connections_sockets();
#ifdef _WIN32
pthread_handler_t handle_connections_sockets_thread(void *arg);
#endif
pthread_handler_t kill_server_thread(void *arg);
#ifdef _WIN32
pthread_handler_t handle_connections_namedpipes(void *arg);
#endif
#ifdef HAVE_SMEM
pthread_handler_t handle_connections_shared_memory(void *arg);
#endif
pthread_handler_t handle_slave(void *arg);
static void clean_up(bool print_message);

#ifndef EMBEDDED_LIBRARY
static void usage(void);
static void close_server_sock();
static void clean_up_mutexes(void);
static void wait_for_signal_thread_to_end(void);
static void mysqld_exit(int exit_code) __attribute__((noreturn));
#endif


#ifndef EMBEDDED_LIBRARY
/****************************************************************************
** Code to end mysqld
****************************************************************************/

static void close_connections(void)
{
#ifdef EXTRA_DEBUG
  int count=0;
#endif
  DBUG_ENTER("close_connections");

  /* Kill blocked pthreads */
  kill_blocked_pthreads_flag++;
  kill_blocked_pthreads();

  close_server_sock();

  /* Abort listening to new connections */
  DBUG_PRINT("quit",("Closing sockets"));
  if (!opt_disable_networking )
  {
    if (mysql_socket_getfd(ip_sock) != INVALID_SOCKET)
    {
      (void) mysql_socket_shutdown(ip_sock, SHUT_RDWR);
      (void) mysql_socket_close(ip_sock);
      ip_sock= MYSQL_INVALID_SOCKET;
    }
  }
#ifdef _WIN32
  if (hPipe != INVALID_HANDLE_VALUE && opt_enable_named_pipe)
  {
    HANDLE temp;
    DBUG_PRINT("quit", ("Closing named pipes") );

    /* Create connection to the handle named pipe handler to break the loop */
    if ((temp = CreateFile(pipe_name,
         GENERIC_READ | GENERIC_WRITE,
         0,
         NULL,
         OPEN_EXISTING,
         0,
         NULL )) != INVALID_HANDLE_VALUE)
    {
      WaitNamedPipe(pipe_name, 1000);
      DWORD dwMode = PIPE_READMODE_BYTE | PIPE_WAIT;
      SetNamedPipeHandleState(temp, &dwMode, NULL, NULL);
      CancelIo(temp);
      DisconnectNamedPipe(temp);
      CloseHandle(temp);
    }
  }
#endif
#ifdef HAVE_SYS_UN_H
  if (mysql_socket_getfd(unix_sock) != INVALID_SOCKET)
  {
    (void) mysql_socket_shutdown(unix_sock, SHUT_RDWR);
    (void) mysql_socket_close(unix_sock);
    (void) unlink(mysqld_unix_port);
    unix_sock= MYSQL_INVALID_SOCKET;
  }
#endif
//   end_thr_alarm(0);      // Abort old alarms.

  /*
    First signal all threads that it's time to die
    This will give the threads some time to gracefully abort their
    statements and inform their clients that the server is about to die.
  */

  sql_print_information("Giving %d client threads a chance to die gracefully",
                        static_cast<int>(get_thread_count()));

  mysql_mutex_lock(&LOCK_thread_count);

  Thread_iterator it= global_thread_list->begin();
  for (; it != global_thread_list->end(); ++it)
  {
    THD *tmp= *it;
    DBUG_PRINT("quit",("Informing thread %ld that it's time to die",
                       tmp->thread_id));
    /* We skip slave threads & scheduler on this first loop through. */
    if (tmp->slave_thread)
      continue;

    tmp->killed= THD::KILL_CONNECTION;
    MYSQL_CALLBACK(thread_scheduler, post_kill_notification, (tmp));
    mysql_mutex_lock(&tmp->LOCK_thd_data);
    if (tmp->mysys_var)
    {
      tmp->mysys_var->abort=1;
      mysql_mutex_lock(&tmp->mysys_var->mutex);
      if (tmp->mysys_var->current_cond)
      {
        mysql_mutex_lock(tmp->mysys_var->current_mutex);
        mysql_cond_broadcast(tmp->mysys_var->current_cond);
        mysql_mutex_unlock(tmp->mysys_var->current_mutex);
      }
      mysql_mutex_unlock(&tmp->mysys_var->mutex);
    }
    mysql_mutex_unlock(&tmp->LOCK_thd_data);
  }
  mysql_mutex_unlock(&LOCK_thread_count);

//   Events::deinit();

  sql_print_information("Shutting down slave threads");
//   end_slave();

  if (get_thread_count() > 0)
    sleep(2);         // Give threads time to die

  /*
    Force remaining threads to die by closing the connection to the client
    This will ensure that threads that are waiting for a command from the
    client on a blocking read call are aborted.
  */

  sql_print_information("Forcefully disconnecting %d remaining clients",
                        static_cast<int>(get_thread_count()));

#ifndef __bsdi__ // Bug in BSDI kernel
  DBUG_PRINT("quit", ("Locking LOCK_thread_count"));
  mysql_mutex_lock(&LOCK_thread_count);
  for (it= global_thread_list->begin(); it != global_thread_list->end(); ++it)
  {
    THD *tmp= *it;
    if (tmp->vio_ok())
    {
      if (log_warnings)
        sql_print_warning(ER_DEFAULT(ER_FORCING_CLOSE),my_progname,
                          tmp->thread_id,
                          (tmp->main_security_ctx.user ?
                           tmp->main_security_ctx.user : ""));
      close_connection(tmp);
    }
  }
  DBUG_PRINT("quit",("Unlocking LOCK_thread_count"));
  mysql_mutex_unlock(&LOCK_thread_count);
#endif // Bug in BSDI kernel

  /* All threads has now been aborted */
  DBUG_PRINT("quit",("Waiting for threads to die (count=%u)",
                     get_thread_count()));
  mysql_mutex_lock(&LOCK_thread_count);
  while (get_thread_count() > 0)
  {
    mysql_cond_wait(&COND_thread_count, &LOCK_thread_count);
    DBUG_PRINT("quit", ("One thread died (count=%u)", get_thread_count()));
  }
  mysql_mutex_unlock(&LOCK_thread_count);

//   close_active_mi();
  DBUG_PRINT("quit",("close_connections thread"));
  DBUG_VOID_RETURN;
}


static void close_server_sock()
{
#ifdef HAVE_CLOSE_SERVER_SOCK
  DBUG_ENTER("close_server_sock");
  MYSQL_SOCKET tmp_sock;
  tmp_sock=ip_sock;
  if (mysql_socket_getfd(tmp_sock) != INVALID_SOCKET)
  {
    ip_sock= MYSQL_INVALID_SOCKET;
    DBUG_PRINT("info",("calling shutdown on TCP/IP socket"));
    (void) mysql_socket_shutdown(tmp_sock, SHUT_RDWR);
  }
  tmp_sock=unix_sock;
  if (mysql_socket_getfd(tmp_sock) != INVALID_SOCKET)
  {
    unix_sock= MYSQL_INVALID_SOCKET;
    DBUG_PRINT("info",("calling shutdown on unix socket"));
    (void) mysql_socket_shutdown(tmp_sock, SHUT_RDWR);
    (void) unlink(mysqld_unix_port);
  }
  DBUG_VOID_RETURN;
#endif
}

#endif /*EMBEDDED_LIBRARY*/

/**
  Force server down. Kill all connections and threads and exit.

  @param  sig_ptr       Signal number that caused kill_server to be called.

  @note
    A signal number of 0 mean that the function was not called
    from a signal handler and there is thus no signal to block
    or stop, we just want to kill the server.
*/

#if !defined(__WIN__)
static void *kill_server(void *sig_ptr)
#define RETURN_FROM_KILL_SERVER return 0
#else
static void __cdecl kill_server(int sig_ptr)
#define RETURN_FROM_KILL_SERVER return
#endif
{
  DBUG_ENTER("kill_server");
  // if there is a signal during the kill in progress, ignore the other
  if (kill_in_progress)       // Safety
  {
    DBUG_LEAVE;
    RETURN_FROM_KILL_SERVER;
  }
  kill_in_progress=TRUE;
  abort_loop=1;         // This should be set
  sql_print_information(ER_DEFAULT(ER_NORMAL_SHUTDOWN),my_progname);

  close_connections();
  clean_up(1);

  /* purecov: begin deadcode */
  DBUG_LEAVE;                                   // Must match DBUG_ENTER()
  /* purecov: end */

  RETURN_FROM_KILL_SERVER;                      // Avoid compiler warnings

  DBUG_LEAVE;
  RETURN_FROM_KILL_SERVER;
}


#if defined(USE_ONE_SIGNAL_HAND)
pthread_handler_t kill_server_thread(void *arg __attribute__((unused)))
{
  my_thread_init();       // Initialize new thread
  kill_server(0);
  /* purecov: begin deadcode */
  my_thread_end();
  pthread_exit(0);
  return 0;
  /* purecov: end */
}
#endif


extern "C" sig_handler print_signal_warning(int sig)
{
  if (log_warnings)
    sql_print_warning("Got signal %d from thread %ld", sig,my_thread_id());
#ifdef SIGNAL_HANDLER_RESET_ON_DELIVERY
  my_sigset(sig,print_signal_warning);    /* int. thread system calls */
#endif
#if !defined(__WIN__)
  if (sig == SIGALRM)
    alarm(2);         /* reschedule alarm */
#endif
}

#ifndef EMBEDDED_LIBRARY

static void init_error_log_mutex()
{
  mysql_mutex_init(key_LOCK_error_log, &LOCK_error_log, MY_MUTEX_INIT_FAST);
}


static void clean_up_error_log_mutex()
{
  mysql_mutex_destroy(&LOCK_error_log);
}


/**
  cleanup all memory and end program nicely.

    If SIGNALS_DONT_BREAK_READ is defined, this function is called
    by the main thread. To get MySQL to shut down nicely in this case
    (Mac OS X) we have to call exit() instead if pthread_exit().

  @note
    This function never returns.
*/
void unireg_end(void)
{
  clean_up(1);
}


extern "C" void unireg_abort(int exit_code)
{
  DBUG_ENTER("unireg_abort");

  if (opt_help)
    usage();
  if (exit_code)
    sql_print_error("Aborting\n");
  clean_up(!opt_help && (exit_code || !opt_bootstrap)); /* purecov: inspected */
  DBUG_PRINT("quit",("done with cleanup in unireg_abort"));
  mysqld_exit(exit_code);
}

static void mysqld_exit(int exit_code)
{
  /*
    Important note: we wait for the signal thread to end,
    but if a kill -15 signal was sent, the signal thread did
    spawn the kill_server_thread thread, which is running concurrently.
  */
  wait_for_signal_thread_to_end();
//   mysql_audit_finalize();
  clean_up_mutexes();
  clean_up_error_log_mutex();
#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  shutdown_performance_schema();
#endif
  my_end(opt_endinfo ? MY_CHECK_ERROR | MY_GIVE_INFO : 0);
  exit(exit_code); /* purecov: inspected */
}

#endif /* !EMBEDDED_LIBRARY */

/**
   GTID cleanup destroys objects and reset their pointer.
   Function is reentrant.
*/
// void gtid_server_cleanup()
// {
//   delete gtid_state;
//   delete global_sid_map;
//   delete global_sid_lock;
//   global_sid_lock= NULL;
//   global_sid_map= NULL;
//   gtid_state= NULL;
// }

/**
   GTID initialization.

   @return true if allocation does not succeed
           false if OK
*/
// bool gtid_server_init()
// {
//   bool res=
//     (!(global_sid_lock= new Checkable_rwlock) ||
//      !(global_sid_map= new Sid_map(global_sid_lock)) ||
//      !(gtid_state= new Gtid_state(global_sid_lock, global_sid_map)));
//   if (res)
//   {
//     gtid_server_cleanup();
//   }
//   return res;
// }

void
mysql_osc_cache_free()
{
    osc_percent_cache_t* node;
    osc_percent_cache_t* nextnode;

    node = LIST_GET_FIRST(global_osc_cache.osc_lst);
    while(node)
    {
        nextnode = LIST_GET_NEXT(link, node);
        LIST_REMOVE(link, global_osc_cache.osc_lst, node);
        my_free(node);
        node = nextnode;
    }
}

void clean_up(bool print_message)
{
  DBUG_PRINT("exit",("clean_up"));
  if (cleanup_done++)
    return; /* purecov: inspected */
  my_free(isql_option);
  mysql_mutex_destroy(&isql_option_mutex);
  mysql_mutex_destroy(&osc_mutex);
  mysql_osc_cache_free();

  my_tz_free();
  my_dboptions_cache_free();
  servers_free(1);
  acl_free(1);
  query_cache_destroy();
  lex_free();       /* Free some memory */
  plugin_shutdown();
  ha_end();//free errors
  my_free_open_file_info();
  if (defaults_argv)
    free_defaults(defaults_argv);
  free_max_user_conn();
  vio_end();
  my_regex_end();
  if (print_message && my_default_lc_messages && server_start_time)
    sql_print_information(ER_DEFAULT(ER_SHUTDOWN_COMPLETE),my_progname);
  cleanup_errmsgs();
  MYSQL_CALLBACK(thread_scheduler, end, ());
  mysql_client_plugin_deinit();
  finish_client_errs();
  (void) my_error_unregister(ER_ERROR_FIRST, ER_ERROR_LAST); // finish server errs
  DBUG_PRINT("quit", ("Error messages freed"));
  my_atomic_rwlock_destroy(&global_query_id_lock);
  my_atomic_rwlock_destroy(&thread_running_lock);
  free_charsets();
  mysql_mutex_lock(&LOCK_thread_count);
  DBUG_PRINT("quit", ("got thread count lock"));
  ready_to_exit=1;
  /* do the broadcast inside the lock to ensure that my_end() is not called */
  mysql_cond_broadcast(&COND_thread_count);
  mysql_mutex_unlock(&LOCK_thread_count);
  sys_var_end();
  delete_global_thread_list();

  if (THR_THD)
    (void) pthread_key_delete(THR_THD);

  if (THR_MALLOC)
    (void) pthread_key_delete(THR_MALLOC);


  /*
    The following lines may never be executed as the main thread may have
    killed us
  */
  DBUG_PRINT("quit", ("done with cleanup"));
} /* clean_up */


#ifndef EMBEDDED_LIBRARY

/**
  This is mainly needed when running with purify, but it's still nice to
  know that all child threads have died when mysqld exits.
*/
static void wait_for_signal_thread_to_end()
{
  uint i;
  /*
    Wait up to 10 seconds for signal thread to die. We use this mainly to
    avoid getting warnings that my_thread_end has not been called
  */
  for (i= 0 ; i < 100 && signal_thread_in_use; i++)
  {
    if (pthread_kill(signal_thread, MYSQL_KILL_SIGNAL) != ESRCH)
      break;
    my_sleep(100);        // Give it time to die
  }
}


static void clean_up_mutexes()
{
  mysql_rwlock_destroy(&LOCK_grant);
  mysql_mutex_destroy(&LOCK_thread_created);
  mysql_mutex_destroy(&LOCK_thread_count);
  mysql_mutex_destroy(&LOCK_log_throttle_qni);
  mysql_mutex_destroy(&LOCK_status);
  mysql_mutex_destroy(&LOCK_delayed_insert);
  mysql_mutex_destroy(&LOCK_delayed_status);
  mysql_mutex_destroy(&LOCK_delayed_create);
//   mysql_mutex_destroy(&LOCK_manager);
  mysql_mutex_destroy(&LOCK_crypt);
  mysql_mutex_destroy(&LOCK_user_conn);
  mysql_mutex_destroy(&LOCK_connection_count);
#ifdef HAVE_OPENSSL
  mysql_mutex_destroy(&LOCK_des_key_file);
#ifndef HAVE_YASSL
  for (int i= 0; i < CRYPTO_num_locks(); ++i)
    mysql_rwlock_destroy(&openssl_stdlocks[i].lock);
  OPENSSL_free(openssl_stdlocks);
#endif
#endif
  mysql_mutex_destroy(&LOCK_active_mi);
  mysql_rwlock_destroy(&LOCK_sys_init_connect);
  mysql_rwlock_destroy(&LOCK_sys_init_slave);
  mysql_mutex_destroy(&LOCK_global_system_variables);
  mysql_rwlock_destroy(&LOCK_system_variables_hash);
  mysql_mutex_destroy(&LOCK_uuid_generator);
  mysql_mutex_destroy(&LOCK_sql_rand);
  mysql_mutex_destroy(&LOCK_prepared_stmt_count);
  mysql_mutex_destroy(&LOCK_sql_slave_skip_counter);
  mysql_mutex_destroy(&LOCK_slave_net_timeout);
  mysql_mutex_destroy(&LOCK_error_messages);
  mysql_cond_destroy(&COND_thread_count);
  mysql_cond_destroy(&COND_thread_cache);
  mysql_cond_destroy(&COND_flush_thread_cache);
//   mysql_cond_destroy(&COND_manager);
}
#endif /*EMBEDDED_LIBRARY*/


/****************************************************************************
** Init IP and UNIX socket
****************************************************************************/


/**
  MY_BIND_ALL_ADDRESSES defines a special value for the bind-address option,
  which means that the server should listen to all available network addresses,
  both IPv6 (if available) and IPv4.

  Basically, this value instructs the server to make an attempt to bind the
  server socket to '::' address, and rollback to '0.0.0.0' if the attempt fails.
*/
const char *MY_BIND_ALL_ADDRESSES= "*";


#ifndef EMBEDDED_LIBRARY
static void set_ports()
{
  char  *env;
  if (!mysqld_port && !opt_disable_networking)
  {         // Get port if not from commandline
    mysqld_port= MYSQL_PORT;

    /*
      if builder specifically requested a default port, use that
      (even if it coincides with our factory default).
      only if they didn't do we check /etc/services (and, failing
      on that, fall back to the factory default of 3306).
      either default can be overridden by the environment variable
      MYSQL_TCP_PORT, which in turn can be overridden with command
      line options.
    */

#if MYSQL_PORT_DEFAULT == 0
    struct  servent *serv_ptr;
    if ((serv_ptr= getservbyname("mysql", "tcp")))
      mysqld_port= ntohs((u_short) serv_ptr->s_port); /* purecov: inspected */
#endif
    if ((env = getenv("MYSQL_TCP_PORT")))
      mysqld_port= (uint) atoi(env);    /* purecov: inspected */
  }
  if (!mysqld_unix_port)
  {
#ifdef __WIN__
    mysqld_unix_port= (char*) MYSQL_NAMEDPIPE;
#else
    mysqld_unix_port= (char*) MYSQL_UNIX_ADDR;
#endif
    if ((env = getenv("MYSQL_UNIX_PORT")))
      mysqld_unix_port= env;      /* purecov: inspected */
  }
}

/** Change root user if started with @c --chroot . */
static void set_root(const char *path)
{
#if !defined(__WIN__)
  if (chroot(path) == -1)
  {
    sql_perror("chroot");
    unireg_abort(1);
  }
  my_setwd("/", MYF(0));
#endif
}


static MYSQL_SOCKET create_socket(const struct addrinfo *addrinfo_list,
                                  int addr_family,
                                  struct addrinfo **use_addrinfo)
{
  MYSQL_SOCKET sock= MYSQL_INVALID_SOCKET;

  for (const struct addrinfo *cur_ai= addrinfo_list; cur_ai != NULL;
       cur_ai= cur_ai->ai_next)
  {
    if (cur_ai->ai_family != addr_family)
      continue;

    sock= mysql_socket_socket(key_socket_tcpip, cur_ai->ai_family,
                              cur_ai->ai_socktype, cur_ai->ai_protocol);

    char ip_addr[INET6_ADDRSTRLEN];

    if (vio_getnameinfo(cur_ai->ai_addr, ip_addr, sizeof (ip_addr),
                        NULL, 0, NI_NUMERICHOST))
    {
      ip_addr[0]= 0;
    }

    if (mysql_socket_getfd(sock) == INVALID_SOCKET)
    {
      sql_print_error("Failed to create a socket for %s '%s': errno: %d.",
                      (addr_family == AF_INET) ? "IPv4" : "IPv6",
                      (const char *) ip_addr,
                      (int) socket_errno);

      continue;
    }

    sql_print_information("Server socket created on IP: '%s'.",
                          (const char *) ip_addr);

    *use_addrinfo= (struct addrinfo *)cur_ai;
    return sock;
  }

  return MYSQL_INVALID_SOCKET;
}

void print_sessions()
{
	char*	proc_info;
	CSET_STRING sql_string;

	if (global_thread_count == 0)
	{
		printf("There have no client thread connected to iSQL.\n");
		return;
	}

	printf("%-10s", "ID");
	printf("%-17s", "User");
	printf("%-20s", "Host");
	printf("%-10s", "DB");
	printf("%-10s", "Command");
	printf("%-10s", "Info");
	printf("\n");

	mysql_mutex_lock(&LOCK_thread_count);

	Thread_iterator it= global_thread_list->begin();
	for (; it != global_thread_list->end(); ++it)
	{
		THD *tmp= *it;
		Security_context *tmp_sctx= tmp->security_ctx;
		struct st_my_thread_var *mysys_var;
		if ((tmp->vio_ok() || tmp->system_thread))
		{
			printf("%-10d", tmp->thread_id);//ID
			printf("%-17s", tmp_sctx->user ? tmp_sctx->user :(tmp->system_thread ? "system user" : "unauthenticated user"));//USER
			printf("%-20s", tmp_sctx->host_or_ip[0] ? tmp_sctx->host_or_ip : tmp_sctx->host ? tmp_sctx->host : "");//host
			if (tmp->get_thd()->thd_sinfo != NULL)
			{
				if (tmp->get_thd()->thd_sinfo->db != NULL)//db
					printf("%-10s", tmp->get_thd()->thd_sinfo->db);
				else
					printf("%-10s", "Unknown DB");
			}
			
			proc_info = NULL;
			mysql_mutex_lock(&tmp->LOCK_thd_data);
			if ((mysys_var= tmp->mysys_var))
				mysql_mutex_lock(&mysys_var->mutex);
			proc_info= (char*) (tmp->killed == THD::KILL_CONNECTION? "Killed" : 0);
			if (mysys_var)
				mysql_mutex_unlock(&mysys_var->mutex);

			if (proc_info)//command
				printf("%-10s", proc_info);
			else
				printf("%-10s", command_name[(int) tmp->get_command()].str);

			proc_info = NULL;

			/* Lock THD mutex that protects its data when looking at it. */
			if (tmp->query())
			{
				uint length= min<uint>(100, tmp->query_length());
				/* Safety: in case strmake failed, we set length to 0. */
				sql_string= CSET_STRING(tmp->query(), tmp->query() ? length : 0, tmp->query_charset());
				printf("%-10s", sql_string.str());
			}
			else
			{
				printf("%-10s", "NULL");
			}
			
			printf("\n");
			mysql_mutex_unlock(&tmp->LOCK_thd_data);
		}
	}

	mysql_mutex_unlock(&LOCK_thread_count);
}

pthread_handler_t console_thread(void *arg __attribute__((unused)))
{
    char		buf[101];
    buf[0] = '\0';

	my_thread_init();
    while (1)
	{
        fgets(buf, 100, stdin);
        buf[strlen(buf) - 1] = '\0';
        if (strcmp(buf, "exit") == 0)
        {
			kill_server(0);
			break;
        }
		else if (strcmp(buf, "sessions") == 0)
		{
			print_sessions();
		}
        else
        {
            sql_print_information(ER_DEFAULT(ER_INVALID_COMMAND));

            continue;
        }
    }

	my_thread_end();
	pthread_exit(0);
    return 0;
}

static
void create_console_thread(void)
{
	pthread_t tmp;

    if (mysql_thread_create(0, &tmp, &connection_attrib, console_thread, (void*) 0))
    {
        sql_print_error("Can't create thread to kill server");
    }
}



static void network_init(void)
{
#ifdef HAVE_SYS_UN_H
  struct sockaddr_un  UNIXaddr;
#endif
  int arg;
  int   ret;
  uint  waited;
  uint  this_wait;
  uint  retry;
  char port_buf[NI_MAXSERV];
  DBUG_ENTER("network_init");
  LINT_INIT(ret);

  if (MYSQL_CALLBACK_ELSE(thread_scheduler, init, (), 0))
    unireg_abort(1);      /* purecov: inspected */

  set_ports();

  if (report_port == 0)
  {
    report_port= mysqld_port;
  }

#ifndef DBUG_OFF
  if (!opt_disable_networking)
    DBUG_ASSERT(report_port != 0);
#endif

  if (mysqld_port != 0 && !opt_disable_networking && !opt_bootstrap)
  {
    struct addrinfo *ai;
    struct addrinfo hints;

    const char *bind_address_str= NULL;
    const char *ipv6_all_addresses= "::";
    const char *ipv4_all_addresses= "0.0.0.0";

    sql_print_information("Server hostname (bind-address): '%s'; port: %d",
                          my_bind_addr_str, mysqld_port);

    // Get list of IP-addresses associated with the bind-address.

    memset(&hints, 0, sizeof (hints));
    hints.ai_flags= AI_PASSIVE;
    hints.ai_socktype= SOCK_STREAM;
    hints.ai_family= AF_UNSPEC;

    my_snprintf(port_buf, NI_MAXSERV, "%d", mysqld_port);

    if (strcasecmp(my_bind_addr_str, MY_BIND_ALL_ADDRESSES) == 0)
    {
      /*
        That's the case when bind-address is set to a special value ('*'),
        meaning "bind to all available IP addresses". If the box supports
        the IPv6 stack, that means binding to '::'. If only IPv4 is available,
        bind to '0.0.0.0'.
      */

      bool ipv6_available= false;

      if (!getaddrinfo(ipv6_all_addresses, port_buf, &hints, &ai))
      {
        /*
          IPv6 might be available (the system might be able to resolve an IPv6
          address, but not be able to create an IPv6-socket). Try to create a
          dummy IPv6-socket. Do not instrument that socket by P_S.
        */

        MYSQL_SOCKET s= mysql_socket_socket(0, AF_INET6, SOCK_STREAM, 0);

        ipv6_available= mysql_socket_getfd(s) != INVALID_SOCKET;

        mysql_socket_close(s);
      }

      if (ipv6_available)
      {
        sql_print_information("IPv6 is available.");

        // Address info (ai) for IPv6 address is already set.

        bind_address_str= ipv6_all_addresses;
      }
      else
      {
        sql_print_information("IPv6 is not available.");

        // Retrieve address info (ai) for IPv4 address.

        if (getaddrinfo(ipv4_all_addresses, port_buf, &hints, &ai))
        {
          sql_perror(ER_DEFAULT(ER_IPSOCK_ERROR));
          sql_print_error("Can't start server: cannot resolve hostname!");
          unireg_abort(1);
        }

        bind_address_str= ipv4_all_addresses;
      }
    }
    else
    {
      if (getaddrinfo(my_bind_addr_str, port_buf, &hints, &ai))
      {
        sql_perror(ER_DEFAULT(ER_IPSOCK_ERROR));  /* purecov: tested */
        sql_print_error("Can't start server: cannot resolve hostname!");
        unireg_abort(1);                          /* purecov: tested */
      }

      bind_address_str= my_bind_addr_str;
    }

    // Log all the IP-addresses.
    for (struct addrinfo *cur_ai= ai; cur_ai != NULL; cur_ai= cur_ai->ai_next)
    {
      char ip_addr[INET6_ADDRSTRLEN];

      if (vio_getnameinfo(cur_ai->ai_addr, ip_addr, sizeof (ip_addr),
                          NULL, 0, NI_NUMERICHOST))
      {
        sql_print_error("Fails to print out IP-address.");
        continue;
      }

      sql_print_information("  - '%s' resolves to '%s';",
                            bind_address_str, ip_addr);
    }

    /*
      If the 'bind-address' option specifies the hostname, which resolves to
      multiple IP-address, use the following rule:
      - if there are IPv4-addresses, use the first IPv4-address
      returned by getaddrinfo();
      - if there are IPv6-addresses, use the first IPv6-address
      returned by getaddrinfo();
    */

    struct addrinfo *a;
    ip_sock= create_socket(ai, AF_INET, &a);

    if (mysql_socket_getfd(ip_sock) == INVALID_SOCKET)
      ip_sock= create_socket(ai, AF_INET6, &a);

    // Report user-error if we failed to create a socket.
    if (mysql_socket_getfd(ip_sock) == INVALID_SOCKET)
    {
      sql_perror(ER_DEFAULT(ER_IPSOCK_ERROR));  /* purecov: tested */
      unireg_abort(1);                          /* purecov: tested */
    }

    mysql_socket_set_thread_owner(ip_sock);

#ifndef __WIN__
    /*
      We should not use SO_REUSEADDR on windows as this would enable a
      user to open two mysqld servers with the same TCP/IP port.
    */
    arg= 1;
    (void) mysql_socket_setsockopt(ip_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&arg,sizeof(arg));
#endif /* __WIN__ */

#ifdef IPV6_V6ONLY
     /*
       For interoperability with older clients, IPv6 socket should
       listen on both IPv6 and IPv4 wildcard addresses.
       Turn off IPV6_V6ONLY option.

       NOTE: this will work starting from Windows Vista only.
       On Windows XP dual stack is not available, so it will not
       listen on the corresponding IPv4-address.
     */
    if (a->ai_family == AF_INET6)
    {
      arg= 0;

      if (mysql_socket_setsockopt(ip_sock, IPPROTO_IPV6, IPV6_V6ONLY,
                                  (char *) &arg, sizeof (arg)))
      {
        sql_print_warning("Failed to reset IPV6_V6ONLY flag (error: %d). "
                          "The server will listen to IPv6 addresses only.",
                          (int) socket_errno);
      }
    }
#endif
    /*
      Sometimes the port is not released fast enough when stopping and
      restarting the server. This happens quite often with the test suite
      on busy Linux systems. Retry to bind the address at these intervals:
      Sleep intervals: 1, 2, 4,  6,  9, 13, 17, 22, ...
      Retry at second: 1, 3, 7, 13, 22, 35, 52, 74, ...
      Limit the sequence by mysqld_port_timeout (set --port-open-timeout=#).
    */
    for (waited= 0, retry= 1; ; retry++, waited+= this_wait)
    {
      if (((ret= mysql_socket_bind(ip_sock, a->ai_addr, a->ai_addrlen)) >= 0 ) ||
          (socket_errno != SOCKET_EADDRINUSE) ||
          (waited >= mysqld_port_timeout))
        break;
      sql_print_information("Retrying bind on TCP/IP port %u", mysqld_port);
      this_wait= retry * retry / 3 + 1;
      sleep(this_wait);
    }
    freeaddrinfo(ai);
    if (ret < 0)
    {
      DBUG_PRINT("error",("Got error: %d from bind",socket_errno));
      sql_perror("Can't start server: Bind on TCP/IP port");
      sql_print_error("Do you already have another mysqld server running on port: %d ?",mysqld_port);
      unireg_abort(1);
    }
    if (mysql_socket_listen(ip_sock, (int)back_log) < 0)
    {
      sql_perror("Can't start server: listen() on TCP/IP port");
      sql_print_error("listen() on TCP/IP failed with error %d",
          socket_errno);
      unireg_abort(1);
    }
  }

#ifdef _WIN32
  /* create named pipe */
  if (Service.IsNT() && mysqld_unix_port[0] && !opt_bootstrap &&
      opt_enable_named_pipe)
  {
    strxnmov(pipe_name, sizeof(pipe_name)-1, "\\\\.\\pipe\\",
       mysqld_unix_port, NullS);
    memset(&saPipeSecurity, 0, sizeof(saPipeSecurity));
    memset(&sdPipeDescriptor, 0, sizeof(sdPipeDescriptor));
    if (!InitializeSecurityDescriptor(&sdPipeDescriptor,
              SECURITY_DESCRIPTOR_REVISION))
    {
      sql_perror("Can't start server : Initialize security descriptor");
      unireg_abort(1);
    }
    if (!SetSecurityDescriptorDacl(&sdPipeDescriptor, TRUE, NULL, FALSE))
    {
      sql_perror("Can't start server : Set security descriptor");
      unireg_abort(1);
    }
    saPipeSecurity.nLength = sizeof(SECURITY_ATTRIBUTES);
    saPipeSecurity.lpSecurityDescriptor = &sdPipeDescriptor;
    saPipeSecurity.bInheritHandle = FALSE;
    if ((hPipe= CreateNamedPipe(pipe_name,
        PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE |
        PIPE_READMODE_BYTE |
        PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        (int) global_system_variables.net_buffer_length,
        (int) global_system_variables.net_buffer_length,
        NMPWAIT_USE_DEFAULT_WAIT,
        &saPipeSecurity)) == INVALID_HANDLE_VALUE)
      {
  LPVOID lpMsgBuf;
  int error=GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
          FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
          (LPTSTR) &lpMsgBuf, 0, NULL );
  sql_perror((char *)lpMsgBuf);
  LocalFree(lpMsgBuf);
  unireg_abort(1);
      }
  }
#endif

#if defined(HAVE_SYS_UN_H)
  /*
  ** Create the UNIX socket
  */
  if (mysqld_unix_port[0] && !opt_bootstrap)
  {
    DBUG_PRINT("general",("UNIX Socket is %s",mysqld_unix_port));

    if (strlen(mysqld_unix_port) > (sizeof(UNIXaddr.sun_path) - 1))
    {
      sql_print_error("The socket file path is too long (> %u): %s",
                      (uint) sizeof(UNIXaddr.sun_path) - 1, mysqld_unix_port);
      unireg_abort(1);
    }

    unix_sock= mysql_socket_socket(key_socket_unix, AF_UNIX, SOCK_STREAM, 0);

    if (mysql_socket_getfd(unix_sock) < 0)
    {
      sql_perror("Can't start server : UNIX Socket "); /* purecov: inspected */
      unireg_abort(1);        /* purecov: inspected */
    }

    mysql_socket_set_thread_owner(unix_sock);

    memset(&UNIXaddr, 0, sizeof(UNIXaddr));
    UNIXaddr.sun_family = AF_UNIX;
    strmov(UNIXaddr.sun_path, mysqld_unix_port);
    (void) unlink(mysqld_unix_port);
    arg= 1;
    (void) mysql_socket_setsockopt(unix_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&arg,
          sizeof(arg));
    umask(0);
    if (mysql_socket_bind(unix_sock, reinterpret_cast<struct sockaddr *> (&UNIXaddr),
                          sizeof(UNIXaddr)) < 0)
    {
      sql_perror("Can't start server : Bind on unix socket"); /* purecov: tested */
      sql_print_error("Do you already have another mysqld server running on socket: %s ?",mysqld_unix_port);
      unireg_abort(1);          /* purecov: tested */
    }
    umask(((~my_umask) & 0666));
#if defined(S_IFSOCK) && defined(SECURE_SOCKETS)
    (void) chmod(mysqld_unix_port,S_IFSOCK);  /* Fix solaris 2.6 bug */
#endif
    if (mysql_socket_listen(unix_sock, (int)back_log) < 0)
      sql_print_warning("listen() on Unix socket failed with error %d",
          socket_errno);
  }
#endif
  DBUG_PRINT("info",("server started"));
  DBUG_VOID_RETURN;
}

#endif /*!EMBEDDED_LIBRARY*/


#ifndef EMBEDDED_LIBRARY
/**
  Close a connection.

  @param thd        Thread handle.
  @param sql_errno  The error code to send before disconnect.

  @note
    For the connection that is doing shutdown, this is called twice
*/
void close_connection(THD *thd, uint sql_errno)
{
  DBUG_ENTER("close_connection");

  if (sql_errno)
    net_send_error(thd, sql_errno, ER_DEFAULT(sql_errno), NULL);

  thd->disconnect();

  MYSQL_CONNECTION_DONE((int) sql_errno, thd->thread_id);

  if (MYSQL_CONNECTION_DONE_ENABLED())
  {
    sleep(0); /* Workaround to avoid tailcall optimisation */
  }
//   MYSQL_AUDIT_NOTIFY_CONNECTION_DISCONNECT(thd, sql_errno);
  DBUG_VOID_RETURN;
}
#endif /* EMBEDDED_LIBRARY */


/** Called when a thread is aborted. */
/* ARGSUSED */
extern "C" sig_handler end_thread_signal(int sig __attribute__((unused)))
{
  THD *thd=current_thd;
  my_safe_printf_stderr("end_thread_signal %p", thd);
  if (thd && ! thd->bootstrap)
  {
    statistic_increment(killed_threads, &LOCK_status);
    MYSQL_CALLBACK(thread_scheduler, end_thread, (thd,0)); /* purecov: inspected */
  }
}


/*
  Rlease resources of the THD, prior to destruction.

  SYNOPSIS
    thd_release_resources()
    thd    Thread handler
*/

void thd_release_resources(THD *thd)
{
  thd->release_resources();
}

/*
  Decrease number of connections

  SYNOPSIS
    dec_connection_count()
*/

void dec_connection_count()
{
  mysql_mutex_lock(&LOCK_connection_count);
  --connection_count;
  mysql_mutex_unlock(&LOCK_connection_count);
}


/**
  Delete the THD object.
 */
void destroy_thd(THD *thd)
{
  mysql_mutex_assert_not_owner(&LOCK_thread_count);
  delete thd;
}


/**
  Block the current pthread for reuse by new connections.

  @retval false  Pthread was not blocked for reuse.
  @retval true   Pthread is to be reused by new connection.
                 (ie, caller should return, not abort with pthread_exit())
*/

static bool block_until_new_connection()
{
  mysql_mutex_lock(&LOCK_thread_count);
  if (blocked_pthread_count < max_blocked_pthreads &&
      !abort_loop && !kill_blocked_pthreads_flag)
  {
    /* Don't kill the pthread, just block it for reuse */
    DBUG_PRINT("info", ("Blocking pthread for reuse"));
    blocked_pthread_count++;

    DBUG_POP();
    /*
      mysys_var is bound to the physical thread,
      so make sure mysys_var->dbug is reset to a clean state
      before picking another session in the thread cache.
    */
    DBUG_ASSERT( ! _db_is_pushed_());

#ifdef HAVE_PSI_THREAD_INTERFACE
    /*
      Delete the instrumentation for the job that just completed,
      before blocking this pthread (blocked on COND_thread_cache).
    */
    PSI_THREAD_CALL(delete_current_thread)();
#endif

    // Block pthread
    while (!abort_loop && !wake_pthread && !kill_blocked_pthreads_flag)
      mysql_cond_wait(&COND_thread_cache, &LOCK_thread_count);

    blocked_pthread_count--;
    if (kill_blocked_pthreads_flag)
      mysql_cond_signal(&COND_flush_thread_cache);
    if (wake_pthread)
    {
      THD *thd;
      wake_pthread--;
      DBUG_ASSERT(!waiting_thd_list->empty());
      thd= waiting_thd_list->front();
      waiting_thd_list->pop_front();
      DBUG_PRINT("info", ("waiting_thd_list->pop %p", thd));

      thd->thread_stack= (char*) &thd;          // For store_globals
      (void) thd->store_globals();

      /*
        THD::mysys_var::abort is associated with physical thread rather
        than with THD object. So we need to reset this flag before using
        this thread for handling of new THD object/connection.
      */
      thd->mysys_var->abort= 0;
      thd->thr_create_utime= my_micro_time();
      add_global_thread(thd);
      mysql_mutex_unlock(&LOCK_thread_count);
      return true;
    }
  }
  mysql_mutex_unlock(&LOCK_thread_count);
  return false;
}


/**
  End thread for the current connection

  @param thd            Thread handler
  @param block_pthread  Block the pthread so it can be reused later.
                        Normally this is true in all cases except when we got
                        out of resources initializing the current thread

  @retval false  Signal to handle_one_connection to reuse connection

  @note If the pthread is blocked, we will wait until the pthread is
        scheduled to be reused and then return.
        If the pthread is not to be blocked, it will be ended.
*/

bool one_thread_per_connection_end(THD *thd, bool block_pthread)
{
  DBUG_ENTER("one_thread_per_connection_end");
  DBUG_PRINT("info", ("thd %p block_pthread %d", thd, (int) block_pthread));

  thd->release_resources();
  dec_connection_count();

  mysql_mutex_lock(&LOCK_thread_count);
  /*
    Used by binlog_reset_master.  It would be cleaner to use
    DEBUG_SYNC here, but that's not possible because the THD's debug
    sync feature has been shut down at this point.
  */
  DBUG_EXECUTE_IF("sleep_after_lock_thread_count_before_delete_thd", sleep(5););
  remove_global_thread(thd);
  mysql_mutex_unlock(&LOCK_thread_count);
  delete thd;

  if (block_pthread)
    block_pthread= block_until_new_connection();

  if (block_pthread)
    DBUG_RETURN(false);                         // Pthread is reused

  /* It's safe to broadcast outside a lock (COND... is not deleted here) */
  DBUG_PRINT("signal", ("Broadcasting COND_thread_count"));
  DBUG_LEAVE;                                   // Must match DBUG_ENTER()
  my_thread_end();
// #ifndef EMBEDDED_LIBRARY
//   ERR_remove_state(0);
// #endif
  mysql_cond_broadcast(&COND_thread_count);

  pthread_exit(0);
  return false;                                 // Avoid compiler warnings
}


void kill_blocked_pthreads()
{
  mysql_mutex_lock(&LOCK_thread_count);
  kill_blocked_pthreads_flag++;
  while (blocked_pthread_count)
  {
    mysql_cond_broadcast(&COND_thread_cache);
    mysql_cond_wait(&COND_flush_thread_cache, &LOCK_thread_count);
  }
  kill_blocked_pthreads_flag--;
  mysql_mutex_unlock(&LOCK_thread_count);
}


#ifdef THREAD_SPECIFIC_SIGPIPE
/**
  Aborts a thread nicely. Comes here on SIGPIPE.

  @todo
    One should have to fix that thr_alarm know about this thread too.
*/
extern "C" sig_handler abort_thread(int sig __attribute__((unused)))
{
  THD *thd=current_thd;
  DBUG_ENTER("abort_thread");
  if (thd)
    thd->killed= THD::KILL_CONNECTION;
  DBUG_VOID_RETURN;
}
#endif

static void console_event_handler(int i)
{
    signal(SIGINT, console_event_handler);
}

/******************************************************************************
  Setup a signal thread with handles all signals.
  Because Linux doesn't support schemas use a mutex to check that
  the signal thread is ready before continuing
******************************************************************************/

#if defined(__WIN__)


/*
  On Windows, we use native SetConsoleCtrlHandler for handle events like Ctrl-C
  with graceful shutdown.
  Also, we do not use signal(), but SetUnhandledExceptionFilter instead - as it
  provides possibility to pass the exception to just-in-time debugger, collect
  dumps and potentially also the exception and thread context used to output
  callstack.
*/





#ifdef DEBUG_UNHANDLED_EXCEPTION_FILTER
#define DEBUGGER_ATTACH_TIMEOUT 120
/*
  Wait for debugger to attach and break into debugger. If debugger is not attached,
  resume after timeout.
*/
static void wait_for_debugger(int timeout_sec)
{
   if(!IsDebuggerPresent())
   {
     int i;
     printf("Waiting for debugger to attach, pid=%u\n",GetCurrentProcessId());
     fflush(stdout);
     for(i= 0; i < timeout_sec; i++)
     {
       Sleep(1000);
       if(IsDebuggerPresent())
       {
         /* Break into debugger */
         __debugbreak();
         return;
       }
     }
     printf("pid=%u, debugger not attached after %d seconds, resuming\n",GetCurrentProcessId(),
       timeout_sec);
     fflush(stdout);
   }
}
#endif /* DEBUG_UNHANDLED_EXCEPTION_FILTER */

LONG WINAPI my_unhandler_exception_filter(EXCEPTION_POINTERS *ex_pointers)
{
   static BOOL first_time= TRUE;
   if(!first_time)
   {
     /*
       This routine can be called twice, typically
       when detaching in JIT debugger.
       Return EXCEPTION_EXECUTE_HANDLER to terminate process.
     */
     return EXCEPTION_EXECUTE_HANDLER;
   }
   first_time= FALSE;
#ifdef DEBUG_UNHANDLED_EXCEPTION_FILTER
   /*
    Unfortunately there is no clean way to debug unhandled exception filters,
    as debugger does not stop there(also documented in MSDN)
    To overcome, one could put a MessageBox, but this will not work in service.
    Better solution is to print error message and sleep some minutes
    until debugger is attached
  */
  wait_for_debugger(DEBUGGER_ATTACH_TIMEOUT);
#endif /* DEBUG_UNHANDLED_EXCEPTION_FILTER */
  __try
  {
    my_set_exception_pointers(ex_pointers);
    handle_fatal_signal(ex_pointers->ExceptionRecord->ExceptionCode);
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    DWORD written;
    const char msg[] = "Got exception in exception handler!\n";
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),msg, sizeof(msg)-1,
      &written,NULL);
  }
  /*
    Return EXCEPTION_CONTINUE_SEARCH to give JIT debugger
    (drwtsn32 or vsjitdebugger) possibility to attach,
    if JIT debugger is configured.
    Windows Error reporting might generate a dump here.
  */
  return EXCEPTION_CONTINUE_SEARCH;
}


void my_init_signals(void)
{
  signal(SIGINT, console_event_handler);

    /* Avoid MessageBox()es*/
  _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);

   /*
     Do not use SEM_NOGPFAULTERRORBOX in the following SetErrorMode (),
     because it would prevent JIT debugger and Windows error reporting
     from working. We need WER or JIT-debugging, since our own unhandled
     exception filter is not guaranteed to work in all situation
     (like heap corruption or stack overflow)
   */
  SetErrorMode(SetErrorMode(0) | SEM_FAILCRITICALERRORS
                               | SEM_NOOPENFILEERRORBOX);
  SetUnhandledExceptionFilter(my_unhandler_exception_filter);
}

#endif /* __WIN__ */


#if BACKTRACE_DEMANGLE
#include <cxxabi.h>
extern "C" char *my_demangle(const char *mangled_name, int *status)
{
  return abi::__cxa_demangle(mangled_name, NULL, NULL, status);
}
#endif


#if !defined(__WIN__)
#ifndef SA_RESETHAND
#define SA_RESETHAND 0
#endif
#ifndef SA_NODEFER
#define SA_NODEFER 0
#endif

#ifndef EMBEDDED_LIBRARY

void my_init_signals(void)
{
  sigset_t set;
  struct sigaction sa;
  DBUG_ENTER("my_init_signals");

  my_sigset(THR_SERVER_ALARM,print_signal_warning); // Should never be called!

  if (!(test_flags & TEST_NO_STACKTRACE) || (test_flags & TEST_CORE_ON_SIGNAL))
  {
    sa.sa_flags = SA_RESETHAND | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigprocmask(SIG_SETMASK,&sa.sa_mask,NULL);

#ifdef HAVE_STACKTRACE
    my_init_stacktrace();
#endif
#if defined(__amiga__)
    sa.sa_handler=(void(*)())handle_fatal_signal;
#else
    sa.sa_handler=handle_fatal_signal;
#endif
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
#ifdef SIGBUS
    sigaction(SIGBUS, &sa, NULL);
#endif
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
  }

#ifdef HAVE_GETRLIMIT
  if (test_flags & TEST_CORE_ON_SIGNAL)
  {
    /* Change limits so that we will get a core file */
    STRUCT_RLIMIT rl;
    rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &rl) && log_warnings)
      sql_print_warning("setrlimit could not change the size of core files to 'infinity';  We may not be able to generate a core file on signals");
  }
#endif
  (void) sigemptyset(&set);
  my_sigset(SIGPIPE,SIG_IGN);
  sigaddset(&set,SIGPIPE);
#ifndef IGNORE_SIGHUP_SIGQUIT
  sigaddset(&set,SIGQUIT);
  sigaddset(&set,SIGHUP);
#endif
  sigaddset(&set,SIGTERM);

  /* Fix signals if blocked by parents (can happen on Mac OS X) */
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = print_signal_warning;
  sigaction(SIGTERM, &sa, (struct sigaction*) 0);
  sa.sa_flags = 0;
  sa.sa_handler = print_signal_warning;
  sigaction(SIGHUP, &sa, (struct sigaction*) 0);
#ifdef SIGTSTP
  sigaddset(&set,SIGTSTP);
#endif
  if (thd_lib_detected != THD_LIB_LT)
    sigaddset(&set,THR_SERVER_ALARM);

  signal(SIGINT, console_event_handler);
  sigprocmask(SIG_SETMASK,&set,NULL);
  pthread_sigmask(SIG_SETMASK,&set,NULL);
  DBUG_VOID_RETURN;
}


// static void start_signal_handler(void)
// {
//   int error;
//   pthread_attr_t thr_attr;
//   DBUG_ENTER("start_signal_handler");
// 
//   (void) pthread_attr_init(&thr_attr);
// #if !defined(HAVE_DEC_3_2_THREADS)
//   pthread_attr_setscope(&thr_attr,PTHREAD_SCOPE_SYSTEM);
//   (void) pthread_attr_setdetachstate(&thr_attr,PTHREAD_CREATE_DETACHED);
// #if defined(__ia64__) || defined(__ia64)
//   /*
//     Peculiar things with ia64 platforms - it seems we only have half the
//     stack size in reality, so we have to double it here
//   */
//   pthread_attr_setstacksize(&thr_attr,my_thread_stack_size*2);
// #else
//   pthread_attr_setstacksize(&thr_attr,my_thread_stack_size);
// #endif
// #endif
// 
//   mysql_mutex_lock(&LOCK_thread_count);
//   if ((error= mysql_thread_create(key_thread_signal_hand,
//                                   &signal_thread, &thr_attr, signal_hand, 0)))
//   {
//     sql_print_error("Can't create interrupt-thread (error %d, errno: %d)",
//         error,errno);
//     exit(1);
//   }
//   mysql_cond_wait(&COND_thread_count, &LOCK_thread_count);
//   mysql_mutex_unlock(&LOCK_thread_count);
// 
//   (void) pthread_attr_destroy(&thr_attr);
//   DBUG_VOID_RETURN;
// }


/** This threads handles all signals and alarms. */
/* ARGSUSED */
pthread_handler_t signal_hand(void *arg __attribute__((unused)))
{
  sigset_t set;
  int sig;
  my_thread_init();       // Init new thread
  signal_thread_in_use= 1;

  /*
    Setup alarm handler
    This should actually be '+ max_number_of_slaves' instead of +10,
    but the +10 should be quite safe.
  */
  if (thd_lib_detected != THD_LIB_LT && (test_flags & TEST_SIGINT))
  {
    (void) sigemptyset(&set);     // Setup up SIGINT for debug
    (void) sigaddset(&set,SIGINT);    // For debugging
    (void) pthread_sigmask(SIG_UNBLOCK,&set,NULL);
  }
  (void) sigemptyset(&set);     // Setup up SIGINT for debug
#ifdef USE_ONE_SIGNAL_HAND
  (void) sigaddset(&set,THR_SERVER_ALARM);  // For alarms
#endif
#ifndef IGNORE_SIGHUP_SIGQUIT
  (void) sigaddset(&set,SIGQUIT);
  (void) sigaddset(&set,SIGHUP);
#endif
  (void) sigaddset(&set,SIGTERM);
  (void) sigaddset(&set,SIGTSTP);

  /* Save pid to this process (or thread on Linux) */
//   if (!opt_bootstrap)
//     create_pid_file();

  /*
    signal to start_signal_handler that we are ready
    This works by waiting for start_signal_handler to free mutex,
    after which we signal it that we are ready.
    At this pointer there is no other threads running, so there
    should not be any other mysql_cond_signal() calls.
  */
  mysql_mutex_lock(&LOCK_thread_count);
  mysql_cond_broadcast(&COND_thread_count);
  mysql_mutex_unlock(&LOCK_thread_count);

  /*
    Waiting for until mysqld_server_started != 0
    to ensure that all server components has been successfully
    initialized. This step is mandatory since signal processing
    could be done safely only when all server components
    has been initialized.
  */
  mysql_mutex_lock(&LOCK_server_started);
  while (!mysqld_server_started)
    mysql_cond_wait(&COND_server_started, &LOCK_server_started);
  mysql_mutex_unlock(&LOCK_server_started);

  for (;;)
  {
    int error;          // Used when debugging
    if (shutdown_in_progress && !abort_loop)
    {
      sig= SIGTERM;
      error=0;
    }
    else
      while ((error=my_sigwait(&set,&sig)) == EINTR) ;
    if (cleanup_done)
    {
      my_thread_end();
      signal_thread_in_use= 0;
      pthread_exit(0);        // Safety
      return 0;                                 // Avoid compiler warnings
    }
    switch (sig) {
    case SIGTERM:
    case SIGQUIT:
    case SIGKILL:
#ifdef EXTRA_DEBUG
      sql_print_information("Got signal %d to shutdown mysqld",sig);
#endif
      /* switch to the old log message processing */
      DBUG_PRINT("info",("Got signal: %d  abort_loop: %d",sig,abort_loop));
      if (!abort_loop)
      {
        abort_loop=1;       // mark abort for threads
#ifdef HAVE_PSI_THREAD_INTERFACE
        /* Delete the instrumentation for the signal thread */
        PSI_THREAD_CALL(delete_current_thread)();
#endif
#ifdef USE_ONE_SIGNAL_HAND
        pthread_t tmp;
        if (mysql_thread_create(0, /* Not instrumented */
                                &tmp, &connection_attrib, kill_server_thread,
                                (void*) &sig))
          sql_print_error("Can't create thread to kill server");
#else
        kill_server((void*) sig); // MIT THREAD has a alarm thread
#endif
      }
      break;
    default:
#ifdef EXTRA_DEBUG
      sql_print_warning("Got signal: %d  error: %d",sig,error); /* purecov: tested */
#endif
      break;          /* purecov: tested */
    }
  }
  return(0);          /* purecov: deadcode */
}

#endif /*!EMBEDDED_LIBRARY*/
#endif  /* __WIN__*/


/**
  All global error messages are sent here where the first one is stored
  for the client.
*/
/* ARGSUSED */
extern "C" void my_message_sql(uint error, const char *str, myf MyFlags);

void my_message_sql(uint error, const char *str, myf MyFlags)
{
  THD *thd= current_thd;
  DBUG_ENTER("my_message_sql");
  DBUG_PRINT("error", ("error: %u  message: '%s'", error, str));

  DBUG_ASSERT(str != NULL);
  /*
    An error should have a valid error number (!= 0), so it can be caught
    in stored procedures by SQL exception handlers.
    Calling my_error() with error == 0 is a bug.
    Remaining known places to fix:
    - storage/myisam/mi_create.c, my_printf_error()
    TODO:
    DBUG_ASSERT(error != 0);
  */

  if (error == 0)
  {
    /* At least, prevent new abuse ... */
    DBUG_ASSERT(strncmp(str, "MyISAM table", 12) == 0);
    error= ER_UNKNOWN_ERROR;
  }

  //mysql_audit_general(thd, MYSQL_AUDIT_GENERAL_ERROR, error, str);

  if (thd)
  {
    if (MyFlags & ME_FATALERROR)
      thd->is_fatal_error= 1;
    (void) thd->raise_condition(error,
                                NULL,
                                Sql_condition::WARN_LEVEL_ERROR,
                                str);
  }

  /* When simulating OOM, skip writing to error log to avoid mtr errors */
  DBUG_EXECUTE_IF("simulate_out_of_memory", DBUG_VOID_RETURN;);

  if (!thd || MyFlags & ME_NOREFRESH)
    sql_print_error("%s: %s",my_progname,str); /* purecov: inspected */
  DBUG_VOID_RETURN;
}


#ifndef EMBEDDED_LIBRARY
extern "C" void *my_str_malloc_mysqld(size_t size);
extern "C" void my_str_free_mysqld(void *ptr);
extern "C" void *my_str_realloc_mysqld(void *ptr, size_t size);

void *my_str_malloc_mysqld(size_t size)
{
  return my_malloc(size, MYF(MY_FAE));
}


void my_str_free_mysqld(void *ptr)
{
  my_free(ptr);
}

void *my_str_realloc_mysqld(void *ptr, size_t size)
{
  return my_realloc(ptr, size, MYF(MY_FAE));
}
#endif /* EMBEDDED_LIBRARY */


#ifdef __WIN__

pthread_handler_t handle_shutdown(void *arg)
{
  MSG msg;
  my_thread_init();

  /* this call should create the message queue for this thread */
  PeekMessage(&msg, NULL, 1, 65534,PM_NOREMOVE);
#if !defined(EMBEDDED_LIBRARY)
  if (WaitForSingleObject(hEventShutdown,INFINITE)==WAIT_OBJECT_0)
#endif /* EMBEDDED_LIBRARY */
     kill_server(MYSQL_KILL_SIGNAL);
  return 0;
}
#endif

const char *load_default_groups[]= {
"inception", 0, 0};

#if defined(__WIN__) && !defined(EMBEDDED_LIBRARY)
static const int load_default_groups_sz=
sizeof(load_default_groups)/sizeof(load_default_groups[0]);
#endif

#ifndef EMBEDDED_LIBRARY
/**
  This function is used to check for stack overrun for pathological
  cases of regular expressions and 'like' expressions.
  The call to current_thd is quite expensive, so we try to avoid it
  for the normal cases.
  The size of each stack frame for the wildcmp() routines is ~128 bytes,
  so checking *every* recursive call is not necessary.
 */
extern "C" int
check_enough_stack_size(int recurse_level)
{
  uchar stack_top;
  if (recurse_level % 16 != 0)
    return 0;

  THD *my_thd= current_thd;
  if (my_thd != NULL)
    return check_stack_overrun(my_thd, STACK_MIN_SIZE * 2, &stack_top);
  return 0;
}
#endif


/**
  Initialize one of the global date/time format variables.

  @param format_type    What kind of format should be supported
  @param var_ptr    Pointer to variable that should be updated

  @retval
    0 ok
  @retval
    1 error
*/

static bool init_global_datetime_format(timestamp_type format_type,
                                        DATE_TIME_FORMAT *format)
{
  /*
    Get command line option
    format->format.str is already set by my_getopt
  */
  format->format.length= strlen(format->format.str);

  if (parse_date_time_format(format_type, format))
  {
    fprintf(stderr, "Wrong date/time format specifier: %s\n",
            format->format.str);
    return true;
  }
  return false;
}

SHOW_VAR com_status_vars[]= {
  {"admin_commands",       (char*) offsetof(STATUS_VAR, com_other), SHOW_LONG_STATUS},
  {"assign_to_keycache",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ASSIGN_TO_KEYCACHE]), SHOW_LONG_STATUS},
  {"alter_db",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_DB]), SHOW_LONG_STATUS},
  {"alter_db_upgrade",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_DB_UPGRADE]), SHOW_LONG_STATUS},
  {"alter_event",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_EVENT]), SHOW_LONG_STATUS},
  {"alter_function",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_FUNCTION]), SHOW_LONG_STATUS},
  {"alter_procedure",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_PROCEDURE]), SHOW_LONG_STATUS},
  {"alter_server",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_SERVER]), SHOW_LONG_STATUS},
  {"alter_table",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_TABLE]), SHOW_LONG_STATUS},
  {"alter_tablespace",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_TABLESPACE]), SHOW_LONG_STATUS},
  {"alter_user",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_USER]), SHOW_LONG_STATUS},
  {"analyze",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ANALYZE]), SHOW_LONG_STATUS},
  {"begin",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_BEGIN]), SHOW_LONG_STATUS},
  {"binlog",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_BINLOG_BASE64_EVENT]), SHOW_LONG_STATUS},
  {"call_procedure",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CALL]), SHOW_LONG_STATUS},
  {"change_db",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHANGE_DB]), SHOW_LONG_STATUS},
  {"change_master",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHANGE_MASTER]), SHOW_LONG_STATUS},
  {"check",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHECK]), SHOW_LONG_STATUS},
  {"checksum",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHECKSUM]), SHOW_LONG_STATUS},
  {"commit",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_COMMIT]), SHOW_LONG_STATUS},
  {"create_db",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_DB]), SHOW_LONG_STATUS},
  {"create_event",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_EVENT]), SHOW_LONG_STATUS},
  {"create_function",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_SPFUNCTION]), SHOW_LONG_STATUS},
  {"create_index",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_INDEX]), SHOW_LONG_STATUS},
  {"create_procedure",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_PROCEDURE]), SHOW_LONG_STATUS},
  {"create_server",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_SERVER]), SHOW_LONG_STATUS},
  {"create_table",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_TABLE]), SHOW_LONG_STATUS},
  {"create_trigger",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_TRIGGER]), SHOW_LONG_STATUS},
  {"create_udf",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_FUNCTION]), SHOW_LONG_STATUS},
  {"create_user",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_USER]), SHOW_LONG_STATUS},
  {"create_view",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_VIEW]), SHOW_LONG_STATUS},
  {"dealloc_sql",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DEALLOCATE_PREPARE]), SHOW_LONG_STATUS},
  {"delete",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DELETE]), SHOW_LONG_STATUS},
  {"delete_multi",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DELETE_MULTI]), SHOW_LONG_STATUS},
  {"do",                   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DO]), SHOW_LONG_STATUS},
  {"drop_db",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_DB]), SHOW_LONG_STATUS},
  {"drop_event",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_EVENT]), SHOW_LONG_STATUS},
  {"drop_function",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_FUNCTION]), SHOW_LONG_STATUS},
  {"drop_index",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_INDEX]), SHOW_LONG_STATUS},
  {"drop_procedure",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_PROCEDURE]), SHOW_LONG_STATUS},
  {"drop_server",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_SERVER]), SHOW_LONG_STATUS},
  {"drop_table",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_TABLE]), SHOW_LONG_STATUS},
  {"drop_trigger",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_TRIGGER]), SHOW_LONG_STATUS},
  {"drop_user",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_USER]), SHOW_LONG_STATUS},
  {"drop_view",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_VIEW]), SHOW_LONG_STATUS},
  {"empty_query",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_EMPTY_QUERY]), SHOW_LONG_STATUS},
  {"execute_sql",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_EXECUTE]), SHOW_LONG_STATUS},
  {"flush",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_FLUSH]), SHOW_LONG_STATUS},
  {"get_diagnostics",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_GET_DIAGNOSTICS]), SHOW_LONG_STATUS},
  {"grant",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_GRANT]), SHOW_LONG_STATUS},
  {"ha_close",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_HA_CLOSE]), SHOW_LONG_STATUS},
  {"ha_open",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_HA_OPEN]), SHOW_LONG_STATUS},
  {"ha_read",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_HA_READ]), SHOW_LONG_STATUS},
  {"help",                 (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_HELP]), SHOW_LONG_STATUS},
  {"insert",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_INSERT]), SHOW_LONG_STATUS},
  {"insert_select",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_INSERT_SELECT]), SHOW_LONG_STATUS},
  {"install_plugin",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_INSTALL_PLUGIN]), SHOW_LONG_STATUS},
  {"kill",                 (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_KILL]), SHOW_LONG_STATUS},
  {"load",                 (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_LOAD]), SHOW_LONG_STATUS},
  {"lock_tables",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_LOCK_TABLES]), SHOW_LONG_STATUS},
  {"optimize",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_OPTIMIZE]), SHOW_LONG_STATUS},
  {"preload_keys",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_PRELOAD_KEYS]), SHOW_LONG_STATUS},
  {"prepare_sql",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_PREPARE]), SHOW_LONG_STATUS},
  {"purge",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_PURGE]), SHOW_LONG_STATUS},
  {"purge_before_date",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_PURGE_BEFORE]), SHOW_LONG_STATUS},
  {"release_savepoint",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RELEASE_SAVEPOINT]), SHOW_LONG_STATUS},
  {"rename_table",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RENAME_TABLE]), SHOW_LONG_STATUS},
  {"rename_user",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RENAME_USER]), SHOW_LONG_STATUS},
  {"repair",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REPAIR]), SHOW_LONG_STATUS},
  {"replace",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REPLACE]), SHOW_LONG_STATUS},
  {"replace_select",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REPLACE_SELECT]), SHOW_LONG_STATUS},
  {"reset",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RESET]), SHOW_LONG_STATUS},
  {"resignal",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RESIGNAL]), SHOW_LONG_STATUS},
  {"revoke",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REVOKE]), SHOW_LONG_STATUS},
  {"revoke_all",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REVOKE_ALL]), SHOW_LONG_STATUS},
  {"rollback",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ROLLBACK]), SHOW_LONG_STATUS},
  {"rollback_to_savepoint",(char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ROLLBACK_TO_SAVEPOINT]), SHOW_LONG_STATUS},
  {"savepoint",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SAVEPOINT]), SHOW_LONG_STATUS},
  {"select",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SELECT]), SHOW_LONG_STATUS},
  {"set_option",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SET_OPTION]), SHOW_LONG_STATUS},
  {"signal",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SIGNAL]), SHOW_LONG_STATUS},
  {"show_binlog_events",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_BINLOG_EVENTS]), SHOW_LONG_STATUS},
  {"show_binlogs",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_BINLOGS]), SHOW_LONG_STATUS},
  {"show_charsets",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CHARSETS]), SHOW_LONG_STATUS},
  {"show_collations",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_COLLATIONS]), SHOW_LONG_STATUS},
  {"show_create_db",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_DB]), SHOW_LONG_STATUS},
  {"show_create_event",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_EVENT]), SHOW_LONG_STATUS},
  {"show_create_func",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_FUNC]), SHOW_LONG_STATUS},
  {"show_create_proc",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_PROC]), SHOW_LONG_STATUS},
  {"show_create_table",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE]), SHOW_LONG_STATUS},
  {"show_create_trigger",  (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_TRIGGER]), SHOW_LONG_STATUS},
  {"show_databases",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_DATABASES]), SHOW_LONG_STATUS},
  {"show_engine_logs",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_ENGINE_LOGS]), SHOW_LONG_STATUS},
  {"show_engine_mutex",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_ENGINE_MUTEX]), SHOW_LONG_STATUS},
  {"show_engine_status",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_ENGINE_STATUS]), SHOW_LONG_STATUS},
  {"show_events",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_EVENTS]), SHOW_LONG_STATUS},
  {"show_errors",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_ERRORS]), SHOW_LONG_STATUS},
  {"show_fields",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_FIELDS]), SHOW_LONG_STATUS},
  {"show_function_code",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_FUNC_CODE]), SHOW_LONG_STATUS},
  {"show_function_status", (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_STATUS_FUNC]), SHOW_LONG_STATUS},
  {"show_grants",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_GRANTS]), SHOW_LONG_STATUS},
  {"show_keys",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_KEYS]), SHOW_LONG_STATUS},
  {"show_master_status",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_MASTER_STAT]), SHOW_LONG_STATUS},
  {"show_open_tables",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_OPEN_TABLES]), SHOW_LONG_STATUS},
  {"show_plugins",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PLUGINS]), SHOW_LONG_STATUS},
  {"show_privileges",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PRIVILEGES]), SHOW_LONG_STATUS},
  {"show_procedure_code",  (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PROC_CODE]), SHOW_LONG_STATUS},
  {"show_procedure_status",(char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_STATUS_PROC]), SHOW_LONG_STATUS},
  {"show_processlist",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PROCESSLIST]), SHOW_LONG_STATUS},
  {"show_profile",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PROFILE]), SHOW_LONG_STATUS},
  {"show_profiles",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PROFILES]), SHOW_LONG_STATUS},
  {"show_relaylog_events", (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_RELAYLOG_EVENTS]), SHOW_LONG_STATUS},
  {"show_slave_hosts",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_SLAVE_HOSTS]), SHOW_LONG_STATUS},
  {"show_slave_status",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_SLAVE_STAT]), SHOW_LONG_STATUS},
  {"show_status",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_STATUS]), SHOW_LONG_STATUS},
  {"show_storage_engines", (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_STORAGE_ENGINES]), SHOW_LONG_STATUS},
  {"show_table_status",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_TABLE_STATUS]), SHOW_LONG_STATUS},
  {"show_tables",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_TABLES]), SHOW_LONG_STATUS},
  {"show_triggers",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_TRIGGERS]), SHOW_LONG_STATUS},
  {"show_variables",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_VARIABLES]), SHOW_LONG_STATUS},
  {"show_warnings",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_WARNS]), SHOW_LONG_STATUS},
  {"slave_start",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SLAVE_START]), SHOW_LONG_STATUS},
  {"slave_stop",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SLAVE_STOP]), SHOW_LONG_STATUS},
  {"stmt_close",           (char*) offsetof(STATUS_VAR, com_stmt_close), SHOW_LONG_STATUS},
  {"stmt_execute",         (char*) offsetof(STATUS_VAR, com_stmt_execute), SHOW_LONG_STATUS},
  {"stmt_fetch",           (char*) offsetof(STATUS_VAR, com_stmt_fetch), SHOW_LONG_STATUS},
  {"stmt_prepare",         (char*) offsetof(STATUS_VAR, com_stmt_prepare), SHOW_LONG_STATUS},
  {"stmt_reprepare",       (char*) offsetof(STATUS_VAR, com_stmt_reprepare), SHOW_LONG_STATUS},
  {"stmt_reset",           (char*) offsetof(STATUS_VAR, com_stmt_reset), SHOW_LONG_STATUS},
  {"stmt_send_long_data",  (char*) offsetof(STATUS_VAR, com_stmt_send_long_data), SHOW_LONG_STATUS},
  {"truncate",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_TRUNCATE]), SHOW_LONG_STATUS},
  {"uninstall_plugin",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_UNINSTALL_PLUGIN]), SHOW_LONG_STATUS},
  {"unlock_tables",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_UNLOCK_TABLES]), SHOW_LONG_STATUS},
  {"update",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_UPDATE]), SHOW_LONG_STATUS},
  {"update_multi",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_UPDATE_MULTI]), SHOW_LONG_STATUS},
  {"xa_commit",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_COMMIT]),SHOW_LONG_STATUS},
  {"xa_end",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_END]),SHOW_LONG_STATUS},
  {"xa_prepare",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_PREPARE]),SHOW_LONG_STATUS},
  {"xa_recover",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_RECOVER]),SHOW_LONG_STATUS},
  {"xa_rollback",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_ROLLBACK]),SHOW_LONG_STATUS},
  {"xa_start",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_START]),SHOW_LONG_STATUS},
  {NullS, NullS, SHOW_LONG}
};

#ifdef HAVE_PSI_STATEMENT_INTERFACE
PSI_statement_info sql_statement_info[(uint) SQLCOM_END + 1];
PSI_statement_info com_statement_info[(uint) COM_END + 1];

/**
  Initialize the command names array.
  Since we do not want to maintain a separate array,
  this is populated from data mined in com_status_vars,
  which already has one name for each command.
*/
void init_sql_statement_info()
{
  char *first_com= (char*) offsetof(STATUS_VAR, com_stat[0]);
  char *last_com= (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_END]);
  int record_size= (char*) offsetof(STATUS_VAR, com_stat[1])
                   - (char*) offsetof(STATUS_VAR, com_stat[0]);
  char *ptr;
  uint i;
  uint com_index;

  static const char* dummy= "";
  for (i= 0; i < ((uint) SQLCOM_END + 1); i++)
  {
    sql_statement_info[i].m_name= dummy;
    sql_statement_info[i].m_flags= 0;
  }

  SHOW_VAR *var= &com_status_vars[0];
  while (var->name != NULL)
  {
    ptr= var->value;
    if ((first_com <= ptr) && (ptr <= last_com))
    {
      com_index= ((int)(ptr - first_com))/record_size;
      DBUG_ASSERT(com_index < (uint) SQLCOM_END);
      sql_statement_info[com_index].m_name= var->name;
    }
    var++;
  }

  DBUG_ASSERT(strcmp(sql_statement_info[(uint) SQLCOM_SELECT].m_name, "select") == 0);
  DBUG_ASSERT(strcmp(sql_statement_info[(uint) SQLCOM_SIGNAL].m_name, "signal") == 0);

  sql_statement_info[(uint) SQLCOM_END].m_name= "error";
}

void init_com_statement_info()
{
  uint index;

  for (index= 0; index < (uint) COM_END + 1; index++)
  {
    com_statement_info[index].m_name= command_name[index].str;
    com_statement_info[index].m_flags= 0;
  }

  /* "statement/com/query" can mutate into "statement/sql/..." */
  com_statement_info[(uint) COM_QUERY].m_flags= PSI_FLAG_MUTABLE;
}
#endif

/**
  Create the name of the default general log file

  @param[IN] buff    Location for building new string.
  @param[IN] log_ext The extension for the file (e.g .log)
  @returns Pointer to a new string containing the name
*/
static inline char *make_default_log_name(char *buff,const char* log_ext)
{
  return make_log_name(buff, default_logfile_name, log_ext);
}

/**
  Create a replication file name or base for file names.

  @param[in] opt Value of option, or NULL
  @param[in] def Default value if option value is not set.
  @param[in] ext Extension to use for the path

  @returns Pointer to string containing the full file path, or NULL if
  it was not possible to create the path.
 */
static inline const char *
rpl_make_log_name(const char *opt,
                  const char *def,
                  const char *ext)
{
  DBUG_ENTER("rpl_make_log_name");
  DBUG_PRINT("enter", ("opt: %s, def: %s, ext: %s", opt, def, ext));
  char buff[FN_REFLEN];
  const char *base= opt ? opt : def;
  unsigned int options=
    MY_REPLACE_EXT | MY_UNPACK_FILENAME | MY_SAFE_PATH;

  /* mysql_real_data_home_ptr  may be null if no value of datadir has been
     specified through command-line or througha cnf file. If that is the 
     case we make mysql_real_data_home_ptr point to mysql_real_data_home
     which, in that case holds the default path for data-dir.
  */ 
  if(mysql_real_data_home_ptr == NULL)
    mysql_real_data_home_ptr= mysql_real_data_home;

  if (fn_format(buff, base, mysql_real_data_home_ptr, ext, options))
    DBUG_RETURN(strdup(buff));
  else
    DBUG_RETURN(NULL);
}

int init_common_variables()
{
	struct tm tm_tmp;

    opt_logname= opt_update_logname= opt_binlog_index_name= 0;

  umask(((~my_umask) & 0666));
  connection_errors_select= 0;
  connection_errors_accept= 0;
  connection_errors_tcpwrap= 0;
  connection_errors_internal= 0;
  connection_errors_max_connection= 0;
  connection_errors_peer_addr= 0;
  my_decimal_set_zero(&decimal_zero); // set decimal_zero constant;
  tzset();      // Set tzname

  max_system_variables.pseudo_thread_id= (ulong)~0;
  server_start_time= flush_status_time= my_time(0);

  if (init_thread_environment() ||
      mysql_init_variables())
    return 1;


  localtime_r(&server_start_time,&tm_tmp);
  /*
    We set SYSTEM time zone as reasonable default and
    also for failure of my_tz_init() and bootstrap mode.
    If user explicitly set time zone with --default-time-zone
    option we will change this value in my_tz_init().
  */
  global_system_variables.time_zone= my_tz_SYSTEM;

  mysql_mutex_init(NULL, &osc_mutex, MY_MUTEX_INIT_FAST);
  LIST_INIT(global_osc_cache.osc_lst);
  
  mysql_mutex_init(NULL, &isql_option_mutex, MY_MUTEX_INIT_FAST);
  isql_option = (char**)my_malloc(sizeof(char*) * (ISQL_OPTION_COUNT + 2), MY_ZEROFILL);
  memset(&global_source, 0, sizeof(sinfo_t));


  init_default_auth_plugin();

  if (get_options(&remaining_argc, &remaining_argv))
    return 1;
  set_server_version();


  back_log= max_connections;

  unireg_init(opt_specialflag); /* Set up extern variabels */


//   if (!(my_default_lc_messages=my_locale_by_name(lc_messages)))
//   {
//     sql_print_error("Unknown locale: '%s'", lc_messages);
//     return 1;
//   }
//   global_system_variables.lc_messages= my_default_lc_messages;
  if (init_errmessage())  /* Read error messages from file */
     return 1;

  init_client_errs();
  lex_init();
  if (item_create_init())
	  return 1;

  /*##############33*/
  item_init();
#ifndef EMBEDDED_LIBRARY
  my_regex_init(&my_charset_latin1, check_enough_stack_size);
  my_string_stack_guard= check_enough_stack_size;
#else
  my_regex_init(&my_charset_latin1, NULL);
#endif
  /*
    Process a comma-separated character set list and choose
    the first available character set. This is mostly for
    test purposes, to be able to start "mysqld" even if
    the requested character set is not available (see bug#18743).
  */
  for (;;)
  {
    char *next_character_set_name= strchr(default_character_set_name, ',');
    if (next_character_set_name)
      *next_character_set_name++= '\0';
    if (!(default_charset_info=
          get_charset_by_csname(default_character_set_name,
                                MY_CS_PRIMARY, MYF(MY_WME))))
    {
      if (next_character_set_name)
      {
        default_character_set_name= next_character_set_name;
        default_collation_name= 0;          // Ignore collation
      }
      else
        return 1;                           // Eof of the list
    }
    else
      break;
  }

  if (default_collation_name)
  {
    CHARSET_INFO *default_collation;
    default_collation= get_charset_by_name(default_collation_name, MYF(0));
    if (!default_collation)
    {
#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
      buffered_logs.print();
      buffered_logs.cleanup();
#endif
      sql_print_error(ER_DEFAULT(ER_UNKNOWN_COLLATION), default_collation_name);
      return 1;
    }
    if (!my_charset_same(default_charset_info, default_collation))
    {
      sql_print_error(ER_DEFAULT(ER_COLLATION_CHARSET_MISMATCH),
          default_collation_name,
          default_charset_info->csname);
      return 1;
    }
    default_charset_info= default_collation;
  }
  /* Set collactions that depends on the default collation */
  global_system_variables.collation_server=  default_charset_info;
  global_system_variables.collation_database=  default_charset_info;
  global_system_variables.collation_connection=  default_charset_info;
  global_system_variables.character_set_results= default_charset_info;
  global_system_variables.character_set_client=  default_charset_info;
  if (!(character_set_filesystem=
        get_charset_by_csname(character_set_filesystem_name,
                              MY_CS_PRIMARY, MYF(MY_WME))))
    return 1;
  global_system_variables.character_set_filesystem= character_set_filesystem;

  if (!(my_default_lc_time_names=my_locale_by_name(lc_time_names_name)))
  {
    sql_print_error("Unknown locale: '%s'", lc_time_names_name);
    return 1;
  }
  global_system_variables.lc_time_names= my_default_lc_time_names;

  if (my_dboptions_cache_init())
    return 1;

  /*
    Ensure that lower_case_table_names is set on system where we have case
    insensitive names.  If this is not done the users MyISAM tables will
    get corrupted if accesses with names of different case.
  */
  DBUG_PRINT("info", ("lower_case_table_names: %d", lower_case_table_names));
  lower_case_file_system= 0;
  if (!lower_case_table_names && lower_case_file_system == 1)
  {
    if (lower_case_table_names_used)
    {
      if (log_warnings)
  sql_print_warning("\
You have forced lower_case_table_names to 0 through a command-line \
option, even though your file system '%s' is case insensitive.  This means \
that you can corrupt a MyISAM table by accessing it with different cases. \
You should consider changing lower_case_table_names to 1 or 2",
      mysql_real_data_home);
    }
    else
    {
      if (log_warnings)
  sql_print_warning("Setting lower_case_table_names=2 because file system for %s is case insensitive", mysql_real_data_home);
      lower_case_table_names= 2;
    }
  }
  else if (lower_case_table_names == 2 &&
           !(lower_case_file_system=0))
  {
    if (log_warnings)
      sql_print_warning("lower_case_table_names was set to 2, even though your "
                        "the file system '%s' is case sensitive.  Now setting "
                        "lower_case_table_names to 0 to avoid future problems.",
      mysql_real_data_home);
    lower_case_table_names= 0;
  }
  else
  {
    lower_case_file_system=0;
  }

  /* Reset table_alias_charset, now that lower_case_table_names is set. */
  table_alias_charset= (lower_case_table_names ?
      &my_charset_utf8_tolower_ci :
      &my_charset_bin);

		
  init_update_queries();
  return 0;
}


static int init_thread_environment()
{
  mysql_mutex_init(key_LOCK_thread_created,
                   &LOCK_thread_created, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_thread_count, &LOCK_thread_count, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_status, &LOCK_status, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_delayed_insert,
                   &LOCK_delayed_insert, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_delayed_status,
                   &LOCK_delayed_status, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_delayed_create,
                   &LOCK_delayed_create, MY_MUTEX_INIT_SLOW);
//   mysql_mutex_init(key_LOCK_manager,
//                    &LOCK_manager, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_crypt, &LOCK_crypt, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_user_conn, &LOCK_user_conn, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_active_mi, &LOCK_active_mi, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_global_system_variables,
                   &LOCK_global_system_variables, MY_MUTEX_INIT_FAST);
  mysql_rwlock_init(key_rwlock_LOCK_system_variables_hash,
                    &LOCK_system_variables_hash);
  mysql_mutex_init(key_LOCK_prepared_stmt_count,
                   &LOCK_prepared_stmt_count, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_sql_slave_skip_counter,
                   &LOCK_sql_slave_skip_counter, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_slave_net_timeout,
                   &LOCK_slave_net_timeout, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_error_messages,
                   &LOCK_error_messages, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_uuid_generator,
                   &LOCK_uuid_generator, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_sql_rand,
                   &LOCK_sql_rand, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_connection_count,
                   &LOCK_connection_count, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_log_throttle_qni,
                   &LOCK_log_throttle_qni, MY_MUTEX_INIT_FAST);
#ifdef HAVE_OPENSSL
  mysql_mutex_init(key_LOCK_des_key_file,
                   &LOCK_des_key_file, MY_MUTEX_INIT_FAST);
#ifndef HAVE_YASSL
  openssl_stdlocks= (openssl_lock_t*) OPENSSL_malloc(CRYPTO_num_locks() *
                                                     sizeof(openssl_lock_t));
  for (int i= 0; i < CRYPTO_num_locks(); ++i)
    mysql_rwlock_init(key_rwlock_openssl, &openssl_stdlocks[i].lock);
  CRYPTO_set_dynlock_create_callback(openssl_dynlock_create);
  CRYPTO_set_dynlock_destroy_callback(openssl_dynlock_destroy);
  CRYPTO_set_dynlock_lock_callback(openssl_lock);
  CRYPTO_set_locking_callback(openssl_lock_function);
  CRYPTO_set_id_callback(openssl_id_function);
#endif
#endif
  mysql_rwlock_init(key_rwlock_LOCK_sys_init_connect, &LOCK_sys_init_connect);
  mysql_rwlock_init(key_rwlock_LOCK_sys_init_slave, &LOCK_sys_init_slave);
  mysql_rwlock_init(key_rwlock_LOCK_grant, &LOCK_grant);
  mysql_cond_init(key_COND_thread_count, &COND_thread_count, NULL);
  mysql_cond_init(key_COND_thread_cache, &COND_thread_cache, NULL);
  mysql_cond_init(key_COND_flush_thread_cache, &COND_flush_thread_cache, NULL);
//   mysql_cond_init(key_COND_manager, &COND_manager, NULL);
  mysql_mutex_init(key_LOCK_server_started,
                   &LOCK_server_started, MY_MUTEX_INIT_FAST);
  mysql_cond_init(key_COND_server_started, &COND_server_started, NULL);
//   sp_cache_init();
#ifdef HAVE_EVENT_SCHEDULER
  Events::init_mutexes();
#endif
  /* Parameter for threads created for connections */
  (void) pthread_attr_init(&connection_attrib);
  (void) pthread_attr_setdetachstate(&connection_attrib,
             PTHREAD_CREATE_DETACHED);
  pthread_attr_setscope(&connection_attrib, PTHREAD_SCOPE_SYSTEM);

  if (pthread_key_create(&THR_THD,NULL) ||
      pthread_key_create(&THR_MALLOC,NULL))
  {
    sql_print_error("Can't create thread-keys");
    return 1;
  }
  return 0;
}


#if defined(HAVE_OPENSSL) && !defined(HAVE_YASSL)
static unsigned long openssl_id_function()
{
  return (unsigned long) pthread_self();
}


static openssl_lock_t *openssl_dynlock_create(const char *file, int line)
{
  openssl_lock_t *lock= new openssl_lock_t;
  mysql_rwlock_init(key_rwlock_openssl, &lock->lock);
  return lock;
}


static void openssl_dynlock_destroy(openssl_lock_t *lock, const char *file,
            int line)
{
  mysql_rwlock_destroy(&lock->lock);
  delete lock;
}


static void openssl_lock_function(int mode, int n, const char *file, int line)
{
  if (n < 0 || n > CRYPTO_num_locks())
  {
    /* Lock number out of bounds. */
    sql_print_error("Fatal: OpenSSL interface problem (n = %d)", n);
    abort();
  }
  openssl_lock(mode, &openssl_stdlocks[n], file, line);
}


static void openssl_lock(int mode, openssl_lock_t *lock, const char *file,
       int line)
{
  int err;
  char const *what;

  switch (mode) {
  case CRYPTO_LOCK|CRYPTO_READ:
    what = "read lock";
    err= mysql_rwlock_rdlock(&lock->lock);
    break;
  case CRYPTO_LOCK|CRYPTO_WRITE:
    what = "write lock";
    err= mysql_rwlock_wrlock(&lock->lock);
    break;
  case CRYPTO_UNLOCK|CRYPTO_READ:
  case CRYPTO_UNLOCK|CRYPTO_WRITE:
    what = "unlock";
    err= mysql_rwlock_unlock(&lock->lock);
    break;
  default:
    /* Unknown locking mode. */
    sql_print_error("Fatal: OpenSSL interface problem (mode=0x%x)", mode);
    abort();
  }
  if (err)
  {
    sql_print_error("Fatal: can't %s OpenSSL lock", what);
    abort();
  }
}
#endif /* HAVE_OPENSSL */

static int init_server_components()
{
  DBUG_ENTER("init_server_components");
  randominit(&sql_rand,(ulong) server_start_time,(ulong) server_start_time/2);
  proc_info_hook= set_thd_stage_info;

  /*
    Now that the logger is available, redirect character set
    errors directly to the logger
    (instead of the buffered_logs used at the server startup time).
  */
  my_charset_error_reporter= charset_error_reporter;

  if (plugin_init(&remaining_argc, remaining_argv,
	  (opt_noacl ? PLUGIN_INIT_SKIP_PLUGIN_TABLE : 0) | PLUGIN_INIT_SKIP_INITIALIZATION | PLUGIN_INIT_SKIP_DYNAMIC_LOADING))
  {
    sql_print_error("Failed to initialize plugins.");
    unireg_abort(1);
  }

  plugins_are_initialized= TRUE;  /* Don't separate from init function */

  /* we do want to exit if there are any other unknown options */
  if (remaining_argc > 1)
  {
    int ho_error;
    struct my_option no_opts[]=
    {
      {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
    };
    /*
      We need to eat any 'loose' arguments first before we conclude
      that there are unprocessed options.
    */
    my_getopt_skip_unknown= 0;

    if ((ho_error= handle_options(&remaining_argc, &remaining_argv, no_opts,
                                  mysqld_get_one_option)))
      unireg_abort(ho_error);
    /* Add back the program name handle_options removes */
    remaining_argc++;
    remaining_argv--;
    my_getopt_skip_unknown= FALSE;

    if (remaining_argc > 1)
    {
      fprintf(stderr, "%s: Too many arguments (first extra is '%s').\n"
              "Use --verbose --help to get a list of available options\n",
              my_progname, remaining_argv[1]);
      unireg_abort(1);
    }
  }

  if (opt_help)
    unireg_abort(0);

  locked_in_memory=0;

  logger.set_handlers(LOG_FILE, LOG_NONE, LOG_FILE);

  init_max_user_conn();
  DBUG_RETURN(0);
}


#if (defined(_WIN32) || defined(HAVE_SMEM)) && !defined(EMBEDDED_LIBRARY)
static void handle_connections_methods()
{
  pthread_t hThread;
  DBUG_ENTER("handle_connections_methods");

  mysql_mutex_lock(&LOCK_thread_count);
  mysql_cond_init(key_COND_handler_count, &COND_handler_count, NULL);
  handler_count=0;
  if (hPipe != INVALID_HANDLE_VALUE)
  {
    handler_count++;
    if (mysql_thread_create(key_thread_handle_con_namedpipes,
                            &hThread, &connection_attrib,
                            handle_connections_namedpipes, 0))
    {
      sql_print_warning("Can't create thread to handle named pipes");
      handler_count--;
    }
  }
  if (have_tcpip && !opt_disable_networking)
  {
    handler_count++;
    if (mysql_thread_create(key_thread_handle_con_sockets,
                            &hThread, &connection_attrib,
                            handle_connections_sockets_thread, 0))
    {
      sql_print_warning("Can't create thread to handle TCP/IP");
      handler_count--;
    }
  }

  while (handler_count > 0)
    mysql_cond_wait(&COND_handler_count, &LOCK_thread_count);
  mysql_mutex_unlock(&LOCK_thread_count);
  DBUG_VOID_RETURN;
}

void decrement_handler_count()
{
  mysql_mutex_lock(&LOCK_thread_count);
  handler_count--;
  mysql_cond_signal(&COND_handler_count);
  mysql_mutex_unlock(&LOCK_thread_count);
  my_thread_end();
}
#else
#define decrement_handler_count()
#endif /* defined(_WIN32) || defined(HAVE_SMEM) */


#ifndef EMBEDDED_LIBRARY
#ifndef DBUG_OFF
/*
  Debugging helper function to keep the locale database
  (see sql_locale.cc) and max_month_name_length and
  max_day_name_length variable values in consistent state.
*/
static void test_lc_time_sz()
{
  DBUG_ENTER("test_lc_time_sz");
  for (MY_LOCALE **loc= my_locales; *loc; loc++)
  {
    uint max_month_len= 0;
    uint max_day_len = 0;
    for (const char **month= (*loc)->month_names->type_names; *month; month++)
    {
      set_if_bigger(max_month_len,
                    my_numchars_mb(&my_charset_utf8_general_ci,
                                   *month, *month + strlen(*month)));
    }
    for (const char **day= (*loc)->day_names->type_names; *day; day++)
    {
      set_if_bigger(max_day_len,
                    my_numchars_mb(&my_charset_utf8_general_ci,
                                   *day, *day + strlen(*day)));
    }
    if ((*loc)->max_month_name_length != max_month_len ||
        (*loc)->max_day_name_length != max_day_len)
    {
      DBUG_PRINT("Wrong max day name(or month name) length for locale:",
                 ("%s", (*loc)->name));
      DBUG_ASSERT(0);
    }
  }
  DBUG_VOID_RETURN;
}
#endif//DBUG_OFF

#ifdef __WIN__
int win_main(int argc, char **argv)
#else
int mysqld_main(int argc, char **argv)
#endif
{
  /*
    Perform basic thread library and malloc initialization,
    to be able to read defaults files and parse options.
  */
  my_progname= argv[0];
#ifdef HAVE_NPTL
  ld_assume_kernel_is_set= (getenv("LD_ASSUME_KERNEL") != 0);
#endif
#ifndef _WIN32
  // For windows, my_init() is called from the win specific mysqld_main
  if (my_init())                 // init my_sys library & pthreads
  {
    fprintf(stderr, "my_init() failed.");
    return 1;
  }
#endif

  orig_argc= argc;
  orig_argv= argv;
  my_getopt_use_args_separator= TRUE;
  if (load_defaults(MYSQL_CONFIG_NAME, load_default_groups, &argc, &argv))
    return 1;
  my_getopt_use_args_separator= FALSE;
  defaults_argc= argc;
  defaults_argv= argv;
  remaining_argc= argc;
  remaining_argv= argv;

  /* Must be initialized early for comparison of options name */
  system_charset_info= &my_charset_utf8_general_ci;

  sys_var_init();

  int ho_error;

  ho_error= handle_early_options();

  adjust_related_options();

  init_error_log_mutex();

  /* Set signal used to kill MySQL */
#if defined(SIGUSR2)
  thr_kill_signal= thd_lib_detected == THD_LIB_LT ? SIGINT : SIGUSR2;
#else
  thr_kill_signal= SIGINT;
#endif

  /* Initialize audit interface globals. Audit plugins are inited later. */
  //mysql_audit_initialize();

  /*
    Perform basic logger initialization logger. Should be called after
    MY_INIT, as it initializes mutexes. Log tables are inited later.
  */
  logger.init_base();

  if (ho_error)
  {
    /*
      Parsing command line option failed,
      Since we don't have a workable remaining_argc/remaining_argv
      to continue the server initialization, this is as far as this
      code can go.
      This is the best effort to log meaningful messages:
      - messages will be printed to stderr, which is not redirected yet,
      - messages will be printed in the NT event log, for windows.
    */
    buffered_logs.print();
    buffered_logs.cleanup();
    /*
      Not enough initializations for unireg_abort()
      Using exit() for windows.
    */
    exit (ho_error);
  }

  char hello[100];
  sprintf(hello, "Welcome to use %s", VERSION);
  sql_print_information((char *)hello);

  if (init_common_variables())
    unireg_abort(1);        // Will do exit

  my_init_signals();
#if defined(__ia64__) || defined(__ia64)
  /*
    Peculiar things with ia64 platforms - it seems we only have half the
    stack size in reality, so we have to double it here
  */
  pthread_attr_setstacksize(&connection_attrib,my_thread_stack_size*2);
#else
  pthread_attr_setstacksize(&connection_attrib,my_thread_stack_size);
#endif

  (void) thr_setconcurrency(10); // 10 by default

  select_thread=pthread_self();
  select_thread_in_use=1;


#ifdef HAVE_LIBWRAP
  libwrapName= my_progname+dirname_length(my_progname);
  openlog(libwrapName, LOG_PID, LOG_AUTH);
#endif
  if (init_server_components())
    unireg_abort(1);

  network_init();
  my_str_malloc= &my_str_malloc_mysqld;
  my_str_free= &my_str_free_mysqld;
  my_str_realloc= &my_str_realloc_mysqld;

  /*
    init signals & alarm
    After this we can't quit by a simple unireg_abort
  */
  error_handler_hook= my_message_sql;
  //start_signal_handler();       // Creates pidfile

  acl_init(opt_noacl);

  /* Signal threads waiting for server to be started */
  mysql_mutex_lock(&LOCK_server_started);
  mysqld_server_started= 1;
  mysql_cond_signal(&COND_server_started);
  mysql_mutex_unlock(&LOCK_server_started);

  //create_console_thread();
#if defined(_WIN32) || defined(HAVE_SMEM)
  handle_connections_methods();
#else
  handle_connections_sockets();
#endif /* _WIN32 || HAVE_SMEM */

  DBUG_PRINT("quit",("Exiting main thread"));

#ifndef __WIN__
#ifdef EXTRA_DEBUG2
  sql_print_error("Before Lock_thread_count");
#endif
  mysql_mutex_lock(&LOCK_thread_count);
  DBUG_PRINT("quit", ("Got thread_count mutex"));
  select_thread_in_use=0;     // For close_connections
  mysql_mutex_unlock(&LOCK_thread_count);
  mysql_cond_broadcast(&COND_thread_count);
#ifdef EXTRA_DEBUG2
  sql_print_error("After lock_thread_count");
#endif
#endif /* __WIN__ */

  /* Wait until cleanup is done */
  mysql_mutex_lock(&LOCK_thread_count);
  while (!ready_to_exit)
    mysql_cond_wait(&COND_thread_count, &LOCK_thread_count);
  mysql_mutex_unlock(&LOCK_thread_count);

  clean_up(1);
  mysqld_exit(0);
}

#endif /* !EMBEDDED_LIBRARY */


/****************************************************************************
  Main and thread entry function for Win32
  (all this is needed only to run mysqld as a service on WinNT)
****************************************************************************/

#if defined(__WIN__) && !defined(EMBEDDED_LIBRARY)
int mysql_service(void *p)
{
  if (my_thread_init())
    return 1;

  if (use_opt_args)
    win_main(opt_argc, opt_argv);
  else
    win_main(Service.my_argc, Service.my_argv);

  my_thread_end();
  return 0;
}


/* Quote string if it contains space, else copy */

static char *add_quoted_string(char *to, const char *from, char *to_end)
{
  uint length= (uint) (to_end-to);

  if (!strchr(from, ' '))
    return strmake(to, from, length-1);
  return strxnmov(to, length-1, "\"", from, "\"", NullS);
}


/**
  Handle basic handling of services, like installation and removal.

  @param argv             Pointer to argument list
  @param servicename    Internal name of service
  @param displayname    Display name of service (in taskbar ?)
  @param file_path    Path to this program
  @param startup_option Startup option to mysqld

  @retval
    0   option handled
  @retval
    1   Could not handle option
*/

static bool
default_service_handling(char **argv,
       const char *servicename,
       const char *displayname,
       const char *file_path,
       const char *extra_opt,
       const char *account_name)
{
  char path_and_service[FN_REFLEN+FN_REFLEN+32], *pos, *end;
  const char *opt_delim;
  end= path_and_service + sizeof(path_and_service)-3;

  /* We have to quote filename if it contains spaces */
  pos= add_quoted_string(path_and_service, file_path, end);
  if (*extra_opt)
  {
    /*
     Add option after file_path. There will be zero or one extra option.  It's
     assumed to be --defaults-file=file but isn't checked.  The variable (not
     the option name) should be quoted if it contains a string.
    */
    *pos++= ' ';
    if (opt_delim= strchr(extra_opt, '='))
    {
      size_t length= ++opt_delim - extra_opt;
      pos= strnmov(pos, extra_opt, length);
    }
    else
      opt_delim= extra_opt;

    pos= add_quoted_string(pos, opt_delim, end);
  }
  /* We must have servicename last */
  *pos++= ' ';
  (void) add_quoted_string(pos, servicename, end);

  if (Service.got_service_option(argv, "install"))
  {
    Service.Install(1, servicename, displayname, path_and_service,
                    account_name);
    return 0;
  }
  if (Service.got_service_option(argv, "install-manual"))
  {
    Service.Install(0, servicename, displayname, path_and_service,
                    account_name);
    return 0;
  }
  if (Service.got_service_option(argv, "remove"))
  {
    Service.Remove(servicename);
    return 0;
  }
  return 1;
}


int mysqld_main(int argc, char **argv)
{
  /*
    When several instances are running on the same machine, we
    need to have an  unique  named  hEventShudown  through the
    application PID e.g.: MySQLShutdown1890; MySQLShutdown2342
  */
  int10_to_str((int) GetCurrentProcessId(),strmov(shutdown_event_name,
                                                  "MySQLShutdown"), 10);

  /* Must be initialized early for comparison of service name */
  system_charset_info= &my_charset_utf8_general_ci;

  if (my_init())
  {
    fprintf(stderr, "my_init() failed.");
    return 1;
  }

  if (Service.GetOS())  /* true NT family */
  {
    char file_path[FN_REFLEN];
    my_path(file_path, argv[0], "");          /* Find name in path */
    fn_format(file_path,argv[0],file_path,"",
        MY_REPLACE_DIR | MY_UNPACK_FILENAME | MY_RESOLVE_SYMLINKS);

    if (argc == 2)
    {
      if (!default_service_handling(argv, MYSQL_SERVICENAME, MYSQL_SERVICENAME,
           file_path, "", NULL))
  return 0;
      if (Service.IsService(argv[1]))        /* Start an optional service */
      {
  /*
    Only add the service name to the groups read from the config file
    if it's not "MySQL". (The default service name should be 'mysqld'
    but we started a bad tradition by calling it MySQL from the start
    and we are now stuck with it.
  */
  if (my_strcasecmp(system_charset_info, argv[1],"mysql"))
    load_default_groups[load_default_groups_sz-2]= argv[1];
        start_mode= 1;
        Service.Init(argv[1], mysql_service);
        return 0;
      }
    }
    else if (argc == 3) /* install or remove any optional service */
    {
      if (!default_service_handling(argv, argv[2], argv[2], file_path, "",
                                    NULL))
  return 0;
      if (Service.IsService(argv[2]))
      {
  /*
    mysqld was started as
    mysqld --defaults-file=my_path\my.ini service-name
  */
  use_opt_args=1;
  opt_argc= 2;        // Skip service-name
  opt_argv=argv;
  start_mode= 1;
  if (my_strcasecmp(system_charset_info, argv[2],"mysql"))
    load_default_groups[load_default_groups_sz-2]= argv[2];
  Service.Init(argv[2], mysql_service);
  return 0;
      }
    }
    else if (argc == 4 || argc == 5)
    {
      /*
        This may seem strange, because we handle --local-service while
        preserving 4.1's behavior of allowing any one other argument that is
        passed to the service on startup. (The assumption is that this is
        --defaults-file=file, but that was not enforced in 4.1, so we don't
        enforce it here.)
      */
      const char *extra_opt= NullS;
      const char *account_name = NullS;
      int index;
      for (index = 3; index < argc; index++)
      {
        if (!strcmp(argv[index], "--local-service"))
          account_name= "NT AUTHORITY\\LocalService";
        else
          extra_opt= argv[index];
      }

      if (argc == 4 || account_name)
        if (!default_service_handling(argv, argv[2], argv[2], file_path,
                                      extra_opt, account_name))
          return 0;
    }
    else if (argc == 1 && Service.IsService(MYSQL_SERVICENAME))
    {
      /* start the default service */
      start_mode= 1;
      Service.Init(MYSQL_SERVICENAME, mysql_service);
      return 0;
    }
  }
  /* Start as standalone server */
  Service.my_argc=argc;
  Service.my_argv=argv;
  mysql_service(NULL);
  return 0;
}
#endif

/**
  Increment number of created threads
*/
void inc_thread_created(void)
{
  mysql_mutex_lock(&LOCK_thread_created);
  thread_created++;
  mysql_mutex_unlock(&LOCK_thread_created);
}

#ifndef EMBEDDED_LIBRARY

/*
   Simple scheduler that use the main thread to handle the request

   NOTES
     This is only used for debugging, when starting mysqld with
     --thread-handling=no-threads or --one-thread

     When we enter this function, LOCK_thread_count is held!
*/

void handle_connection_in_main_thread(THD *thd)
{
  mysql_mutex_assert_owner(&LOCK_thread_count);
  add_global_thread(thd);
  mysql_mutex_unlock(&LOCK_thread_count);
  thd->start_utime= my_micro_time();
  do_handle_one_connection(thd);
}


/*
  Scheduler that uses one thread per connection
*/

void create_thread_to_handle_connection(THD *thd)
{

  mysql_mutex_assert_owner(&LOCK_thread_count);
  if (blocked_pthread_count >  wake_pthread)
  {
    /* Wake up blocked pthread */
    DBUG_PRINT("info", ("waiting_thd_list->push %p", thd));
    waiting_thd_list->push_back(thd);
    wake_pthread++;
    mysql_cond_signal(&COND_thread_cache);
  }
  else
  {
    char error_message_buff[MYSQL_ERRMSG_SIZE];
    /* Create new thread to handle connection */
    int error;
    inc_thread_created();
    DBUG_PRINT("info",(("creating thread %lu"), thd->thread_id));
    thd->prior_thr_create_utime= thd->start_utime= my_micro_time();
    if ((error= mysql_thread_create(key_thread_one_connection,
                                    &thd->real_id, &connection_attrib,
                                    handle_one_connection,
                                    (void*) thd)))
    {
      /* purecov: begin inspected */
      DBUG_PRINT("error",
                 ("Can't create thread to handle request (error %d)",
                  error));
      thd->killed= THD::KILL_CONNECTION;      // Safety
      mysql_mutex_unlock(&LOCK_thread_count);

      mysql_mutex_lock(&LOCK_connection_count);
      --connection_count;
      mysql_mutex_unlock(&LOCK_connection_count);

      statistic_increment(aborted_connects,&LOCK_status);
      statistic_increment(connection_errors_internal, &LOCK_status);
      /* Can't use my_error() since store_globals has not been called. */
      my_snprintf(error_message_buff, sizeof(error_message_buff),
                  ER_THD(thd, ER_CANT_CREATE_THREAD), error);
      net_send_error(thd, ER_CANT_CREATE_THREAD, error_message_buff, NULL);
      close_connection(thd);
      delete thd;
      return;
      /* purecov: end */
    }
    add_global_thread(thd);
  }
  mysql_mutex_unlock(&LOCK_thread_count);
  DBUG_PRINT("info",("Thread created"));
}


/**
  Create new thread to handle incoming connection.

    This function will create new thread to handle the incoming
    connection.  If there are idle cached threads one will be used.

    In single-threaded mode (\#define ONE_THREAD) connection will be
    handled inside this function.

  @param[in,out] thd    Thread handle of future thread.
*/

static void create_new_thread(THD *thd)
{
  DBUG_ENTER("create_new_thread");

  /*
    Don't allow too many connections. We roughly check here that we allow
    only (max_connections + 1) connections.
  */

  mysql_mutex_lock(&LOCK_connection_count);

  if (connection_count >= max_connections + 1 || abort_loop)
  {
    mysql_mutex_unlock(&LOCK_connection_count);

    DBUG_PRINT("error",("Too many connections"));
    /*
      The server just accepted the socket connection from the network,
      and we already have too many connections.
      Note that the server knows nothing of the client yet,
      and in particular thd->client_capabilities has not been negotiated.
      ER_CON_COUNT_ERROR is normally associated with SQLSTATE '08004',
      but sending a SQLSTATE in the network assumes CLIENT_PROTOCOL_41.
      See net_send_error_packet().
      The error packet returned here will only contain the error code,
      with no sqlstate.
      A client expecting a SQLSTATE will not find any, and assume 'HY000'.
    */
    close_connection(thd, ER_CON_COUNT_ERROR);
    delete thd;
    statistic_increment(connection_errors_max_connection, &LOCK_status);
    DBUG_VOID_RETURN;
  }

  ++connection_count;

  if (connection_count > max_used_connections)
    max_used_connections= connection_count;

  mysql_mutex_unlock(&LOCK_connection_count);

  /* Start a new thread to handle connection. */

  mysql_mutex_lock(&LOCK_thread_count);

  /*
    The initialization of thread_id is done in create_embedded_thd() for
    the embedded library.
    TODO: refactor this to avoid code duplication there
  */
  thd->thread_id= thd->variables.pseudo_thread_id= thread_id++;

  MYSQL_CALLBACK(thread_scheduler, add_connection, (thd));

  DBUG_VOID_RETURN;
}
#endif /* EMBEDDED_LIBRARY */


#ifdef SIGNALS_DONT_BREAK_READ
inline void kill_broken_server()
{
  /* hack to get around signals ignored in syscalls for problem OS's */
  if (mysql_get_fd(unix_sock) == INVALID_SOCKET ||
      (!opt_disable_networking && mysql_socket_getfd(ip_sock) == INVALID_SOCKET))
  {
    select_thread_in_use = 0;
    /* The following call will never return */
    kill_server((void*) MYSQL_KILL_SIGNAL);
  }
}
#define MAYBE_BROKEN_SYSCALL kill_broken_server();
#else
#define MAYBE_BROKEN_SYSCALL
#endif

  /* Handle new connections and spawn new process to handle them */

#ifndef EMBEDDED_LIBRARY

void handle_connections_sockets()
{
  MYSQL_SOCKET sock= mysql_socket_invalid();
  MYSQL_SOCKET new_sock= mysql_socket_invalid();
  uint error_count=0;
  THD *thd;
  struct sockaddr_storage cAddr;
  int ip_flags=0,socket_flags=0,flags=0,retval;
  st_vio *vio_tmp;
#ifdef HAVE_POLL
  int socket_count= 0;
  struct pollfd fds[2]; // for ip_sock and unix_sock
  MYSQL_SOCKET pfs_fds[2]; // for performance schema
#else
  fd_set readFDs,clientFDs;
  uint max_used_connection= max<uint>(mysql_socket_getfd(ip_sock), mysql_socket_getfd(unix_sock)) + 1;
#endif

  DBUG_ENTER("handle_connections_sockets");

  (void) ip_flags;
  (void) socket_flags;

#ifndef HAVE_POLL
  FD_ZERO(&clientFDs);
#endif

  if (mysql_socket_getfd(ip_sock) != INVALID_SOCKET)
  {
    mysql_socket_set_thread_owner(ip_sock);
#ifdef HAVE_POLL
    fds[socket_count].fd= mysql_socket_getfd(ip_sock);
    fds[socket_count].events= POLLIN;
    pfs_fds[socket_count]= ip_sock;
    socket_count++;
#else
    FD_SET(mysql_socket_getfd(ip_sock), &clientFDs);
#endif
#ifdef HAVE_FCNTL
    ip_flags = fcntl(mysql_socket_getfd(ip_sock), F_GETFL, 0);
#endif
  }
#ifdef HAVE_SYS_UN_H
  mysql_socket_set_thread_owner(unix_sock);
#ifdef HAVE_POLL
  fds[socket_count].fd= mysql_socket_getfd(unix_sock);
  fds[socket_count].events= POLLIN;
  pfs_fds[socket_count]= unix_sock;
  socket_count++;
#else
  FD_SET(mysql_socket_getfd(unix_sock), &clientFDs);
#endif
#ifdef HAVE_FCNTL
  socket_flags=fcntl(mysql_socket_getfd(unix_sock), F_GETFL, 0);
#endif
#endif

  DBUG_PRINT("general",("Waiting for connections."));
  MAYBE_BROKEN_SYSCALL;
  while (!abort_loop)
  {
#ifdef HAVE_POLL
    retval= poll(fds, socket_count, -1);
#else
    readFDs=clientFDs;

    retval= select((int) max_used_connection,&readFDs,0,0,0);
#endif

    if (retval < 0)
    {
      if (socket_errno != SOCKET_EINTR)
      {
        /*
          select(2)/poll(2) failed on the listening port.
          There is not much details to report about the client,
          increment the server global status variable.
        */
        statistic_increment(connection_errors_select, &LOCK_status);
        if (!select_errors++ && !abort_loop)  /* purecov: inspected */
          sql_print_error("mysqld: Got error %d from select",socket_errno); /* purecov: inspected */
      }
      MAYBE_BROKEN_SYSCALL
      continue;
    }

    if (abort_loop)
    {
      MAYBE_BROKEN_SYSCALL;
      break;
    }

    /* Is this a new connection request ? */
#ifdef HAVE_POLL
    for (int i= 0; i < socket_count; ++i)
    {
      if (fds[i].revents & POLLIN)
      {
        sock= pfs_fds[i];
#ifdef HAVE_FCNTL
        flags= fcntl(mysql_socket_getfd(sock), F_GETFL, 0);
#else
        flags= 0;
#endif // HAVE_FCNTL
        break;
      }
    }
#else  // HAVE_POLL
#ifdef HAVE_SYS_UN_H
    if (FD_ISSET(mysql_socket_getfd(unix_sock), &readFDs))
    {
      sock = unix_sock;
      flags= socket_flags;
    }
    else
#endif // HAVE_SYS_UN_H
    {
      sock = ip_sock;
      flags= ip_flags;
    }
#endif // HAVE_POLL

#if !defined(NO_FCNTL_NONBLOCK)
    if (!(test_flags & TEST_BLOCKING))
    {
#if defined(O_NONBLOCK)
      fcntl(mysql_socket_getfd(sock), F_SETFL, flags | O_NONBLOCK);
#elif defined(O_NDELAY)
      fcntl(mysql_socket_getfd(sock), F_SETFL, flags | O_NDELAY);
#endif
    }
#endif /* NO_FCNTL_NONBLOCK */
    for (uint retry=0; retry < MAX_ACCEPT_RETRY; retry++)
    {
      size_socket length= sizeof(struct sockaddr_storage);
      new_sock= mysql_socket_accept(key_socket_client_connection, sock,
                                    (struct sockaddr *)(&cAddr), &length);
      if (mysql_socket_getfd(new_sock) != INVALID_SOCKET ||
          (socket_errno != SOCKET_EINTR && socket_errno != SOCKET_EAGAIN))
        break;
      MAYBE_BROKEN_SYSCALL;
#if !defined(NO_FCNTL_NONBLOCK)
      if (!(test_flags & TEST_BLOCKING))
      {
        if (retry == MAX_ACCEPT_RETRY - 1)
          fcntl(mysql_socket_getfd(sock), F_SETFL, flags);    // Try without O_NONBLOCK
      }
#endif
    }
#if !defined(NO_FCNTL_NONBLOCK)
    if (!(test_flags & TEST_BLOCKING))
      fcntl(mysql_socket_getfd(sock), F_SETFL, flags);
#endif
    if (mysql_socket_getfd(new_sock) == INVALID_SOCKET)
    {
      /*
        accept(2) failed on the listening port, after many retries.
        There is not much details to report about the client,
        increment the server global status variable.
      */
      statistic_increment(connection_errors_accept, &LOCK_status);
      if ((error_count++ & 255) == 0)   // This can happen often
        sql_perror("Error in accept");
      MAYBE_BROKEN_SYSCALL;
      if (socket_errno == SOCKET_ENFILE || socket_errno == SOCKET_EMFILE)
        sleep(1);       // Give other threads some time
      continue;
    }

#ifdef HAVE_LIBWRAP
    {
      if (mysql_socket_getfd(sock) == mysql_socket_getfd(ip_sock))
      {
        struct request_info req;
        signal(SIGCHLD, SIG_DFL);
        request_init(&req, RQ_DAEMON, libwrapName, RQ_FILE, mysql_socket_getfd(new_sock), NULL);
        my_fromhost(&req);

        if (!my_hosts_access(&req))
        {
          /*
            This may be stupid but refuse() includes an exit(0)
            which we surely don't want...
            clean_exit() - same stupid thing ...
          */
          syslog(deny_severity, "refused connect from %s",
          my_eval_client(&req));

          /*
            C++ sucks (the gibberish in front just translates the supplied
            sink function pointer in the req structure from a void (*sink)();
            to a void(*sink)(int) if you omit the cast, the C++ compiler
            will cry...
          */
          if (req.sink)
            ((void (*)(int))req.sink)(req.fd);

          mysql_socket_shutdown(new_sock, SHUT_RDWR);
          mysql_socket_close(new_sock);
          /*
            The connection was refused by TCP wrappers.
            There are no details (by client IP) available to update the host_cache.
          */
          statistic_increment(connection_tcpwrap_errors, &LOCK_status);
          continue;
        }
      }
    }
#endif /* HAVE_LIBWRAP */

    /*
    ** Don't allow too many connections
    */

    if (!(thd= new THD))
    {
      (void) mysql_socket_shutdown(new_sock, SHUT_RDWR);
      (void) mysql_socket_close(new_sock);
      statistic_increment(connection_errors_internal, &LOCK_status);
      continue;
    }

    bool is_unix_sock= (mysql_socket_getfd(sock) == mysql_socket_getfd(unix_sock));
    enum_vio_type vio_type= (is_unix_sock ? VIO_TYPE_SOCKET : VIO_TYPE_TCPIP);
    uint vio_flags= (is_unix_sock ? VIO_LOCALHOST : 0);

    vio_tmp= mysql_socket_vio_new(new_sock, vio_type, vio_flags);

    if (!vio_tmp || my_net_init(&thd->net, vio_tmp))
    {
      /*
        Only delete the temporary vio if we didn't already attach it to the
        NET object. The destructor in THD will delete any initialized net
        structure.
      */
      if (vio_tmp && thd->net.vio != vio_tmp)
        vio_delete(vio_tmp);
      else
      {
        (void) mysql_socket_shutdown(new_sock, SHUT_RDWR);
        (void) mysql_socket_close(new_sock);
      }
      delete thd;
      statistic_increment(connection_errors_internal, &LOCK_status);
      continue;
    }
    init_net_server_extension(thd);
    if (mysql_socket_getfd(sock) == mysql_socket_getfd(unix_sock))
      thd->security_ctx->host=(char*) my_localhost;

    create_new_thread(thd);
  }
  DBUG_VOID_RETURN;
}


#ifdef _WIN32
pthread_handler_t handle_connections_sockets_thread(void *arg)
{
  my_thread_init();
  handle_connections_sockets();
  decrement_handler_count();
  return 0;
}

pthread_handler_t handle_connections_namedpipes(void *arg)
{
  HANDLE hConnectedPipe;
  OVERLAPPED connectOverlapped= {0};
  THD *thd;
  my_thread_init();
  DBUG_ENTER("handle_connections_namedpipes");
  connectOverlapped.hEvent= CreateEvent(NULL, TRUE, FALSE, NULL);
  if (!connectOverlapped.hEvent)
  {
    sql_print_error("Can't create event, last error=%u", GetLastError());
    unireg_abort(1);
  }
  DBUG_PRINT("general",("Waiting for named pipe connections."));
  while (!abort_loop)
  {
    /* wait for named pipe connection */
    BOOL fConnected= ConnectNamedPipe(hPipe, &connectOverlapped);
    if (!fConnected && (GetLastError() == ERROR_IO_PENDING))
    {
        /*
          ERROR_IO_PENDING says async IO has started but not yet finished.
          GetOverlappedResult will wait for completion.
        */
        DWORD bytes;
        fConnected= GetOverlappedResult(hPipe, &connectOverlapped,&bytes, TRUE);
    }
    if (abort_loop)
      break;
    if (!fConnected)
      fConnected = GetLastError() == ERROR_PIPE_CONNECTED;
    if (!fConnected)
    {
      CloseHandle(hPipe);
      if ((hPipe= CreateNamedPipe(pipe_name,
                                  PIPE_ACCESS_DUPLEX |
                                  FILE_FLAG_OVERLAPPED,
                                  PIPE_TYPE_BYTE |
                                  PIPE_READMODE_BYTE |
                                  PIPE_WAIT,
                                  PIPE_UNLIMITED_INSTANCES,
                                  (int) global_system_variables.
                                  net_buffer_length,
                                  (int) global_system_variables.
                                  net_buffer_length,
                                  NMPWAIT_USE_DEFAULT_WAIT,
                                  &saPipeSecurity)) ==
    INVALID_HANDLE_VALUE)
      {
  sql_perror("Can't create new named pipe!");
  break;          // Abort
      }
    }
    hConnectedPipe = hPipe;
    /* create new pipe for new connection */
    if ((hPipe = CreateNamedPipe(pipe_name,
                 PIPE_ACCESS_DUPLEX |
                 FILE_FLAG_OVERLAPPED,
         PIPE_TYPE_BYTE |
         PIPE_READMODE_BYTE |
         PIPE_WAIT,
         PIPE_UNLIMITED_INSTANCES,
         (int) global_system_variables.net_buffer_length,
         (int) global_system_variables.net_buffer_length,
         NMPWAIT_USE_DEFAULT_WAIT,
         &saPipeSecurity)) ==
  INVALID_HANDLE_VALUE)
    {
      sql_perror("Can't create new named pipe!");
      hPipe=hConnectedPipe;
      continue;         // We have to try again
    }

    if (!(thd = new THD))
    {
      DisconnectNamedPipe(hConnectedPipe);
      CloseHandle(hConnectedPipe);
      continue;
    }
    if (!(thd->net.vio= vio_new_win32pipe(hConnectedPipe)) ||
  my_net_init(&thd->net, thd->net.vio))
    {
      close_connection(thd, ER_OUT_OF_RESOURCES);
      delete thd;
      continue;
    }
    /* Host is unknown */
    thd->security_ctx->host= my_strdup(my_localhost, MYF(0));
    create_new_thread(thd);
  }
  CloseHandle(connectOverlapped.hEvent);
  DBUG_LEAVE;
  decrement_handler_count();
  return 0;
}
#endif /* _WIN32 */


#ifdef HAVE_SMEM

/**
  Thread of shared memory's service.

  @param arg                              Arguments of thread
*/
// pthread_handler_t handle_connections_shared_memory(void *arg)
// {
//   /* file-mapping object, use for create shared memory */
//   HANDLE handle_connect_file_map= 0;
//   char  *handle_connect_map= 0;                 // pointer on shared memory
//   HANDLE event_connect_answer= 0;
//   ulong smem_buffer_length= shared_memory_buffer_length + 4;
//   ulong connect_number= 1;
//   char *tmp= NULL;
//   char *suffix_pos;
//   char connect_number_char[22], *p;
//   const char *errmsg= 0;
//   SECURITY_ATTRIBUTES *sa_event= 0, *sa_mapping= 0;
//   my_thread_init();
//   DBUG_ENTER("handle_connections_shared_memorys");
//   DBUG_PRINT("general",("Waiting for allocated shared memory."));
// 
//   /*
//      get enough space base-name + '_' + longest suffix we might ever send
//    */
//   if (!(tmp= (char *)my_malloc(strlen(shared_memory_base_name) + 32L, MYF(MY_FAE))))
//     goto error;
// 
//   if (my_security_attr_create(&sa_event, &errmsg,
//                               GENERIC_ALL, SYNCHRONIZE | EVENT_MODIFY_STATE))
//     goto error;
// 
//   if (my_security_attr_create(&sa_mapping, &errmsg,
//                              GENERIC_ALL, FILE_MAP_READ | FILE_MAP_WRITE))
//     goto error;
// 
//   /*
//     The name of event and file-mapping events create agree next rule:
//       shared_memory_base_name+unique_part
//     Where:
//       shared_memory_base_name is unique value for each server
//       unique_part is unique value for each object (events and file-mapping)
//   */
//   suffix_pos= strxmov(tmp,shared_memory_base_name,"_",NullS);
//   strmov(suffix_pos, "CONNECT_REQUEST");
// //   if ((smem_event_connect_request= CreateEvent(sa_event,
// //                                                FALSE, FALSE, tmp)) == 0)
// //   {
// //     errmsg= "Could not create request event";
// //     goto error;
// //   }
//   strmov(suffix_pos, "CONNECT_ANSWER");
//   if ((event_connect_answer= CreateEvent(sa_event, FALSE, FALSE, tmp)) == 0)
//   {
//     errmsg="Could not create answer event";
//     goto error;
//   }
//   strmov(suffix_pos, "CONNECT_DATA");
//   if ((handle_connect_file_map=
//        CreateFileMapping(INVALID_HANDLE_VALUE, sa_mapping,
//                          PAGE_READWRITE, 0, sizeof(connect_number), tmp)) == 0)
//   {
//     errmsg= "Could not create file mapping";
//     goto error;
//   }
//   if ((handle_connect_map= (char *)MapViewOfFile(handle_connect_file_map,
//               FILE_MAP_WRITE,0,0,
//               sizeof(DWORD))) == 0)
//   {
//     errmsg= "Could not create shared memory service";
//     goto error;
//   }
// 
//   while (!abort_loop)
//   {
//     /* Wait a request from client */
// //     WaitForSingleObject(smem_event_connect_request,INFINITE);
// 
//     /*
//        it can be after shutdown command
//     */
//     if (abort_loop)
//       goto error;
// 
//     HANDLE handle_client_file_map= 0;
//     char  *handle_client_map= 0;
//     HANDLE event_client_wrote= 0;
//     HANDLE event_client_read= 0;    // for transfer data server <-> client
//     HANDLE event_server_wrote= 0;
//     HANDLE event_server_read= 0;
//     HANDLE event_conn_closed= 0;
//     THD *thd= 0;
// 
//     p= int10_to_str(connect_number, connect_number_char, 10);
//     /*
//       The name of event and file-mapping events create agree next rule:
//         shared_memory_base_name+unique_part+number_of_connection
//         Where:
//     shared_memory_base_name is uniquel value for each server
//     unique_part is unique value for each object (events and file-mapping)
//     number_of_connection is connection-number between server and client
//     */
//     suffix_pos= strxmov(tmp,shared_memory_base_name,"_",connect_number_char,
//        "_",NullS);
//     strmov(suffix_pos, "DATA");
//     if ((handle_client_file_map=
//          CreateFileMapping(INVALID_HANDLE_VALUE, sa_mapping,
//                            PAGE_READWRITE, 0, smem_buffer_length, tmp)) == 0)
//     {
//       errmsg= "Could not create file mapping";
//       goto errorconn;
//     }
//     if ((handle_client_map= (char*)MapViewOfFile(handle_client_file_map,
//               FILE_MAP_WRITE,0,0,
//               smem_buffer_length)) == 0)
//     {
//       errmsg= "Could not create memory map";
//       goto errorconn;
//     }
//     strmov(suffix_pos, "CLIENT_WROTE");
//     if ((event_client_wrote= CreateEvent(sa_event, FALSE, FALSE, tmp)) == 0)
//     {
//       errmsg= "Could not create client write event";
//       goto errorconn;
//     }
//     strmov(suffix_pos, "CLIENT_READ");
//     if ((event_client_read= CreateEvent(sa_event, FALSE, FALSE, tmp)) == 0)
//     {
//       errmsg= "Could not create client read event";
//       goto errorconn;
//     }
//     strmov(suffix_pos, "SERVER_READ");
//     if ((event_server_read= CreateEvent(sa_event, FALSE, FALSE, tmp)) == 0)
//     {
//       errmsg= "Could not create server read event";
//       goto errorconn;
//     }
//     strmov(suffix_pos, "SERVER_WROTE");
//     if ((event_server_wrote= CreateEvent(sa_event,
//                                          FALSE, FALSE, tmp)) == 0)
//     {
//       errmsg= "Could not create server write event";
//       goto errorconn;
//     }
//     strmov(suffix_pos, "CONNECTION_CLOSED");
//     if ((event_conn_closed= CreateEvent(sa_event,
//                                         TRUE, FALSE, tmp)) == 0)
//     {
//       errmsg= "Could not create closed connection event";
//       goto errorconn;
//     }
//     if (abort_loop)
//       goto errorconn;
//     if (!(thd= new THD))
//       goto errorconn;
//     /* Send number of connection to client */
//     int4store(handle_connect_map, connect_number);
//     if (!SetEvent(event_connect_answer))
//     {
//       errmsg= "Could not send answer event";
//       goto errorconn;
//     }
//     /* Set event that client should receive data */
//     if (!SetEvent(event_client_read))
//     {
//       errmsg= "Could not set client to read mode";
//       goto errorconn;
//     }
//     if (!(thd->net.vio= vio_new_win32shared_memory(handle_client_file_map,
//                                                    handle_client_map,
//                                                    event_client_wrote,
//                                                    event_client_read,
//                                                    event_server_wrote,
//                                                    event_server_read,
//                                                    event_conn_closed)) ||
//                         my_net_init(&thd->net, thd->net.vio))
//     {
//       close_connection(thd, ER_OUT_OF_RESOURCES);
//       errmsg= 0;
//       goto errorconn;
//     }
//     thd->security_ctx->host= my_strdup(my_localhost, MYF(0)); /* Host is unknown */
//     create_new_thread(thd);
//     connect_number++;
//     continue;
// 
// errorconn:
//     /* Could not form connection;  Free used handlers/memort and retry */
//     if (errmsg)
//     {
//       char buff[180];
//       strxmov(buff, "Can't create shared memory connection: ", errmsg, ".",
//         NullS);
//       sql_perror(buff);
//     }
//     if (handle_client_file_map)
//       CloseHandle(handle_client_file_map);
//     if (handle_client_map)
//       UnmapViewOfFile(handle_client_map);
//     if (event_server_wrote)
//       CloseHandle(event_server_wrote);
//     if (event_server_read)
//       CloseHandle(event_server_read);
//     if (event_client_wrote)
//       CloseHandle(event_client_wrote);
//     if (event_client_read)
//       CloseHandle(event_client_read);
//     if (event_conn_closed)
//       CloseHandle(event_conn_closed);
//     delete thd;
//   }
// 
//   /* End shared memory handling */
// error:
//   if (tmp)
//     my_free(tmp);
// 
//   if (errmsg)
//   {
//     char buff[180];
//     strxmov(buff, "Can't create shared memory service: ", errmsg, ".", NullS);
//     sql_perror(buff);
//   }
//   my_security_attr_free(sa_event);
//   my_security_attr_free(sa_mapping);
//   if (handle_connect_map) UnmapViewOfFile(handle_connect_map);
//   if (handle_connect_file_map)  CloseHandle(handle_connect_file_map);
//   if (event_connect_answer) CloseHandle(event_connect_answer);
// //   if (smem_event_connect_request) CloseHandle(smem_event_connect_request);
//   DBUG_LEAVE;
//   decrement_handler_count();
//   return 0;
// }
#endif /* HAVE_SMEM */
#endif /* EMBEDDED_LIBRARY */


/****************************************************************************
  Handle start options
******************************************************************************/

/**
  Process command line options flagged as 'early'.
  Some components needs to be initialized as early as possible,
  because the rest of the server initialization depends on them.
  Options that needs to be parsed early includes:
  - the performance schema, when compiled in,
  - options related to the help,
  - options related to the bootstrap
  The performance schema needs to be initialized as early as possible,
  before to-be-instrumented objects of the server are initialized.
*/
int handle_early_options()
{
  int ho_error;
  vector<my_option> all_early_options;
  all_early_options.reserve(100);

  my_getopt_register_get_addr(NULL);
  /* Skip unknown options so that they may be processed later */
  my_getopt_skip_unknown= TRUE;

  /* Add the system variables parsed early */
  sys_var_add_options(&all_early_options, sys_var::PARSE_EARLY);

  /* Add the command line options parsed early */
  for (my_option *opt= my_long_early_options;
       opt->name != NULL;
       opt++)
    all_early_options.push_back(*opt);

  add_terminator(&all_early_options);

  /*
    Logs generated while parsing the command line
    options are buffered and printed later.
  */
  buffered_logs.init();
  my_getopt_error_reporter= buffered_option_error_reporter;
  my_charset_error_reporter= buffered_option_error_reporter;

  ho_error= handle_options(&remaining_argc, &remaining_argv,
                           &all_early_options[0], mysqld_get_one_option);
  if (ho_error == 0)
  {
    /* Add back the program name handle_options removes */
    remaining_argc++;
    remaining_argv--;
  }

  // Swap with an empty vector, i.e. delete elements and free allocated space.
  vector<my_option>().swap(all_early_options);

  return ho_error;
}

void adjust_related_options()
{
  /* In bootstrap, disable grant tables (we are about to create them) */
  if (opt_bootstrap)
    opt_noacl= 1;
}

vector<my_option> all_options;


struct my_option my_long_early_options[]=
{
  {"help", '?', "Display this help and exit.",
   &opt_help, &opt_help, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"verbose", 'v', "Used with --help option for detailed help.",
   &opt_verbose, &opt_verbose, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"version", 'V', "Output version information and exit.", 0, 0, 0, GET_NO_ARG,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
};

sinfo_t global_source;
char** isql_option;

mysql_mutex_t	isql_option_mutex;

struct my_option my_isql_options[]=
{
  {"host", 0, "remote server address.",	
    &global_source.host, &global_source.host, 0, 
    GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0,	0, 0},

  {"password", 0, "the user's password.",	
    &global_source.password, &global_source.password, 0, 
    GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},

  {"user", 0, "login user.", 
    &global_source.user, &global_source.user, 0, 
    GET_STR_ALLOC,	REQUIRED_ARG, 0, 0, 0, 0, 0, 0},

  {"port", 0, "mysql server's port.", 
    &global_source.port, &global_source.port, 0, 
    GET_INT,	REQUIRED_ARG, 0, 0, 0, 0, 0, 0},

  {"check", 0, "to check.", 
    &global_source.check, &global_source.check, 0, 
    GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},

  {"execute", 0, "to execute.", 
    &global_source.execute, &global_source.execute, 0, 
    GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},

  {"force", 0, "force to execute though exist error before.", 
    &global_source.force, &global_source.force, 0, 
    GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},

  {"remote_backup", 0, "backup in execute.",
    &global_source.backup, &global_source.backup, 0, 
    GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},

  {"ignore_warnings", 0, "ignore warnings in check stage when execute.",
    &global_source.ignore_warnings, &global_source.ignore_warnings, 0,
    GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},

  {"split", 0, "split the sql statements to several parts.",
    &global_source.split, &global_source.split, 0,
    GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},

  {"query_print", 0, "print the query tree.",
    &global_source.query_print, &global_source.query_print, 0,
    GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
};

/**
  System variables are automatically command-line options (few
  exceptions are documented in sys_var.h), so don't need
  to be listed here.
*/

struct my_option my_long_options[]=
{
  {"ansi", 'a', "Use ANSI SQL syntax instead of MySQL syntax. This mode "
   "will also set transaction isolation level 'serializable'.", 0, 0, 0,
   GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"character-set-client-handshake", 0,
   "Don't ignore client side character set value sent during handshake.",
   &opt_character_set_client_handshake,
   &opt_character_set_client_handshake,
    0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},
  {"character-set-filesystem", 0,
   "Set the filesystem character set.",
   &character_set_filesystem_name,
   &character_set_filesystem_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
  {"character-set-server", 'C', "Set the default character set.",
   &default_character_set_name, &default_character_set_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
  {"chroot", 'r', "Chroot mysqld daemon during startup.",
   &mysqld_chroot, &mysqld_chroot, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0},
  {"collation-server", 0, "Set the default collation.",
   &default_collation_name, &default_collation_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
  {"core-file", OPT_WANT_CORE, "Write core on errors.", 0, 0, 0, GET_NO_ARG,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  /* default-storage-engine should have "MyISAM" as def_value. Instead
     of initializing it here it is done in init_common_variables() due
     to a compiler bug in Sun Studio compiler. */
  {"default-time-zone", 0, "Set the default time zone.",
   &default_tz_name, &default_tz_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
  {"memlock", 0, "Lock mysqld in memory.", &locked_in_memory,
   &locked_in_memory, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"port-open-timeout", 0,
   "Maximum time in seconds to wait for the port to become free. "
   "(Default: No wait).", &mysqld_port_timeout, &mysqld_port_timeout, 0,
   GET_UINT, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"skip-host-cache", OPT_SKIP_HOST_CACHE, "Don't cache host names.", 0, 0, 0,
   GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"skip-stack-trace", OPT_SKIP_STACK_TRACE,
   "Don't print a stack trace on failure.", 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0,
   0, 0, 0, 0},
  {"user", 'u', "Run mysqld daemon as user.", 0, 0, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0},
  {"default_authentication_plugin", OPT_DEFAULT_AUTH,
   "Defines what password- and authentication algorithm to use per default",
   0, 0, 0,
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
};


static int show_queries(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONGLONG;
  var->value= (char *)&thd->query_id;
  return 0;
}


static int show_net_compression(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_MY_BOOL;
  var->value= (char *)&thd->net.compress;
  return 0;
}

static int show_starttime(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONGLONG;
  var->value= buff;
  *((longlong *)buff)= (longlong) (thd->query_start() - server_start_time);
  return 0;
}

#ifdef ENABLED_PROFILING
static int show_flushstatustime(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONGLONG;
  var->value= buff;
  *((longlong *)buff)= (longlong) (thd->query_start() - flush_status_time);
  return 0;
}
#endif

// #ifdef HAVE_REPLICATION
// static int show_slave_running(THD *thd, SHOW_VAR *var, char *buff)
// {
//   var->type= SHOW_MY_BOOL;
//   mysql_mutex_lock(&LOCK_active_mi);
//   var->value= buff;
//   *((my_bool *)buff)= (my_bool) (active_mi &&
//                                  active_mi->slave_running == MYSQL_SLAVE_RUN_CONNECT &&
//                                  active_mi->rli->slave_running);
//   mysql_mutex_unlock(&LOCK_active_mi);
//   return 0;
// }
// 
// static int show_slave_retried_trans(THD *thd, SHOW_VAR *var, char *buff)
// {
//   /*
//     TODO: with multimaster, have one such counter per line in
//     SHOW SLAVE STATUS, and have the sum over all lines here.
//   */
//   mysql_mutex_lock(&LOCK_active_mi);
//   if (active_mi)
//   {
//     var->type= SHOW_LONG;
//     var->value= buff;
//     mysql_mutex_lock(&active_mi->rli->data_lock);
//     *((long *)buff)= (long)active_mi->rli->retried_trans;
//     mysql_mutex_unlock(&active_mi->rli->data_lock);
//   }
//   else
//     var->type= SHOW_UNDEF;
//   mysql_mutex_unlock(&LOCK_active_mi);
//   return 0;
// }
// 
// static int show_slave_received_heartbeats(THD *thd, SHOW_VAR *var, char *buff)
// {
//   mysql_mutex_lock(&LOCK_active_mi);
//   if (active_mi)
//   {
//     var->type= SHOW_LONGLONG;
//     var->value= buff;
//     mysql_mutex_lock(&active_mi->rli->data_lock);
//     *((longlong *)buff)= active_mi->received_heartbeats;
//     mysql_mutex_unlock(&active_mi->rli->data_lock);
//   }
//   else
//     var->type= SHOW_UNDEF;
//   mysql_mutex_unlock(&LOCK_active_mi);
//   return 0;
// }
// 
// static int show_slave_last_heartbeat(THD *thd, SHOW_VAR *var, char *buff)
// {
//   MYSQL_TIME received_heartbeat_time;
//   mysql_mutex_lock(&LOCK_active_mi);
//   if (active_mi)
//   {
//     var->type= SHOW_CHAR;
//     var->value= buff;
//     if (active_mi->last_heartbeat == 0)
//       buff[0]='\0';
//     else
//     {
//       thd->variables.time_zone->gmt_sec_to_TIME(&received_heartbeat_time, 
//         active_mi->last_heartbeat);
//       my_datetime_to_str(&received_heartbeat_time, buff, 0);
//     }
//   }
//   else
//     var->type= SHOW_UNDEF;
//   mysql_mutex_unlock(&LOCK_active_mi);
//   return 0;
// }
// 
// static int show_heartbeat_period(THD *thd, SHOW_VAR *var, char *buff)
// {
//   mysql_mutex_lock(&LOCK_active_mi);
//   if (active_mi)
//   {
//     var->type= SHOW_CHAR;
//     var->value= buff;
//     sprintf(buff, "%.3f", active_mi->heartbeat_period);
//   }
//   else
//     var->type= SHOW_UNDEF;
//   mysql_mutex_unlock(&LOCK_active_mi);
//   return 0;
// }
// 
// #ifndef DBUG_OFF
// static int show_slave_rows_last_search_algorithm_used(THD *thd, SHOW_VAR *var, char *buff)
// {
//   uint res= slave_rows_last_search_algorithm_used;
//   const char* s= ((res == Rows_log_event::ROW_LOOKUP_TABLE_SCAN) ? "TABLE_SCAN" :
//                   ((res == Rows_log_event::ROW_LOOKUP_HASH_SCAN) ? "HASH_SCAN" : 
//                    "INDEX_SCAN"));
// 
//   var->type= SHOW_CHAR;
//   var->value= buff;
//   sprintf(buff, "%s", s);
// 
//   return 0;
// }
// #endif
// 
// #endif /* HAVE_REPLICATION */

static int show_open_tables(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
//   *((long *)buff)= (long)table_cache_manager.cached_tables();
  return 0;
}

static int show_prepared_stmt_count(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  mysql_mutex_lock(&LOCK_prepared_stmt_count);
  *((long *)buff)= (long)prepared_stmt_count;
  mysql_mutex_unlock(&LOCK_prepared_stmt_count);
  return 0;
}

static int show_table_definitions(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (long)cached_table_definitions();
  return 0;
}

SHOW_VAR status_vars[]= {
  {"Aborted_clients",          (char*) &aborted_threads,        SHOW_LONG},
  {"Aborted_connects",         (char*) &aborted_connects,       SHOW_LONG},
  {"Binlog_cache_disk_use",    (char*) &binlog_cache_disk_use,  SHOW_LONG},
  {"Binlog_cache_use",         (char*) &binlog_cache_use,       SHOW_LONG},
  {"Binlog_stmt_cache_disk_use",(char*) &binlog_stmt_cache_disk_use,  SHOW_LONG},
  {"Binlog_stmt_cache_use",    (char*) &binlog_stmt_cache_use,       SHOW_LONG},
  {"Bytes_received",           (char*) offsetof(STATUS_VAR, bytes_received), SHOW_LONGLONG_STATUS},
  {"Bytes_sent",               (char*) offsetof(STATUS_VAR, bytes_sent), SHOW_LONGLONG_STATUS},
  {"Com",                      (char*) com_status_vars, SHOW_ARRAY},
  {"Compression",              (char*) &show_net_compression, SHOW_FUNC},
  {"Connections",              (char*) &thread_id,              SHOW_LONG_NOFLUSH},
  {"Connection_errors_accept", (char*) &connection_errors_accept, SHOW_LONG},
  {"Connection_errors_internal", (char*) &connection_errors_internal, SHOW_LONG},
  {"Connection_errors_max_connections", (char*) &connection_errors_max_connection, SHOW_LONG},
  {"Connection_errors_peer_address", (char*) &connection_errors_peer_addr, SHOW_LONG},
  {"Connection_errors_select", (char*) &connection_errors_select, SHOW_LONG},
  {"Connection_errors_tcpwrap", (char*) &connection_errors_tcpwrap, SHOW_LONG},
  {"Created_tmp_disk_tables",  (char*) offsetof(STATUS_VAR, created_tmp_disk_tables), SHOW_LONGLONG_STATUS},
  {"Created_tmp_files",        (char*) &my_tmp_file_created, SHOW_LONG},
  {"Created_tmp_tables",       (char*) offsetof(STATUS_VAR, created_tmp_tables), SHOW_LONGLONG_STATUS},
  {"Delayed_errors",           (char*) &delayed_insert_errors,  SHOW_LONG},
  {"Delayed_insert_threads",   (char*) &delayed_insert_threads, SHOW_LONG_NOFLUSH},
  {"Delayed_writes",           (char*) &delayed_insert_writes,  SHOW_LONG},
  {"Flush_commands",           (char*) &refresh_version,        SHOW_LONG_NOFLUSH},
  {"Handler_commit",           (char*) offsetof(STATUS_VAR, ha_commit_count), SHOW_LONGLONG_STATUS},
  {"Handler_delete",           (char*) offsetof(STATUS_VAR, ha_delete_count), SHOW_LONGLONG_STATUS},
  {"Handler_discover",         (char*) offsetof(STATUS_VAR, ha_discover_count), SHOW_LONGLONG_STATUS},
  {"Handler_external_lock",    (char*) offsetof(STATUS_VAR, ha_external_lock_count), SHOW_LONGLONG_STATUS},
  {"Handler_mrr_init",         (char*) offsetof(STATUS_VAR, ha_multi_range_read_init_count),  SHOW_LONGLONG_STATUS},
  {"Handler_prepare",          (char*) offsetof(STATUS_VAR, ha_prepare_count),  SHOW_LONGLONG_STATUS},
  {"Handler_read_first",       (char*) offsetof(STATUS_VAR, ha_read_first_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_key",         (char*) offsetof(STATUS_VAR, ha_read_key_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_last",        (char*) offsetof(STATUS_VAR, ha_read_last_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_next",        (char*) offsetof(STATUS_VAR, ha_read_next_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_prev",        (char*) offsetof(STATUS_VAR, ha_read_prev_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_rnd",         (char*) offsetof(STATUS_VAR, ha_read_rnd_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_rnd_next",    (char*) offsetof(STATUS_VAR, ha_read_rnd_next_count), SHOW_LONGLONG_STATUS},
  {"Handler_rollback",         (char*) offsetof(STATUS_VAR, ha_rollback_count), SHOW_LONGLONG_STATUS},
  {"Handler_savepoint",        (char*) offsetof(STATUS_VAR, ha_savepoint_count), SHOW_LONGLONG_STATUS},
  {"Handler_savepoint_rollback",(char*) offsetof(STATUS_VAR, ha_savepoint_rollback_count), SHOW_LONGLONG_STATUS},
  {"Handler_update",           (char*) offsetof(STATUS_VAR, ha_update_count), SHOW_LONGLONG_STATUS},
  {"Handler_write",            (char*) offsetof(STATUS_VAR, ha_write_count), SHOW_LONGLONG_STATUS},
  {"Key_blocks_not_flushed",   (char*) offsetof(KEY_CACHE, global_blocks_changed), SHOW_KEY_CACHE_LONG},
  {"Key_blocks_unused",        (char*) offsetof(KEY_CACHE, blocks_unused), SHOW_KEY_CACHE_LONG},
  {"Key_blocks_used",          (char*) offsetof(KEY_CACHE, blocks_used), SHOW_KEY_CACHE_LONG},
  {"Key_read_requests",        (char*) offsetof(KEY_CACHE, global_cache_r_requests), SHOW_KEY_CACHE_LONGLONG},
  {"Key_reads",                (char*) offsetof(KEY_CACHE, global_cache_read), SHOW_KEY_CACHE_LONGLONG},
  {"Key_write_requests",       (char*) offsetof(KEY_CACHE, global_cache_w_requests), SHOW_KEY_CACHE_LONGLONG},
  {"Key_writes",               (char*) offsetof(KEY_CACHE, global_cache_write), SHOW_KEY_CACHE_LONGLONG},
  {"Last_query_cost",          (char*) offsetof(STATUS_VAR, last_query_cost), SHOW_DOUBLE_STATUS},
  {"Last_query_partial_plans", (char*) offsetof(STATUS_VAR, last_query_partial_plans), SHOW_LONGLONG_STATUS},
  {"Max_used_connections",     (char*) &max_used_connections,  SHOW_LONG},
  {"Not_flushed_delayed_rows", (char*) &delayed_rows_in_use,    SHOW_LONG_NOFLUSH},
  {"Open_files",               (char*) &my_file_opened,         SHOW_LONG_NOFLUSH},
  {"Open_streams",             (char*) &my_stream_opened,       SHOW_LONG_NOFLUSH},
  {"Open_table_definitions",   (char*) &show_table_definitions, SHOW_FUNC},
  {"Open_tables",              (char*) &show_open_tables,       SHOW_FUNC},
  {"Opened_files",             (char*) &my_file_total_opened, SHOW_LONG_NOFLUSH},
  {"Opened_tables",            (char*) offsetof(STATUS_VAR, opened_tables), SHOW_LONGLONG_STATUS},
  {"Opened_table_definitions", (char*) offsetof(STATUS_VAR, opened_shares), SHOW_LONGLONG_STATUS},
  {"Prepared_stmt_count",      (char*) &show_prepared_stmt_count, SHOW_FUNC},
#ifdef HAVE_QUERY_CACHE
  {"Qcache_free_blocks",       (char*) &query_cache.free_memory_blocks, SHOW_LONG_NOFLUSH},
  {"Qcache_free_memory",       (char*) &query_cache.free_memory, SHOW_LONG_NOFLUSH},
  {"Qcache_hits",              (char*) &query_cache.hits,       SHOW_LONG},
  {"Qcache_inserts",           (char*) &query_cache.inserts,    SHOW_LONG},
  {"Qcache_lowmem_prunes",     (char*) &query_cache.lowmem_prunes, SHOW_LONG},
  {"Qcache_not_cached",        (char*) &query_cache.refused,    SHOW_LONG},
  {"Qcache_queries_in_cache",  (char*) &query_cache.queries_in_cache, SHOW_LONG_NOFLUSH},
  {"Qcache_total_blocks",      (char*) &query_cache.total_blocks, SHOW_LONG_NOFLUSH},
#endif /*HAVE_QUERY_CACHE*/
  {"Queries",                  (char*) &show_queries,            SHOW_FUNC},
  {"Questions",                (char*) offsetof(STATUS_VAR, questions), SHOW_LONGLONG_STATUS},
  {"Select_full_join",         (char*) offsetof(STATUS_VAR, select_full_join_count), SHOW_LONGLONG_STATUS},
  {"Select_full_range_join",   (char*) offsetof(STATUS_VAR, select_full_range_join_count), SHOW_LONGLONG_STATUS},
  {"Select_range",             (char*) offsetof(STATUS_VAR, select_range_count), SHOW_LONGLONG_STATUS},
  {"Select_range_check",       (char*) offsetof(STATUS_VAR, select_range_check_count), SHOW_LONGLONG_STATUS},
  {"Select_scan",	       (char*) offsetof(STATUS_VAR, select_scan_count), SHOW_LONGLONG_STATUS},
  {"Slave_open_temp_tables",   (char*) &slave_open_temp_tables, SHOW_INT},
// #ifdef HAVE_REPLICATION
//   {"Slave_retried_transactions",(char*) &show_slave_retried_trans, SHOW_FUNC},
//   {"Slave_heartbeat_period",   (char*) &show_heartbeat_period, SHOW_FUNC},
//   {"Slave_received_heartbeats",(char*) &show_slave_received_heartbeats, SHOW_FUNC},
//   {"Slave_last_heartbeat",     (char*) &show_slave_last_heartbeat, SHOW_FUNC},
// #ifndef DBUG_OFF
//   {"Slave_rows_last_search_algorithm_used",(char*) &show_slave_rows_last_search_algorithm_used, SHOW_FUNC},
// #endif
//   {"Slave_running",            (char*) &show_slave_running,     SHOW_FUNC},
// #endif
  {"Slow_launch_threads",      (char*) &slow_launch_threads,    SHOW_LONG},
  {"Slow_queries",             (char*) offsetof(STATUS_VAR, long_query_count), SHOW_LONGLONG_STATUS},
  {"Sort_merge_passes",        (char*) offsetof(STATUS_VAR, filesort_merge_passes), SHOW_LONGLONG_STATUS},
  {"Sort_range",               (char*) offsetof(STATUS_VAR, filesort_range_count), SHOW_LONGLONG_STATUS},
  {"Sort_rows",                (char*) offsetof(STATUS_VAR, filesort_rows), SHOW_LONGLONG_STATUS},
  {"Sort_scan",                (char*) offsetof(STATUS_VAR, filesort_scan_count), SHOW_LONGLONG_STATUS},
// #ifdef HAVE_OPENSSL
// #ifndef EMBEDDED_LIBRARY
//   {"Ssl_accept_renegotiates",  (char*) &show_ssl_ctx_sess_accept_renegotiate, SHOW_FUNC},
//   {"Ssl_accepts",              (char*) &show_ssl_ctx_sess_accept, SHOW_FUNC},
//   {"Ssl_callback_cache_hits",  (char*) &show_ssl_ctx_sess_cb_hits, SHOW_FUNC},
//   {"Ssl_cipher",               (char*) &show_ssl_get_cipher, SHOW_FUNC},
//   {"Ssl_cipher_list",          (char*) &show_ssl_get_cipher_list, SHOW_FUNC},
//   {"Ssl_client_connects",      (char*) &show_ssl_ctx_sess_connect, SHOW_FUNC},
//   {"Ssl_connect_renegotiates", (char*) &show_ssl_ctx_sess_connect_renegotiate, SHOW_FUNC},
//   {"Ssl_ctx_verify_depth",     (char*) &show_ssl_ctx_get_verify_depth, SHOW_FUNC},
//   {"Ssl_ctx_verify_mode",      (char*) &show_ssl_ctx_get_verify_mode, SHOW_FUNC},
//   {"Ssl_default_timeout",      (char*) &show_ssl_get_default_timeout, SHOW_FUNC},
//   {"Ssl_finished_accepts",     (char*) &show_ssl_ctx_sess_accept_good, SHOW_FUNC},
//   {"Ssl_finished_connects",    (char*) &show_ssl_ctx_sess_connect_good, SHOW_FUNC},
//   {"Ssl_session_cache_hits",   (char*) &show_ssl_ctx_sess_hits, SHOW_FUNC},
//   {"Ssl_session_cache_misses", (char*) &show_ssl_ctx_sess_misses, SHOW_FUNC},
//   {"Ssl_session_cache_mode",   (char*) &show_ssl_ctx_get_session_cache_mode, SHOW_FUNC},
//   {"Ssl_session_cache_overflows", (char*) &show_ssl_ctx_sess_cache_full, SHOW_FUNC},
//   {"Ssl_session_cache_size",   (char*) &show_ssl_ctx_sess_get_cache_size, SHOW_FUNC},
//   {"Ssl_session_cache_timeouts", (char*) &show_ssl_ctx_sess_timeouts, SHOW_FUNC},
//   {"Ssl_sessions_reused",      (char*) &show_ssl_session_reused, SHOW_FUNC},
//   {"Ssl_used_session_cache_entries",(char*) &show_ssl_ctx_sess_number, SHOW_FUNC},
//   {"Ssl_verify_depth",         (char*) &show_ssl_get_verify_depth, SHOW_FUNC},
//   {"Ssl_verify_mode",          (char*) &show_ssl_get_verify_mode, SHOW_FUNC},
//   {"Ssl_version",              (char*) &show_ssl_get_version, SHOW_FUNC},
//   {"Ssl_server_not_before",    (char*) &show_ssl_get_server_not_before,
//     SHOW_FUNC},
//   {"Ssl_server_not_after",     (char*) &show_ssl_get_server_not_after,
//     SHOW_FUNC},
// #ifndef HAVE_YASSL
//   {"Rsa_public_key",           (char*) &show_rsa_public_key, SHOW_FUNC},
// #endif
// #endif
// #endif /* HAVE_OPENSSL */
  {"Table_locks_immediate",    (char*) &locks_immediate,        SHOW_LONG},
  {"Table_locks_waited",       (char*) &locks_waited,           SHOW_LONG},
  {"Table_open_cache_hits",    (char*) offsetof(STATUS_VAR, table_open_cache_hits), SHOW_LONGLONG_STATUS},
  {"Table_open_cache_misses",  (char*) offsetof(STATUS_VAR, table_open_cache_misses), SHOW_LONGLONG_STATUS},
  {"Table_open_cache_overflows",(char*) offsetof(STATUS_VAR, table_open_cache_overflows), SHOW_LONGLONG_STATUS},
  {"Threads_cached",           (char*) &blocked_pthread_count,    SHOW_LONG_NOFLUSH},
  {"Threads_connected",        (char*) &connection_count,       SHOW_INT},
  {"Threads_created",        (char*) &thread_created,   SHOW_LONG_NOFLUSH},
  {"Threads_running",          (char*) &num_thread_running,     SHOW_INT},
  {"Uptime",                   (char*) &show_starttime,         SHOW_FUNC},
#ifdef ENABLED_PROFILING
  {"Uptime_since_flush_status",(char*) &show_flushstatustime,   SHOW_FUNC},
#endif
  {NullS, NullS, SHOW_LONG}
};

void add_terminator(vector<my_option> *options)
{
  my_option empty_element=
    {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0};
  options->push_back(empty_element);
}

#ifndef EMBEDDED_LIBRARY
static void print_version(void)
{
  set_server_version();

  printf("%s  Ver %s for %s on %s (%s)\n",my_progname,
   server_version,SYSTEM_TYPE,MACHINE_TYPE, MYSQL_COMPILATION_COMMENT);
}

/** Compares two options' names, treats - and _ the same */
static bool operator<(const my_option &a, const my_option &b)
{
  const char *sa= a.name;
  const char *sb= b.name;
  for (; *sa || *sb; sa++, sb++)
  {
    if (*sa < *sb)
    {
      if (*sa == '-' && *sb == '_')
        continue;
      else
        return true;
    }
    if (*sa > *sb)
    {
      if (*sa == '_' && *sb == '-')
        continue;
      else
        return false;
    }
  }
  DBUG_ASSERT(a.name == b.name);
  return false;
}

static void print_help()
{
  MEM_ROOT mem_root;
  init_alloc_root(&mem_root, 4096, 4096);

  all_options.pop_back();
  sys_var_add_options(&all_options, sys_var::PARSE_EARLY);
  for (my_option *opt= my_long_early_options;
       opt->name != NULL;
       opt++)
  {
    all_options.push_back(*opt);
  }
  add_plugin_options(&all_options, &mem_root);
  std::sort(all_options.begin(), all_options.end(), std::less<my_option>());
  add_terminator(&all_options);

  my_print_help(&all_options[0]);
  my_print_variables(&all_options[0]);

  free_root(&mem_root, MYF(0));
  vector<my_option>().swap(all_options);  // Deletes the vector contents.
}

static void usage(void)
{
  DBUG_ENTER("usage");
  if (!(default_charset_info= get_charset_by_csname(default_character_set_name,
                     MY_CS_PRIMARY,
               MYF(MY_WME))))
    exit(1);
  if (!default_collation_name)
    default_collation_name= (char*) default_charset_info->name;
  print_version();
  puts(ORACLE_WELCOME_COPYRIGHT_NOTICE("2000"));
  puts("Starts the MySQL database server.\n");
  printf("Usage: %s [OPTIONS]\n", my_progname);
  if (!opt_verbose)
    puts("\nFor more help options (several pages), use mysqld --verbose --help.");
  else
  {
#ifdef __WIN__
  puts("NT and Win32 specific options:\n\
  --install                     Install the default service (NT).\n\
  --install-manual              Install the default service started manually (NT).\n\
  --install service_name        Install an optional service (NT).\n\
  --install-manual service_name Install an optional service started manually (NT).\n\
  --remove                      Remove the default service from the service list (NT).\n\
  --remove service_name         Remove the service_name from the service list (NT).\n\
  --enable-named-pipe           Only to be used for the default server (NT).\n\
  --standalone                  Dummy option to start as a standalone server (NT).\
");
  puts("");
#endif
  print_defaults(MYSQL_CONFIG_NAME,load_default_groups);
  puts("");
  set_ports();

  /* Print out all the options including plugin supplied options */
  print_help();

  if (! plugins_are_initialized)
  {
    puts("\n\
Plugins have parameters that are not reflected in this list\n\
because execution stopped before plugins were initialized.");
  }

  puts("\n\
To see what values a running MySQL server is using, type\n\
'mysqladmin variables' instead of 'mysqld --verbose --help'.");
  }
  DBUG_VOID_RETURN;
}
#endif /*!EMBEDDED_LIBRARY*/

/**
  Initialize MySQL global variables to default values.

  @note
    The reason to set a lot of global variables to zero is to allow one to
    restart the embedded server with a clean environment
    It's also needed on some exotic platforms where global variables are
    not set to 0 when a program starts.

    We don't need to set variables refered to in my_long_options
    as these are initialized by my_getopt.
*/

static int mysql_init_variables(void)
{
  /* Things reset to zero */
  opt_skip_slave_start= opt_reckless_slave = 0;
  mysql_home[0]= pidfile_name[0]= 0;
  //myisam_test_invalid_symlink= test_if_data_home_dir;
  opt_log= opt_slow_log= 0;
  opt_bin_log= 0;
  opt_disable_networking= opt_skip_show_db=0;
  opt_skip_name_resolve= 0;
  opt_ignore_builtin_innodb= 0;
  opt_update_logname= opt_binlog_index_name= 0;
  opt_tc_log_file= (char *)"tc.log";      // no hostname in tc_log file name !
  opt_secure_auth= 0;
  opt_secure_file_priv= NULL;
  opt_myisam_log= 0;
  mqh_used= 0;
  kill_in_progress= 0;
  cleanup_done= 0;
  server_id_supplied= 0;
  test_flags= select_errors= dropping_tables= ha_open_options=0;
  global_thread_count= num_thread_running= kill_blocked_pthreads_flag= wake_pthread=0;
  slave_open_temp_tables= 0;
  blocked_pthread_count= 0;
  opt_endinfo= using_udf_functions= 0;
  opt_using_transactions= 0;
  abort_loop= 0;
  ready_to_exit= shutdown_in_progress= grant_option= 0;
  aborted_threads= aborted_connects= 0;
  delayed_insert_threads= delayed_insert_writes= delayed_rows_in_use= 0;
  delayed_insert_errors= thread_created= 0;
  specialflag= SPECIAL_NO_HOST_CACHE;
  binlog_cache_use=  binlog_cache_disk_use= 0;
  max_used_connections= slow_launch_threads = 0;
  mysqld_user= mysqld_chroot= opt_init_file= opt_bin_logname = 0;
  prepared_stmt_count= 0;
  mysqld_unix_port= opt_mysql_tmpdir= my_bind_addr_str= NullS;
  memset(&mysql_tmpdir_list, 0, sizeof(mysql_tmpdir_list));
  memset(&global_status_var, 0, sizeof(global_status_var));
  opt_large_pages= 0;
  opt_super_large_pages= 0;
  key_map_full.set_all();
  server_uuid[0]= 0;

  /* Character sets */
  system_charset_info= &my_charset_utf8_general_ci;
  files_charset_info= &my_charset_utf8_general_ci;
  national_charset_info= &my_charset_utf8_general_ci;
  table_alias_charset= &my_charset_bin;
  character_set_filesystem= &my_charset_bin;

  opt_specialflag= SPECIAL_ENGLISH | SPECIAL_NO_HOST_CACHE;
  unix_sock= MYSQL_INVALID_SOCKET;
  ip_sock= MYSQL_INVALID_SOCKET;
  mysql_home_ptr= mysql_home;
  pidfile_name_ptr= pidfile_name;
  lc_messages_dir_ptr= lc_messages_dir;
  protocol_version= PROTOCOL_VERSION;
  what_to_log= ~ (1L << (uint) COM_TIME);
  refresh_version= 1L;  /* Increments on each reload */
  global_query_id= thread_id= 1L;
  my_atomic_rwlock_init(&global_query_id_lock);
  my_atomic_rwlock_init(&thread_running_lock);
  strmov(server_version, MYSQL_SERVER_VERSION);
  global_thread_list= new std::set<THD*>;
  waiting_thd_list= new std::list<THD*>;

  /* Set directory paths */
  mysql_real_data_home_len=
    strmake(mysql_real_data_home, get_relative_path(MYSQL_DATADIR),
            sizeof(mysql_real_data_home)-1) - mysql_real_data_home;
  /* Replication parameters */
  master_info_file= (char*) "master.info",
    relay_log_info_file= (char*) "relay-log.info";
  report_user= report_password = report_host= 0;  /* TO BE DELETED */
  opt_relay_logname= opt_relaylog_index_name= 0;
//   log_bin_basename= NULL;
//   log_bin_index= NULL;

  /* Handler variables */
  total_ha= 0;
  total_ha_2pc= 0;
  /* Variables in libraries */
  charsets_dir= 0;
  default_character_set_name= (char*) MYSQL_DEFAULT_CHARSET_NAME;
  default_collation_name= compiled_default_collation_name;
  character_set_filesystem_name= (char*) "binary";
  lc_messages= (char*) "en_US";
  lc_time_names_name= (char*) "en_US";

  /* Variables that depends on compile options */
#ifndef DBUG_OFF
  default_dbug_option=IF_WIN("d:t:i:O,\\mysqld.trace",
           "d:t:i:o,/tmp/mysqld.trace");
#endif
  opt_error_log= IF_WIN(1,0);
#ifdef ENABLED_PROFILING
    have_profiling = SHOW_OPTION_YES;
#else
    have_profiling = SHOW_OPTION_NO;
#endif

#ifdef HAVE_OPENSSL
  have_ssl=SHOW_OPTION_YES;
#else
  have_ssl=SHOW_OPTION_NO;
#endif
#ifdef HAVE_BROKEN_REALPATH
  have_symlink=SHOW_OPTION_NO;
#else
  have_symlink=SHOW_OPTION_YES;
#endif
#ifdef HAVE_DLOPEN
  have_dlopen=SHOW_OPTION_YES;
#else
  have_dlopen=SHOW_OPTION_NO;
#endif
#ifdef HAVE_QUERY_CACHE
  have_query_cache=SHOW_OPTION_YES;
#else
  have_query_cache=SHOW_OPTION_NO;
#endif
#ifdef HAVE_SPATIAL
  have_geometry=SHOW_OPTION_YES;
#else
  have_geometry=SHOW_OPTION_NO;
#endif
#ifdef HAVE_RTREE_KEYS
  have_rtree_keys=SHOW_OPTION_YES;
#else
  have_rtree_keys=SHOW_OPTION_NO;
#endif
#ifdef HAVE_CRYPT
  have_crypt=SHOW_OPTION_YES;
#else
  have_crypt=SHOW_OPTION_NO;
#endif
#ifdef HAVE_COMPRESS
  have_compress= SHOW_OPTION_YES;
#else
  have_compress= SHOW_OPTION_NO;
#endif
#ifdef HAVE_LIBWRAP
  libwrapName= NullS;
#endif
#ifdef HAVE_OPENSSL
  des_key_file = 0;
#ifndef EMBEDDED_LIBRARY
  ssl_acceptor_fd= 0;
#endif /* ! EMBEDDED_LIBRARY */
#endif /* HAVE_OPENSSL */
// #ifdef HAVE_SMEM
//   shared_memory_base_name= default_shared_memory_base_name;
// #endif

#if defined(__WIN__)
  /* Allow Win32 users to move MySQL anywhere */
  {
    char prg_dev[LIBLEN];
    char executing_path_name[LIBLEN];
    if (!test_if_hard_path(my_progname))
    {
      // we don't want to use GetModuleFileName inside of my_path since
      // my_path is a generic path dereferencing function and here we care
      // only about the executing binary.
      GetModuleFileName(NULL, executing_path_name, sizeof(executing_path_name));
      my_path(prg_dev, executing_path_name, NULL);
    }
    else
      my_path(prg_dev, my_progname, "mysql/bin");
    strcat(prg_dev,"/../");     // Remove 'bin' to get base dir
    cleanup_dirname(mysql_home,prg_dev);
  }
#endif
  return 0;
}

my_bool
mysqld_get_one_option(int optid,
                      const struct my_option *opt __attribute__((unused)),
                      char *argument)
{
  switch(optid) {
  case '#':
#ifndef DBUG_OFF
    DBUG_SET_INITIAL(argument ? argument : default_dbug_option);
#endif
    opt_endinfo=1;        /* unireg: memory allocation */
    break;
  case 'a':
    global_system_variables.sql_mode= MODE_ANSI;
    global_system_variables.tx_isolation= ISO_SERIALIZABLE;
    break;
  case 'b':
    strmake(mysql_home,argument,sizeof(mysql_home)-1);
    break;
  case 'C':
    if (default_collation_name == compiled_default_collation_name)
      default_collation_name= 0;
    break;
  case 'h':
    strmake(mysql_real_data_home,argument, sizeof(mysql_real_data_home)-1);
    /* Correct pointer set by my_getopt (for embedded library) */
    mysql_real_data_home_ptr= mysql_real_data_home;
    break;
  case 'u':
    if (!mysqld_user || !strcmp(mysqld_user, argument))
      mysqld_user= argument;
    else
      sql_print_warning("Ignoring user change to '%s' because the user was set to '%s' earlier on the command line\n", argument, mysqld_user);
    break;
  case 'L':
    WARN_DEPRECATED(NULL, "--language/-l", "'--lc-messages-dir'");
    /* Note:  fall-through */
#include <sslopt-case.h>
#ifndef EMBEDDED_LIBRARY
  case 'V':
    print_version();
    exit(0);
#endif /*EMBEDDED_LIBRARY*/
  case 'W':
    if (!argument)
      log_warnings++;
    else if (argument == disabled_my_option)
      log_warnings= 0L;
    else
      log_warnings= atoi(argument);
    break;
  case 'T':
    test_flags= argument ? (uint) atoi(argument) : 0;
    opt_endinfo=1;
    break;
  case (int) OPT_SKIP_HOST_CACHE:
    opt_specialflag|= SPECIAL_NO_HOST_CACHE;
    break;
  case (int) OPT_WANT_CORE:
    test_flags |= TEST_CORE_ON_SIGNAL;
    break;
  case (int) OPT_SKIP_STACK_TRACE:
    test_flags|=TEST_NO_STACKTRACE;
    break;
  case OPT_SERVER_ID:
    server_id_supplied = 1;
    break;
  case OPT_LOG_ERROR:
    break;

  case OPT_SECURE_AUTH:
    if (opt_secure_auth == 0)
      WARN_DEPRECATED(NULL, "pre-4.1 password hash", "post-4.1 password hash");
    break;
  case OPT_PFS_INSTRUMENT:
    {
      break;
    }
  case OPT_HOST_CACHE_SIZE:
    host_cache_size_specified= true;
    break;
  }
  return 0;
}


/** Handle arguments for multiple key caches. */

C_MODE_START

static void*
mysql_getopt_value(const char *keyname, uint key_length,
       const struct my_option *option, int *error)
{
  if (error)
    *error= 0;
//   switch (option->id) {
//   case OPT_KEY_BUFFER_SIZE:
//   case OPT_KEY_CACHE_BLOCK_SIZE:
//   case OPT_KEY_CACHE_DIVISION_LIMIT:
//   case OPT_KEY_CACHE_AGE_THRESHOLD:
//   {
//     KEY_CACHE *key_cache;
//     if (!(key_cache= get_or_create_key_cache(keyname, key_length)))
//     {
//       if (error)
//         *error= EXIT_OUT_OF_MEMORY;
//       return 0;
//     }
//     switch (option->id) {
//     case OPT_KEY_BUFFER_SIZE:
//       return &key_cache->param_buff_size;
//     case OPT_KEY_CACHE_BLOCK_SIZE:
//       return &key_cache->param_block_size;
//     case OPT_KEY_CACHE_DIVISION_LIMIT:
//       return &key_cache->param_division_limit;
//     case OPT_KEY_CACHE_AGE_THRESHOLD:
//       return &key_cache->param_age_threshold;
//     }
//   }
//   }
  return option->value;
}

static void option_error_reporter(enum loglevel level, const char *format, ...)
{
  va_list args;
  va_start(args, format);

  /* Don't print warnings for --loose options during bootstrap */
  if (level == ERROR_LEVEL || !opt_bootstrap ||
      log_warnings)
  {
    vprint_msg_to_log(level, format, args);
  }
  va_end(args);
}

C_MODE_END

/**
  Get server options from the command line,
  and perform related server initializations.
  @param [in, out] argc_ptr       command line options (count)
  @param [in, out] argv_ptr       command line options (values)
  @return 0 on success

  @todo
  - FIXME add EXIT_TOO_MANY_ARGUMENTS to "mysys_err.h" and return that code?
*/
static int get_options(int *argc_ptr, char ***argv_ptr)
{
  int ho_error;

  my_getopt_register_get_addr(mysql_getopt_value);
  my_getopt_error_reporter= option_error_reporter;

  /* prepare all_options array */
  all_options.reserve(array_elements(my_long_options));
  for (my_option *opt= my_long_options;
       opt < my_long_options + array_elements(my_long_options) - 1;
       opt++)
  {
    all_options.push_back(*opt);
  }
  sys_var_add_options(&all_options, sys_var::PARSE_NORMAL);
  add_terminator(&all_options);

  /* Skip unknown options so that they may be processed later by plugins */
  my_getopt_skip_unknown= TRUE;

  if ((ho_error= handle_options(argc_ptr, argv_ptr, &all_options[0],
                                mysqld_get_one_option)))
    return ho_error;

  if (!opt_help)
    vector<my_option>().swap(all_options);  // Deletes the vector contents.

  /* Add back the program name handle_options removes */
  (*argc_ptr)++;
  (*argv_ptr)--;

  /*
    Options have been parsed. Now some of them need additional special
    handling, like custom value checking, checking of incompatibilites
    between options, setting of multiple variables, etc.
    Do them here.
  */

  if ((opt_log_slow_admin_statements || opt_log_queries_not_using_indexes ||
       opt_log_slow_slave_statements) &&
      !opt_slow_log)
    sql_print_warning("options --log-slow-admin-statements, "
                      "--log-queries-not-using-indexes and "
                      "--log-slow-slave-statements have no effect if "
                      "--slow-query-log is not set");
  if (global_system_variables.net_buffer_length >
      global_system_variables.max_allowed_packet)
  {
    sql_print_warning("net_buffer_length (%lu) is set to be larger "
                      "than max_allowed_packet (%lu). Please rectify.",
                      global_system_variables.net_buffer_length,
                      global_system_variables.max_allowed_packet);
  }

  if (global_system_variables.low_priority_updates)
    thr_upgraded_concurrent_insert_lock= TL_WRITE_LOW_PRIORITY;

  if (opt_disable_networking)
    mysqld_port= 0;

  if (opt_skip_show_db)
    opt_specialflag|= SPECIAL_SKIP_SHOW_DB;

  if (global_system_variables.max_join_size == HA_POS_ERROR)
    global_system_variables.option_bits|= OPTION_BIG_SELECTS;
  else
    global_system_variables.option_bits&= ~OPTION_BIG_SELECTS;

  // Synchronize @@global.autocommit on --autocommit
  const ulonglong turn_bit_on= opt_autocommit ?
    OPTION_AUTOCOMMIT : OPTION_NOT_AUTOCOMMIT;
  global_system_variables.option_bits=
    (global_system_variables.option_bits &
     ~(OPTION_NOT_AUTOCOMMIT | OPTION_AUTOCOMMIT)) | turn_bit_on;

  // global_system_variables.sql_mode=
  //   expand_sql_mode(global_system_variables.sql_mode);
#if defined(HAVE_BROKEN_REALPATH)
  my_use_symdir=0;
  my_disable_symlinks=1;
  have_symlink=SHOW_OPTION_NO;
#else
  if (!my_use_symdir)
  {
    my_disable_symlinks=1;
    have_symlink=SHOW_OPTION_DISABLED;
  }
#endif
  if (opt_debugging)
  {
    /* Allow break with SIGINT, no core or stack trace */
    test_flags|= TEST_SIGINT | TEST_NO_STACKTRACE;
    test_flags&= ~TEST_CORE_ON_SIGNAL;
  }
  /* Set global MyISAM variables from delay_key_write_options */
//   fix_delay_key_write(0, 0, OPT_GLOBAL);

#ifndef EMBEDDED_LIBRARY
  if (mysqld_chroot)
    set_root(mysqld_chroot);
#else
  thread_handling = SCHEDULER_NO_THREADS;
  max_allowed_packet= global_system_variables.max_allowed_packet;
  net_buffer_length= global_system_variables.net_buffer_length;
#endif
  if (fix_paths())
    return 1;

  /*
    Set some global variables from the global_system_variables
    In most cases the global variables will not be used
  */
  //my_disable_locking= myisam_single_user= test(opt_external_locking == 0);
  my_default_record_cache_size=global_system_variables.read_buff_size;

  global_system_variables.long_query_time= (ulonglong)
    (global_system_variables.long_query_time_double * 1e6);

  if (opt_short_log_format)
    opt_specialflag|= SPECIAL_SHORT_LOG_FORMAT;

  if (init_global_datetime_format(MYSQL_TIMESTAMP_DATE,
                                  &global_date_format) ||
      init_global_datetime_format(MYSQL_TIMESTAMP_TIME,
                                  &global_time_format) ||
      init_global_datetime_format(MYSQL_TIMESTAMP_DATETIME,
                                  &global_datetime_format))
    return 1;

#ifdef EMBEDDED_LIBRARY
  one_thread_scheduler();
#else
  if (thread_handling <= SCHEDULER_ONE_THREAD_PER_CONNECTION)
    one_thread_per_connection_scheduler();
  else                  /* thread_handling == SCHEDULER_NO_THREADS) */
    one_thread_scheduler();
#endif

  global_system_variables.engine_condition_pushdown=
    test(global_system_variables.optimizer_switch &
         OPTIMIZER_SWITCH_ENGINE_CONDITION_PUSHDOWN);

  opt_readonly= read_only;

  return 0;
}


/*
  Create version name for running mysqld version
  We automaticly add suffixes -debug, -embedded and -log to the version
  name to make the version more descriptive.
  (MYSQL_SERVER_SUFFIX is set by the compilation environment)
*/

static void set_server_version(void)
{
  char *end= strxmov(server_version, MYSQL_SERVER_VERSION,
                     MYSQL_SERVER_SUFFIX_STR, NullS);
//   if (!strstr(MYSQL_SERVER_SUFFIX_STR, "-debug"))
//     end= strmov(end, "-debug");
//   if (opt_log || opt_slow_log || opt_bin_log)
//     strmov(end, "-log");                        // This may slow down system
}


static char *get_relative_path(const char *path)
{
//   if (test_if_hard_path(path) &&
//       is_prefix(path,DEFAULT_MYSQL_HOME) &&
//       strcmp(DEFAULT_MYSQL_HOME,FN_ROOTDIR))
//   {
//     path+=(uint) strlen(DEFAULT_MYSQL_HOME);
//     while (*path == FN_LIBCHAR || *path == FN_LIBCHAR2)
//       path++;
//   }
  return (char*) path;
}


/**
  Fix filename and replace extension where 'dir' is relative to
  mysql_real_data_home.
  @return
    1 if len(path) > FN_REFLEN
*/

bool
fn_format_relative_to_data_home(char * to, const char *name,
        const char *dir, const char *extension)
{
  char tmp_path[FN_REFLEN];
  if (!test_if_hard_path(dir))
  {
    strxnmov(tmp_path,sizeof(tmp_path)-1, mysql_real_data_home,
       dir, NullS);
    dir=tmp_path;
  }
  return !fn_format(to, name, dir, extension,
        MY_APPEND_EXT | MY_UNPACK_FILENAME | MY_SAFE_PATH);
}

static int fix_paths(void)
{
  char buff[FN_REFLEN],*pos;
  convert_dirname(mysql_home,mysql_home,NullS);
  /* Resolve symlinks to allow 'mysql_home' to be a relative symlink */
  my_realpath(mysql_home,mysql_home,MYF(0));
  /* Ensure that mysql_home ends in FN_LIBCHAR */
  pos=strend(mysql_home);
  if (pos[-1] != FN_LIBCHAR)
  {
    pos[0]= FN_LIBCHAR;
    pos[1]= 0;
  }
  convert_dirname(lc_messages_dir, lc_messages_dir, NullS);
  convert_dirname(mysql_real_data_home,mysql_real_data_home,NullS);
  (void) my_load_path(mysql_home,mysql_home,""); // Resolve current dir
  (void) my_load_path(mysql_real_data_home,mysql_real_data_home,mysql_home);
  (void) my_load_path(pidfile_name, pidfile_name_ptr, mysql_real_data_home);

  convert_dirname(opt_plugin_dir, opt_plugin_dir_ptr ? opt_plugin_dir_ptr : 
                                  get_relative_path(PLUGINDIR), NullS);
  (void) my_load_path(opt_plugin_dir, opt_plugin_dir, mysql_home);
  opt_plugin_dir_ptr= opt_plugin_dir;

  my_realpath(mysql_unpacked_real_data_home, mysql_real_data_home, MYF(0));
  mysql_unpacked_real_data_home_len=
    (int) strlen(mysql_unpacked_real_data_home);
  if (mysql_unpacked_real_data_home[mysql_unpacked_real_data_home_len-1] == FN_LIBCHAR)
    --mysql_unpacked_real_data_home_len;

  char *sharedir=get_relative_path(SHAREDIR);
  if (test_if_hard_path(sharedir))
    strmake(buff,sharedir,sizeof(buff)-1);    /* purecov: tested */
  else
    strxnmov(buff,sizeof(buff)-1,mysql_home,sharedir,NullS);
  convert_dirname(buff,buff,NullS);
  (void) my_load_path(lc_messages_dir, lc_messages_dir, buff);

  /* If --character-sets-dir isn't given, use shared library dir */
  if (charsets_dir)
    strmake(mysql_charsets_dir, charsets_dir, sizeof(mysql_charsets_dir)-1);
  else
    strxnmov(mysql_charsets_dir, sizeof(mysql_charsets_dir)-1, buff,
       CHARSET_DIR, NullS);
  (void) my_load_path(mysql_charsets_dir, mysql_charsets_dir, buff);
  convert_dirname(mysql_charsets_dir, mysql_charsets_dir, NullS);
  charsets_dir=mysql_charsets_dir;

//   if (init_tmpdir(&mysql_tmpdir_list, opt_mysql_tmpdir))
//     return 1;
//   if (!opt_mysql_tmpdir)
//     opt_mysql_tmpdir= mysql_tmpdir;

  if (opt_secure_file_priv)
  {
    if (*opt_secure_file_priv == 0)
      opt_secure_file_priv= NULL;
    else
    {
      if (strlen(opt_secure_file_priv) >= FN_REFLEN)
        opt_secure_file_priv[FN_REFLEN-1]= '\0';
      if (my_realpath(buff, opt_secure_file_priv, 0))
      {
        sql_print_warning("Failed to normalize the argument for --secure-file-priv.");
        return 1;
      }
      convert_dirname(secure_file_real_path, buff, NullS);
      opt_secure_file_priv= secure_file_real_path;
    }
  }

  return 0;
}
