/* Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA */


/**
  @addtogroup Replication
  @{

  @file

  @brief Code to run the io thread and the sql thread on the
  replication slave.
*/

#include "sql_priv.h"
#include "my_global.h"
#include "rpl_slave.h"
#include "sql_parse.h"                         // execute_init_command
#include "sql_table.h"                         // mysql_rm_table
#include "rpl_mi.h"
#include "rpl_rli.h"
#include "rpl_filter.h"
#include "rpl_info_factory.h"
#include "transaction.h"
#include <thr_alarm.h>
#include <my_dir.h>
#include <sql_common.h>
#include <errmsg.h>
#include <mysqld_error.h>
#include <mysys_err.h>
#include "rpl_handler.h"
#include "rpl_info_dummy.h"
#include <signal.h>
#include <mysql.h>
#include <myisam.h>

#include "sql_base.h"                           // close_thread_tables
#include "tztime.h"                             // struct Time_zone
#include "log_event.h"                          // Rotate_log_event,
                                                // Create_file_log_event,
                                                // Format_description_log_event
#include "dynamic_ids.h"
#include "rpl_rli_pdb.h"
#include "global_threads.h"

#ifdef HAVE_REPLICATION

#include "rpl_tblmap.h"
#include "debug_sync.h"

using std::min;
using std::max;

#define FLAGSTR(V,F) ((V)&(F)?#F" ":"")

#define MAX_SLAVE_RETRY_PAUSE 5
/*
  a parameter of sql_slave_killed() to defer the killed status
*/
#define SLAVE_WAIT_GROUP_DONE 60
bool use_slave_mask = 0;
MY_BITMAP slave_error_mask;
char slave_skip_error_names[SHOW_VAR_FUNC_BUFF_SIZE];

char* slave_load_tmpdir = 0;
Master_info *active_mi= 0;
my_bool replicate_same_server_id;
ulonglong relay_log_space_limit = 0;

const char *relay_log_index= 0;
const char *relay_log_basename= 0;

/*
  MTS load-ballancing parameter.
  Max length of one MTS Worker queue. The value also determines the size
  of Relay_log_info::gaq (see @c slave_start_workers()).
  It can be set to any value in [1, ULONG_MAX - 1] range.
*/
const ulong mts_slave_worker_queue_len_max= 16384;

/*
  Statistics go to the error log every # of seconds when --log-warnings > 1
*/
const long mts_online_stat_period= 60 * 2;


/*
  MTS load-ballancing parameter.
  Time unit in microsecs to sleep by MTS Coordinator to avoid extra thread
  signalling in the case of Worker queues are close to be filled up.
*/
const ulong mts_coordinator_basic_nap= 5;

/*
  MTS load-ballancing parameter.
  Percent of Worker queue size at which Worker is considered to become
  hungry.

  C enqueues --+                   . underrun level
               V                   "
   +----------+-+------------------+--------------+
   | empty    |.|::::::::::::::::::|xxxxxxxxxxxxxx| ---> Worker dequeues
   +----------+-+------------------+--------------+

   Like in the above diagram enqueuing to the x-d area would indicate
   actual underrruning by Worker.
*/
const ulong mts_worker_underrun_level= 10;

Slave_job_item * de_queue(Slave_jobs_queue *jobs, Slave_job_item *ret);
bool append_item_to_jobs(slave_job_item *job_item,
                         Slave_worker *w, Relay_log_info *rli);

/*
  When slave thread exits, we need to remember the temporary tables so we
  can re-use them on slave start.

  TODO: move the vars below under Master_info
*/

int disconnect_slave_event_count = 0, abort_slave_event_count = 0;

static pthread_key(Master_info*, RPL_MASTER_INFO);

enum enum_slave_reconnect_actions
{
  SLAVE_RECON_ACT_REG= 0,
  SLAVE_RECON_ACT_DUMP= 1,
  SLAVE_RECON_ACT_EVENT= 2,
  SLAVE_RECON_ACT_MAX
};

enum enum_slave_reconnect_messages
{
  SLAVE_RECON_MSG_WAIT= 0,
  SLAVE_RECON_MSG_KILLED_WAITING= 1,
  SLAVE_RECON_MSG_AFTER= 2,
  SLAVE_RECON_MSG_FAILED= 3,
  SLAVE_RECON_MSG_COMMAND= 4,
  SLAVE_RECON_MSG_KILLED_AFTER= 5,
  SLAVE_RECON_MSG_MAX
};

static const char *reconnect_messages[SLAVE_RECON_ACT_MAX][SLAVE_RECON_MSG_MAX]=
{
  {
    "Waiting to reconnect after a failed registration on master",
    "Slave I/O thread killed while waitnig to reconnect after a failed \
registration on master",
    "Reconnecting after a failed registration on master",
    "failed registering on master, reconnecting to try again, \
log '%s' at position %s",
    "COM_REGISTER_SLAVE",
    "Slave I/O thread killed during or after reconnect"
  },
  {
    "Waiting to reconnect after a failed binlog dump request",
    "Slave I/O thread killed while retrying master dump",
    "Reconnecting after a failed binlog dump request",
    "failed dump request, reconnecting to try again, log '%s' at position %s",
    "COM_BINLOG_DUMP",
    "Slave I/O thread killed during or after reconnect"
  },
  {
    "Waiting to reconnect after a failed master event read",
    "Slave I/O thread killed while waiting to reconnect after a failed read",
    "Reconnecting after a failed master event read",
    "Slave I/O thread: Failed reading log event, reconnecting to retry, \
log '%s' at position %s",
    "",
    "Slave I/O thread killed during or after a reconnect done to recover from \
failed read"
  }
};

enum enum_slave_apply_event_and_update_pos_retval
{
  SLAVE_APPLY_EVENT_AND_UPDATE_POS_OK= 0,
  SLAVE_APPLY_EVENT_AND_UPDATE_POS_APPLY_ERROR= 1,
  SLAVE_APPLY_EVENT_AND_UPDATE_POS_UPDATE_POS_ERROR= 2,
  SLAVE_APPLY_EVENT_AND_UPDATE_POS_APPEND_JOB_ERROR= 3,
  SLAVE_APPLY_EVENT_AND_UPDATE_POS_MAX
};


static int process_io_create_file(Master_info* mi, Create_file_log_event* cev);
static inline bool io_slave_killed(THD* thd,Master_info* mi);
static inline bool sql_slave_killed(THD* thd,Relay_log_info* rli);
static int init_slave_thread(THD* thd, SLAVE_THD_TYPE thd_type);
static void print_slave_skip_errors(void);
static int safe_connect(THD* thd, MYSQL* mysql, Master_info* mi);
static int safe_reconnect(THD* thd, MYSQL* mysql, Master_info* mi,
                          bool suppress_warnings);
static int connect_to_master(THD* thd, MYSQL* mysql, Master_info* mi,
                             bool reconnect, bool suppress_warnings);
static int get_master_version_and_clock(MYSQL* mysql, Master_info* mi);
static int get_master_uuid(MYSQL *mysql, Master_info *mi);
int io_thread_init_commands(MYSQL *mysql, Master_info *mi);
static Log_event* next_event(Relay_log_info* rli);
static int queue_event(Master_info* mi,const char* buf,ulong event_len);
static int terminate_slave_thread(THD *thd,
                                  mysql_mutex_t *term_lock,
                                  mysql_cond_t *term_cond,
                                  volatile uint *slave_running,
                                  bool need_lock_term);
static bool check_io_slave_killed(THD *thd, Master_info *mi, const char *info);
int slave_worker_exec_job(Slave_worker * w, Relay_log_info *rli);
static int mts_event_coord_cmp(LOG_POS_COORD *id1, LOG_POS_COORD *id2);

/*
  Find out which replications threads are running

  SYNOPSIS
    init_thread_mask()
    mask                Return value here
    mi                  master_info for slave
    inverse             If set, returns which threads are not running

  IMPLEMENTATION
    Get a bit mask for which threads are running so that we can later restart
    these threads.

  RETURN
    mask        If inverse == 0, running threads
                If inverse == 1, stopped threads
*/

void init_thread_mask(int* mask, Master_info* mi, bool inverse)
{
  bool set_io = mi->slave_running, set_sql = mi->rli->slave_running;
  register int tmp_mask=0;
  DBUG_ENTER("init_thread_mask");

  if (set_io)
    tmp_mask |= SLAVE_IO;
  if (set_sql)
    tmp_mask |= SLAVE_SQL;
  if (inverse)
    tmp_mask^= (SLAVE_IO | SLAVE_SQL);
  *mask = tmp_mask;
  DBUG_VOID_RETURN;
}


/*
  lock_slave_threads()
*/

void lock_slave_threads(Master_info* mi)
{
  DBUG_ENTER("lock_slave_threads");

  //TODO: see if we can do this without dual mutex
  mysql_mutex_lock(&mi->run_lock);
  mysql_mutex_lock(&mi->rli->run_lock);
  DBUG_VOID_RETURN;
}


/*
  unlock_slave_threads()
*/

void unlock_slave_threads(Master_info* mi)
{
  DBUG_ENTER("unlock_slave_threads");

  //TODO: see if we can do this without dual mutex
  mysql_mutex_unlock(&mi->rli->run_lock);
  mysql_mutex_unlock(&mi->run_lock);
  DBUG_VOID_RETURN;
}

#ifdef HAVE_PSI_INTERFACE
static PSI_thread_key key_thread_slave_io, key_thread_slave_sql;

static PSI_thread_info all_slave_threads[]=
{
  { &key_thread_slave_io, "slave_io", PSI_FLAG_GLOBAL},
  { &key_thread_slave_sql, "slave_sql", PSI_FLAG_GLOBAL}
};

static void init_slave_psi_keys(void)
{
  const char* category= "sql";
  int count;

  count= array_elements(all_slave_threads);
  mysql_thread_register(category, all_slave_threads, count);
}
#endif /* HAVE_PSI_INTERFACE */

/* Initialize slave structures */

/*
  Updates the master info based on the information stored in the
  relay info and ignores relay logs previously retrieved by the IO
  thread, which thus starts fetching again based on to the
  master_log_pos and master_log_name. Eventually, the old
  relay logs will be purged by the normal purge mechanism.

  In the feature, we should improve this routine in order to avoid throwing
  away logs that are safely stored in the disk. Note also that this recovery
  routine relies on the correctness of the relay-log.info and only tolerates
  coordinate problems in master.info.

  In this function, there is no need for a mutex as the caller
  (i.e. init_slave) already has one acquired.

  Specifically, the following structures are updated:

  1 - mi->master_log_pos  <-- rli->group_master_log_pos
  2 - mi->master_log_name <-- rli->group_master_log_name
  3 - It moves the relay log to the new relay log file, by
      rli->group_relay_log_pos  <-- BIN_LOG_HEADER_SIZE;
      rli->event_relay_log_pos  <-- BIN_LOG_HEADER_SIZE;
      rli->group_relay_log_name <-- rli->relay_log.get_log_fname();
      rli->event_relay_log_name <-- rli->relay_log.get_log_fname();

   If there is an error, it returns (1), otherwise returns (0).
 */
int init_recovery(Master_info* mi, const char** errmsg)
{
  DBUG_ENTER("init_recovery");

  int error= 0;
  Relay_log_info *rli= mi->rli;
  char *group_master_log_name= NULL;

  if (rli->recovery_parallel_workers)
  {
    /*
      This is not idempotent and a crash after this function and before
      the recovery is actually done may lead the system to an inconsistent
      state.

      This may happen because the gap is not persitent stored anywhere
      and eventually old relay log files will be removed and further
      calculations on the gaps will be impossible.

      We need to improve this. /Alfranio.
    */
    error= mts_recovery_groups(rli);
    if (rli->mts_recovery_group_cnt)
    {
      error= 1;
      sql_print_error("--relay-log-recovery cannot be executed when the slave "
                        "was stopped with an error or killed in MTS mode; "
                        "consider using RESET SLAVE or restart the server "
                        "with --relay-log-recovery = 0 followed by "
                        "START SLAVE UNTIL SQL_AFTER_MTS_GAPS");
    }
  }

  group_master_log_name= const_cast<char *>(rli->get_group_master_log_name());
  if (!error && group_master_log_name[0])
  {
    mi->set_master_log_pos(max<ulonglong>(BIN_LOG_HEADER_SIZE,
                                               rli->get_group_master_log_pos()));
    mi->set_master_log_name(rli->get_group_master_log_name());

    sql_print_warning("Recovery from master pos %ld and file %s.",
                      (ulong) mi->get_master_log_pos(), mi->get_master_log_name());

    rli->set_group_relay_log_name(rli->relay_log.get_log_fname());
    rli->set_event_relay_log_name(rli->relay_log.get_log_fname());
    rli->set_group_relay_log_pos(BIN_LOG_HEADER_SIZE);
    rli->set_event_relay_log_pos(BIN_LOG_HEADER_SIZE);
  }

  DBUG_RETURN(error);
}

int global_init_info(Master_info* mi, bool ignore_if_no_info, int thread_mask)
{
  DBUG_ENTER("init_info");
  DBUG_ASSERT(mi != NULL && mi->rli != NULL);
  int init_error= 0;
  enum_return_check check_return= ERROR_CHECKING_REPOSITORY;

  /*
    We need a mutex while we are changing master info parameters to
    keep other threads from reading bogus info
  */
  mysql_mutex_lock(&mi->data_lock);
  mysql_mutex_lock(&mi->rli->data_lock);

  /*
    This takes care of the startup dependency between the master_info
    and relay_info. It initializes the master info if the SLAVE_IO
    thread is being started and the relay log info if either the
    SLAVE_SQL thread is being started or was not initialized as it is
    required by the SLAVE_IO thread.
  */
  check_return= mi->check_info();
  if (check_return == ERROR_CHECKING_REPOSITORY)
    goto end;

  if (!(ignore_if_no_info && check_return == REPOSITORY_DOES_NOT_EXIST))
  {
    if ((thread_mask & SLAVE_IO) != 0 && mi->mi_init_info())
      init_error= 1;
  }

  check_return= mi->rli->check_info();
  if (check_return == ERROR_CHECKING_REPOSITORY)
    goto end;
  if (!(ignore_if_no_info && check_return == REPOSITORY_DOES_NOT_EXIST))
  {
    if (((thread_mask & SLAVE_SQL) != 0 || !(mi->rli->inited))
        && mi->rli->rli_init_info())
      init_error= 1;
  }

end:
  mysql_mutex_unlock(&mi->rli->data_lock);
  mysql_mutex_unlock(&mi->data_lock);
  DBUG_RETURN(check_return == ERROR_CHECKING_REPOSITORY || init_error);
}

void end_info(Master_info* mi)
{
  DBUG_ENTER("end_info");
  DBUG_ASSERT(mi != NULL && mi->rli != NULL);

  /*
    The previous implementation was not acquiring locks.  We do the same here.
    However, this is quite strange.
  */
  mi->end_info();
  mi->rli->end_info();

  DBUG_VOID_RETURN;
}

int remove_info(Master_info* mi)
{
  int error= 1;
  DBUG_ENTER("remove_info");
  DBUG_ASSERT(mi != NULL && mi->rli != NULL);

  /*
    The previous implementation was not acquiring locks.
    We do the same here. However, this is quite strange.
  */
  /*
    Reset errors (the idea is that we forget about the
    old master).
  */
  mi->clear_error();
  mi->rli->clear_error();
  mi->rli->clear_until_condition();
  mi->rli->clear_sql_delay();

  mi->end_info();
  mi->rli->end_info();

  if (mi->remove_info() || Rpl_info_factory::reset_workers(mi->rli) ||
      mi->rli->remove_info())
    goto err;

  error= 0;

err:
  DBUG_RETURN(error);
}

int flush_master_info(Master_info* mi, bool force)
{
  DBUG_ENTER("flush_master_info");
  DBUG_ASSERT(mi != NULL && mi->rli != NULL);
  /*
    The previous implementation was not acquiring locks.
    We do the same here. However, this is quite strange.
  */
  /*
    With the appropriate recovery process, we will not need to flush
    the content of the current log.

    For now, we flush the relay log BEFORE the master.info file, because
    if we crash, we will get a duplicate event in the relay log at restart.
    If we change the order, there might be missing events.

    If we don't do this and the slave server dies when the relay log has
    some parts (its last kilobytes) in memory only, with, say, from master's
    position 100 to 150 in memory only (not on disk), and with position 150
    in master.info, there will be missing information. When the slave restarts,
    the I/O thread will fetch binlogs from 150, so in the relay log we will
    have "[0, 100] U [150, infinity[" and nobody will notice it, so the SQL
    thread will jump from 100 to 150, and replication will silently break.
  */
  mysql_mutex_t *log_lock= mi->rli->relay_log.get_log_lock();

  mysql_mutex_lock(log_lock);

  int err=  (mi->rli->flush_current_log() ||
             mi->flush_info(force));

  mysql_mutex_unlock(log_lock);

  DBUG_RETURN (err);
}

/**
  Convert slave skip errors bitmap into a printable string.
*/

static void print_slave_skip_errors(void)
{
  /*
    To be safe, we want 10 characters of room in the buffer for a number
    plus terminators. Also, we need some space for constant strings.
    10 characters must be sufficient for a number plus {',' | '...'}
    plus a NUL terminator. That is a max 6 digit number.
  */
  const size_t MIN_ROOM= 10;
  DBUG_ENTER("print_slave_skip_errors");
  DBUG_ASSERT(sizeof(slave_skip_error_names) > MIN_ROOM);
  DBUG_ASSERT(MAX_SLAVE_ERROR <= 999999); // 6 digits

  if (!use_slave_mask || bitmap_is_clear_all(&slave_error_mask))
  {
    /* purecov: begin tested */
    memcpy(slave_skip_error_names, STRING_WITH_LEN("OFF"));
    /* purecov: end */
  }
  else if (bitmap_is_set_all(&slave_error_mask))
  {
    /* purecov: begin tested */
    memcpy(slave_skip_error_names, STRING_WITH_LEN("ALL"));
    /* purecov: end */
  }
  else
  {
    char *buff= slave_skip_error_names;
    char *bend= buff + sizeof(slave_skip_error_names);
    int  errnum;

    for (errnum= 0; errnum < MAX_SLAVE_ERROR; errnum++)
    {
      if (bitmap_is_set(&slave_error_mask, errnum))
      {
        if (buff + MIN_ROOM >= bend)
          break; /* purecov: tested */
        buff= int10_to_str(errnum, buff, 10);
        *buff++= ',';
      }
    }
    if (buff != slave_skip_error_names)
      buff--; // Remove last ','
    if (errnum < MAX_SLAVE_ERROR)
    {
      /* Couldn't show all errors */
      buff= strmov(buff, "..."); /* purecov: tested */
    }
    *buff=0;
  }
  DBUG_PRINT("init", ("error_names: '%s'", slave_skip_error_names));
  DBUG_VOID_RETURN;
}

/**
 Change arg to the string with the nice, human-readable skip error values.
   @param slave_skip_errors_ptr
          The pointer to be changed
*/
void set_slave_skip_errors(char** slave_skip_errors_ptr)
{
  DBUG_ENTER("set_slave_skip_errors");
  print_slave_skip_errors();
  *slave_skip_errors_ptr= slave_skip_error_names;
  DBUG_VOID_RETURN;
}

/**
  Init function to set up array for errors that should be skipped for slave
*/
static void init_slave_skip_errors()
{
  DBUG_ENTER("init_slave_skip_errors");
  DBUG_ASSERT(!use_slave_mask); // not already initialized

  if (bitmap_init(&slave_error_mask,0,MAX_SLAVE_ERROR,0))
  {
    fprintf(stderr, "Badly out of memory, please check your system status\n");
    exit(1);
  }
  use_slave_mask = 1;
  DBUG_VOID_RETURN;
}

static void add_slave_skip_errors(const uint* errors, uint n_errors)
{
  DBUG_ENTER("add_slave_skip_errors");
  DBUG_ASSERT(errors);
  DBUG_ASSERT(use_slave_mask);

  for (uint i = 0; i < n_errors; i++)
  {
    const uint err_code = errors[i];
    if (err_code < MAX_SLAVE_ERROR)
       bitmap_set_bit(&slave_error_mask, err_code);
  }
  DBUG_VOID_RETURN;
}

/*
  Add errors that should be skipped for slave

  SYNOPSIS
    add_slave_skip_errors()
    arg         List of errors numbers to be added to skip, separated with ','

  NOTES
    Called from get_options() in mysqld.cc on start-up
*/

void add_slave_skip_errors(const char* arg)
{
  const char *p= NULL;
  /*
    ALL is only valid when nothing else is provided.
  */
  const uchar SKIP_ALL[]= "all";
  size_t SIZE_SKIP_ALL= strlen((const char *) SKIP_ALL) + 1;
  /*
    IGNORE_DDL_ERRORS can be combined with other parameters
    but must be the first one provided.
  */
  const uchar SKIP_DDL_ERRORS[]= "ddl_exist_errors";
  size_t SIZE_SKIP_DDL_ERRORS= strlen((const char *) SKIP_DDL_ERRORS);
  DBUG_ENTER("add_slave_skip_errors");

  // initialize mask if not done yet
  if (!use_slave_mask)
    init_slave_skip_errors();

  for (; my_isspace(system_charset_info,*arg); ++arg)
    /* empty */;
  if (!my_strnncoll(system_charset_info, (uchar*)arg, SIZE_SKIP_ALL,
                    SKIP_ALL, SIZE_SKIP_ALL))
  {
    bitmap_set_all(&slave_error_mask);
    DBUG_VOID_RETURN;
  }
  if (!my_strnncoll(system_charset_info, (uchar*)arg, SIZE_SKIP_DDL_ERRORS,
                    SKIP_DDL_ERRORS, SIZE_SKIP_DDL_ERRORS))
  {
    // DDL errors to be skipped for relaxed 'exist' handling
    const uint ddl_errors[] = {
      // error codes with create/add <schema object>
      ER_DB_CREATE_EXISTS, ER_TABLE_EXISTS_ERROR, ER_DUP_KEYNAME,
      ER_MULTIPLE_PRI_KEY,
      // error codes with change/rename <schema object>
      ER_BAD_FIELD_ERROR, ER_NO_SUCH_TABLE, ER_DUP_FIELDNAME,
      // error codes with drop <schema object>
      ER_DB_DROP_EXISTS, ER_BAD_TABLE_ERROR, ER_CANT_DROP_FIELD_OR_KEY
    };

    add_slave_skip_errors(ddl_errors,
                          sizeof(ddl_errors)/sizeof(ddl_errors[0]));
    /*
      After processing the SKIP_DDL_ERRORS, the pointer is
      increased to the position after the comma.
    */
    if (strlen(arg) > SIZE_SKIP_DDL_ERRORS + 1)
      arg+= SIZE_SKIP_DDL_ERRORS + 1;
  }
  for (p= arg ; *p; )
  {
    long err_code;
    if (!(p= str2int(p, 10, 0, LONG_MAX, &err_code)))
      break;
    if (err_code < MAX_SLAVE_ERROR)
       bitmap_set_bit(&slave_error_mask,(uint)err_code);
    while (!my_isdigit(system_charset_info,*p) && *p)
      p++;
  }
  DBUG_VOID_RETURN;
}

static void set_thd_in_use_temporary_tables(Relay_log_info *rli)
{
  TABLE *table;

  for (table= rli->save_temporary_tables ; table ; table= table->next)
  {
    table->in_use= rli->info_thd;
    if (table->file != NULL)
    {
      /*
        Since we are stealing opened temporary tables from one thread to another,
        we need to let the performance schema know that,
        for aggregates per thread to work properly.
      */
      table->file->unbind_psi();
      table->file->rebind_psi();
    }
  }
}

int terminate_slave_threads(Master_info* mi,int thread_mask,bool need_lock_term)
{
  DBUG_ENTER("terminate_slave_threads");

  if (!mi->inited)
    DBUG_RETURN(0); /* successfully do nothing */
  int error,force_all = (thread_mask & SLAVE_FORCE_ALL);
  mysql_mutex_t *sql_lock = &mi->rli->run_lock, *io_lock = &mi->run_lock;
  mysql_mutex_t *log_lock= mi->rli->relay_log.get_log_lock();

  if (thread_mask & (SLAVE_SQL|SLAVE_FORCE_ALL))
  {
    DBUG_PRINT("info",("Terminating SQL thread"));
    mi->rli->abort_slave= 1;
    if ((error=terminate_slave_thread(mi->rli->info_thd, sql_lock,
                                      &mi->rli->stop_cond,
                                      &mi->rli->slave_running,
                                      need_lock_term)) &&
        !force_all)
      DBUG_RETURN(error);

    mysql_mutex_lock(log_lock);

    DBUG_PRINT("info",("Flushing relay-log info file."));

    /*
      Flushes the relay log info regardles of the sync_relay_log_info option.
    */
    if (mi->rli->flush_info(TRUE))
    {
      mysql_mutex_unlock(log_lock);
      DBUG_RETURN(ER_ERROR_DURING_FLUSH_LOGS);
    }

    mysql_mutex_unlock(log_lock);
  }
  if (thread_mask & (SLAVE_IO|SLAVE_FORCE_ALL))
  {
    DBUG_PRINT("info",("Terminating IO thread"));
    mi->abort_slave=1;
    if ((error=terminate_slave_thread(mi->info_thd,io_lock,
                                      &mi->stop_cond,
                                      &mi->slave_running,
                                      need_lock_term)) &&
        !force_all)
      DBUG_RETURN(error);

    mysql_mutex_lock(log_lock);

    DBUG_PRINT("info",("Flushing relay log and master info repository."));

    /*
      Flushes the master info regardles of the sync_master_info option.
    */
    if (mi->flush_info(TRUE))
    {
      mysql_mutex_unlock(log_lock);
      DBUG_RETURN(ER_ERROR_DURING_FLUSH_LOGS);
    }

    /*
      Flushes the relay log regardles of the sync_relay_log option.
    */
    if (mi->rli->relay_log.is_open() &&
        mi->rli->relay_log.flush_and_sync(true))
    {
      mysql_mutex_unlock(log_lock);
      DBUG_RETURN(ER_ERROR_DURING_FLUSH_LOGS);
    }

    mysql_mutex_unlock(log_lock);
  }
  DBUG_RETURN(0);
}


/**
   Wait for a slave thread to terminate.

   This function is called after requesting the thread to terminate
   (by setting @c abort_slave member of @c Relay_log_info or @c
   Master_info structure to 1). Termination of the thread is
   controlled with the the predicate <code>*slave_running</code>.

   Function will acquire @c term_lock before waiting on the condition
   unless @c need_lock_term is false in which case the mutex should be
   owned by the caller of this function and will remain acquired after
   return from the function.

   @param term_lock
          Associated lock to use when waiting for @c term_cond

   @param term_cond
          Condition that is signalled when the thread has terminated

   @param slave_running
          Pointer to predicate to check for slave thread termination

   @param need_lock_term
          If @c false the lock will not be acquired before waiting on
          the condition. In this case, it is assumed that the calling
          function acquires the lock before calling this function.

   @retval 0 All OK ER_SLAVE_NOT_RUNNING otherwise.

   @note  If the executing thread has to acquire term_lock
          (need_lock_term is true, the negative running status does not
          represent any issue therefore no error is reported.

 */
static int
terminate_slave_thread(THD *thd,
                       mysql_mutex_t *term_lock,
                       mysql_cond_t *term_cond,
                       volatile uint *slave_running,
                       bool need_lock_term)
{
  DBUG_ENTER("terminate_slave_thread");
  if (need_lock_term)
  {
    mysql_mutex_lock(term_lock);
  }
  else
  {
    mysql_mutex_assert_owner(term_lock);
  }
  if (!*slave_running)
  {
    if (need_lock_term)
    {
      /*
        if run_lock (term_lock) is acquired locally then either
        slave_running status is fine
      */
      mysql_mutex_unlock(term_lock);
      DBUG_RETURN(0);
    }
    else
    {
      DBUG_RETURN(ER_SLAVE_NOT_RUNNING);
    }
  }
  DBUG_ASSERT(thd != 0);
  THD_CHECK_SENTRY(thd);

  /*
    Is is critical to test if the slave is running. Otherwise, we might
    be referening freed memory trying to kick it
  */

//   while (*slave_running)                        // Should always be true
//   {
//     int error;
//     DBUG_PRINT("loop", ("killing slave thread"));
// 
//     mysql_mutex_lock(&thd->LOCK_thd_data);
// #ifndef DONT_USE_THR_ALARM
//     /*
//       Error codes from pthread_kill are:
//       EINVAL: invalid signal number (can't happen)
//       ESRCH: thread already killed (can happen, should be ignored)
//     */
//     int err __attribute__((unused))= pthread_kill(thd->real_id, thr_client_alarm);
//     DBUG_ASSERT(err != EINVAL);
// #endif
//     thd->awake(THD::NOT_KILLED);
//     mysql_mutex_unlock(&thd->LOCK_thd_data);
// 
//     /*
//       There is a small chance that slave thread might miss the first
//       alarm. To protect againts it, resend the signal until it reacts
//     */
//     struct timespec abstime;
//     set_timespec(abstime,2);
//     error= mysql_cond_timedwait(term_cond, term_lock, &abstime);
//     DBUG_ASSERT(error == ETIMEDOUT || error == 0);
//   }

  DBUG_ASSERT(*slave_running == 0);

  if (need_lock_term)
    mysql_mutex_unlock(term_lock);
  DBUG_RETURN(0);
}

/*
  start_slave_threads()

  NOTES
    SLAVE_FORCE_ALL is not implemented here on purpose since it does not make
    sense to do that for starting a slave--we always care if it actually
    started the threads that were not previously running
*/


/*
  Release slave threads at time of executing shutdown.

  SYNOPSIS
    end_slave()
*/

/**
   Free all resources used by slave threads at time of executing shutdown.
   The routine must be called after all possible users of @c active_mi
   have left.

   SYNOPSIS
     close_active_mi()

*/
static bool io_slave_killed(THD* thd, Master_info* mi)
{
  DBUG_ENTER("io_slave_killed");

  DBUG_ASSERT(mi->info_thd == thd);
  DBUG_ASSERT(mi->slave_running); // tracking buffer overrun
  DBUG_RETURN(mi->abort_slave || abort_loop || thd->killed);
}

/**
   The function analyzes a possible killed status and makes
   a decision whether to accept it or not.
   Normally upon accepting the sql thread goes to shutdown.
   In the event of deferring decision @rli->last_event_start_time waiting
   timer is set to force the killed status be accepted upon its expiration.

   Notice Multi-Threaded-Slave behaves similarly in that when it's being
   stopped and the current group of assigned events has not yet scheduled 
   completely, Coordinator defers to accept to leave its read-distribute
   state. The above timeout ensures waiting won't last endlessly, and in
   such case an error is reported.

   @param thd   pointer to a THD instance
   @param rli   pointer to Relay_log_info instance

   @return TRUE the killed status is recognized, FALSE a possible killed
           status is deferred.
*/
static bool sql_slave_killed(THD* thd, Relay_log_info* rli)
{
  bool ret= FALSE;
  bool is_parallel_warn= FALSE;

  DBUG_ENTER("sql_slave_killed");

  DBUG_ASSERT(rli->info_thd == thd);
  DBUG_ASSERT(rli->slave_running == 1);
  if (abort_loop || thd->killed || rli->abort_slave)
  {
    is_parallel_warn= (rli->is_parallel_exec() && 
                       (rli->is_mts_in_group() || thd->killed));
    /*
      Slave can execute stop being in one of two MTS or Single-Threaded mode.
      The modes define different criteria to accept the stop.
      In particular that relates to the concept of groupping.
      Killed Coordinator thread expects the worst so it warns on
      possible consistency issue.
    */
    if (is_parallel_warn ||
        (!rli->is_parallel_exec() &&
         thd->transaction.all.cannot_safely_rollback() && rli->is_in_group()))
    {
      char msg_stopped[]=
        "... Slave SQL Thread stopped with incomplete event group "
        "having non-transactional changes. "
        "If the group consists solely of row-based events, you can try "
        "to restart the slave with --slave-exec-mode=IDEMPOTENT, which "
        "ignores duplicate key, key not found, and similar errors (see "
        "documentation for details).";
      char msg_stopped_mts[]=
        "... The slave coordinator and worker threads are stopped, possibly "
        "leaving data in inconsistent state. A restart should "
        "restore consistency automatically, although using non-transactional "
        "storage for data or info tables or DDL queries could lead to problems. "
        "In such cases you have to examine your data (see documentation for "
        "details).";

      ret= TRUE;
      if (rli->abort_slave)
      {
        DBUG_PRINT("info", ("Request to stop slave SQL Thread received while "
                            "applying an MTS group or a group that "
                            "has non-transactional "
                            "changes; waiting for completion of the group ... "));

        /*
          Slave sql thread shutdown in face of unfinished group modified 
          Non-trans table is handled via a timer. The slave may eventually
          give out to complete the current group and in that case there
          might be issues at consequent slave restart, see the error message.
          WL#2975 offers a robust solution requiring to store the last exectuted
          event's coordinates along with the group's coordianates
          instead of waiting with @c last_event_start_time the timer.
        */

        if (rli->last_event_start_time == 0)
          rli->last_event_start_time= my_time(0);
        ret= difftime(my_time(0), rli->last_event_start_time) <=
          SLAVE_WAIT_GROUP_DONE ? FALSE : TRUE;

        DBUG_EXECUTE_IF("stop_slave_middle_group", 
                        DBUG_EXECUTE_IF("incomplete_group_in_relay_log",
                                        ret= TRUE;);); // time is over

        if (!ret && !rli->reported_unsafe_warning)
        {
          rli->report(WARNING_LEVEL, 0,
                      !is_parallel_warn ?
                      "Request to stop slave SQL Thread received while "
                      "applying a group that has non-transactional "
                      "changes; waiting for completion of the group ... "
                      :
                      "Coordinator thread of multi-threaded slave is being "
                      "stopped in the middle of assigning a group of events; "
                      "deferring to exit until the group completion ... ");
          rli->reported_unsafe_warning= true;
        }
      }
      if (ret)
      {
        if (is_parallel_warn)
          rli->report(!rli->is_error() ? ERROR_LEVEL :
                      WARNING_LEVEL,    // an error was reported by Worker
                      ER_MTS_INCONSISTENT_DATA,
                      ER(ER_MTS_INCONSISTENT_DATA),
                      msg_stopped_mts);
        else
          rli->report(ERROR_LEVEL, ER_SLAVE_FATAL_ERROR,
                      ER(ER_SLAVE_FATAL_ERROR), msg_stopped);
      }
    }
    else
    {
      ret= TRUE;
    }
  }
  if (ret)
  {
    rli->last_event_start_time= 0;
    if (rli->mts_group_status == Relay_log_info::MTS_IN_GROUP)
    {
      rli->mts_group_status= Relay_log_info::MTS_KILLED_GROUP;
    }
  }
  
  DBUG_RETURN(ret);
}


/*
  skip_load_data_infile()

  NOTES
    This is used to tell a 3.23 master to break send_file()
*/

void skip_load_data_infile(NET *net)
{
  DBUG_ENTER("skip_load_data_infile");

  (void)net_request_file(net, "/dev/null");
  (void)my_net_read(net);                               // discard response
  (void)net_write_command(net, 0, (uchar*) "", 0, (uchar*) "", 0); // ok
  DBUG_VOID_RETURN;
}


bool net_request_file(NET* net, const char* fname)
{
  DBUG_ENTER("net_request_file");
  DBUG_RETURN(net_write_command(net, 251, (uchar*) fname, strlen(fname),
                                (uchar*) "", 0));
}

/*
  From other comments and tests in code, it looks like
  sometimes Query_log_event and Load_log_event can have db == 0
  (see rewrite_db() above for example)
  (cases where this happens are unclear; it may be when the master is 3.23).
*/

const char *print_slave_db_safe(const char* db)
{
  DBUG_ENTER("*print_slave_db_safe");

  DBUG_RETURN((db ? db : ""));
}

/*
  Check if the error is caused by network.
  @param[in]   errorno   Number of the error.
  RETURNS:
  TRUE         network error
  FALSE        not network error
*/

bool is_network_error(uint errorno)
{ 
  if (errorno == CR_CONNECTION_ERROR || 
      errorno == CR_CONN_HOST_ERROR ||
      errorno == CR_SERVER_GONE_ERROR ||
      errorno == CR_SERVER_LOST ||
      errorno == ER_CON_COUNT_ERROR ||
      errorno == ER_SERVER_SHUTDOWN)
    return TRUE;

  return FALSE;   
}


/**
  Execute an initialization query for the IO thread.

  If there is an error, then this function calls mysql_free_result;
  otherwise the MYSQL object holds the result after this call.  If
  there is an error other than allowed_error, then this function
  prints a message and returns -1.

  @param mysql MYSQL object.
  @param query Query string.
  @param allowed_error Allowed error code, or 0 if no errors are allowed.
  @param[out] master_res If this is not NULL and there is no error, then
  mysql_store_result() will be called and the result stored in this pointer.
  @param[out] master_row If this is not NULL and there is no error, then
  mysql_fetch_row() will be called and the result stored in this pointer.

  @retval COMMAND_STATUS_OK No error.
  @retval COMMAND_STATUS_ALLOWED_ERROR There was an error and the
  error code was 'allowed_error'.
  @retval COMMAND_STATUS_ERROR There was an error and the error code
  was not 'allowed_error'.
*/
enum enum_command_status
{ COMMAND_STATUS_OK, COMMAND_STATUS_ERROR, COMMAND_STATUS_ALLOWED_ERROR };
static enum_command_status
io_thread_init_command(Master_info *mi, const char *query, int allowed_error,
                       MYSQL_RES **master_res= NULL,
                       MYSQL_ROW *master_row= NULL)
{
  DBUG_ENTER("io_thread_init_command");
  DBUG_PRINT("info", ("IO thread initialization command: '%s'", query));
  MYSQL *mysql= mi->mysql;
  int ret= mysql_real_query(mysql, query, strlen(query));
  if (io_slave_killed(mi->info_thd, mi))
  {
    sql_print_information("The slave IO thread was killed while executing "
                          "initialization query '%s'", query);
    mysql_free_result(mysql_store_result(mysql));
    DBUG_RETURN(COMMAND_STATUS_ERROR);
  }
  if (ret != 0)
  {
    int err= mysql_errno(mysql);
    mysql_free_result(mysql_store_result(mysql));
    if (!err || err != allowed_error)
    {
      mi->report(is_network_error(err) ? WARNING_LEVEL : ERROR_LEVEL, err,
                 "The slave IO thread stops because the initialization query "
                 "'%s' failed with error '%s'.",
                 query, mysql_error(mysql));
      DBUG_RETURN(COMMAND_STATUS_ERROR);
    }
    DBUG_RETURN(COMMAND_STATUS_ALLOWED_ERROR);
  }
  if (master_res != NULL)
  {
    if ((*master_res= mysql_store_result(mysql)) == NULL)
    {
      mi->report(WARNING_LEVEL, mysql_errno(mysql),
                 "The slave IO thread stops because the initialization query "
                 "'%s' did not return any result.",
                 query);
      DBUG_RETURN(COMMAND_STATUS_ERROR);
    }
    if (master_row != NULL)
    {
      if ((*master_row= mysql_fetch_row(*master_res)) == NULL)
      {
        mysql_free_result(*master_res);
        mi->report(WARNING_LEVEL, mysql_errno(mysql),
                   "The slave IO thread stops because the initialization query "
                   "'%s' did not return any row.",
                   query);
        DBUG_RETURN(COMMAND_STATUS_ERROR);
      }
    }
  }
  else
    DBUG_ASSERT(master_row == NULL);
  DBUG_RETURN(COMMAND_STATUS_OK);
}


/**
  Set user variables after connecting to the master.

  @param  mysql MYSQL to request uuid from master.
  @param  mi    Master_info to set master_uuid

  @return 0: Success, 1: Fatal error, 2: Network error.
 */
int io_thread_init_commands(MYSQL *mysql, Master_info *mi)
{
  char query[256];
  int ret= 0;

  sprintf(query, "SET @slave_uuid= '%s'", server_uuid);
  if (mysql_real_query(mysql, query, strlen(query))
      && !check_io_slave_killed(mi->info_thd, mi, NULL))
    goto err;

  mysql_free_result(mysql_store_result(mysql));
  return ret;

err:
  if (mysql_errno(mysql) && is_network_error(mysql_errno(mysql)))
  {
    mi->report(WARNING_LEVEL, mysql_errno(mysql),
               "The initialization command '%s' failed with the following"
               " error: '%s'.", query, mysql_error(mysql));
    ret= 2;
  }
  else
  {
    char errmsg[512];
    const char *errmsg_fmt=
      "The slave I/O thread stops because a fatal error is encountered "
      "when it tries to send query to master(query: %s).";

    sprintf(errmsg, errmsg_fmt, query);
    mi->report(ERROR_LEVEL, ER_SLAVE_FATAL_ERROR, ER(ER_SLAVE_FATAL_ERROR),
               errmsg);
    ret= 1;
  }
  mysql_free_result(mysql_store_result(mysql));
  return ret;
}

/**
  Get master's uuid on connecting.

  @param  mysql MYSQL to request uuid from master.
  @param  mi    Master_info to set master_uuid

  @return 0: Success, 1: Fatal error, 2: Network error.
*/
static int get_master_uuid(MYSQL *mysql, Master_info *mi)
{
  const char *errmsg;
  MYSQL_RES *master_res= NULL;
  MYSQL_ROW master_row= NULL;
  int ret= 0;

  if (!mysql_real_query(mysql,
                        STRING_WITH_LEN("SHOW VARIABLES LIKE 'SERVER_UUID'")) &&
      (master_res= mysql_store_result(mysql)) &&
      (master_row= mysql_fetch_row(master_res)))
  {
    if (!strcmp(::server_uuid, master_row[1]) &&
        !mi->rli->replicate_same_server_id)
    {
      errmsg= "The slave I/O thread stops because master and slave have equal "
              "MySQL server UUIDs; these UUIDs must be different for "
              "replication to work.";
      mi->report(ERROR_LEVEL, ER_SLAVE_FATAL_ERROR, ER(ER_SLAVE_FATAL_ERROR),
                 errmsg);
      // Fatal error
      ret= 1;
    }
    else
    {
      if (mi->master_uuid[0] != 0 && strcmp(mi->master_uuid, master_row[1]))
        sql_print_warning("The master's UUID has changed, although this should"
                          " not happen unless you have changed it manually."
                          " The old UUID was %s.",
                          mi->master_uuid);
      strncpy(mi->master_uuid, master_row[1], UUID_LENGTH);
      mi->master_uuid[UUID_LENGTH]= 0;
    }
  }
  else if (mysql_errno(mysql))
  {
    if (is_network_error(mysql_errno(mysql)))
    {
      mi->report(WARNING_LEVEL, mysql_errno(mysql),
                 "Get master SERVER_UUID failed with error: %s",
                 mysql_error(mysql));
      ret= 2;
    }
    else
    {
      /* Fatal error */
      errmsg= "The slave I/O thread stops because a fatal error is encountered "
        "when it tries to get the value of SERVER_UUID variable from master.";
      mi->report(ERROR_LEVEL, ER_SLAVE_FATAL_ERROR, ER(ER_SLAVE_FATAL_ERROR),
                 errmsg);
      ret= 1;
    }
  }
  else if (!master_row && master_res)
  {
    mi->report(WARNING_LEVEL, ER_UNKNOWN_SYSTEM_VARIABLE,
               "Unknown system variable 'SERVER_UUID' on master, "
               "maybe it is a *VERY OLD MASTER*.");
  }

  if (master_res)
    mysql_free_result(master_res);
  return ret;
}

/*
  Note that we rely on the master's version (3.23, 4.0.14 etc) instead of
  relying on the binlog's version. This is not perfect: imagine an upgrade
  of the master without waiting that all slaves are in sync with the master;
  then a slave could be fooled about the binlog's format. This is what happens
  when people upgrade a 3.23 master to 4.0 without doing RESET MASTER: 4.0
  slaves are fooled. So we do this only to distinguish between 3.23 and more
  recent masters (it's too late to change things for 3.23).

  RETURNS
  0       ok
  1       error
  2       transient network problem, the caller should try to reconnect
*/

static int get_master_version_and_clock(MYSQL* mysql, Master_info* mi)
{
	char err_buff[MAX_SLAVE_ERRMSG];
	const char* errmsg= 0;
	int err_code= 0;
	MYSQL_RES *master_res= 0;
	MYSQL_ROW master_row;
	DBUG_ENTER("get_master_version_and_clock");

	/*
	Free old mi_description_event (that is needed if we are in
	a reconnection).
	*/
	mi->set_mi_description_event(NULL);

	if (!my_isdigit(&my_charset_bin,*mysql->server_version))
	{
		errmsg = "Master reported unrecognized MySQL version";
		err_code= ER_SLAVE_FATAL_ERROR;
		sprintf(err_buff, ER(err_code), errmsg);
	}
	else
	{
		/*
		Note the following switch will bug when we have MySQL branch 30 ;)
		*/
		switch (*mysql->server_version)
		{
		case '0':
		case '1':
		case '2':
			errmsg = "Master reported unrecognized MySQL version";
			err_code= ER_SLAVE_FATAL_ERROR;
			sprintf(err_buff, ER(err_code), errmsg);
			break;
		case '3':
			mi->set_mi_description_event(new
				Format_description_log_event(1, mysql->server_version));
			break;
		case '4':
			mi->set_mi_description_event(new
				Format_description_log_event(3, mysql->server_version));
			break;
		default:
			/*
			Master is MySQL >=5.0. Give a default Format_desc event, so that we can
			take the early steps (like tests for "is this a 3.23 master") which we
			have to take before we receive the real master's Format_desc which will
			override this one. Note that the Format_desc we create below is garbage
			(it has the format of the *slave*); it's only good to help know if the
			master is 3.23, 4.0, etc.
			*/
			mi->set_mi_description_event(new
				Format_description_log_event(4, mysql->server_version));
			break;
		}
	}

	/*
	This does not mean that a 5.0 slave will be able to read a 5.5 master; but
	as we don't know yet, we don't want to forbid this for now. If a 5.0 slave
	can't read a 5.5 master, this will show up when the slave can't read some
	events sent by the master, and there will be error messages.
	*/

	if (errmsg)
		DBUG_RETURN(1);

	/* as we are here, we tried to allocate the event */
	if (mi->get_mi_description_event() == NULL)
	{
		errmsg= "default Format_description_log_event";
		err_code= ER_SLAVE_CREATE_EVENT_FAILURE;
		sprintf(err_buff, ER(err_code), errmsg);
		DBUG_RETURN(1);
	}

	mi->get_mi_description_event()->checksum_alg=mi->relay_log_checksum_alg;

	DBUG_ASSERT(mi->get_mi_description_event()->checksum_alg !=
		BINLOG_CHECKSUM_ALG_UNDEF);
	DBUG_ASSERT(mi->rli->relay_log.relay_log_checksum_alg !=
		BINLOG_CHECKSUM_ALG_UNDEF); 


	/* redundant with rest of code but safer against later additions */
	if (*mysql->server_version == '3')
		DBUG_RETURN(1);

	/*
	Querying if master is capable to checksum and notifying it about own
	CRC-awareness. The master's side instant value of @@global.binlog_checksum 
	is stored in the dump thread's uservar area as well as cached locally
	to become known in consensus by master and slave.
	*/
	mi->checksum_alg_before_fd= BINLOG_CHECKSUM_ALG_OFF;

	DBUG_RETURN(0);
}


/*
  Builds a Rotate from the ignored events' info and writes it to relay log.

  The caller must hold mi->data_lock before invoking this function.

  @param thd pointer to I/O Thread's Thd.
  @param mi  point to I/O Thread metadata class.

  @return 0 if everything went fine, 1 otherwise.
*/
static int write_ignored_events_info_to_relay_log(THD *thd, Master_info *mi)
{
  Relay_log_info *rli= mi->rli;
  mysql_mutex_t *log_lock= rli->relay_log.get_log_lock();
  int error= 0;
  DBUG_ENTER("write_ignored_events_info_to_relay_log");

  DBUG_ASSERT(thd == mi->info_thd);
  mysql_mutex_assert_owner(&mi->data_lock);
  mysql_mutex_lock(log_lock);
  if (rli->ign_master_log_name_end[0])
  {
    DBUG_PRINT("info",("writing a Rotate event to track down ignored events"));
    Rotate_log_event *ev= new Rotate_log_event(rli->ign_master_log_name_end,
                                               0, rli->ign_master_log_pos_end,
                                               Rotate_log_event::DUP_NAME);
    if (mi->get_mi_description_event() != NULL)
      ev->checksum_alg= mi->get_mi_description_event()->checksum_alg;
    
    rli->ign_master_log_name_end[0]= 0;
    /* can unlock before writing as slave SQL thd will soon see our Rotate */
    mysql_mutex_unlock(log_lock);
    if (likely((bool)ev))
    {
      ev->server_id= 0; // don't be ignored by slave SQL thread
      if (unlikely(rli->relay_log.append_event(ev, mi) != 0))
        mi->report(ERROR_LEVEL, ER_SLAVE_RELAY_LOG_WRITE_FAILURE,
                   ER(ER_SLAVE_RELAY_LOG_WRITE_FAILURE),
                   "failed to write a Rotate event"
                   " to the relay log, SHOW SLAVE STATUS may be"
                   " inaccurate");
      rli->relay_log.harvest_bytes_written(&rli->log_space_total);
      if (flush_master_info(mi, TRUE))
      {
        error= 1;
        sql_print_error("Failed to flush master info file.");
      }
      delete ev;
    }
    else
    {
      error= 1;
      mi->report(ERROR_LEVEL, ER_SLAVE_CREATE_EVENT_FAILURE,
                 ER(ER_SLAVE_CREATE_EVENT_FAILURE),
                 "Rotate_event (out of memory?),"
                 " SHOW SLAVE STATUS may be inaccurate");
    }
  }
  else
    mysql_mutex_unlock(log_lock);

  DBUG_RETURN(error);
}


int register_slave_on_master(MYSQL* mysql, Master_info *mi,
                             bool *suppress_warnings)
{
  uchar buf[1024], *pos= buf;
  uint report_host_len=0, report_user_len=0, report_password_len=0;
  DBUG_ENTER("register_slave_on_master");

  *suppress_warnings= FALSE;
  if (report_host)
    report_host_len= strlen(report_host);
  if (report_host_len > HOSTNAME_LENGTH)
  {
    sql_print_warning("The length of report_host is %d. "
                      "It is larger than the max length(%d), so this "
                      "slave cannot be registered to the master.",
                      report_host_len, HOSTNAME_LENGTH);
    DBUG_RETURN(0);
  }

  if (report_user)
    report_user_len= strlen(report_user);
  if (report_user_len > USERNAME_LENGTH)
  {
    sql_print_warning("The length of report_user is %d. "
                      "It is larger than the max length(%d), so this "
                      "slave cannot be registered to the master.",
                      report_user_len, USERNAME_LENGTH);
    DBUG_RETURN(0);
  }

  if (report_password)
    report_password_len= strlen(report_password);
  if (report_password_len > MAX_PASSWORD_LENGTH)
  {
    sql_print_warning("The length of report_password is %d. "
                      "It is larger than the max length(%d), so this "
                      "slave cannot be registered to the master.",
                      report_password_len, MAX_PASSWORD_LENGTH);
    DBUG_RETURN(0);
  }

  int4store(pos, server_id); pos+= 4;
  pos= net_store_data(pos, (uchar*) report_host, report_host_len);
  pos= net_store_data(pos, (uchar*) report_user, report_user_len);
  pos= net_store_data(pos, (uchar*) report_password, report_password_len);
  int2store(pos, (uint16) report_port); pos+= 2;
  /* 
    Fake rpl_recovery_rank, which was removed in BUG#13963,
    so that this server can register itself on old servers,
    see BUG#49259.
   */
  int4store(pos, /* rpl_recovery_rank */ 0);    pos+= 4;
  /* The master will fill in master_id */
  int4store(pos, 0);                    pos+= 4;

  if (simple_command(mysql, COM_REGISTER_SLAVE, buf, (size_t) (pos- buf), 0))
  {
    if (mysql_errno(mysql) == ER_NET_READ_INTERRUPTED)
    {
      *suppress_warnings= TRUE;                 // Suppress reconnect warning
    }
    else if (!check_io_slave_killed(mi->info_thd, mi, NULL))
    {
      char buf[256];
      my_snprintf(buf, sizeof(buf), "%s (Errno: %d)", mysql_error(mysql), 
                  mysql_errno(mysql));
      mi->report(ERROR_LEVEL, ER_SLAVE_MASTER_COM_FAILURE,
                 ER(ER_SLAVE_MASTER_COM_FAILURE), "COM_REGISTER_SLAVE", buf);
    }
    DBUG_RETURN(1);
  }
  DBUG_RETURN(0);
}


void set_slave_thread_options(THD* thd)
{
  DBUG_ENTER("set_slave_thread_options");
  /*
     It's nonsense to constrain the slave threads with max_join_size; if a
     query succeeded on master, we HAVE to execute it. So set
     OPTION_BIG_SELECTS. Setting max_join_size to HA_POS_ERROR is not enough
     (and it's not needed if we have OPTION_BIG_SELECTS) because an INSERT
     SELECT examining more than 4 billion rows would still fail (yes, because
     when max_join_size is 4G, OPTION_BIG_SELECTS is automatically set, but
     only for client threads.
  */
  ulonglong options= thd->variables.option_bits | OPTION_BIG_SELECTS;
  if (opt_log_slave_updates)
    options|= OPTION_BIN_LOG;
  else
    options&= ~OPTION_BIN_LOG;
  thd->variables.option_bits= options;
  thd->variables.completion_type= 0;
  DBUG_VOID_RETURN;
}

void set_slave_thread_default_charset(THD* thd, Relay_log_info const *rli)
{
  DBUG_ENTER("set_slave_thread_default_charset");

  thd->variables.character_set_client=
    global_system_variables.character_set_client;
  thd->variables.collation_connection=
    global_system_variables.collation_connection;
  thd->variables.collation_server=
    global_system_variables.collation_server;
  thd->update_charset();

  /*
    We use a const cast here since the conceptual (and externally
    visible) behavior of the function is to set the default charset of
    the thread.  That the cache has to be invalidated is a secondary
    effect.
   */
  const_cast<Relay_log_info*>(rli)->cached_charset_invalidate();
  DBUG_VOID_RETURN;
}

/*
  init_slave_thread()
*/

static int init_slave_thread(THD* thd, SLAVE_THD_TYPE thd_type)
{
  DBUG_ENTER("init_slave_thread");
#if !defined(DBUG_OFF)
  int simulate_error= 0;
#endif
  thd->system_thread= (thd_type == SLAVE_THD_WORKER) ? 
    SYSTEM_THREAD_SLAVE_WORKER : (thd_type == SLAVE_THD_SQL) ?
    SYSTEM_THREAD_SLAVE_SQL : SYSTEM_THREAD_SLAVE_IO;
  thd->security_ctx->skip_grants();
  my_net_init(&thd->net, 0);
/*
  Adding MAX_LOG_EVENT_HEADER_LEN to the max_allowed_packet on all
  slave threads, since a replication event can become this much larger
  than the corresponding packet (query) sent from client to master.
*/
  thd->variables.max_allowed_packet= slave_max_allowed_packet;
  thd->slave_thread = 1;
  thd->enable_slow_log= opt_log_slow_slave_statements;
  set_slave_thread_options(thd);
  thd->client_capabilities = CLIENT_LOCAL_FILES;
  mysql_mutex_lock(&LOCK_thread_count);
  thd->thread_id= thd->variables.pseudo_thread_id= thread_id++;
  mysql_mutex_unlock(&LOCK_thread_count);

  DBUG_EXECUTE_IF("simulate_io_slave_error_on_init",
                  simulate_error|= (1 << SLAVE_THD_IO););
  DBUG_EXECUTE_IF("simulate_sql_slave_error_on_init",
                  simulate_error|= (1 << SLAVE_THD_SQL););
#if !defined(DBUG_OFF)
  if (init_thr_lock() || thd->store_globals() || simulate_error & (1<< thd_type))
#else
  if (init_thr_lock() || thd->store_globals())
#endif
  {
    DBUG_RETURN(-1);
  }

  thd->set_time();
  /* Do not use user-supplied timeout value for system threads. */
  thd->variables.lock_wait_timeout= LONG_TIMEOUT;
  DBUG_RETURN(0);
}


/**
  Sleep for a given amount of time or until killed.

  @param thd        Thread context of the current thread.
  @param seconds    The number of seconds to sleep.
  @param func       Function object to check if the thread has been killed.
  @param info       The Rpl_info object associated with this sleep.

  @retval True if the thread has been killed, false otherwise.
*/
template <typename killed_func, typename rpl_info>
static inline bool slave_sleep(THD *thd, time_t seconds,
                               killed_func func, rpl_info info)
{
  bool ret;
  struct timespec abstime;
  mysql_mutex_t *lock= &info->sleep_lock;
  mysql_cond_t *cond= &info->sleep_cond;

  /* Absolute system time at which the sleep time expires. */
  set_timespec(abstime, seconds);

  mysql_mutex_lock(lock);
  thd->ENTER_COND(cond, lock, NULL, NULL);

  while (! (ret= func(thd, info)))
  {
    int error= mysql_cond_timedwait(cond, lock, &abstime);
    if (error == ETIMEDOUT || error == ETIME)
      break;
  }

  /* Implicitly unlocks the mutex. */
  thd->EXIT_COND(NULL);

  return ret;
}

static int request_dump(THD *thd, MYSQL* mysql, Master_info* mi,
                        bool *suppress_warnings)
{
  DBUG_ENTER("request_dump");

  const int BINLOG_NAME_INFO_SIZE= strlen(mi->get_master_log_name());
  int error= 1;
  size_t command_size= 0;
  enum_server_command command= mi->is_auto_position() ?
    COM_BINLOG_DUMP_GTID : COM_BINLOG_DUMP;
  uchar* command_buffer= NULL;
  ushort binlog_flags= 0;

//   if (RUN_HOOK(binlog_relay_io,
//                before_request_transmit,
//                (thd, mi, binlog_flags)))
//     goto err;

  *suppress_warnings= false;
  if (command == COM_BINLOG_DUMP_GTID)
  {
    // get set of GTIDs
    Sid_map sid_map(NULL/*no lock needed*/);
    Gtid_set gtid_executed(&sid_map);
    global_sid_lock->wrlock();
    gtid_state->dbug_print();
    if (gtid_executed.add_gtid_set(mi->rli->get_gtid_set()) != RETURN_STATUS_OK ||
        gtid_executed.add_gtid_set(gtid_state->get_logged_gtids()) !=
        RETURN_STATUS_OK)
    {
      global_sid_lock->unlock();
      goto err;
    }
    global_sid_lock->unlock();
     
    // allocate buffer
    size_t encoded_data_size= gtid_executed.get_encoded_length();
    size_t allocation_size= 
      ::BINLOG_FLAGS_INFO_SIZE + ::BINLOG_SERVER_ID_INFO_SIZE +
      ::BINLOG_NAME_SIZE_INFO_SIZE + BINLOG_NAME_INFO_SIZE +
      ::BINLOG_POS_INFO_SIZE + ::BINLOG_DATA_SIZE_INFO_SIZE +
      encoded_data_size + 1;
    if (!(command_buffer= (uchar *) my_malloc(allocation_size, MYF(MY_WME))))
      goto err;
    uchar* ptr_buffer= command_buffer;

    DBUG_PRINT("info", ("Do I know something about the master? (binary log's name %s - auto position %d).",
               mi->get_master_log_name(), mi->is_auto_position()));
    /*
      Note: binlog_flags is always 0.  However, in versions up to 5.6
      RC, the master would check the lowest bit and do something
      unexpected if it was set; in early versions of 5.6 it would also
      use the two next bits.  Therefore, for backward compatibility,
      if we ever start to use the flags, we should leave the three
      lowest bits unused.
    */
    int2store(ptr_buffer, binlog_flags);
    ptr_buffer+= ::BINLOG_FLAGS_INFO_SIZE;
    int4store(ptr_buffer, server_id);
    ptr_buffer+= ::BINLOG_SERVER_ID_INFO_SIZE;
    int4store(ptr_buffer, BINLOG_NAME_INFO_SIZE);
    ptr_buffer+= ::BINLOG_NAME_SIZE_INFO_SIZE;
    memset(ptr_buffer, 0, BINLOG_NAME_INFO_SIZE);
    ptr_buffer+= BINLOG_NAME_INFO_SIZE;
    int8store(ptr_buffer, 4);
    ptr_buffer+= ::BINLOG_POS_INFO_SIZE;

    int4store(ptr_buffer, encoded_data_size);
    ptr_buffer+= ::BINLOG_DATA_SIZE_INFO_SIZE;
    gtid_executed.encode(ptr_buffer);
    ptr_buffer+= encoded_data_size;

    command_size= ptr_buffer - command_buffer;
    DBUG_ASSERT(command_size == (allocation_size - 1));
  }
  else
  {
    size_t allocation_size= ::BINLOG_POS_OLD_INFO_SIZE +
      BINLOG_NAME_INFO_SIZE + ::BINLOG_FLAGS_INFO_SIZE +
      ::BINLOG_SERVER_ID_INFO_SIZE + 1;
    if (!(command_buffer= (uchar *) my_malloc(allocation_size, MYF(MY_WME))))
      goto err;
    uchar* ptr_buffer= command_buffer;
  
    int4store(ptr_buffer, mi->get_master_log_pos());
    ptr_buffer+= ::BINLOG_POS_OLD_INFO_SIZE;
    // See comment regarding binlog_flags above.
    int2store(ptr_buffer, binlog_flags);
    ptr_buffer+= ::BINLOG_FLAGS_INFO_SIZE;
    int4store(ptr_buffer, server_id);
    ptr_buffer+= ::BINLOG_SERVER_ID_INFO_SIZE;
    memcpy(ptr_buffer, mi->get_master_log_name(), BINLOG_NAME_INFO_SIZE);
    ptr_buffer+= BINLOG_NAME_INFO_SIZE;

    command_size= ptr_buffer - command_buffer;
    DBUG_ASSERT(command_size == (allocation_size - 1));
  }

  if (simple_command(mysql, command, command_buffer, command_size, 1))
  {
    /*
      Something went wrong, so we will just reconnect and retry later
      in the future, we should do a better error analysis, but for
      now we just fill up the error log :-)
    */
    if (mysql_errno(mysql) == ER_NET_READ_INTERRUPTED)
      *suppress_warnings= true;                 // Suppress reconnect warning
    else
      sql_print_error("Error on %s: %d  %s, will retry in %d secs",
                      command_name[command].str,
                      mysql_errno(mysql), mysql_error(mysql),
                      mi->connect_retry);
    goto err;
  }
  error= 0;

err:
  my_free(command_buffer);
  DBUG_RETURN(error);
}


/*
  Read one event from the master

  SYNOPSIS
    read_event()
    mysql               MySQL connection
    mi                  Master connection information
    suppress_warnings   TRUE when a normal net read timeout has caused us to
                        try a reconnect.  We do not want to print anything to
                        the error log in this case because this a anormal
                        event in an idle server.

    RETURN VALUES
    'packet_error'      Error
    number              Length of packet
*/

static ulong read_event(MYSQL* mysql, Master_info *mi, bool* suppress_warnings)
{
  ulong len;
  DBUG_ENTER("read_event");

  *suppress_warnings= FALSE;
  /*
    my_real_read() will time us out
    We check if we were told to die, and if not, try reading again
  */
#ifndef DBUG_OFF
  if (disconnect_slave_event_count && !(mi->events_until_exit--))
    DBUG_RETURN(packet_error);
#endif

  len = cli_safe_read(mysql);
  if (len == packet_error || (long) len < 1)
  {
    if (mysql_errno(mysql) == ER_NET_READ_INTERRUPTED)
    {
      /*
        We are trying a normal reconnect after a read timeout;
        we suppress prints to .err file as long as the reconnect
        happens without problems
      */
      *suppress_warnings= TRUE;
    }
    else
      sql_print_error("Error reading packet from server: %s ( server_errno=%d)",
                      mysql_error(mysql), mysql_errno(mysql));
    DBUG_RETURN(packet_error);
  }

  /* Check if eof packet */
  if (len < 8 && mysql->net.read_pos[0] == 254)
  {
    sql_print_information("Slave: received end packet from server, apparent "
                          "master shutdown: %s",
                     mysql_error(mysql));
     DBUG_RETURN(packet_error);
  }

  DBUG_PRINT("exit", ("len: %lu  net->read_pos[4]: %d",
                      len, mysql->net.read_pos[4]));
  DBUG_RETURN(len - 1);
}


/**
  If this is a lagging slave (specified with CHANGE MASTER TO MASTER_DELAY = X), delays accordingly. Also unlocks rli->data_lock.

  Design note: this is the place to unlock rli->data_lock. The lock
  must be held when reading delay info from rli, but it should not be
  held while sleeping.

  @param ev Event that is about to be executed.

  @param thd The sql thread's THD object.

  @param rli The sql thread's Relay_log_info structure.

  @retval 0 If the delay timed out and the event shall be executed.

  @retval nonzero If the delay was interrupted and the event shall be skipped.
*/
static int sql_delay_event(Log_event *ev, THD *thd, Relay_log_info *rli)
{
  long sql_delay= rli->get_sql_delay();

  DBUG_ENTER("sql_delay_event");
  mysql_mutex_assert_owner(&rli->data_lock);
  DBUG_ASSERT(!rli->belongs_to_client());

  int type= ev->get_type_code();
  if (sql_delay && type != ROTATE_EVENT &&
      type != FORMAT_DESCRIPTION_EVENT && type != START_EVENT_V3)
  {
    // The time when we should execute the event.
    time_t sql_delay_end=
      ev->when.tv_sec + rli->mi->clock_diff_with_master + sql_delay;
    // The current time.
    time_t now= my_time(0);
    // The time we will have to sleep before executing the event.
    unsigned long nap_time= 0;
    if (sql_delay_end > now)
      nap_time= sql_delay_end - now;

    DBUG_PRINT("info", ("sql_delay= %lu "
                        "ev->when= %lu "
                        "rli->mi->clock_diff_with_master= %lu "
                        "now= %ld "
                        "sql_delay_end= %ld "
                        "nap_time= %ld",
                        sql_delay, (long) ev->when.tv_sec,
                        rli->mi->clock_diff_with_master,
                        (long)now, (long)sql_delay_end, (long)nap_time));

    if (sql_delay_end > now)
    {
      DBUG_PRINT("info", ("delaying replication event %lu secs",
                          nap_time));
      rli->start_sql_delay(sql_delay_end);
      mysql_mutex_unlock(&rli->data_lock);
      DBUG_RETURN(slave_sleep(thd, nap_time, sql_slave_killed, rli));
    }
  }

  mysql_mutex_unlock(&rli->data_lock);

  DBUG_RETURN(0);
}

/**
   a sort_dynamic function on ulong type
   returns as specified by @c qsort_cmp
*/
int ulong_cmp(ulong *id1, ulong *id2)
{
  return *id1 < *id2? -1 : (*id1 > *id2? 1 : 0);
}

static bool check_io_slave_killed(THD *thd, Master_info *mi, const char *info)
{
  if (io_slave_killed(thd, mi))
  {
    if (info && log_warnings)
      sql_print_information("%s", info);
    return TRUE;
  }
  return FALSE;
}

/**
  @brief Try to reconnect slave IO thread.

  @details Terminates current connection to master, sleeps for
  @c mi->connect_retry msecs and initiates new connection with
  @c safe_reconnect(). Variable pointed by @c retry_count is increased -
  if it exceeds @c mi->retry_count then connection is not re-established
  and function signals error.
  Unless @c suppres_warnings is TRUE, a warning is put in the server error log
  when reconnecting. The warning message and messages used to report errors
  are taken from @c messages array. In case @c mi->retry_count is exceeded,
  no messages are added to the log.

  @param[in]     thd                 Thread context.
  @param[in]     mysql               MySQL connection.
  @param[in]     mi                  Master connection information.
  @param[in,out] retry_count         Number of attempts to reconnect.
  @param[in]     suppress_warnings   TRUE when a normal net read timeout 
                                     has caused to reconnecting.
  @param[in]     messages            Messages to print/log, see 
                                     reconnect_messages[] array.

  @retval        0                   OK.
  @retval        1                   There was an error.
*/

/*
  Check the temporary directory used by commands like
  LOAD DATA INFILE.
 */
static 
int check_temp_dir(char* tmp_file)
{
  int fd;
  MY_DIR *dirp;
  char tmp_dir[FN_REFLEN];
  size_t tmp_dir_size;

  DBUG_ENTER("check_temp_dir");

  /*
    Get the directory from the temporary file.
  */
  dirname_part(tmp_dir, tmp_file, &tmp_dir_size);

  /*
    Check if the directory exists.
   */
  if (!(dirp=my_dir(tmp_dir,MYF(MY_WME))))
    DBUG_RETURN(1);
  my_dirend(dirp);

  /*
    Check permissions to create a file.
   */
  //append the server UUID to the temp file name.
  char *unique_tmp_file_name= (char*)my_malloc((FN_REFLEN+TEMP_FILE_MAX_LEN)*sizeof(char), MYF(0));
  sprintf(unique_tmp_file_name, "%s%s", tmp_file, server_uuid);
  if ((fd= mysql_file_create(key_file_misc,
                             unique_tmp_file_name, CREATE_MODE,
                             O_WRONLY | O_BINARY | O_EXCL | O_NOFOLLOW,
                             MYF(MY_WME))) < 0)
  DBUG_RETURN(1);

  /*
    Clean up.
   */
  mysql_file_close(fd, MYF(0));

  mysql_file_delete(key_file_misc, unique_tmp_file_name, MYF(0));
  my_free(unique_tmp_file_name);
  DBUG_RETURN(0);
}

/*
  Worker thread for the parallel execution of the replication events.
*/

/**
   Orders jobs by comparing relay log information.
*/

int mts_event_coord_cmp(LOG_POS_COORD *id1, LOG_POS_COORD *id2)
{
  longlong filecmp= strcmp(id1->file_name, id2->file_name);
  longlong poscmp= id1->pos - id2->pos;
  return (filecmp < 0  ? -1 : (filecmp > 0  ?  1 :
         (poscmp  < 0  ? -1 : (poscmp  > 0  ?  1 : 0))));
}

int mts_recovery_groups(Relay_log_info *rli)
{ 
  Log_event *ev= NULL;
  const char *errmsg= NULL;
  bool error= FALSE;
  bool flag_group_seen_begin= FALSE;
  uint recovery_group_cnt= 0;
  bool not_reached_commit= true;
  DYNAMIC_ARRAY above_lwm_jobs;
  Slave_job_group job_worker;
  IO_CACHE log;
  File file;
  LOG_INFO linfo;
  my_off_t offset= 0;
  MY_BITMAP *groups= &rli->recovery_groups;

  DBUG_ENTER("mts_recovery_groups");

  DBUG_ASSERT(rli->slave_parallel_workers == 0);

  /* 
     Although mts_recovery_groups() is reentrant it returns
     early if the previous invocation raised any bit in 
     recovery_groups bitmap.
  */
  if (rli->is_mts_recovery())
    DBUG_RETURN(0);

  /*
    Save relay log position to compare with worker's position.
  */
  LOG_POS_COORD cp=
  {
    (char *) rli->get_group_master_log_name(),
    rli->get_group_master_log_pos()
  };

  Format_description_log_event fdle(BINLOG_VERSION), *p_fdle= &fdle;

  if (!p_fdle->is_valid())
    DBUG_RETURN(TRUE);

  /*
    Gathers information on valuable workers and stores it in 
    above_lwm_jobs in asc ordered by the master binlog coordinates.
  */
  my_init_dynamic_array(&above_lwm_jobs, sizeof(Slave_job_group),
                        rli->recovery_parallel_workers,
                        rli->recovery_parallel_workers);

  for (uint id= 0; id < rli->recovery_parallel_workers; id++)
  {
    Slave_worker *worker=
      Rpl_info_factory::create_worker(0, id, rli, true);

    if (!worker)
    {
      error= TRUE;
      goto err;
    }

    LOG_POS_COORD w_last= { const_cast<char*>(worker->get_group_master_log_name()),
                            worker->get_group_master_log_pos() };
    if (mts_event_coord_cmp(&w_last, &cp) > 0)
    {
      /*
        Inserts information into a dynamic array for further processing.
        The jobs/workers are ordered by the last checkpoint positions
        workers have seen.
      */
      job_worker.worker= worker;
      job_worker.checkpoint_log_pos= worker->checkpoint_master_log_pos;
      job_worker.checkpoint_log_name= worker->checkpoint_master_log_name;

      insert_dynamic(&above_lwm_jobs, (uchar*) &job_worker);
    }
    else
    {
      /*
        Deletes the worker because its jobs are included in the latest
        checkpoint.
      */
      delete worker;
    }
  }

  /*
    In what follows, the group Recovery Bitmap is constructed.

     seek(lwm);

     while(w= next(above_lwm_w))
       do
         read G
         if G == w->last_comm
           w.B << group_cnt++;
           RB |= w.B;
            break;
         else
           group_cnt++;
        while(!eof);
        continue;
  */
  DBUG_ASSERT(!rli->recovery_groups_inited);

  if (above_lwm_jobs.elements != 0)
  {
    bitmap_init(groups, NULL, MTS_MAX_BITS_IN_GROUP, FALSE);
    rli->recovery_groups_inited= true;
    bitmap_clear_all(groups);
  }
  rli->mts_recovery_group_cnt= 0;
  for (uint it_job= 0; it_job < above_lwm_jobs.elements; it_job++)
  {
    Slave_worker *w= ((Slave_job_group *)
                      dynamic_array_ptr(&above_lwm_jobs, it_job))->worker;
    LOG_POS_COORD w_last= { const_cast<char*>(w->get_group_master_log_name()),
                            w->get_group_master_log_pos() };
    bool checksum_detected= FALSE;

    sql_print_information("Slave: MTS group recovery relay log info based on Worker-Id %lu, "
                          "group_relay_log_name %s, group_relay_log_pos %llu "
                          "group_master_log_name %s, group_master_log_pos %llu",
                          w->id,
                          w->get_group_relay_log_name(),
                          w->get_group_relay_log_pos(),
                          w->get_group_master_log_name(),
                          w->get_group_master_log_pos());

    recovery_group_cnt= 0;
    not_reached_commit= true;
    if (rli->relay_log.find_log_pos(&linfo, rli->get_group_relay_log_name(), 1))
    {
      error= TRUE;
      sql_print_error("Error looking for %s.", rli->get_group_relay_log_name());
      goto err;
    }
    offset= rli->get_group_relay_log_pos();
    for (int checking= 0 ; not_reached_commit; checking++)
    {
      if ((file= open_binlog_file(&log, linfo.log_file_name, &errmsg)) < 0)
      {
        error= TRUE;
        sql_print_error("%s", errmsg);
        goto err;
      }
      /*
        Looking for the actual relay checksum algorithm that is present in
        a FD at head events of the relay log.
      */
      if (!checksum_detected)
      {
        int i= 0;
        while (i < 4 && (ev= Log_event::read_log_event(&log,
               (mysql_mutex_t*) 0, p_fdle, 0)))
        {
          if (ev->get_type_code() == FORMAT_DESCRIPTION_EVENT)
          {
            p_fdle->checksum_alg= ev->checksum_alg;
            checksum_detected= TRUE;
          }
          delete ev;
          i++;
        }
        if (!checksum_detected)
        {
          error= TRUE;
          sql_print_error("%s", "malformed or very old relay log which "
                          "does not have FormatDescriptor");
          goto err;
        }
      }

      my_b_seek(&log, offset);

      while (not_reached_commit &&
             (ev= Log_event::read_log_event(&log, 0, p_fdle,
                                            opt_slave_sql_verify_checksum)))
      {
        DBUG_ASSERT(ev->is_valid());

        if (ev->get_type_code() == FORMAT_DESCRIPTION_EVENT)
          p_fdle->checksum_alg= ev->checksum_alg;

        if (ev->get_type_code() == ROTATE_EVENT ||
            ev->get_type_code() == FORMAT_DESCRIPTION_EVENT ||
            ev->get_type_code() == PREVIOUS_GTIDS_LOG_EVENT)
        {
          delete ev;
          ev= NULL;
          continue;
        }

        DBUG_PRINT("mts", ("Event Recoverying relay log info "
                   "group_mster_log_name %s, event_master_log_pos %llu type code %u.",
                   linfo.log_file_name, ev->log_pos, ev->get_type_code()));

        if (ev->starts_group())
        {
          flag_group_seen_begin= true;
        }
        else if ((ev->ends_group() || !flag_group_seen_begin) &&
                 !is_gtid_event(ev))
        {
          int ret= 0;
          LOG_POS_COORD ev_coord= { (char *) rli->get_group_master_log_name(),
                                      ev->log_pos };
          flag_group_seen_begin= false;
          recovery_group_cnt++;

          sql_print_information("Slave: MTS group recovery relay log info "
                                "group_master_log_name %s, "
                                "event_master_log_pos %llu.",
                                rli->get_group_master_log_name(), ev->log_pos);
          if ((ret= mts_event_coord_cmp(&ev_coord, &w_last)) == 0)
          {
#ifndef DBUG_OFF
            for (uint i= 0; i <= w->checkpoint_seqno; i++)
            {
              if (bitmap_is_set(&w->group_executed, i))
                DBUG_PRINT("mts", ("Bit %u is set.", i));
              else
                DBUG_PRINT("mts", ("Bit %u is not set.", i));
            }
#endif
            DBUG_PRINT("mts",
                       ("Doing a shift ini(%lu) end(%lu).",
                       (w->checkpoint_seqno + 1) - recovery_group_cnt,
                        w->checkpoint_seqno));

            for (uint i= (w->checkpoint_seqno + 1) - recovery_group_cnt,
                 j= 0; i <= w->checkpoint_seqno; i++, j++)
            {
              if (bitmap_is_set(&w->group_executed, i))
              {
                DBUG_PRINT("mts", ("Setting bit %u.", j));
                bitmap_fast_test_and_set(groups, j);
              }
            }
            not_reached_commit= false;
          }
          else
            DBUG_ASSERT(ret < 0);
        }
        delete ev;
        ev= NULL;
      }
      end_io_cache(&log);
      mysql_file_close(file, MYF(MY_WME));
      offset= BIN_LOG_HEADER_SIZE;
      if (not_reached_commit && rli->relay_log.find_next_log(&linfo, 1))
      {
         error= TRUE;
         sql_print_error("Error looking for file after %s.", linfo.log_file_name);
         goto err;
      }
    }

    rli->mts_recovery_group_cnt= (rli->mts_recovery_group_cnt < recovery_group_cnt ?
      recovery_group_cnt : rli->mts_recovery_group_cnt);
  }

  DBUG_ASSERT(!rli->recovery_groups_inited ||
              rli->mts_recovery_group_cnt <= groups->n_bits);

err:
  
  for (uint it_job= 0; it_job < above_lwm_jobs.elements; it_job++)
  {
    get_dynamic(&above_lwm_jobs, (uchar *) &job_worker, it_job);
    delete job_worker.worker;
  }

  delete_dynamic(&above_lwm_jobs);
  if (rli->recovery_groups_inited && rli->mts_recovery_group_cnt == 0)
  {
    bitmap_free(groups);
    rli->recovery_groups_inited= false;
  }

  DBUG_RETURN(error ? ER_MTS_RECOVERY_FAILURE : 0);
}

/**
   Processing rli->gaq to find out the low-water-mark (lwm) coordinates
   which is stored into the cental recovery table.

   @param rli            pointer to Relay-log-info of Coordinator
   @param period         period of processing GAQ, normally derived from
                         @c mts_checkpoint_period
   @param force          if TRUE then hang in a loop till some progress
   @param need_data_lock False if rli->data_lock mutex is aquired by
                         the caller.

   @return FALSE success, TRUE otherwise
*/
bool mts_checkpoint_routine(Relay_log_info *rli, ulonglong period,
                            bool force, bool need_data_lock)
{
  ulong cnt;
  bool error= FALSE;
  struct timespec curr_clock;

  DBUG_ENTER("checkpoint_routine");

#ifndef DBUG_OFF
  if (DBUG_EVALUATE_IF("check_slave_debug_group", 1, 0))
  {
    if (!rli->gaq->count_done(rli))
      DBUG_RETURN(FALSE);
  }
#endif

  /*
    rli->checkpoint_group can have two possible values due to
    two possible status of the last (being scheduled) group. 
  */
  DBUG_ASSERT(!rli->gaq->full() ||
              ((rli->checkpoint_seqno == rli->checkpoint_group -1 &&
                rli->mts_group_status == Relay_log_info::MTS_IN_GROUP) ||
               rli->checkpoint_seqno == rli->checkpoint_group));

  /*
    Currently, the checkpoint routine is being called by the SQL Thread.
    For that reason, this function is called call from appropriate points
    in the SQL Thread's execution path and the elapsed time is calculated
    here to check if it is time to execute it.
  */
  set_timespec_nsec(curr_clock, 0);
  ulonglong diff= diff_timespec(curr_clock, rli->last_clock);
  if (!force && diff < period)
  {
    /*
      We do not need to execute the checkpoint now because
      the time elapsed is not enough.
    */
    DBUG_RETURN(FALSE);
  }

  do
  {
    cnt= rli->gaq->move_queue_head(&rli->workers);
#ifndef DBUG_OFF
    if (DBUG_EVALUATE_IF("check_slave_debug_group", 1, 0) &&
        cnt != opt_mts_checkpoint_period)
      sql_print_error("This an error cnt != mts_checkpoint_period");
#endif
  } while (!sql_slave_killed(rli->info_thd, rli) &&
           cnt == 0 && force &&
           !DBUG_EVALUATE_IF("check_slave_debug_group", 1, 0) &&
           (my_sleep(rli->mts_coordinator_basic_nap), 1));
  /*
    This checks how many consecutive jobs where processed.
    If this value is different than zero the checkpoint
    routine can proceed. Otherwise, there is nothing to be
    done.
  */      
  if (cnt == 0)
    goto end;


  /* TODO: 
     to turn the least occupied selection in terms of jobs pieces
  */
  for (uint i= 0; i < rli->workers.elements; i++)
  {
    Slave_worker *w_i;
    get_dynamic(&rli->workers, (uchar *) &w_i, i);
    set_dynamic(&rli->least_occupied_workers, (uchar*) &w_i->jobs.len, w_i->id);
  };
  sort_dynamic(&rli->least_occupied_workers, (qsort_cmp) ulong_cmp);

  if (need_data_lock)
    mysql_mutex_lock(&rli->data_lock);
  else
    mysql_mutex_assert_owner(&rli->data_lock);

  /*
    "Coordinator::commit_positions" {

    rli->gaq->lwm has been updated in move_queue_head() and 
    to contain all but rli->group_master_log_name which 
    is altered solely by Coordinator at special checkpoints.
  */
  rli->set_group_master_log_pos(rli->gaq->lwm.group_master_log_pos);
  rli->set_group_relay_log_pos(rli->gaq->lwm.group_relay_log_pos);
  DBUG_PRINT("mts", ("New checkpoint %llu %llu %s",
             rli->gaq->lwm.group_master_log_pos,
             rli->gaq->lwm.group_relay_log_pos,
             rli->gaq->lwm.group_relay_log_name));

  if (rli->gaq->lwm.group_relay_log_name[0] != 0)
    rli->set_group_relay_log_name(rli->gaq->lwm.group_relay_log_name);

  /* 
     todo: uncomment notifies when UNTIL will be supported

     rli->notify_group_master_log_name_update();
     rli->notify_group_relay_log_name_update();

     Todo: optimize with if (wait_flag) broadcast
         waiter: set wait_flag; waits....; drops wait_flag;
  */

  error= rli->flush_info(TRUE);

  mysql_cond_broadcast(&rli->data_cond);
  if (need_data_lock)
    mysql_mutex_unlock(&rli->data_lock);

  /*
    We need to ensure that this is never called at this point when
    cnt is zero. This value means that the checkpoint information
    will be completely reset.
  */
  rli->reset_notified_checkpoint(cnt, rli->gaq->lwm.ts, need_data_lock);

  /* end-of "Coordinator::"commit_positions" */

end:
#ifndef DBUG_OFF
  if (DBUG_EVALUATE_IF("check_slave_debug_group", 1, 0))
    DBUG_SUICIDE();
#endif
  set_timespec_nsec(rli->last_clock, 0);
  
  DBUG_RETURN(error);
}

#endif /* HAVE_REPLICATION */
