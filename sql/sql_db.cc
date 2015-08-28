/*
   Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.

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


/* create and drop of databases */

#include "my_global.h"                          /* NO_EMBEDDED_ACCESS_CHECKS */
#include "sql_priv.h"
#include "unireg.h"
#include "sql_db.h"
#include "sql_cache.h"                   // query_cache_*
#include "lock.h"                        // lock_schema_name
#include "sql_table.h"                   // build_table_filename,
                                         // filename_to_tablename
#include "sql_rename.h"                  // mysql_rename_tables
#include "sql_acl.h"                     // SELECT_ACL, DB_ACLS,
                                         // acl_get, check_grant_db
#include "sql_base.h"                    // lock_table_names, tdc_remove_table
#include "sql_handler.h"                 // mysql_ha_rm_tables
#include <mysys_err.h>
#include "sp.h"
#include "events.h"
#include <my_dir.h>
#include <m_ctype.h>
#include "log.h"
#ifdef __WIN__
#include <direct.h>
#endif
#include "debug_sync.h"
#include "mysql.h"

#define MAX_DROP_TABLE_Q_LEN      1024

const char *del_exts[]= {".frm", ".BAK", ".TMD", ".opt", ".OLD", NullS};
static TYPELIB deletable_extentions=
{array_elements(del_exts)-1,"del_exts", del_exts, NULL};

static bool find_db_tables_and_rm_known_files(THD *thd, MY_DIR *dirp,
                                              const char *db,
                                              const char *path,
                                              TABLE_LIST **tables,
                                              bool *found_other_files);

long mysql_rm_arc_files(THD *thd, MY_DIR *dirp, const char *org_path);
static my_bool rm_dir_w_symlink(const char *org_path, my_bool send_error);

/* Database options hash */
static HASH dboptions;
static my_bool dboptions_init= 0;
static mysql_rwlock_t LOCK_dboptions;

/* Structure for database options */
typedef struct my_dbopt_st
{
  char *name;			/* Database name                  */
  uint name_length;		/* Database length name           */
  const CHARSET_INFO *charset;	/* Database default character set */
} my_dbopt_t;


/*
  Function we use in the creation of our hash to get key.
*/

extern "C" uchar* dboptions_get_key(my_dbopt_t *opt, size_t *length,
                                    my_bool not_used);

uchar* dboptions_get_key(my_dbopt_t *opt, size_t *length,
                         my_bool not_used __attribute__((unused)))
{
  *length= opt->name_length;
  return (uchar*) opt->name;
}


/*
  Helper function to write a query to binlog used by mysql_rm_db()
*/

/*
  Function to free dboptions hash element
*/

extern "C" void free_dbopt(void *dbopt);

void free_dbopt(void *dbopt)
{
  my_free(dbopt);
}

#ifdef HAVE_PSI_INTERFACE
static PSI_rwlock_key key_rwlock_LOCK_dboptions;

static PSI_rwlock_info all_database_names_rwlocks[]=
{
  { &key_rwlock_LOCK_dboptions, "LOCK_dboptions", PSI_FLAG_GLOBAL}
};

static void init_database_names_psi_keys(void)
{
  const char* category= "sql";
  int count;

  count= array_elements(all_database_names_rwlocks);
  mysql_rwlock_register(category, all_database_names_rwlocks, count);
}
#endif

/**
  Initialize database option cache.

  @note Must be called before any other database function is called.

  @retval  0	ok
  @retval  1	Fatal error
*/

bool my_dboptions_cache_init(void)
{
#ifdef HAVE_PSI_INTERFACE
  init_database_names_psi_keys();
#endif

  bool error= 0;
  mysql_rwlock_init(key_rwlock_LOCK_dboptions, &LOCK_dboptions);
  if (!dboptions_init)
  {
    dboptions_init= 1;
    error= my_hash_init(&dboptions, lower_case_table_names ?
                        &my_charset_bin : system_charset_info,
                        32, 0, 0, (my_hash_get_key) dboptions_get_key,
                        free_dbopt,0);
  }
  return error;
}



/**
  Free database option hash and locked databases hash.
*/

void my_dboptions_cache_free(void)
{
  if (dboptions_init)
  {
    dboptions_init= 0;
    my_hash_free(&dboptions);
    mysql_rwlock_destroy(&LOCK_dboptions);
  }
}


/**
  Cleanup cached options.
*/

void my_dbopt_cleanup(void)
{
  mysql_rwlock_wrlock(&LOCK_dboptions);
  my_hash_free(&dboptions);
  my_hash_init(&dboptions, lower_case_table_names ? 
               &my_charset_bin : system_charset_info,
               32, 0, 0, (my_hash_get_key) dboptions_get_key,
               free_dbopt,0);
  mysql_rwlock_unlock(&LOCK_dboptions);
}


/*
  Find database options in the hash.
  
  DESCRIPTION
    Search a database options in the hash, usings its path.
    Fills "create" on success.
  
  RETURN VALUES
    0 on success.
    1 on error.
*/

static my_bool get_dbopt(const char *dbname, HA_CREATE_INFO *create)
{
  my_dbopt_t *opt;
  uint length;
  my_bool error= 1;
  
  length= (uint) strlen(dbname);
  
  mysql_rwlock_rdlock(&LOCK_dboptions);
  if ((opt= (my_dbopt_t*) my_hash_search(&dboptions, (uchar*) dbname, length)))
  {
    create->default_table_charset= opt->charset;
    error= 0;
  }
  mysql_rwlock_unlock(&LOCK_dboptions);
  return error;
}


/*
  Writes database options into the hash.
  
  DESCRIPTION
    Inserts database options into the hash, or updates
    options if they are already in the hash.
  
  RETURN VALUES
    0 on success.
    1 on error.
*/

static my_bool put_dbopt(const char *dbname, HA_CREATE_INFO *create)
{
  my_dbopt_t *opt;
  uint length;
  my_bool error= 0;
  DBUG_ENTER("put_dbopt");

  length= (uint) strlen(dbname);
  
  mysql_rwlock_wrlock(&LOCK_dboptions);
  if (!(opt= (my_dbopt_t*) my_hash_search(&dboptions, (uchar*) dbname,
                                          length)))
  { 
    /* Options are not in the hash, insert them */
    char *tmp_name;
    if (!my_multi_malloc(MYF(MY_WME | MY_ZEROFILL),
                         &opt, (uint) sizeof(*opt), &tmp_name, (uint) length+1,
                         NullS))
    {
      error= 1;
      goto end;
    }
    
    opt->name= tmp_name;
    strmov(opt->name, dbname);
    opt->name_length= length;
    
    if ((error= my_hash_insert(&dboptions, (uchar*) opt)))
    {
      my_free(opt);
      goto end;
    }
  }

  /* Update / write options in hash */
  opt->charset= create->default_table_charset;

end:
  mysql_rwlock_unlock(&LOCK_dboptions);
  DBUG_RETURN(error);
}


/*
  Deletes database options from the hash.
*/

static void del_dbopt(const char *path)
{
  my_dbopt_t *opt;
  mysql_rwlock_wrlock(&LOCK_dboptions);
  if ((opt= (my_dbopt_t *)my_hash_search(&dboptions, (const uchar*) path,
                                         strlen(path))))
    my_hash_delete(&dboptions, (uchar*) opt);
  mysql_rwlock_unlock(&LOCK_dboptions);
}


/*
  Create database options file:

  DESCRIPTION
    Currently database default charset is only stored there.

  RETURN VALUES
  0	ok
  1	Could not create file or write to it.  Error sent through my_error()
*/

static bool write_db_opt(THD *thd, const char *path, HA_CREATE_INFO *create)
{
  register File file;
  char buf[256]; // Should be enough for one option
  bool error=1;

  if (!create->default_table_charset)
    create->default_table_charset= thd->variables.collation_server;

  if (put_dbopt(path, create))
    return 1;

  if ((file= mysql_file_create(key_file_dbopt, path, CREATE_MODE,
                               O_RDWR | O_TRUNC, MYF(MY_WME))) >= 0)
  {
    ulong length;
    length= (ulong) (strxnmov(buf, sizeof(buf)-1, "default-character-set=",
                              create->default_table_charset->csname,
                              "\ndefault-collation=",
                              create->default_table_charset->name,
                              "\n", NullS) - buf);

    /* Error is written by mysql_file_write */
    if (!mysql_file_write(file, (uchar*) buf, length, MYF(MY_NABP+MY_WME)))
      error=0;
    mysql_file_close(file, MYF(0));
  }
  return error;
}


/*
  Load database options file

  load_db_opt()
  path		Path for option file
  create	Where to store the read options

  DESCRIPTION

  RETURN VALUES
  0	File found
  1	No database file or could not open it

*/

bool load_db_opt(THD *thd, const char *path, HA_CREATE_INFO *create)
{
  File file;
  char buf[256];
  DBUG_ENTER("load_db_opt");
  bool error=1;
  uint nbytes;

  memset(create, 0, sizeof(*create));
  create->default_table_charset= thd->variables.collation_server;

  /* Check if options for this database are already in the hash */
  if (!get_dbopt(path, create))
    DBUG_RETURN(0);

  /* Otherwise, load options from the .opt file */
  if ((file= mysql_file_open(key_file_dbopt,
                             path, O_RDONLY | O_SHARE, MYF(0))) < 0)
    goto err1;

  IO_CACHE cache;
  if (init_io_cache(&cache, file, IO_SIZE, READ_CACHE, 0, 0, MYF(0)))
    goto err2;

  while ((int) (nbytes= my_b_gets(&cache, (char*) buf, sizeof(buf))) > 0)
  {
    char *pos= buf+nbytes-1;
    /* Remove end space and control characters */
    while (pos > buf && !my_isgraph(&my_charset_latin1, pos[-1]))
      pos--;
    *pos=0;
    if ((pos= strchr(buf, '=')))
    {
      if (!strncmp(buf,"default-character-set", (pos-buf)))
      {
        /*
           Try character set name, and if it fails
           try collation name, probably it's an old
           4.1.0 db.opt file, which didn't have
           separate default-character-set and
           default-collation commands.
        */
        if (!(create->default_table_charset=
        get_charset_by_csname(pos+1, MY_CS_PRIMARY, MYF(0))) &&
            !(create->default_table_charset=
              get_charset_by_name(pos+1, MYF(0))))
        {
          sql_print_error("Error while loading database options: '%s':",path);
          sql_print_error(ER(ER_UNKNOWN_CHARACTER_SET),pos+1);
          create->default_table_charset= default_charset_info;
        }
      }
      else if (!strncmp(buf,"default-collation", (pos-buf)))
      {
        if (!(create->default_table_charset= get_charset_by_name(pos+1,
                                                           MYF(0))))
        {
          sql_print_error("Error while loading database options: '%s':",path);
          sql_print_error(ER(ER_UNKNOWN_COLLATION),pos+1);
          create->default_table_charset= default_charset_info;
        }
      }
    }
  }
  /*
    Put the loaded value into the hash.
    Note that another thread could've added the same
    entry to the hash after we called get_dbopt(),
    but it's not an error, as put_dbopt() takes this
    possibility into account.
  */
  error= put_dbopt(path, create);

  end_io_cache(&cache);
err2:
  mysql_file_close(file, MYF(0));
err1:
  DBUG_RETURN(error);
}


/*
  Retrieve database options by name. Load database options file or fetch from
  cache.

  SYNOPSIS
    load_db_opt_by_name()
    db_name         Database name
    db_create_info  Where to store the database options

  DESCRIPTION
    load_db_opt_by_name() is a shortcut for load_db_opt().

  NOTE
    Although load_db_opt_by_name() (and load_db_opt()) returns status of
    the operation, it is useless usually and should be ignored. The problem
    is that there are 1) system databases ("mysql") and 2) virtual
    databases ("information_schema"), which do not contain options file.
    So, load_db_opt[_by_name]() returns FALSE for these databases, but this
    is not an error.

    load_db_opt[_by_name]() clears db_create_info structure in any case, so
    even on failure it contains valid data. So, common use case is just
    call load_db_opt[_by_name]() without checking return value and use
    db_create_info right after that.

  RETURN VALUES (read NOTE!)
    FALSE   Success
    TRUE    Failed to retrieve options
*/

bool load_db_opt_by_name(THD *thd, const char *db_name,
                         HA_CREATE_INFO *db_create_info)
{
  char db_opt_path[FN_REFLEN + 1];

  /*
    Pass an empty file name, and the database options file name as extension
    to avoid table name to file name encoding.
  */
  (void) build_table_filename(db_opt_path, sizeof(db_opt_path) - 1,
                              db_name, "", MY_DB_OPT_FILE, 0);

  return load_db_opt(thd, db_opt_path, db_create_info);
}


/**
  Return default database collation.

  @param thd     Thread context.
  @param db_name Database name.

  @return CHARSET_INFO object. The operation always return valid character
    set, even if the database does not exist.
*/

const CHARSET_INFO *get_default_db_collation(THD *thd, const char *db_name)
{
  HA_CREATE_INFO db_info;

  if (thd->db != NULL && strcmp(db_name, thd->db) == 0)
    return thd->db_charset;

  load_db_opt_by_name(thd, db_name, &db_info);

  /*
    NOTE: even if load_db_opt_by_name() fails,
    db_info.default_table_charset contains valid character set
    (collation_server). We should not fail if load_db_opt_by_name() fails,
    because it is valid case. If a database has been created just by
    "mkdir", it does not contain db.opt file, but it is valid database.
  */

  return db_info.default_table_charset;
}


/*
  Create a database

  SYNOPSIS
  mysql_create_db()
  thd		Thread handler
  db		Name of database to create
		Function assumes that this is already validated.
  create_info	Database create options (like character set)
  silent	Used by replication when internally creating a database.
		In this case the entry should not be logged.

  SIDE-EFFECTS
   1. Report back to client that command succeeded (my_ok)
   2. Report errors to client
   3. Log event to binary log
   (The 'silent' flags turns off 1 and 3.)

  RETURN VALUES
  FALSE ok
  TRUE  Error

*/

int mysql_create_db(THD *thd, char *db, HA_CREATE_INFO *create_info,
                     bool silent)
{
  char	 path[FN_REFLEN+16];
  char	 tmp_query[FN_REFLEN+16];
  long result= 1;
  int error= 0;
  MY_STAT stat_info;
  uint create_options= create_info ? create_info->options : 0;
  uint path_len;
  bool was_truncated;
  DBUG_ENTER("mysql_create_db");

  /* do not create 'information_schema' db */
  if (is_infoschema_db(db))
  {
    my_error(ER_DB_CREATE_EXISTS, MYF(0), db);
    DBUG_RETURN(-1);
  }

  if (lock_schema_name(thd, db))
    DBUG_RETURN(-1);

  /* Check directory */
  path_len= build_table_filename(path, sizeof(path) - 1, db, "", "", 0,
                                 &was_truncated);
  if (was_truncated)
  {
    my_error(ER_IDENT_CAUSES_TOO_LONG_PATH, MYF(0), sizeof(path)-1, path);
    DBUG_RETURN(-1);
  }
  path[path_len-1]= 0;                    // Remove last '/' from path

  if (mysql_file_stat(key_file_misc, path, &stat_info, MYF(0)))
  {
    if (!(create_options & HA_LEX_CREATE_IF_NOT_EXISTS))
    {
      my_error(ER_DB_CREATE_EXISTS, MYF(0), db);
      error= -1;
      goto exit;
    }
    push_warning_printf(thd, Sql_condition::WARN_LEVEL_NOTE,
			ER_DB_CREATE_EXISTS, ER(ER_DB_CREATE_EXISTS), db);
    error= 0;
    goto not_silent;
  }
  else
  {
    if (my_errno != ENOENT)
    {
      char errbuf[MYSYS_STRERROR_SIZE];
      my_error(EE_STAT, MYF(0), path,
               my_errno, my_strerror(errbuf, sizeof(errbuf), my_errno));
      goto exit;
    }
    if (my_mkdir(path,0777,MYF(0)) < 0)
    {
      my_error(ER_CANT_CREATE_DB, MYF(0), db, my_errno);
      error= -1;
      goto exit;
    }
  }

  path[path_len-1]= FN_LIBCHAR;
  strmake(path+path_len, MY_DB_OPT_FILE, sizeof(path)-path_len-1);
  if (write_db_opt(thd, path, create_info))
  {
    /*
      Could not create options file.
      Restore things to beginning.
    */
    path[path_len]= 0;
    if (rmdir(path) >= 0)
    {
      error= -1;
      goto exit;
    }
    /*
      We come here when we managed to create the database, but not the option
      file.  In this case it's best to just continue as if nothing has
      happened.  (This is a very unlikely senario)
    */
    thd->clear_error();
  }

not_silent:
  if (!silent)
  {
    char *query;
    uint query_length;
    char db_name_quoted[2 * FN_REFLEN + sizeof("create database ") + 2];
    int id_len= 0;

//     if (!thd->query())                          // Only in replication
//     {
//       id_len= my_strmov_quoted_identifier(thd, (char *) db_name_quoted, db,
//                                           0);
//       db_name_quoted[id_len]= '\0';
//       query= tmp_query;
//       query_length= (uint) (strxmov(tmp_query,"create database ",
//                                     db_name_quoted, NullS) - tmp_query);
//     }
//     else
//     {
//       query=        thd->query();
//       query_length= thd->query_length();
//     }

    ha_binlog_log_query(thd, 0, LOGCOM_CREATE_DB,
                        query, query_length,
                        db, "");

//     if (mysql_bin_log.is_open())
//     {
//       int errcode= query_error_code(thd, TRUE);
//       Query_log_event qinfo(thd, query, query_length, FALSE, TRUE,
// 			    /* suppress_use */ TRUE, errcode);
// 
//       /*
// 	Write should use the database being created as the "current
//         database" and not the threads current database, which is the
//         default. If we do not change the "current database" to the
//         database being created, the CREATE statement will not be
//         replicated when using --binlog-do-db to select databases to be
//         replicated. 
// 
// 	An example (--binlog-do-db=sisyfos):
//        
//           CREATE DATABASE bob;        # Not replicated
//           USE bob;                    # 'bob' is the current database
//           CREATE DATABASE sisyfos;    # Not replicated since 'bob' is
//                                       # current database.
//           USE sisyfos;                # Will give error on slave since
//                                       # database does not exist.
//       */
//       qinfo.db     = db;
//       qinfo.db_len = strlen(db);
//       thd->add_to_binlog_accessed_dbs(db);
//       /*
//         These DDL methods and logging are protected with the exclusive
//         metadata lock on the schema
//       */
//       if (mysql_bin_log.write_event(&qinfo))
//       {
//         error= -1;
//         goto exit;
//       }
//     }
    my_ok(thd, result);
  }

exit:
  DBUG_RETURN(error);
}


/* db-name is already validated when we come here */

bool mysql_alter_db(THD *thd, const char *db, HA_CREATE_INFO *create_info)
{
  char path[FN_REFLEN+16];
  long result=1;
  int error= 0;
  DBUG_ENTER("mysql_alter_db");

  if (lock_schema_name(thd, db))
    DBUG_RETURN(TRUE);

  /* 
     Recreate db options file: /dbpath/.db.opt
     We pass MY_DB_OPT_FILE as "extension" to avoid
     "table name to file name" encoding.
  */
  build_table_filename(path, sizeof(path) - 1, db, "", MY_DB_OPT_FILE, 0);
  if ((error=write_db_opt(thd, path, create_info)))
    goto exit;

  /* Change options if current database is being altered. */

  if (thd->db && !strcmp(thd->db,db))
  {
    thd->db_charset= create_info->default_table_charset ?
		     create_info->default_table_charset :
		     thd->variables.collation_server;
    thd->variables.collation_database= thd->db_charset;
  }

  ha_binlog_log_query(thd, 0, LOGCOM_ALTER_DB,
                      thd->query(), thd->query_length(),
                      db, "");

//   if (mysql_bin_log.is_open())
//   {
//     int errcode= query_error_code(thd, TRUE); 
//     Query_log_event qinfo(thd, thd->query(), thd->query_length(), FALSE, TRUE,
// 			  /* suppress_use */ TRUE, errcode);
//     /*
//       Write should use the database being created as the "current
//       database" and not the threads current database, which is the
//       default.
//     */
//     qinfo.db     = db;
//     qinfo.db_len = strlen(db);
// 
//     /*
//       These DDL methods and logging are protected with the exclusive
//       metadata lock on the schema.
//     */
//     if ((error= mysql_bin_log.write_event(&qinfo)))
//       goto exit;
//   }
  my_ok(thd, result);

exit:
  DBUG_RETURN(error);
}


/**
  Drop all tables, routines and events in a database and the database itself.

  @param  thd        Thread handle
  @param  db         Database name in the case given by user
                     It's already validated and set to lower case
                     (if needed) when we come here
  @param  if_exists  Don't give error if database doesn't exists
  @param  silent     Don't write the statement to the binary log and don't
                     send ok packet to the client

  @retval  false  OK (Database dropped)
  @retval  true   Error
*/


/*
  Remove directory with symlink

  SYNOPSIS
    rm_dir_w_symlink()
    org_path    path of derictory
    send_error  send errors
  RETURN
    0 OK
    1 ERROR
*/

static my_bool rm_dir_w_symlink(const char *org_path, my_bool send_error)
{
  char tmp_path[FN_REFLEN], *pos;
  char *path= tmp_path;
  DBUG_ENTER("rm_dir_w_symlink");
  unpack_filename(tmp_path, org_path);
#ifdef HAVE_READLINK
  int error;
  char tmp2_path[FN_REFLEN];

  /* Remove end FN_LIBCHAR as this causes problem on Linux in readlink */
  pos= strend(path);
  if (pos > path && pos[-1] == FN_LIBCHAR)
    *--pos=0;

  if ((error= my_readlink(tmp2_path, path, MYF(MY_WME))) < 0)
    DBUG_RETURN(1);
  if (!error)
  {
    if (mysql_file_delete(key_file_misc, path, MYF(send_error ? MY_WME : 0)))
    {
      DBUG_RETURN(send_error);
    }
    /* Delete directory symbolic link pointed at */
    path= tmp2_path;
  }
#endif
  /* Remove last FN_LIBCHAR to not cause a problem on OS/2 */
  pos= strend(path);

  if (pos > path && pos[-1] == FN_LIBCHAR)
    *--pos=0;
  if (rmdir(path) < 0 && send_error)
  {
    my_error(ER_DB_DROP_RMDIR, MYF(0), path, errno);
    DBUG_RETURN(1);
  }
  DBUG_RETURN(0);
}


/*
  Remove .frm archives from directory

  SYNOPSIS
    thd       thread handler
    dirp      list of files in archive directory
    db        data base name
    org_path  path of archive directory

  RETURN
    > 0 number of removed files
    -1  error

  NOTE
    A support of "arc" directories is obsolete, however this
    function should exist to remove existent "arc" directories.
*/
long mysql_rm_arc_files(THD *thd, MY_DIR *dirp, const char *org_path)
{
  long deleted= 0;
  ulong found_other_files= 0;
  char filePath[FN_REFLEN];
  DBUG_ENTER("mysql_rm_arc_files");
  DBUG_PRINT("enter", ("path: %s", org_path));

  for (uint idx=0 ;
       idx < (uint) dirp->number_off_files && !thd->killed ;
       idx++)
  {
    FILEINFO *file=dirp->dir_entry+idx;
    char *extension, *revision;
    DBUG_PRINT("info",("Examining: %s", file->name));

    /* skiping . and .. */
    if (file->name[0] == '.' && (!file->name[1] ||
       (file->name[1] == '.' &&  !file->name[2])))
      continue;

    extension= fn_ext(file->name);
    if (extension[0] != '.' ||
        extension[1] != 'f' || extension[2] != 'r' ||
        extension[3] != 'm' || extension[4] != '-')
    {
      found_other_files++;
      continue;
    }
    revision= extension+5;
    while (*revision && my_isdigit(system_charset_info, *revision))
      revision++;
    if (*revision)
    {
      found_other_files++;
      continue;
    }
    strxmov(filePath, org_path, "/", file->name, NullS);
    if (mysql_file_delete_with_symlink(key_file_misc, filePath, MYF(MY_WME)))
    {
      goto err;
    }
    deleted++;
  }
  if (thd->killed)
    goto err;

  my_dirend(dirp);

  /*
    If the directory is a symbolic link, remove the link first, then
    remove the directory the symbolic link pointed at
  */
  if (!found_other_files &&
      rm_dir_w_symlink(org_path, 0))
    DBUG_RETURN(-1);
  DBUG_RETURN(deleted);

err:
  my_dirend(dirp);
  DBUG_RETURN(-1);
}


/**
  @brief Internal implementation: switch current database to a valid one.

  @param thd            Thread context.
  @param new_db_name    Name of the database to switch to. The function will
                        take ownership of the name (the caller must not free
                        the allocated memory). If the name is NULL, we're
                        going to switch to NULL db.
  @param new_db_access  Privileges of the new database.
  @param new_db_charset Character set of the new database.
*/



/**
  Backup the current database name before switch.

  @param[in]      thd             thread handle
  @param[in, out] saved_db_name   IN: "str" points to a buffer where to store
                                  the old database name, "length" contains the
                                  buffer size
                                  OUT: if the current (default) database is
                                  not NULL, its name is copied to the
                                  buffer pointed at by "str"
                                  and "length" is updated accordingly.
                                  Otherwise "str" is set to NULL and
                                  "length" is set to 0.
*/

static void backup_current_db_name(THD *thd,
                                   LEX_STRING *saved_db_name)
{
  if (!thd->db)
  {
    /* No current (default) database selected. */

    saved_db_name->str= NULL;
    saved_db_name->length= 0;
  }
  else
  {
    strmake(saved_db_name->str, thd->db, saved_db_name->length - 1);
    saved_db_name->length= thd->db_length;
  }
}


/**
  Return TRUE if db1_name is equal to db2_name, FALSE otherwise.

  The function allows to compare database names according to the MySQL
  rules. The database names db1 and db2 are equal if:
     - db1 is NULL and db2 is NULL;
     or
     - db1 is not-NULL, db2 is not-NULL, db1 is equal (ignoring case) to
       db2 in system character set (UTF8).
*/

static inline bool
cmp_db_names(const char *db1_name,
             const char *db2_name)
{
  return
         /* db1 is NULL and db2 is NULL */
         (!db1_name && !db2_name) ||

         /* db1 is not-NULL, db2 is not-NULL, db1 == db2. */
         (db1_name && db2_name &&
         my_strcasecmp(system_charset_info, db1_name, db2_name) == 0);
}


/**
  @brief Change the current database and its attributes unconditionally.

  @param thd          thread handle
  @param new_db_name  database name
  @param force_switch if force_switch is FALSE, then the operation will fail if

                        - new_db_name is NULL or empty;

                        - OR new database name is invalid
                          (check_db_name() failed);

                        - OR user has no privilege on the new database;

                        - OR new database does not exist;

                      if force_switch is TRUE, then

                        - if new_db_name is NULL or empty, the current
                          database will be NULL, @@collation_database will
                          be set to @@collation_server, the operation will
                          succeed.

                        - if new database name is invalid
                          (check_db_name() failed), the current database
                          will be NULL, @@collation_database will be set to
                          @@collation_server, but the operation will fail;

                        - user privileges will not be checked
                          (THD::db_access however is updated);

                          TODO: is this really the intention?
                                (see sp-security.test).

                        - if new database does not exist,the current database
                          will be NULL, @@collation_database will be set to
                          @@collation_server, a warning will be thrown, the
                          operation will succeed.

  @details The function checks that the database name corresponds to a
  valid and existent database, checks access rights and changes the current
  database with database attributes (@@collation_database session variable,
  THD::db_access).

  This function is not the only way to switch the database that is
  currently employed. When the replication slave thread switches the
  database before executing a query, it calls thd->set_db directly.
  However, if the query, in turn, uses a stored routine, the stored routine
  will use this function, even if it's run on the slave.

  This function allocates the name of the database on the system heap: this
  is necessary to be able to uniformly change the database from any module
  of the server. Up to 5.0 different modules were using different memory to
  store the name of the database, and this led to memory corruption:
  a stack pointer set by Stored Procedures was used by replication after
  the stack address was long gone.

  @return Operation status
    @retval FALSE Success
    @retval TRUE  Error
*/



/**
  Change the current database and its attributes if needed.

  @param          thd             thread handle
  @param          new_db_name     database name
  @param[in, out] saved_db_name   IN: "str" points to a buffer where to store
                                  the old database name, "length" contains the
                                  buffer size
                                  OUT: if the current (default) database is
                                  not NULL, its name is copied to the
                                  buffer pointed at by "str"
                                  and "length" is updated accordingly.
                                  Otherwise "str" is set to NULL and
                                  "length" is set to 0.
  @param          force_switch    @see mysql_change_db()
  @param[out]     cur_db_changed  out-flag to indicate whether the current
                                  database has been changed (valid only if
                                  the function suceeded)
*/

bool mysql_opt_change_db(THD *thd,
                         const LEX_STRING *new_db_name,
                         LEX_STRING *saved_db_name,
                         bool force_switch,
                         bool *cur_db_changed)
{
  *cur_db_changed= !cmp_db_names(thd->db, new_db_name->str);

  if (!*cur_db_changed)
    return FALSE;

  backup_current_db_name(thd, saved_db_name);

  return mysql_change_db(thd, new_db_name, force_switch);
}


/*
  Check if there is directory for the database name.

  SYNOPSIS
    check_db_dir_existence()
    db_name   database name

  RETURN VALUES
    FALSE   There is directory for the specified database name.
    TRUE    The directory does not exist.
*/

bool check_db_dir_existence(const char *db_name)
{
  char db_dir_path[FN_REFLEN + 1];
  uint db_dir_path_len;

  db_dir_path_len= build_table_filename(db_dir_path, sizeof(db_dir_path) - 1,
                                        db_name, "", "", 0);

  if (db_dir_path_len && db_dir_path[db_dir_path_len - 1] == FN_LIBCHAR)
    db_dir_path[db_dir_path_len - 1]= 0;

  /* Check access. */

  return my_access(db_dir_path, F_OK);
}
