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

#define MYSQL_LEX 1
// #include "mysql_thread.h"
#include "my_global.h"
#include "sql_priv.h"
#include "unireg.h"                    // REQUIRED: for other includes
#include "sql_parse.h"        // sql_kill, *_precheck, *_prepare
#include "lock.h"             // try_transactional_lock,
// check_transactional_lock,
// set_handler_table_locks,
// lock_global_read_lock,
// make_global_read_lock_block_commit
#include "sql_base.h"         // find_temporary_table
#include "sql_cache.h"        // QUERY_CACHE_FLAGS_SIZE, query_cache_*
#include "sql_show.h"         // mysqld_list_*, mysqld_show_*,
// calc_sum_of_all_status
#include "mysqld.h"
#include "sql_locale.h"                         // my_locale_en_US
#include "log.h"                                // flush_error_log
#include "sql_view.h"         // mysql_create_view, mysql_drop_view
#include "sql_delete.h"       // mysql_delete
#include "sql_insert.h"       // mysql_insert
#include "sql_update.h"       // mysql_update, mysql_multi_update
#include "sql_partition.h"    // struct partition_info
#include "sql_db.h"           // mysql_change_db, mysql_create_db,
// mysql_rm_db, mysql_upgrade_db,
// mysql_alter_db,
// check_db_dir_existence,
// my_dbopt_cleanup
#include "sql_table.h"        // mysql_create_like_table,
// mysql_create_table,
// mysql_alter_table,
// mysql_backup_table,
// mysql_restore_table
#include "sql_reload.h"       // reload_acl_and_cache
#include "sql_admin.h"        // mysql_assign_to_keycache
#include "sql_connect.h"      // check_user,
// decrease_user_connections,
// thd_init_client_charset, check_mqh,
// reset_mqh
#include "sql_rename.h"       // mysql_rename_table
#include <string.h>
#include "sql_tablespace.h"   // mysql_alter_tablespace
#include "hostname.h"         // hostname_cache_refresh
#include "sql_acl.h"          // *_ACL, check_grant, is_acl_user,
// has_any_table_level_privileges,
// mysql_drop_user, mysql_rename_user,
// check_grant_routine,
// mysql_routine_grant,
// mysql_show_grants,
// sp_grant_privileges, ...
#include "sql_test.h"         // mysql_print_status
#include "sql_select.h"       // handle_select, mysql_select,
#include "sql_load.h"         // mysql_load
#include "sql_servers.h"      // create_servers, alter_servers,
// drop_servers, servers_reload
#include "sql_handler.h"      // mysql_ha_open, mysql_ha_close,
// mysql_ha_read
#include "sql_binlog.h"       // mysql_client_binlog_statement
#include "sql_do.h"           // mysql_do
#include "sql_help.h"         // mysqld_help
#include "rpl_constants.h"    // Incident, INCIDENT_LOST_EVENTS
#include "log_event.h"
#include "rpl_slave.h"
#include "rpl_master.h"
#include "rpl_filter.h"
#include <m_ctype.h>
#include <myisam.h>
#include <my_dir.h>
#include "sql_lex.h"
#include "rpl_mi.h"
#include "errmsg.h"
#include "sp_head.h"
#include "sp.h"
#include "sp_cache.h"
#include "events.h"
#include "sql_trigger.h"
#include "transaction.h"
#include "sql_audit.h"
#include "sql_prepare.h"
#include "debug_sync.h"
#include "probes_mysql.h"
#include "set_var.h"
#include "opt_trace.h"
#include "mysql/psi/mysql_statement.h"
#include "sql_bootstrap.h"
#include "opt_explain.h"
#include "sql_rewrite.h"
#include "global_threads.h"
#include "sql_analyse.h"
//#include "table_cache.h" // table_cache_manager
#include "sql_common.h"
#include "derror.h"
#include "mysys_err.h"
#include <sql_class.h>
#include "sql_show.h"
#include "ptosc.h"
#include <algorithm>
#include "item_subselect.h"
#include "sql_time.h"
#include "thr_alarm.h"

int mysql_optimize_tables(
    THD* thd, 
    st_select_lex *select_lex,
    TABLE_LIST* tables
)
{
    return false;
}

int 
mysql_optimize_where(
    THD* thd, 
    st_select_lex *select_lex
)
{
    return false;
}

int optimize_item(
    THD* thd, 
    Item* item,
    st_select_lex *select_lex
)
{
    return false;
}

int mysql_optimize_subselect(
    THD* thd, 
    optimize_cache_node_t* optimize_node,
    st_select_lex *select_lex, 
    bool top
)
{
    Item* item;
    TABLE_LIST* tables;

    if (mysql_load_tables(thd, &optimize_node->rt_lst, select_lex))
        return true;

    List_iterator<Item> it(select_lex->item_list);
    while ((item= it++))
    {
        optimize_item(thd, item, select_lex);
    }

    if (top && (thd->lex->sql_command == SQLCOM_INSERT_SELECT ||
        thd->lex->sql_command == SQLCOM_DELETE ||
        thd->lex->sql_command == SQLCOM_DELETE_MULTI ||
        thd->lex->sql_command == SQLCOM_UPDATE_MULTI ||
        thd->lex->sql_command == SQLCOM_UPDATE))
        tables = select_lex->table_list.first->next_local;
    else
        tables = select_lex->table_list.first;

    if (tables)
    {
        mysql_optimize_tables(thd, select_lex, tables);
    }

    mysql_optimize_where(thd, select_lex);
    return 0;
}

int mysql_optimize_change_db(THD* thd)
{
    LEX_STRING db_str= { (char *) thd->lex->select_lex.db, strlen(thd->lex->select_lex.db) };
    mysql_change_db(thd, &db_str, FALSE);

    return false;
}

int mysql_optimize_select(THD* thd)
{
    SELECT_LEX* select_lex = &thd->lex->select_lex;
    optimize_cache_node_t* optimize_cache_node;
    optimize_cache_t* optimize_cache = NULL;

    optimize_cache = thd->optimize_cache;
    optimize_cache_node = (optimize_cache_node_t*)my_malloc(
        sizeof(optimize_cache_node_t), MY_ZEROFILL);

    thd->current_optimize = optimize_cache_node;
    mysql_optimize_subselect(thd, optimize_cache_node, select_lex, true);

    LIST_ADD_LAST(link, optimize_cache->field_lst, optimize_cache_node);

    return false;
}

int mysql_optimize_not_support(THD* thd)
{
    optimize_cache_node_t* optimize_cache_node;
    optimize_cache_t* optimize_cache = NULL;

    optimize_cache = thd->optimize_cache;
    optimize_cache_node = (optimize_cache_node_t*)my_malloc(
        sizeof(optimize_cache_node_t), MY_ZEROFILL);

    thd->current_optimize = optimize_cache_node;
    my_error(ER_NOT_SUPPORTED_YET, MYF(0));
    mysql_errmsg_append(thd);

    LIST_ADD_LAST(link, optimize_cache->field_lst, optimize_cache_node);
    return false;
}

