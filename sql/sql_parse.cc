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
using std::max;
using std::min;

#define FLAGSTR(V,F) ((V)&(F)?#F" ":"")

/**
@defgroup Runtime_Environment Runtime Environment
*/

enum enum_tbl_map_status
{
    /* no duplicate identifier found */
    OK_TO_PROCESS= 0,

    /* this table map must be filtered out */
    FILTERED_OUT= 1,

    /* identifier mapping table with different properties */
    SAME_ID_MAPPING_DIFFERENT_TABLE= 2,

    /* a duplicate identifier was found mapping the same table */
    SAME_ID_MAPPING_SAME_TABLE= 3
};

/* Used in error handling only */
#define SP_TYPE_STRING(LP) \
    ((LP)->sphead->m_type == SP_TYPE_FUNCTION ? "FUNCTION" : "PROCEDURE")
#define SP_COM_STRING(LP) \
    ((LP)->sql_command == SQLCOM_CREATE_SPFUNCTION || \
    (LP)->sql_command == SQLCOM_ALTER_FUNCTION || \
    (LP)->sql_command == SQLCOM_SHOW_CREATE_FUNC || \
    (LP)->sql_command == SQLCOM_DROP_FUNCTION ? \
    "FUNCTION" : "PROCEDURE")

const char *any_db="*any*"; // Special symbol for check_access

const LEX_STRING command_name[]={
    { C_STRING_WITH_LEN("Sleep") },
    { C_STRING_WITH_LEN("Quit") },
    { C_STRING_WITH_LEN("Init DB") },
    { C_STRING_WITH_LEN("Query") },
    { C_STRING_WITH_LEN("Field List") },
    { C_STRING_WITH_LEN("Create DB") },
    { C_STRING_WITH_LEN("Drop DB") },
    { C_STRING_WITH_LEN("Refresh") },
    { C_STRING_WITH_LEN("Shutdown") },
    { C_STRING_WITH_LEN("Statistics") },
    { C_STRING_WITH_LEN("Processlist") },
    { C_STRING_WITH_LEN("Connect") },
    { C_STRING_WITH_LEN("Kill") },
    { C_STRING_WITH_LEN("Debug") },
    { C_STRING_WITH_LEN("Ping") },
    { C_STRING_WITH_LEN("Time") },
    { C_STRING_WITH_LEN("Delayed insert") },
    { C_STRING_WITH_LEN("Change user") },
    { C_STRING_WITH_LEN("Binlog Dump") },
    { C_STRING_WITH_LEN("Table Dump") },
    { C_STRING_WITH_LEN("Connect Out") },
    { C_STRING_WITH_LEN("Register Slave") },
    { C_STRING_WITH_LEN("Prepare") },
    { C_STRING_WITH_LEN("Execute") },
    { C_STRING_WITH_LEN("Long Data") },
    { C_STRING_WITH_LEN("Close stmt") },
    { C_STRING_WITH_LEN("Reset stmt") },
    { C_STRING_WITH_LEN("Set option") },
    { C_STRING_WITH_LEN("Fetch") },
    { C_STRING_WITH_LEN("Daemon") },
    { C_STRING_WITH_LEN("Binlog Dump GTID") },
    { C_STRING_WITH_LEN("Error") }  // Last command number
};

const char *xa_state_names[]={
    "NON-EXISTING", "ACTIVE", "IDLE", "PREPARED", "ROLLBACK ONLY"
};

#define REMOTE_BACKUP_TABLE "$_$Inception_backup_information$_$"

#define INC_VARCHAR_MAX_TO_TEXT     8000
#define INC_CHAR_MAX_TO_VARCHAR     16

extern const char *osc_recursion_method[];

int mysql_check_subselect_item( THD* thd, st_select_lex *select_lex, bool top);
int mysql_check_item( THD* thd, Item* item, st_select_lex *select_lex);
int print_item(THD* thd, query_print_cache_node_t*   query_node, str_t* print_str, Item* item, st_select_lex *select_lex);
int mysql_execute_commit(THD *thd);
void mysql_free_all_table_definition(THD*  thd);
int mysql_alloc_record(table_info_t* table_info, MYSQL *mysql);
int mysql_check_binlog_format(THD* thd, char* binlogformat);

void mysql_data_seek2(MYSQL_RES *result, my_ulonglong row)
{
    MYSQL_ROWS *tmp=0;
    DBUG_PRINT("info",("mysql_data_seek(%ld)",(long) row));
    if (result->data)
        for (tmp=result->data->data; row-- && tmp ; tmp = tmp->next) ;
    result->current_row=0;
    result->data_cursor = tmp;
}

uint
mysql_get_explain_info(
    THD*        thd,
    MYSQL*  mysql,
    char*  select_sql,
    explain_info_t** explain_ret,
    int report_err,
    char* dbname
);

int mysql_anlyze_explain(
    THD*   thd,
    explain_info_t* explain
);

str_t*
str_init(str_t* str)
{
    str->str = str->str_buf;
    str->str_len = NAME_CHAR_LEN;
    memset(str->str, 0, NAME_CHAR_LEN);

    return str;
}

str_t*
str_append(
    str_t*  str,
    const char* new_string
)
{
    int    namelen;
    char*   select_item_tmp;
    int    buflen = NAME_CHAR_LEN;

    namelen = strlen(str->str) + strlen(new_string) + 1;
    if (namelen >= str->str_len)
    {
        select_item_tmp = (char*)malloc(namelen + NAME_CHAR_LEN);
        memset(select_item_tmp, 0, namelen + NAME_CHAR_LEN);
        buflen = namelen + NAME_CHAR_LEN;
        strcpy(select_item_tmp, str->str);
        if (str->str != str->str_buf)
            free(str->str);

        str->str_len = buflen;
        str->str = select_item_tmp;
    }

    strcat(str->str, new_string);
    return str;
}

str_t*
str_append_with_length(
        str_t*  str,
        const char* new_string,
        int len
)
{
    int    namelen;
    char*   select_item_tmp;
    int    buflen = NAME_CHAR_LEN;

    namelen = strlen(str->str) + len + 1;
    if (namelen >= str->str_len)
    {
        select_item_tmp = (char*)malloc(namelen + NAME_CHAR_LEN);
        memset(select_item_tmp, 0, namelen + NAME_CHAR_LEN);
        buflen = namelen + NAME_CHAR_LEN;
        strcpy(select_item_tmp, str->str);
        if (str->str != str->str_buf)
            free(str->str);

        str->str_len = buflen;
        str->str = select_item_tmp;
    }

    strncat(str->str, new_string, len);
    return str;
}

str_t*
str_truncate(str_t* str, int endlen)
{
    int len;

    len = strlen(str->str);
    if (endlen >= len)
        endlen = len;

    str->str[len - endlen] = '\0';
    return str;
}

void
str_deinit(str_t* str)
{
    if (str == NULL)
        return;

    if (str->str != str->str_buf)
        free(str->str);
}

char*
str_get(str_t* str)
{
    return str->str;
}

int
str_get_len(str_t* str)
{
    return strlen(str->str);
}


/**
This works because items are allocated with sql_alloc().
@note The function also handles null pointers (empty list).
*/
void cleanup_items(Item *item)
{
    DBUG_ENTER("cleanup_items");
    for (; item ; item=item->next)
        item->cleanup();
    DBUG_VOID_RETURN;
}

#ifndef EMBEDDED_LIBRARY

/**
Read one command from connection and execute it (query or simple command).
This function is called in loop from thread function.

For profiling to work, it must never be called recursively.

@retval
0  success
@retval
1  request of thread shutdown (see dispatch_command() description)
*/

bool do_command(THD *thd)
{
    bool return_value;
    char *packet= 0;
    ulong packet_length;
    NET *net= &thd->net;
    enum enum_server_command command;

    DBUG_ENTER("do_command");

    /*
    indicator of uninitialized lex => normal flow of errors handling
    (see my_message_sql)
    */
    thd->lex->current_select= 0;

    /*
    This thread will do a blocking read from the client which
    will be interrupted when the next command is received from
    the client, the connection is closed or "net_wait_timeout"
    number of seconds has passed.
    */
    my_net_set_read_timeout(net, thd->variables.net_wait_timeout);

    /*
    XXX: this code is here only to clear possible errors of init_connect.
    Consider moving to init_connect() instead.
    */
    thd->clear_error();    // Clear error message
    thd->get_stmt_da()->reset_diagnostics_area();

    net_new_transaction(net);

    /*
    Synchronization point for testing of KILL_CONNECTION.
    This sync point can wait here, to simulate slow code execution
    between the last test of thd->killed and blocking in read().

    The goal of this test is to verify that a connection does not
    hang, if it is killed at this point of execution.
    (Bug#37780 - main.kill fails randomly)

    Note that the sync point wait itself will be terminated by a
    kill. In this case it consumes a condition broadcast, but does
    not change anything else. The consumed broadcast should not
    matter here, because the read/recv() below doesn't use it.
    */
    DEBUG_SYNC(thd, "before_do_command_net_read");

    /*
    Because of networking layer callbacks in place,
    this call will maintain the following instrumentation:
    - IDLE events
    - SOCKET events
    - STATEMENT events
    - STAGE events
    when reading a new network packet.
    In particular, a new instrumented statement is started.
    See init_net_server_extension()
    */
    thd->m_server_idle= true;
    packet_length= my_net_read(net);
    thd->m_server_idle= false;

    if (packet_length == packet_error)
    {
        DBUG_PRINT("info",("Got error %d reading command from socket %s",
            net->error,
            vio_description(net->vio)));

        /* Instrument this broken statement as "statement/com/error" */
        thd->m_statement_psi= MYSQL_REFINE_STATEMENT(thd->m_statement_psi,
            com_statement_info[COM_END].m_key);

        /* Check if we can continue without closing the connection */

        /* The error must be set. */
        DBUG_ASSERT(thd->is_error());
        thd->protocol->end_statement();

        /* Mark the statement completed. */
        MYSQL_END_STATEMENT(thd->m_statement_psi, thd->get_stmt_da());
        thd->m_statement_psi= NULL;

        if (net->error != 3)
        {
            return_value= TRUE;                       // We have to close it.
            goto out;
        }

        net->error= 0;
        return_value= FALSE;
        goto out;
    }

    packet= (char*) net->read_pos;
    /*
    'packet_length' contains length of data, as it was stored in packet
    header. In case of malformed header, my_net_read returns zero.
    If packet_length is not zero, my_net_read ensures that the returned
    number of bytes was actually read from network.
    There is also an extra safety measure in my_net_read:
    it sets packet[packet_length]= 0, but only for non-zero packets.
    */
    if (packet_length == 0)                       /* safety */
    {
        /* Initialize with COM_SLEEP packet */
        packet[0]= (uchar) COM_SLEEP;
        packet_length= 1;
    }
    /* Do not rely on my_net_read, extra safety against programming errors. */
    packet[packet_length]= '\0';                  /* safety */

    command= (enum enum_server_command) (uchar) packet[0];

    if (command >= COM_END)
        command= COM_END;    // Wrong command

    DBUG_PRINT("info",("Command on %s = %d (%s)",
        vio_description(net->vio), command,
        command_name[command].str));

    /* Restore read timeout value */
    my_net_set_read_timeout(net, thd->variables.net_read_timeout);

    DBUG_ASSERT(packet_length);

    return_value= dispatch_command(command, thd, packet+1, (uint) (packet_length-1));

out:
    /* The statement instrumentation must be closed in all cases. */
    DBUG_ASSERT(thd->m_statement_psi == NULL);
    DBUG_RETURN(return_value);
}
#endif  /* EMBEDDED_LIBRARY */

//inception start
//
int mysql_get_remote_backup_dbname(
    char* host,
    uint port,
    char* dbname,
    char* new_dbname
)
{
    char* dbname_p;

    DBUG_ENTER("mysql_get_remote_backup_dbname");

    if (strlen(host) + 6 + strlen(dbname) + 2 > NAME_CHAR_LEN)
    {
        my_error(ER_TOO_LONG_BAKDB_NAME, MYF(0), host, port, dbname);
        DBUG_RETURN(true);
    }

    sprintf(new_dbname, "%s_%d_%s", host, port, dbname);

    dbname_p = new_dbname;
    while (*dbname_p)
    {
        if (*dbname_p == '.' || *dbname_p == '-')
        {
            *dbname_p = '_';
        }

        dbname_p++;
    }

    DBUG_RETURN(false);
}

int
mysql_statement_is_backup(
    sql_cache_node_t* sql_cache_node
)
{
    if (
        sql_cache_node->optype == SQLCOM_INSERT ||
        sql_cache_node->optype == SQLCOM_DELETE ||
        sql_cache_node->optype == SQLCOM_INSERT_SELECT ||
        sql_cache_node->optype == SQLCOM_UPDATE ||
        sql_cache_node->optype == SQLCOM_CREATE_TABLE ||
        sql_cache_node->optype == SQLCOM_DROP_TABLE ||
        sql_cache_node->optype == SQLCOM_ALTER_TABLE)
    {
        return TRUE;
    }

    return FALSE;
}

int mysql_is_remote_show(THD* thd)
{
    if (((thd->lex->sql_command == SQLCOM_INCEPTION && 
        thd->lex->inception_cmd_type == INCEPTION_COMMAND_REMOTE_SHOW)))
        return true;

    return false;
}

enum enum_inception_optype inception_get_type(THD* thd)
{
    return thd->thd_sinfo->optype;
}

void mysql_compute_sql_sha1(THD* thd, sql_cache_node_t* sql_cache_node)
{
    str_t       sqlinfo_space;
    str_t*      sqlinfo;
    char        port[10];

    //只有使用OSC的时候，才会返回这个HASH值
    if (!sql_cache_node->use_osc)
        return;

    sqlinfo = str_init(&sqlinfo_space);
    sqlinfo = str_append(sqlinfo, sql_cache_node->dbname);
    sqlinfo = str_append(sqlinfo, thd->thd_sinfo->password);
    sqlinfo = str_append(sqlinfo, thd->thd_sinfo->host);
    sqlinfo = str_append(sqlinfo, thd->thd_sinfo->user);

    sprintf(port, "%d", thd->thd_sinfo->port);
    sqlinfo = str_append(sqlinfo, port);
    //add the seqno, to solve execute same sql in different database
    sprintf(port, "%d", sql_cache_node->seqno);
    sqlinfo = str_append(sqlinfo, port);

    sqlinfo = str_append_with_length(sqlinfo, thd->query(), thd->query_length());

    char m_hashed_password_buffer[CRYPT_MAX_PASSWORD_SIZE + 1];
    String str(str_get(sqlinfo), system_charset_info);
    calculate_password(&str, m_hashed_password_buffer);
    strcpy(sql_cache_node->sqlsha1, m_hashed_password_buffer);
}

int mysql_cache_one_sql(THD* thd)
{
    int               errmsg_len;
    sql_cache_node_t* sql_cache_node;

    DBUG_ENTER("mysql_cache_one_sql");

    if (!thd->have_begin)
    {
        my_error(ER_START_AS_BEGIN, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    sql_cache_node = (sql_cache_node_t*)my_malloc(sizeof(sql_cache_node_t), MY_ZEROFILL);
    if (sql_cache_node == NULL)
    {
        my_error(ER_OUTOFMEMORY, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    sql_cache_node->stagereport = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(sql_cache_node->stagereport);

    String sql_with_charset(thd->query(), thd->query_length(), thd->query_charset());
    thd->convert_string(&sql_with_charset, sql_with_charset.charset(), system_charset_info);
    errmsg_len = sql_with_charset.length();
    //hide internal tag 'inception_magic_commit'
    if (thd->parse_error)
        errmsg_len = truncate_inception_commit(sql_with_charset.ptr(), errmsg_len);

    if (mysql_is_remote_show(thd))
        sql_cache_node->sql_statement = (char*)my_malloc(sql_with_charset.length() +
            str_get_len(thd->show_result) + 10, MY_ZEROFILL);
    else
        sql_cache_node->sql_statement = (char*)my_malloc(sql_with_charset.length() + 10, 
            MY_ZEROFILL);

    strncpy(sql_cache_node->sql_statement, sql_with_charset.ptr(), errmsg_len);
    if (mysql_is_remote_show(thd) && str_get_len(thd->show_result) > 0)
    {
        strcat(sql_cache_node->sql_statement, ":\n");
        strcat(sql_cache_node->sql_statement, str_get(thd->show_result));
    }

    sql_cache_node->use_osc = thd->use_osc;
    sql_cache_node->optype = thd->lex->sql_command;
    sql_cache_node->seqno = thd->sql_cache->seqno_cache++;
    mysql_compute_sql_sha1(thd, sql_cache_node);
    sql_cache_node->affected_rows = thd->affected_rows;
    sql_cache_node->ignore = thd->lex->ignore;
    thd->affected_rows = 0;
    sprintf(sql_cache_node->execute_time, "0");
    if (thd->lex->query_tables != NULL)
    {
        strcpy(sql_cache_node->dbname, thd->lex->query_tables->db);
        strcpy(sql_cache_node->tablename, thd->lex->query_tables->table_name);
    }

    if (mysql_statement_is_backup(sql_cache_node))
        mysql_get_remote_backup_dbname(thd->thd_sinfo->host, thd->thd_sinfo->port,
                sql_cache_node->dbname, sql_cache_node->backup_dbname);
    else
        sprintf(sql_cache_node->backup_dbname, "None");

    sql_cache_node->errlevel = thd->err_level > INCEPTION_PARSE ? INCEPTION_PARSE : thd->err_level;
    if (sql_cache_node->errlevel == INCEPTION_PARSE)
        thd->thd_sinfo->ignore_warnings = 0;

    sql_cache_node->rt_lst = thd->rt_lst;
    thd->rt_lst = NULL;

    thd->use_osc = FALSE;

    thd->err_level = INCEPTION_NOERR;

    if (thd->errmsg != NULL)
    {
        sql_cache_node->errrno = 0;
        sql_cache_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
        sql_cache_node->err_stage = 1;//check
    }

    if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE)
    {
        sql_cache_node->ddl_rollback = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
        str_init(sql_cache_node->ddl_rollback);
        str_append(sql_cache_node->ddl_rollback, str_get(&thd->ddl_rollback));
    }

    sql_cache_node->stage = 1;//checked
    LIST_ADD_LAST(link, thd->sql_cache->field_lst, sql_cache_node);

    DBUG_RETURN(FALSE);
}

int mysql_send_query_print_results(THD* thd)
{
    query_print_cache_node_t*  sql_cache_node;
    Protocol *    protocol= thd->protocol;
    List<Item>    field_list;
    int      id = 1;
    int errlevel=0;

    DBUG_ENTER("mysql_send_query_print_results");

    field_list.push_back(new Item_return_int("ID", 20, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("statement", FN_REFLEN));
    field_list.push_back(new Item_return_int("errlevel", 20, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("query_tree", FN_REFLEN));
    field_list.push_back(new Item_empty_string("errmsg", FN_REFLEN));

    if (protocol->send_result_set_metadata(&field_list,
        Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    {
        DBUG_RETURN(true);
    }

    if (thd->query_print_cache) {
        sql_cache_node = LIST_GET_FIRST(thd->query_print_cache->field_lst);
        while (sql_cache_node != NULL)
        {
            protocol->prepare_for_resend();

            protocol->store(id++);

            protocol->store(str_get(sql_cache_node->sql_statements), thd->charset());
            if (sql_cache_node->errmsg)
            {
                protocol->store(sql_cache_node->errlevel);
                protocol->store("None", thd->charset());
                protocol->store(str_get(sql_cache_node->errmsg), thd->charset());
            }
            else
            {
                protocol->store(sql_cache_node->errlevel);
                protocol->store(str_get(sql_cache_node->query_tree), thd->charset());
                protocol->store("None", thd->charset());
            }

            if (protocol->write())
                break;

            sql_cache_node = LIST_GET_NEXT(link, sql_cache_node);
        }
    }

    // if (thd->is_error() || thd->parse_error) {
    if (thd->errmsg)
    {
        protocol->prepare_for_resend();

        protocol->store(id++);
        protocol->store("None", thd->charset());
        protocol->store(errlevel);
        protocol->store(str_get(thd->errmsg), system_charset_info);
        protocol->store("Global environment", system_charset_info);

        protocol->write();
    }

    if (thd->query_print_cache || thd->errmsg) 
    {
        thd->clear_error();
        my_eof(thd);
    }

    DBUG_RETURN(false);
}

int mysql_send_split_results(THD* thd)
{
    split_cache_node_t*  sql_cache_node;
    Protocol *    protocol= thd->protocol;
    List<Item>    field_list;
    int      id = 1;

    DBUG_ENTER("mysql_send_split_results");

    field_list.push_back(new Item_return_int("ID", 20, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("sql_statement", FN_REFLEN));
    field_list.push_back(new Item_return_int("ddlflag", 20, MYSQL_TYPE_LONG));

    if (protocol->send_result_set_metadata(&field_list,
        Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    {
        DBUG_RETURN(true);
    }

    if (thd->errmsg) {
        protocol->prepare_for_resend();

        protocol->store(0);
        protocol->store(str_get(thd->errmsg), thd->charset());
        protocol->store(0);

        protocol->write();
        thd->clear_error();
        my_eof(thd);
        DBUG_RETURN(false);
    }

    if (thd->split_cache) {
        sql_cache_node = LIST_GET_FIRST(thd->split_cache->field_lst);
        while (sql_cache_node != NULL)
        {
            protocol->prepare_for_resend();

            protocol->store(id++);

            protocol->store(str_get(&sql_cache_node->sql_statements), thd->charset());
            protocol->store(sql_cache_node->ddlflag);

            if (protocol->write())
                break;

            sql_cache_node = LIST_GET_NEXT(link, sql_cache_node);
        }

        thd->clear_error();
        my_eof(thd);
    }

    DBUG_RETURN(false);
}

int mysql_not_need_data_source(THD* thd)
{
    DBUG_ENTER("mysql_not_need_data_source");
    
    if (thd->lex->sql_command == SQLCOM_INCEPTION &&
        (thd->lex->inception_cmd_type == INCEPTION_COMMAND_LOCAL_SHOW ||
        thd->lex->inception_cmd_type == INCEPTION_COMMAND_LOCAL_SHOWALL ||
        thd->lex->inception_cmd_type == INCEPTION_COMMAND_OSC_SHOW ||
        thd->lex->inception_cmd_type == INCEPTION_COMMAND_OSC_PROCESSLIST ||
        thd->lex->inception_cmd_type == INCEPTION_COMMAND_PROCESSLIST ||
        thd->lex->inception_cmd_type == INCEPTION_COMMAND_OSC_ABORT ||
        thd->lex->inception_cmd_type == INCEPTION_COMMAND_LOCAL_SET))
        DBUG_RETURN(TRUE);
    
    DBUG_RETURN(FALSE);
}

int mysql_send_all_results(THD* thd)
{
    sql_cache_node_t*  sql_cache_node;
    Protocol *    protocol= thd->protocol;
    List<Item>    field_list;
    int      id = 1;
    char            tmp_buf[256];

    DBUG_ENTER("mysql_send_all_results");
    thd->thread_state = INCEPTION_STATE_SEND;

    if (mysql_not_need_data_source(thd))
        DBUG_RETURN(false);

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        mysql_send_split_results(thd);
        DBUG_RETURN(false);
    }

    if (inception_get_type(thd) == INCEPTION_TYPE_PRINT) {
        mysql_send_query_print_results(thd);
        DBUG_RETURN(false);
    }

    field_list.push_back(new Item_return_int("ID", 20, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("stage", NAME_CHAR_LEN));
    field_list.push_back(new Item_return_int("errlevel", 20, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("stagestatus",NAME_CHAR_LEN));
    field_list.push_back(new Item_empty_string("errormessage",FN_REFLEN));
    field_list.push_back(new Item_empty_string("SQL", FN_REFLEN));
    field_list.push_back(new Item_return_int("Affected_rows", 20, MYSQL_TYPE_LONGLONG));
    field_list.push_back(new Item_empty_string("sequence", FN_REFLEN));
    field_list.push_back(new Item_empty_string("backup_dbname", FN_REFLEN));
    field_list.push_back(new Item_empty_string("execute_time", FN_REFLEN));
    field_list.push_back(new Item_empty_string("sqlsha1", FN_REFLEN));

    if (protocol->send_result_set_metadata(&field_list,
        Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    {
        DBUG_RETURN(true);
    }

    if (thd->sql_cache) {
        sql_cache_node = LIST_GET_FIRST(thd->sql_cache->field_lst);
        while (sql_cache_node != NULL)
        {
            protocol->prepare_for_resend();

            protocol->store(id++);
            if (sql_cache_node->stage == 1)
                protocol->store("CHECKED", thd->charset());
            else if (sql_cache_node->stage == 2)
            {   
                if (sql_cache_node->optype == SQLCOM_SET_OPTION ||
                    sql_cache_node->optype == SQLCOM_CHANGE_DB)
                    protocol->store("RERUN", thd->charset());
                else 
                    protocol->store("EXECUTED", thd->charset());
            }
            else
                protocol->store("NONE", thd->charset());

            protocol->store(sql_cache_node->errlevel);
            if (str_get_len(sql_cache_node->stagereport) > 0)
                protocol->store(str_get(str_truncate(sql_cache_node->stagereport, 1)),
                        thd->charset());
            else
                protocol->store("Audit completed", thd->charset());

            if (sql_cache_node->errmsg == NULL)
                protocol->store("None", thd->charset());
            else
                protocol->store(str_get(str_truncate(sql_cache_node->errmsg, 1)), thd->charset());

            protocol->store(sql_cache_node->sql_statement, system_charset_info);

            protocol->store(sql_cache_node->affected_rows);

            sprintf(tmp_buf, "\'%ld_%d_%d\'", sql_cache_node->exec_time,
                    (int)sql_cache_node->thread_id, (int)sql_cache_node->seqno);
            protocol->store(tmp_buf, system_charset_info);

            protocol->store(sql_cache_node->backup_dbname, system_charset_info);
            protocol->store(sql_cache_node->execute_time, system_charset_info);
            protocol->store(sql_cache_node->sqlsha1, system_charset_info);

            if (protocol->write())
                break;

            sql_cache_node = LIST_GET_NEXT(link, sql_cache_node);
        }
    }

    if (thd->is_error() && !thd->parse_error) {
        my_ulonglong   affected_rows = 0;
        protocol->prepare_for_resend();

        protocol->store(id++);
        protocol->store("NONE", thd->charset());

        protocol->store(INCEPTION_PARSE);
        protocol->store("None", thd->charset());

        protocol->store(thd->get_stmt_da()->message(), thd->charset());

        protocol->store("Global environment", system_charset_info);

        protocol->store(affected_rows);
        protocol->store("None", system_charset_info);
        protocol->store("None", system_charset_info);
        protocol->store("0", system_charset_info);//execute time
        protocol->store("None", system_charset_info);

        protocol->write();
    }

    if (thd->sql_cache || (thd->is_error() && !thd->parse_error))
    {
        thd->clear_error();
        my_eof(thd);
    }

    DBUG_RETURN(false);
}


int mysql_clear_execute_env(THD* thd)
{
    DBUG_ENTER("mysql_clear_execute_env");
    if (thd->parse_error || thd->is_error())
        mysql_send_all_results(thd);

    mysql_free_all_table_definition(thd);
    mysql_deinit_sql_cache(thd);
    thd->have_begin = FALSE;
    thd->thd_sinfo->host[0]='\0';
    thd->close_all_connections();
    DBUG_RETURN(false);
}


/**
Perform one connection-level (COM_XXXX) command.

@param command         type of command to perform
@param thd             connection handle
@param packet          data for the command, packet is always null-terminated
@param packet_length   length of packet + 1 (to show that data is
null-terminated) except for COM_SLEEP, where it
can be zero.

@todo
set thd->lex->sql_command to SQLCOM_END here.
@todo
The following has to be changed to an 8 byte integer

@retval
0   ok
@retval
1   request of thread shutdown, i. e. if command is
COM_QUIT/COM_SHUTDOWN
*/

bool dispatch_command(enum enum_server_command command, THD *thd,
    char* packet, uint packet_length)
{
    bool error= 0;
    DBUG_ENTER("dispatch_command");
    DBUG_PRINT("info",("packet: '%*.s'; command: %d", packet_length, packet, command));

    /* SHOW PROFILE instrumentation, begin */
#if defined(ENABLED_PROFILING)
    thd->profiling.start_new_query();
#endif

    /* DTRACE instrumentation, begin */
    MYSQL_COMMAND_START(thd->thread_id, command, 
        &thd->security_ctx->priv_user[0], (char *) thd->security_ctx->host_or_ip);

    /* Performance Schema Interface instrumentation, begin */
    thd->m_statement_psi= MYSQL_REFINE_STATEMENT(thd->m_statement_psi, 
        com_statement_info[command].m_key);

    thd->set_command(command);
    thd->client_capabilities |= CLIENT_MULTI_STATEMENTS;

    /*
    Commands which always take a long time are logged into
    the slow log only if opt_log_slow_admin_statements is set.
    */
    thd->enable_slow_log= TRUE;
    thd->lex->sql_command= SQLCOM_END; /* to avoid confusing VIEW detectors */
    thd->set_time();
    thd->set_query_id(next_query_id());
    inc_thread_running();

    switch (command) {
    case COM_QUERY:
        {
            if (alloc_query(thd, packet, packet_length))
                break;

            char *packet_end= thd->query() + thd->query_length();

            Parser_state parser_state;
            if (parser_state.init(thd, thd->query(), thd->query_length()))
                break;

            if (!opt_log_raw)
                general_log_write(thd, COM_QUERY, thd->query(), thd->query_length());

            mysql_parse(thd, thd->query_length(), &parser_state);

            while (!thd->killed && (parser_state.m_lip.found_semicolon != NULL) && ! thd->is_error() && !thd->parse_error)
            {
                char *beginning_of_next_stmt= (char*) parser_state.m_lip.found_semicolon;

                /* Finalize server status flags after executing a statement. */
                thd->update_server_status();
                ulong length= (ulong)(packet_end - beginning_of_next_stmt);
                while (length > 0 && my_isspace(thd->charset(), *beginning_of_next_stmt))
                {
                    beginning_of_next_stmt++;
                    length--;
                }

                thd->set_query_and_id(beginning_of_next_stmt, length, thd->charset(), next_query_id());
                thd->set_time(); /* Reset the query start time. */
                parser_state.reset(beginning_of_next_stmt, length);
                mysql_parse(thd, length, &parser_state);
            }

            if (thd->is_error() || thd->parse_error)
                mysql_clear_execute_env(thd);

            break;
        }

    case COM_QUIT:
        thd->get_stmt_da()->disable_status();              // Don't send anything back
        error=TRUE;                 // End server
        break;

    default:
        {
            my_error(ER_NOT_SUPPORTED_YET, MYF(0));
        }
    }

    /* Finalize server status flags after executing a command. */
    thd->update_server_status();
    if (thd->killed)
        thd->send_kill_message();
    thd->protocol->end_statement();
    query_cache_end_of_result(thd);

    thd->reset_query();
    thd->set_command(COM_SLEEP);

    /* Performance Schema Interface instrumentation, end */
    thd->m_statement_psi= NULL;

    dec_thread_running();
    thd->packet.shrink(thd->variables.net_buffer_length); // Reclaim some memory
    free_root(thd->mem_root,MYF(MY_KEEP_PREALLOC));

    /* DTRACE instrumentation, end */
    if (MYSQL_QUERY_DONE_ENABLED() || MYSQL_COMMAND_DONE_ENABLED())
    {
        int res __attribute__((unused));
        res= (int) thd->is_error();
        if (command == COM_QUERY)
        {
            MYSQL_QUERY_DONE(res);
        }
        MYSQL_COMMAND_DONE(res);
    }

    DBUG_RETURN(error);
}

uint sql_command_flags[SQLCOM_END+1];
uint server_command_flags[COM_END+1];

void init_update_queries(void)
{
    /* Initialize the server command flags array. */
    memset(server_command_flags, 0, sizeof(server_command_flags));

    server_command_flags[COM_STATISTICS]= CF_SKIP_QUESTIONS;
    server_command_flags[COM_PING]=       CF_SKIP_QUESTIONS;
    server_command_flags[COM_STMT_PREPARE]= CF_SKIP_QUESTIONS;
    server_command_flags[COM_STMT_CLOSE]=   CF_SKIP_QUESTIONS;
    server_command_flags[COM_STMT_RESET]=   CF_SKIP_QUESTIONS;

    /* Initialize the sql command flags array. */
    memset(sql_command_flags, 0, sizeof(sql_command_flags));

    /*
    In general, DDL statements do not generate row events and do not go
    through a cache before being written to the binary log. However, the
    CREATE TABLE...SELECT is an exception because it may generate row
    events. For that reason,  the SQLCOM_CREATE_TABLE  which represents
    a CREATE TABLE, including the CREATE TABLE...SELECT, has the
    CF_CAN_GENERATE_ROW_EVENTS flag. The distinction between a regular
    CREATE TABLE and the CREATE TABLE...SELECT is made in other parts of
    the code, in particular in the Query_log_event's constructor.
    */
    sql_command_flags[SQLCOM_CREATE_TABLE]=   CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_AUTO_COMMIT_TRANS |
        CF_CAN_GENERATE_ROW_EVENTS;
    sql_command_flags[SQLCOM_CREATE_INDEX]=   CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ALTER_TABLE]=    CF_CHANGES_DATA | CF_WRITE_LOGS_COMMAND |
        CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_TRUNCATE]=       CF_CHANGES_DATA | CF_WRITE_LOGS_COMMAND |
        CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_TABLE]=     CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_LOAD]=           CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS;
    sql_command_flags[SQLCOM_CREATE_DB]=      CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_DB]=        CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ALTER_DB_UPGRADE]= CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ALTER_DB]=       CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_RENAME_TABLE]=   CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_INDEX]=     CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_CREATE_VIEW]=    CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_VIEW]=      CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_CREATE_TRIGGER]= CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_TRIGGER]=   CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_CREATE_EVENT]=   CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ALTER_EVENT]=    CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_EVENT]=     CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;

    sql_command_flags[SQLCOM_UPDATE]=     CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    sql_command_flags[SQLCOM_UPDATE_MULTI]=   CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    // This is INSERT VALUES(...), can be VALUES(stored_func()) so we trace it
    sql_command_flags[SQLCOM_INSERT]=     CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    sql_command_flags[SQLCOM_INSERT_SELECT]=  CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    sql_command_flags[SQLCOM_DELETE]=         CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    sql_command_flags[SQLCOM_DELETE_MULTI]=   CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    sql_command_flags[SQLCOM_REPLACE]=        CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    sql_command_flags[SQLCOM_REPLACE_SELECT]= CF_CHANGES_DATA | CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    sql_command_flags[SQLCOM_SELECT]=         CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE |
        CF_CAN_BE_EXPLAINED;
    // (1) so that subquery is traced when doing "SET @var = (subquery)"
    /*
    @todo SQLCOM_SET_OPTION should have CF_CAN_GENERATE_ROW_EVENTS
    set, because it may invoke a stored function that generates row
    events. /Sven
    */
    sql_command_flags[SQLCOM_SET_OPTION]=     CF_REEXECUTION_FRAGILE |
        CF_AUTO_COMMIT_TRANS |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE; // (1)
    // (1) so that subquery is traced when doing "DO @var := (subquery)"
    sql_command_flags[SQLCOM_DO]=             CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE; // (1)

    sql_command_flags[SQLCOM_SHOW_STATUS_PROC]= CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_STATUS]=      CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_DATABASES]=   CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_TRIGGERS]=    CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_EVENTS]=      CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_OPEN_TABLES]= CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_PLUGINS]=     CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_FIELDS]=      CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_KEYS]=        CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_VARIABLES]=   CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_CHARSETS]=    CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_COLLATIONS]=  CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_BINLOGS]=     CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_SLAVE_HOSTS]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_BINLOG_EVENTS]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_STORAGE_ENGINES]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_PRIVILEGES]=  CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_WARNS]=       CF_STATUS_COMMAND | CF_DIAGNOSTIC_STMT;
    sql_command_flags[SQLCOM_SHOW_ERRORS]=      CF_STATUS_COMMAND | CF_DIAGNOSTIC_STMT;
    sql_command_flags[SQLCOM_SHOW_ENGINE_STATUS]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_ENGINE_MUTEX]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_ENGINE_LOGS]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_PROCESSLIST]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_GRANTS]=      CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_CREATE_DB]=   CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_CREATE]=  CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_MASTER_STAT]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_SLAVE_STAT]=  CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_CREATE_PROC]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_CREATE_FUNC]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_CREATE_TRIGGER]=  CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_STATUS_FUNC]= CF_STATUS_COMMAND | CF_REEXECUTION_FRAGILE;
    sql_command_flags[SQLCOM_SHOW_PROC_CODE]=   CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_FUNC_CODE]=   CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_CREATE_EVENT]= CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_PROFILES]=    CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_SHOW_PROFILE]=     CF_STATUS_COMMAND;
    sql_command_flags[SQLCOM_BINLOG_BASE64_EVENT]= CF_STATUS_COMMAND |
        CF_CAN_GENERATE_ROW_EVENTS;

    sql_command_flags[SQLCOM_SHOW_TABLES]=       (CF_STATUS_COMMAND |
        CF_SHOW_TABLE_COMMAND |
        CF_REEXECUTION_FRAGILE);
    sql_command_flags[SQLCOM_SHOW_TABLE_STATUS]= (CF_STATUS_COMMAND |
        CF_SHOW_TABLE_COMMAND |
        CF_REEXECUTION_FRAGILE);

    sql_command_flags[SQLCOM_CREATE_USER]=       CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_RENAME_USER]=       CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_DROP_USER]=         CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_ALTER_USER]=        CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_GRANT]=             CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_REVOKE]=            CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_REVOKE_ALL]=        CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_OPTIMIZE]=          CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_CREATE_FUNCTION]=   CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_CREATE_PROCEDURE]=  CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_CREATE_SPFUNCTION]= CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_PROCEDURE]=    CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_FUNCTION]=     CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ALTER_PROCEDURE]=   CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ALTER_FUNCTION]=    CF_CHANGES_DATA | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_INSTALL_PLUGIN]=    CF_CHANGES_DATA;
    sql_command_flags[SQLCOM_UNINSTALL_PLUGIN]=  CF_CHANGES_DATA;

    /* Does not change the contents of the diagnostics area. */
    sql_command_flags[SQLCOM_GET_DIAGNOSTICS]= CF_DIAGNOSTIC_STMT;

    /*
    (1): without it, in "CALL some_proc((subq))", subquery would not be
    traced.
    */
    sql_command_flags[SQLCOM_CALL]=      CF_REEXECUTION_FRAGILE |
        CF_CAN_GENERATE_ROW_EVENTS |
        CF_OPTIMIZER_TRACE; // (1)
    sql_command_flags[SQLCOM_EXECUTE]=   CF_CAN_GENERATE_ROW_EVENTS;

    /*
    The following admin table operations are allowed
    on log tables.
    */
    sql_command_flags[SQLCOM_REPAIR]=    CF_WRITE_LOGS_COMMAND | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_OPTIMIZE]|= CF_WRITE_LOGS_COMMAND | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ANALYZE]=   CF_WRITE_LOGS_COMMAND | CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_CHECK]=     CF_WRITE_LOGS_COMMAND | CF_AUTO_COMMIT_TRANS;

    sql_command_flags[SQLCOM_CREATE_USER]|=       CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_USER]|=         CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_RENAME_USER]|=       CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ALTER_USER]|=        CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_REVOKE]|=            CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_REVOKE_ALL]|=        CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_GRANT]|=             CF_AUTO_COMMIT_TRANS;

    sql_command_flags[SQLCOM_ASSIGN_TO_KEYCACHE]= CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_PRELOAD_KEYS]=       CF_AUTO_COMMIT_TRANS;

    sql_command_flags[SQLCOM_FLUSH]=              CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_RESET]=              CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_CREATE_SERVER]=      CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_ALTER_SERVER]=       CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_DROP_SERVER]=        CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_CHANGE_MASTER]=      CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_SLAVE_START]=        CF_AUTO_COMMIT_TRANS;
    sql_command_flags[SQLCOM_SLAVE_STOP]=         CF_AUTO_COMMIT_TRANS;

    /*
    The following statements can deal with temporary tables,
    so temporary tables should be pre-opened for those statements to
    simplify privilege checking.

    There are other statements that deal with temporary tables and open
    them, but which are not listed here. The thing is that the order of
    pre-opening temporary tables for those statements is somewhat custom.
    */
    sql_command_flags[SQLCOM_CREATE_TABLE]|=    CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_DROP_TABLE]|=      CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_CREATE_INDEX]|=    CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_ALTER_TABLE]|=     CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_TRUNCATE]|=        CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_LOAD]|=            CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_DROP_INDEX]|=      CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_UPDATE]|=          CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_UPDATE_MULTI]|=    CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_INSERT_SELECT]|=   CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_DELETE]|=          CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_DELETE_MULTI]|=    CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_REPLACE_SELECT]|=  CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_SELECT]|=          CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_SET_OPTION]|=      CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_DO]|=              CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_CALL]|=            CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_CHECKSUM]|=        CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_ANALYZE]|=         CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_CHECK]|=           CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_OPTIMIZE]|=        CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_REPAIR]|=          CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_PRELOAD_KEYS]|=    CF_PREOPEN_TMP_TABLES;
    sql_command_flags[SQLCOM_ASSIGN_TO_KEYCACHE]|= CF_PREOPEN_TMP_TABLES;

    /*
    DDL statements that should start with closing opened handlers.

    We use this flag only for statements for which open HANDLERs
    have to be closed before emporary tables are pre-opened.
    */
    sql_command_flags[SQLCOM_CREATE_TABLE]|=    CF_HA_CLOSE;
    sql_command_flags[SQLCOM_DROP_TABLE]|=      CF_HA_CLOSE;
    sql_command_flags[SQLCOM_ALTER_TABLE]|=     CF_HA_CLOSE;
    sql_command_flags[SQLCOM_TRUNCATE]|=        CF_HA_CLOSE;
    sql_command_flags[SQLCOM_REPAIR]|=          CF_HA_CLOSE;
    sql_command_flags[SQLCOM_OPTIMIZE]|=        CF_HA_CLOSE;
    sql_command_flags[SQLCOM_ANALYZE]|=         CF_HA_CLOSE;
    sql_command_flags[SQLCOM_CHECK]|=           CF_HA_CLOSE;
    sql_command_flags[SQLCOM_CREATE_INDEX]|=    CF_HA_CLOSE;
    sql_command_flags[SQLCOM_DROP_INDEX]|=      CF_HA_CLOSE;
    sql_command_flags[SQLCOM_PRELOAD_KEYS]|=    CF_HA_CLOSE;
    sql_command_flags[SQLCOM_ASSIGN_TO_KEYCACHE]|=  CF_HA_CLOSE;

    /*
    Mark statements that always are disallowed in read-only
    transactions. Note that according to the SQL standard,
    even temporary table DDL should be disallowed.
    */
    sql_command_flags[SQLCOM_CREATE_TABLE]|=     CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_TABLE]|=      CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_TABLE]|=       CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_RENAME_TABLE]|=     CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_INDEX]|=     CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_INDEX]|=       CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_DB]|=        CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_DB]|=          CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_DB_UPGRADE]|= CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_DB]|=         CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_VIEW]|=      CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_VIEW]|=        CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_TRIGGER]|=   CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_TRIGGER]|=     CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_EVENT]|=     CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_EVENT]|=      CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_EVENT]|=       CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_USER]|=      CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_RENAME_USER]|=      CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_USER]|=       CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_USER]|=        CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_SERVER]|=    CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_SERVER]|=     CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_SERVER]|=      CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_FUNCTION]|=  CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_PROCEDURE]|= CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_CREATE_SPFUNCTION]|=CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_PROCEDURE]|=   CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_DROP_FUNCTION]|=    CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_PROCEDURE]|=  CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_FUNCTION]|=   CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_TRUNCATE]|=         CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_ALTER_TABLESPACE]|= CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_REPAIR]|=           CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_OPTIMIZE]|=         CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_GRANT]|=            CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_REVOKE]|=           CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_REVOKE_ALL]|=       CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_INSTALL_PLUGIN]|=   CF_DISALLOW_IN_RO_TRANS;
    sql_command_flags[SQLCOM_UNINSTALL_PLUGIN]|= CF_DISALLOW_IN_RO_TRANS;
}

bool sqlcom_can_generate_row_events(const THD *thd)
{
    return (sql_command_flags[thd->lex->sql_command] &
        CF_CAN_GENERATE_ROW_EVENTS);
}


/**
Read query from packet and store in thd->query.
Used in COM_QUERY and COM_STMT_PREPARE.

Sets the following THD variables:
- query
- query_length

@retval
FALSE ok
@retval
TRUE  error;  In this case thd->fatal_error is set
*/

bool alloc_query(THD *thd, const char *packet, uint packet_length)
{
    char *query;
    /* Remove garbage at start and end of query */
    while (packet_length > 0 && my_isspace(thd->charset(), packet[0]))
    {
        packet++;
        packet_length--;
    }
    const char *pos= packet + packet_length;     // Point at end null
    while (packet_length > 0 &&
        (pos[-1] == ';' || my_isspace(thd->charset() ,pos[-1])))
    {
        pos--;
        packet_length--;
    }
    /* We must allocate some extra memory for query cache

    The query buffer layout is:
    buffer :==
    <statement>   The input statement(s)
    '\0'          Terminating null char  (1 byte)
    <length>      Length of following current database name (size_t)
    <db_name>     Name of current database
    <flags>       Flags struct
    */
    if (! (query= (char*) thd->memdup_w_gap(packet,
        packet_length,
        1 + sizeof(size_t) + thd->db_length +
        QUERY_CACHE_FLAGS_SIZE)))
        return TRUE;
    query[packet_length]= '\0';
    /*
    Space to hold the name of the current database is allocated.  We
    also store this length, in case current database is changed during
    execution.  We might need to reallocate the 'query' buffer
    */
    char *len_pos = (query + packet_length + 1);
    memcpy(len_pos, (char *) &thd->db_length, sizeof(size_t));

    thd->set_query(query, packet_length);
    thd->rewritten_query.free();                 // free here lest PS break

    /* Reclaim some memory */
    thd->packet.shrink(thd->variables.net_buffer_length);
    thd->convert_buffer.shrink(thd->variables.net_buffer_length);

    return FALSE;
}

/**
check for global access and give descriptive error message if it fails.

@param thd   Thread handler
@param want_access  Use should have any of these global rights

@warning
One gets access right if one has ANY of the rights in want_access.
This is useful as one in most cases only need one global right,
but in some case we want to check if the user has SUPER or
REPL_CLIENT_ACL rights.

@retval
0 ok
@retval
1 Access denied.  In this case an error is sent to the client
*/

/****************************************************************************
Check stack size; Send error if there isn't enough stack to continue
****************************************************************************/


#if STACK_DIRECTION < 0
#define used_stack(A,B) (long) (A - B)
#else
#define used_stack(A,B) (long) (B - A)
#endif

#ifndef DBUG_OFF
long max_stack_used;
#endif

/**
@note
Note: The 'buf' parameter is necessary, even if it is unused here.
- fix_fields functions has a "dummy" buffer large enough for the
corresponding exec. (Thus we only have to check in fix_fields.)
- Passing to check_stack_overrun() prevents the compiler from removing it.
*/
bool check_stack_overrun(THD *thd, long margin,
    uchar *buf __attribute__((unused)))
{
    long stack_used;
    DBUG_ASSERT(thd == current_thd);
    if ((stack_used=used_stack(thd->thread_stack,(char*) &stack_used)) >=
        (long) (my_thread_stack_size - margin))
    {
        /*
        Do not use stack for the message buffer to ensure correct
        behaviour in cases we have close to no stack left.
        */
        char* ebuff= new (std::nothrow) char[MYSQL_ERRMSG_SIZE];
        if (ebuff) {
            my_snprintf(ebuff, MYSQL_ERRMSG_SIZE, ER(ER_STACK_OVERRUN_NEED_MORE),
                stack_used, my_thread_stack_size, margin);
            my_message(ER_STACK_OVERRUN_NEED_MORE, ebuff, MYF(ME_FATALERROR));
            delete [] ebuff;
        }
        return 1;
    }
#ifndef DBUG_OFF
    max_stack_used= max(max_stack_used, stack_used);
#endif
    return 0;
}


#define MY_YACC_INIT 1000   // Start with big alloc
#define MY_YACC_MAX  32000   // Because of 'short'

bool my_yyoverflow(short **yyss, YYSTYPE **yyvs, ulong *yystacksize)
{
    Yacc_state *state= & current_thd->m_parser_state->m_yacc;
    ulong old_info=0;
    DBUG_ASSERT(state);
    if ((uint) *yystacksize >= MY_YACC_MAX)
        return 1;
    if (!state->yacc_yyvs)
        old_info= *yystacksize;
    *yystacksize= set_zone((*yystacksize)*2,MY_YACC_INIT,MY_YACC_MAX);
    if (!(state->yacc_yyvs= (uchar*)
        my_realloc(state->yacc_yyvs,
        *yystacksize*sizeof(**yyvs),
        MYF(MY_ALLOW_ZERO_PTR | MY_FREE_ON_ERROR))) ||
        !(state->yacc_yyss= (uchar*)
        my_realloc(state->yacc_yyss,
        *yystacksize*sizeof(**yyss),
        MYF(MY_ALLOW_ZERO_PTR | MY_FREE_ON_ERROR))))
        return 1;
    if (old_info)
    {
        /*
        Only copy the old stack on the first call to my_yyoverflow(),
        when replacing a static stack (YYINITDEPTH) by a dynamic stack.
        For subsequent calls, my_realloc already did preserve the old stack.
        */
        memcpy(state->yacc_yyss, *yyss, old_info*sizeof(**yyss));
        memcpy(state->yacc_yyvs, *yyvs, old_info*sizeof(**yyvs));
    }
    *yyss= (short*) state->yacc_yyss;
    *yyvs= (YYSTYPE*) state->yacc_yyvs;
    return 0;
}


/**
Reset the part of THD responsible for the state of command
processing.

This needs to be called before execution of every statement
(prepared or conventional).  It is not called by substatements of
routines.

@todo Remove mysql_reset_thd_for_next_command and only use the
member function.

@todo Call it after we use THD for queries, not before.
*/
void mysql_reset_thd_for_next_command(THD *thd)
{
    thd->reset_for_next_command();
}

void THD::reset_for_next_command()
{
    // TODO: Why on earth is this here?! We should probably fix this
    // function and move it to the proper file. /Matz
    THD *thd= this;
    DBUG_ENTER("mysql_reset_thd_for_next_command");
    DBUG_ASSERT(!thd->sp_runtime_ctx); /* not for substatements of routines */
    DBUG_ASSERT(! thd->in_sub_stmt);
    thd->free_list= 0;
    thd->select_number= 1;
    /*
    Those two lines below are theoretically unneeded as
    THD::cleanup_after_query() should take care of this already.
    */
    thd->auto_inc_intervals_in_cur_stmt_for_binlog.empty();
    thd->stmt_depends_on_first_successful_insert_id_in_prev_stmt= 0;

    thd->query_start_used= thd->query_start_usec_used= 0;
    thd->is_fatal_error= thd->time_zone_used= 0;
    /*
    Clear the status flag that are expected to be cleared at the
    beginning of each SQL statement.
    */
    thd->server_status&= ~SERVER_STATUS_CLEAR_SET;
    /*
    If in autocommit mode and not in a transaction, reset flag
    that identifies if a transaction has done some operations
    that cannot be safely rolled back.

    If the flag is set an warning message is printed out in
    ha_rollback_trans() saying that some tables couldn't be
    rolled back.
    */
    if (!thd->in_multi_stmt_transaction_mode())
    {
        thd->transaction.all.reset_unsafe_rollback_flags();
    }
    DBUG_ASSERT(thd->security_ctx== &thd->main_security_ctx);
    thd->thread_specific_used= FALSE;

    if (opt_bin_log)
    {
        reset_dynamic(&thd->user_var_events);
        thd->user_var_events_alloc= thd->mem_root;
    }
    thd->clear_error();
    thd->get_stmt_da()->reset_diagnostics_area();
    thd->get_stmt_da()->reset_for_next_command();
    thd->rand_used= 0;
    thd->m_sent_row_count= thd->m_examined_row_count= 0;

    thd->reset_current_stmt_binlog_format_row();
    thd->binlog_unsafe_warning_flags= 0;

    thd->m_trans_end_pos= 0;
    thd->m_trans_log_file= NULL;
    thd->commit_error= 0;
    thd->durability_property= HA_REGULAR_DURABILITY;
    thd->set_trans_pos(NULL, 0);

    DBUG_PRINT("debug",
        ("is_current_stmt_binlog_format_row(): %d",
        thd->is_current_stmt_binlog_format_row()));

    DBUG_VOID_RETURN;
}


/**
Resets the lex->current_select object.
@note It is assumed that lex->current_select != NULL

This function is a wrapper around select_lex->init_select() with an added
check for the special situation when using INTO OUTFILE and LOAD DATA.
*/

void
    mysql_init_select(LEX *lex)
{
    SELECT_LEX *select_lex= lex->current_select;
    select_lex->init_select();
    lex->wild= 0;
    if (select_lex == &lex->select_lex)
    {
        DBUG_ASSERT(lex->result == 0);
        lex->exchange= 0;
    }
}


/**
Used to allocate a new SELECT_LEX object on the current thd mem_root and
link it into the relevant lists.

This function is always followed by mysql_init_select.

@see mysql_init_select

@retval TRUE An error occurred
@retval FALSE The new SELECT_LEX was successfully allocated.
*/

bool
    mysql_new_select(LEX *lex, bool move_down)
{
    SELECT_LEX *select_lex;
    THD *thd= lex->thd;
    Name_resolution_context *outer_context= lex->current_context();
    DBUG_ENTER("mysql_new_select");

    if (!(select_lex= new (thd->mem_root) SELECT_LEX()))
        DBUG_RETURN(1);
    select_lex->select_number= ++thd->select_number;
    select_lex->parent_lex= lex; /* Used in init_query. */
    select_lex->init_query();
    select_lex->init_select();
    lex->nest_level++;
    if (lex->nest_level > (int) MAX_SELECT_NESTING)
    {
        my_error(ER_TOO_HIGH_LEVEL_OF_NESTING_FOR_SELECT, MYF(0));
        DBUG_RETURN(1);
    }
    select_lex->nest_level= lex->nest_level;
    if (move_down)
    {
        SELECT_LEX_UNIT *unit;
        lex->subqueries= TRUE;
        /* first select_lex of subselect or derived table */
        if (!(unit= new (thd->mem_root) SELECT_LEX_UNIT()))
            DBUG_RETURN(1);

        unit->init_query();
        unit->init_select();
        unit->thd= thd;
        unit->include_down(lex->current_select);
        unit->link_next= 0;
        unit->link_prev= 0;
        select_lex->include_down(unit);
        /*
        By default we assume that it is usual subselect and we have outer name
        resolution context, if no we will assign it to 0 later
        */
        if (select_lex->outer_select()->parsing_place == IN_ON)
            /*
            This subquery is part of an ON clause, so we need to link the
            name resolution context for this subquery with the ON context.

            @todo In which cases is this not the same as
            &select_lex->outer_select()->context?
            */
            select_lex->context.outer_context= outer_context;
        else
            select_lex->context.outer_context= &select_lex->outer_select()->context;
    }
    else
    {
        if (lex->current_select->order_list.first && !lex->current_select->braces)
        {
            my_error(ER_WRONG_USAGE, MYF(0), "UNION", "ORDER BY");
            DBUG_RETURN(1);
        }
        select_lex->include_neighbour(lex->current_select);
        SELECT_LEX_UNIT *unit= select_lex->master_unit();
        if (!unit->fake_select_lex && unit->add_fake_select_lex(lex->thd))
            DBUG_RETURN(1);
        select_lex->context.outer_context=
            unit->first_select()->context.outer_context;
    }

    select_lex->master_unit()->global_parameters= select_lex;
    select_lex->include_global((st_select_lex_node**)&lex->all_selects_list);
    lex->current_select= select_lex;
    /*
    in subquery is SELECT query and we allow resolution of names in SELECT
    list
    */
    select_lex->context.resolve_in_select_list= TRUE;
    DBUG_RETURN(0);
}

/**
Create a select to return the same output as 'SELECT @@var_name'.

Used for SHOW COUNT(*) [ WARNINGS | ERROR].

This will crash with a core dump if the variable doesn't exists.

@param var_name  Variable name
*/

void create_select_for_variable(const char *var_name)
{
    THD *thd;
    LEX *lex;
    LEX_STRING tmp, null_lex_string;
    Item *var;
    char buff[MAX_SYS_VAR_LENGTH*2+4+8], *end;
    DBUG_ENTER("create_select_for_variable");

    thd= current_thd;
    lex= thd->lex;
    mysql_init_select(lex);
    lex->sql_command= SQLCOM_SELECT;
    tmp.str= (char*) var_name;
    tmp.length=strlen(var_name);
    memset(&null_lex_string, 0, sizeof(null_lex_string));
    /*
    We set the name of Item to @@session.var_name because that then is used
    as the column name in the output.
    */
    if ((var= get_system_var(thd, OPT_SESSION, tmp, null_lex_string)))
    {
        end= strxmov(buff, "@@session.", var_name, NullS);
        var->item_name.copy(buff, end - buff);
        add_item_to_list(thd, var);
    }
    DBUG_VOID_RETURN;
}


void mysql_init_multi_delete(LEX *lex)
{
    lex->sql_command=  SQLCOM_DELETE_MULTI;
    mysql_init_select(lex);
    lex->select_lex.select_limit= 0;
    lex->unit.select_limit_cnt= HA_POS_ERROR;
    lex->select_lex.table_list.save_and_clear(&lex->auxiliary_table_list);
    lex->query_tables= 0;
    lex->query_tables_last= &lex->query_tables;
}


int mysql_get_err_level_by_errno(THD *   thd)
{
    switch(thd->get_stmt_da()->sql_errno())
    {
    case ER_WITH_INSERT_FIELD:
    case ER_BAD_NULL_ERROR:
    case ER_NO_WHERE_CONDITION:
    case ER_WITH_ORDERBY_CONDITION:
    case ER_SELECT_ONLY_STAR:
    case ER_ORDERY_BY_RAND:
    case ER_UNKNOWN_COLLATION:
    case ER_INVALID_DATA_TYPE:
    case ER_NOT_ALLOWED_NULLABLE:
    case ER_FOREIGN_KEY:
    case ER_TOO_MANY_KEY_PARTS:
    case ER_UDPATE_TOO_MUCH_ROWS:
    case ER_TOO_MANY_KEYS:
    case ER_TIMESTAMP_DEFAULT:
    case ER_CANT_DROP_FIELD_OR_KEY:
    case ER_CHAR_TO_VARCHAR_LEN:
    case ER_USE_ENUM:
    case ER_OUTOFMEMORY:
    case ER_INC_INIT_ERR:
    case ER_CHARSET_ON_COLUMN:
    case ER_IDENT_USE_KEYWORD:
    case ER_TABLE_CHARSET_MUST_UTF8:
    case ER_AUTO_INCR_ID_WARNING:
    case ER_ALTER_TABLE_ONCE:
    case ER_BLOB_CANT_HAVE_DEFAULT:
    case ER_WITH_DEFAULT_ADD_COLUMN:
    case ER_NOT_SUPPORTED_YET:
    case ER_NOT_SUPPORTED_ALTER_OPTION:
    case ER_COLUMN_HAVE_NO_COMMENT:
    case ER_TABLE_MUST_HAVE_COMMENT:
    case ER_WITH_LIMIT_CONDITION:
    case ER_INDEX_NAME_IDX_PREFIX:
    case ER_INDEX_NAME_UNIQ_PREFIX:
    case ER_AUTOINC_UNSIGNED:
    case ER_PARTITION_NOT_ALLOWED:
    case ER_TABLE_MUST_HAVE_PK:
    case ER_TOO_LONG_INDEX_COMMENT:
    case ER_TABLE_MUST_INNODB:
    case ER_NAMES_MUST_UTF8:
    case ER_TEXT_NOT_NULLABLE_ERROR:
    case ER_INVALID_IDENT:
        return INCEPTION_RULES;

    case ER_CONFLICTING_DECLARATIONS:
    case ER_NO_DB_ERROR:
    case ER_KEY_COLUMN_DOES_NOT_EXITS:
    case ER_TOO_LONG_BAKDB_NAME:
    case ER_DB_NOT_EXISTED_ERROR:
    case ER_TABLE_EXISTS_ERROR:
    case ER_COLUMN_EXISTED:
    case ER_START_AS_BEGIN:
    case ER_COLUMN_NOT_EXISTED:
    case ER_WRONG_STRING_LENGTH:
    case ER_BLOB_USED_AS_KEY:
    case ER_INVALID_DEFAULT:
    case ER_NOT_SUPPORTED_KEY_TYPE:
    case ER_DUP_INDEX:
    case ER_TEMP_TABLE_TMP_PREFIX:
    case ER_TOO_LONG_KEY:
    case ER_MULTIPLE_PRI_KEY:
    case ER_DUP_KEYNAME:
    case ER_DUP_FIELDNAME:
    case ER_WRONG_KEY_COLUMN:
    case ER_WRONG_COLUMN_NAME:
    case ER_WRONG_AUTO_KEY:
    case ER_WRONG_SUB_KEY:
    case ER_WRONG_NAME_FOR_INDEX:
    case ER_TOO_LONG_IDENT:
    case ER_SQL_INVALID_SOURCE:
    case ER_WRONG_DB_NAME:
    case ER_WITH_INSERT_VALUES:
    case ER_WRONG_VALUE_COUNT_ON_ROW:
    case ER_BAD_FIELD_ERROR:
    case ER_FIELD_SPECIFIED_TWICE:
    case ER_SQL_NO_SOURCE:
    case ER_PARSE_ERROR:
    case ER_SYNTAX_ERROR:
    case ER_END_WITH_SEMICOLON:
    case ER_INDEX_USE_ALTER_TABLE:
    case ER_INVALID_GROUP_FUNC_USE:
    case ER_TABLE_NOT_EXISTED_ERROR:
    case ER_UNKNOWN_TABLE:
    case ER_TOO_MUCH_AUTO_TIMESTAMP_COLS:
    case ER_INVALID_ON_UPDATE:
    case ER_NON_UNIQ_ERROR:
    case ER_DDL_DML_COEXIST:
    case ER_COLLATION_CHARSET_MISMATCH:
    case ER_VIEW_SELECT_CLAUSE:
    case ER_NOT_SUPPORTED_ITEM_TYPE:
        return INCEPTION_PARSE;

    default:
        return INCEPTION_PARSE;
    }
}

int
mysql_check_inception_variables(
    THD * thd
)
{
    switch(thd->get_stmt_da()->sql_errno())
    {
    case ER_WITH_INSERT_FIELD:
        if (inception_check_insert_field)
            return true;
        else 
            return false;
        break;

    case ER_NO_WHERE_CONDITION:
        if (inception_check_dml_where)
            return true;
        else 
            return false;
        break;

    case ER_WITH_LIMIT_CONDITION:
        if (inception_check_dml_limit)
            return true;
        else 
            return false;
        break;

    case ER_WITH_ORDERBY_CONDITION:
        if (inception_check_dml_orderby)
            return true;
        else 
            return false;
        break;

    case ER_SELECT_ONLY_STAR:
        if (inception_enable_select_star)
            return false;
        break;

    case ER_ORDERY_BY_RAND:
        if (inception_enable_orderby_rand)
            return false;
        break;

    case ER_NOT_ALLOWED_NULLABLE:
        if (inception_enable_nullable)
            return false;
        break;

    case ER_FOREIGN_KEY:
        if (inception_enable_foreign_key)
            return false;
        break;

    case ER_USE_TEXT_OR_BLOB:
        if (inception_enable_blob_type)
            return false;
        break;

    case ER_TABLE_MUST_INNODB:
        if (inception_enable_not_innodb)
            return false;
        break;


    case ER_TABLE_MUST_HAVE_COMMENT:
        if (inception_check_table_comment)
            return true;
        else 
            return false;
        break;

    case ER_COLUMN_HAVE_NO_COMMENT:
        if (inception_check_column_comment)
            return true;
        else 
            return false;
        break;

    case ER_TABLE_MUST_HAVE_PK:
        if (inception_check_primary_key)
            return true;
        else 
            return false;
        break;

    case ER_PARTITION_NOT_ALLOWED:
        if (inception_enable_partition_table)
            return false;
        break;

    case ER_USE_ENUM:
    case ER_INVALID_DATA_TYPE:
        if (inception_enable_enum_set_bit)
            return false;
        break;

    case ER_INDEX_NAME_IDX_PREFIX:
    case ER_INDEX_NAME_UNIQ_PREFIX:
        if (inception_check_index_prefix)
            return true;
        else 
            return false;
        break;

    case ER_AUTOINC_UNSIGNED:
        if (inception_enable_autoincrement_unsigned)
            return true;
        else 
            return false;
        break;

    case ER_INC_INIT_ERR:
        if (inception_check_autoincrement_init_value)
            return true;
        else 
            return false;
        break;
    case ER_INVALID_IDENT:
        if (inception_check_identifier)
            return true;
        else 
            return false;
        break;

    case ER_SET_DATA_TYPE_INT_BIGINT:
        if (inception_check_autoincrement_datatype)
            return true;
        else 
            return false;
        break;

    case ER_TIMESTAMP_DEFAULT:
        if (inception_check_timestamp_default)
            return true;
        else 
            return false;
        break;

    case ER_CHARSET_ON_COLUMN:
        if (inception_enable_column_charset)
            return false;
        break;

    case ER_IDENT_USE_KEYWORD:
        if (inception_enable_identifer_keyword)
            return false;
        break;

    case ER_AUTO_INCR_ID_WARNING:
        if (inception_check_autoincrement_name)
            return true;
        else 
            return false;
        break;

    case ER_ALTER_TABLE_ONCE:
        if (inception_merge_alter_table)
            return true;
        else 
            return false;
        break;

    case ER_WITH_DEFAULT_ADD_COLUMN:
        if (inception_check_column_default_value)
            return true;
        else 
            return false;
        break;

    default:
        return true;
    }

    return true;
}

void
mysql_errmsg_append_without_errno(
    THD * thd,
    sql_cache_node_t* sql_cache_node,
    char* errmsg
)
{
    if (sql_cache_node->errmsg == NULL)
    {
        sql_cache_node->errmsg = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
        str_init(sql_cache_node->errmsg);
    }
    str_append(sql_cache_node->errmsg, errmsg);
    thd->clear_error();
}

void
mysql_errmsg_append_without_errno_osc(
    THD * thd,
    sql_cache_node_t* sql_cache_node,
    char* errmsg
)
{
    if (sql_cache_node->errmsg == NULL)
    {
        sql_cache_node->errmsg = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
        str_init(sql_cache_node->errmsg);
    }
    str_append(sql_cache_node->errmsg, errmsg);
    str_append(sql_cache_node->errmsg, "\n");
    //如果执行出错，这里直接报为错误，而不是警告, 但如果是正常完成了，则不报错
    if (sql_cache_node->oscpercent != 100)
        sql_cache_node->errlevel = INCEPTION_PARSE;
    thd->clear_error();
}

void
mysql_errmsg_append(
    THD * thd
)
{
    if (thd->is_error() && 
        thd->have_begin && 
        inception_get_type(thd) != INCEPTION_TYPE_SPLIT)
    {
        if (mysql_check_inception_variables(thd))
        {
            if (thd->errmsg == NULL)
            {
                thd->errmsg = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
                str_init(thd->errmsg);
            }
            str_append(thd->errmsg, thd->get_stmt_da()->message());
            str_append(thd->errmsg, "\n");
            thd->err_level |= mysql_get_err_level_by_errno(thd);
            thd->check_error_before = TRUE;
        }

        thd->clear_error();
    }

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT)
        thd->clear_error();
}

void
mysql_sqlcachenode_errmsg_append(
    THD*                    thd,
    sql_cache_node_t*       node,
    int                     type
)
{
    if (thd->is_error())
    {
        if (node->errmsg == NULL)
        {
            node->errmsg = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
            str_init(node->errmsg);
        }

        if (type == INC_ERROR_EXECUTE_STAGE)
            str_append(node->errmsg, "Execute: ");
        else
            str_append(node->errmsg, "Backup: ");

        node->errrno = thd->get_stmt_da()->sql_errno();
        str_append(node->errmsg, thd->get_stmt_da()->message());
        str_append(node->errmsg, "\n");
        //如果执行出错，这里直接报为错误，而不是警告
        node->errlevel = INCEPTION_PARSE;
        thd->clear_error();
    }
}

void thd_sql_statistic_increment(THD* thd, uint alterflag)
{
    sql_statistic_t* statistic;

    if (inception_get_type(thd) != INCEPTION_TYPE_EXECUTE || 
        !inception_enable_sql_statistic)
        return;

    statistic = &thd->sql_statistic;
    switch (thd->lex->sql_command)
    {
    case SQLCOM_CHANGE_DB:
        statistic->usedb++;
        break;
    case SQLCOM_INSERT:
    case SQLCOM_INSERT_SELECT:
        statistic->insert++;
        break;
    case SQLCOM_UPDATE:
    case SQLCOM_UPDATE_MULTI:
        statistic->update++;
        break;
    case SQLCOM_DELETE:
    case SQLCOM_DELETE_MULTI:
        statistic->deleting++;
        break;
    case SQLCOM_SELECT:
        statistic->select++;
        break;
    case SQLCOM_ALTER_TABLE:
        {
            if (alterflag == 0)
                statistic->altertable++;
            switch (alterflag)
            {
                case Alter_info::ALTER_ADD_COLUMN:
                case Alter_info::ALTER_COLUMN_ORDER:
                    statistic->addcolumn++;
                    break;
                case Alter_info::ALTER_ADD_INDEX:
                    statistic->createindex++;
                    break;
                case Alter_info::ALTER_DROP_COLUMN:
                    statistic->dropcolumn++;
                    break;
                case Alter_info::ALTER_RENAME:
                    statistic->rename++;
                    break;
                case Alter_info::ALTER_CHANGE_COLUMN:
                    statistic->changecolumn++;
                    break;
                case Alter_info::ALTER_DROP_INDEX:
                    statistic->dropindex++;
                    break;
                case Alter_info::ALTER_CHANGE_COLUMN_DEFAULT:
                    statistic->changedefault++;
                    break;
                case Alter_info::ALTER_OPTIONS:
                    statistic->alteroption++;
                    break;
                case Alter_info::ALTER_CONVERT:
                    statistic->alterconvert++;
                    break;
                default:
                    break;
            }
        }
        break;
    case SQLCOM_CREATE_TABLE:
        statistic->createtable++;
        break;
    case SQLCOM_DROP_TABLE:
        statistic->droptable++;
        break;
    case SQLCOM_CREATE_DB:
        statistic->createdb++;
        break;
    case SQLCOM_TRUNCATE:
        statistic->truncate++;
    default:
        break;
    }
}

int thd_parse_options(
    THD * thd,
    char* sql
)
{
    char* str;
    char* str_comment;
    char *strToken = NULL;
    int i = 0;
    int ho_error;
    char*  comment;
    int  found = FALSE;
    int length;
    int err = ER_NO;
    char errmsg[1024];

    DBUG_ENTER("thd_parse_options");

    if (thd->have_begin)
    {
        thd->sql_statement = sql;
        DBUG_RETURN(FALSE);
    }

    str = sql;

    length = strlen(str);
    while (length > 0 && my_isspace(thd->charset(), *str))
    {
        str++;
        length--;
    }

    if (length <= 2 || (*str != '/' && *(str + 1) != '*'))
    {
        my_error(ER_SQL_NO_SOURCE, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    while (*str != '\0' && *(str + 1) != '\0')
    {
        if (*str=='*' && *(str+1) == '/')
        {
            found = TRUE;
            break;
        }

        str++;
    }

    if (!found)
    {
        if (thd->thd_sinfo->host[0] == '\0')
        {
            my_error(ER_SQL_NO_SOURCE, MYF(0));
            DBUG_RETURN(ER_NO);
        }
        else
        {
            thd->sql_statement = sql;
            DBUG_RETURN(FALSE);
        }
    }

    if (thd->lex->sql_command != SQLCOM_INCEPTION_START)
    {
        my_error(ER_START_AS_BEGIN, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    if (thd->have_begin)
    {
        if (mysql_execute_commit(thd))
            DBUG_RETURN(TRUE);
    }

    comment = (char*)my_malloc(str - sql + 1, MY_ZEROFILL);
    memcpy(comment, sql, str - sql);
    str_comment = strtok(comment, "*/");
    if (str_comment == NULL)
    {
        my_error(ER_SQL_INVALID_SOURCE, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    mysql_mutex_lock(&isql_option_mutex);

    length = strlen(str_comment);
    while (length > 0 && my_isspace(thd->charset(), *str_comment))
    {
        str_comment++;
        length--;
    }

    strToken = strtok(str_comment, ";");
    while (strToken != NULL)
    {
        length = strlen(strToken);
        while (length > 0 && my_isspace(thd->charset(), *strToken))
        {
            strToken++;
            length--;
        }

        isql_option[++i] = strToken;
        strToken = strtok(NULL, ";");
    }

    if (i > ISQL_OPTION_COUNT)
    {
        my_error(ER_SQL_INVALID_SOURCE, MYF(0));
        goto ERROR;
    }

    sprintf(errmsg, "Invalid source infomation.");
    global_source.password = global_source.user = NULL;
    ho_error = my_handle_options(&++i, &isql_option, my_isql_options, NULL, NULL, errmsg);
    isql_option--;
    if (ho_error)
    {
        my_message(ho_error, errmsg, MYF(0));
        goto ERROR;
    }

    if (global_source.host == NULL || global_source.port == 0)
    {
        my_error(ER_SQL_INVALID_SOURCE, MYF(0));
        goto ERROR;
    }

    if (check_string_char_with_length(global_source.host, strlen(global_source.host),
        ER(ER_HOSTNAME), HOSTNAME_LENGTH, system_charset_info, 0))
        goto ERROR;

    if (global_source.password == NULL && global_source.user == NULL)
    {
        if (inception_user == NULL || inception_password == NULL)
        {
            my_error(ER_SQL_INVALID_SOURCE, MYF(0));
            goto ERROR;
        }

        strcpy(thd->thd_sinfo->user, inception_user);
        strcpy(thd->thd_sinfo->password, inception_password);
        thd->thd_sinfo->optype = INCEPTION_TYPE_CHECK;
    }
    else
    {
        strcpy(thd->thd_sinfo->user, global_source.user);
        strcpy(thd->thd_sinfo->password, global_source.password);
    }

    if (global_source.query_print == 1)
        thd->thd_sinfo->optype = INCEPTION_TYPE_PRINT;
    else if (global_source.split == 1)
        thd->thd_sinfo->optype = INCEPTION_TYPE_SPLIT;
    else if (global_source.execute == 1)
        thd->thd_sinfo->optype = INCEPTION_TYPE_EXECUTE;
    else if (global_source.check== 1)
        thd->thd_sinfo->optype = INCEPTION_TYPE_CHECK;

    if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE ||
        inception_get_type(thd) == INCEPTION_TYPE_CHECK ||
        inception_get_type(thd) == INCEPTION_TYPE_PRINT)
    {
        if (thd->thd_sinfo->user[0] == '\0' ||
            thd->thd_sinfo->password == '\0' )
        {
            my_error(ER_SQL_INVALID_SOURCE, MYF(0));
            goto ERROR;
        }
    }

    //只能设置一个操作类型
    // if (global_source.query_print + global_source.check +
    //     global_source.execute + global_source.split != 1)
    // {
    //     my_error(ER_SQL_INVALID_SOURCE, MYF(0));
    //     goto ERROR;
    // }

    thd->thd_sinfo->ignore_warnings = global_source.ignore_warnings;
    strcpy(thd->thd_sinfo->host, global_source.host);
    thd->thd_sinfo->port = global_source.port;
    thd->thd_sinfo->force = global_source.force;
    thd->thd_sinfo->backup = global_source.backup;
    if (inception_get_type(thd) != INCEPTION_TYPE_EXECUTE)
        thd->thd_sinfo->backup = FALSE;

    err = FALSE;
ERROR:
    mysql_mutex_unlock(&isql_option_mutex);

    my_free(comment);
    thd->sql_statement = sql;

    DBUG_RETURN(err);
}

void
mysql_table_info_free(
    table_info_t* table_info
)
{
    field_info_t*  field_info;
    field_info_t*  next_field_info;

    DBUG_ENTER("mysql_table_info_free");

    if (table_info == NULL)
        DBUG_VOID_RETURN;

    field_info = LIST_GET_FIRST(table_info->field_lst);
    while (field_info != NULL)
    {
        next_field_info = LIST_GET_NEXT(link, field_info);
        LIST_REMOVE(link, table_info->field_lst, field_info);

        if (field_info->field)
            delete field_info->field;

        free(field_info);
        field_info = next_field_info;
    }

    my_free(table_info->record);
    my_free(table_info->null_arr);
    free(table_info);

    DBUG_VOID_RETURN;
}

void
mysql_free_all_table_definition(
    THD*  thd
)
{
    table_info_t* tableinfo = NULL;
    table_info_t* tableinfo_next = NULL;

    tableinfo = LIST_GET_FIRST(thd->tablecache.tablecache_lst);
    while (tableinfo != NULL)
    {
        tableinfo_next = LIST_GET_NEXT(link, tableinfo);

        mysql_table_info_free(tableinfo);
        tableinfo = tableinfo_next;
    }

    LIST_INIT(thd->tablecache.tablecache_lst);
}

table_info_t*
mysql_get_table_object_from_cache(
    THD*  thd,
    char*  dbname,
    char*  tablename
)
{
    table_info_t* tableinfo = NULL;

    if (dbname == NULL && tablename == NULL) {
        return NULL;
    }

    tableinfo = LIST_GET_FIRST(thd->tablecache.tablecache_lst);
    while (tableinfo != NULL)
    {
        if (!strcasecmp(tableinfo->db_name, dbname) &&
            !strcasecmp(tableinfo->table_name, tablename))
        {
            return tableinfo;
        }

        tableinfo = LIST_GET_NEXT(link, tableinfo);
    }

    return NULL;
}

void
mysql_remove_table_object(
    THD*  thd,
    table_info_t* table_info
)
{
    table_info_t* tableinfo = NULL;

    if (table_info == NULL) {
        return ;
    }

    tableinfo = LIST_GET_FIRST(thd->tablecache.tablecache_lst);
    while (tableinfo != NULL)
    {
        if (table_info == tableinfo)
        {
            LIST_REMOVE(link, thd->tablecache.tablecache_lst, tableinfo);
            return ;
        }

        tableinfo = LIST_GET_NEXT(link, tableinfo);
    }

    return ;
}

void
mysql_add_table_object(
    THD*  thd,
    table_info_t* tableinfo
)
{
    //to do: limit the object number
    LIST_ADD_LAST(link, thd->tablecache.tablecache_lst, tableinfo);
}

table_info_t*
mysql_copy_table_info(
    table_info_t* src
)
{
    table_info_t*  table_info;
    field_info_t*  field_info;
    field_info_t*  field_info_new;

    DBUG_ENTER("mysql_copy_table_info");

    //free memory
    table_info = (table_info_t*)malloc(sizeof(table_info_t));
    memset(table_info, 0, sizeof(table_info_t));
    LIST_INIT(table_info->field_lst);

    strcpy(table_info->table_name, src->table_name);
    strcpy(table_info->db_name, src->db_name);

    field_info = LIST_GET_FIRST(src->field_lst);
    while (field_info)
    {
        //free memory
        field_info_new = (field_info_t*)malloc(sizeof(field_info_t));

        memset(field_info_new, 0, sizeof(field_info_t));
        strcpy(field_info_new->field_name, field_info->field_name);
        field_info_new->nullable = field_info->nullable;
        field_info_new->primary_key = field_info->primary_key;
        table_info->have_pk = src->have_pk;
        field_info_new->auto_increment = field_info->auto_increment;
        strcpy(field_info_new->data_type, field_info->data_type);
        field_info_new->max_length = field_info->max_length;
        field_info_new->charset = field_info->charset;

        LIST_ADD_LAST(link, table_info->field_lst, field_info_new);
        field_info = LIST_GET_NEXT(link, field_info);
    }

    DBUG_RETURN(table_info);
}

table_info_t*
mysql_convert_desc_to_table_info(
    MYSQL_RES* source_res,
    char*  dbname,
    char*  tablename
)
{
    table_info_t*  table_info;
    field_info_t*  field_info;
    MYSQL_ROW   source_row;

    DBUG_ENTER("mysql_convert_desc_to_table_info");

    //free memory
    table_info = (table_info_t*)malloc(sizeof(table_info_t));
    memset(table_info, 0, sizeof(table_info_t));
    LIST_INIT(table_info->field_lst);

    strcpy(table_info->table_name, tablename);
    strcpy(table_info->db_name, dbname);

    source_row = mysql_fetch_row(source_res);
    while (source_row)
    {
        //free memory
        field_info = (field_info_t*)malloc(sizeof(field_info_t));

        memset(field_info, 0, sizeof(field_info_t));
        strcpy(field_info->field_name, source_row[0]);
        if (strcasecmp(source_row[3], "YES") == 0)
            field_info->nullable = true;
        else
            field_info->nullable = false;

        if (strcasecmp(source_row[4], "PRI") == 0)
        {
            field_info->primary_key = true;
            table_info->have_pk = true;
        }

        if (strcasecmp(source_row[6], "auto_increment") == 0)
            field_info->auto_increment = true;

        if (source_row[2] != NULL)
            field_info->charset = get_charset(get_collation_number(source_row[2]),MYF(0));

        strcpy(field_info->data_type, source_row[1]);

        LIST_ADD_LAST(link, table_info->field_lst, field_info);
        source_row = mysql_fetch_row(source_res);
    }

    mysql_free_result(source_res);

    DBUG_RETURN(table_info);
}

table_info_t*
mysql_query_table_from_source(
    THD*  thd,
    MYSQL*  mysql,
    char*  dbname,
    char*  tablename,
    int   not_exist_report
)
{
    char  sql[100];
    MYSQL_RES* source_res= 0;
    table_info_t* table_info;

    DBUG_ENTER("mysql_query_table_from_source");

    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        DBUG_RETURN(NULL);
    }

    sprintf(sql, "SHOW FULL FIELDS FROM `%s`.`%s`", dbname, tablename);
    if (mysql_real_query(mysql, sql, strlen(sql)))
    {
        if (!(!not_exist_report && mysql_errno(mysql) == 1146)/*ER_NO_SUCH_TABLE*/)
        {//主要是为了处理创建表时对表是不是存在进行检查，创建表时表不存在不应该报错
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
            mysql_errmsg_append(thd);
        }

        DBUG_RETURN(NULL);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(thd);
        DBUG_RETURN(NULL);
    }

    table_info = mysql_convert_desc_to_table_info(source_res, dbname, tablename);

    DBUG_RETURN(table_info);
}


table_info_t*
mysql_get_table_object(
    THD*  thd,
    char*  dbname,
    char*  tablename,
    int   not_exist_report
)
{
    table_info_t* tableinfo = NULL;

    tableinfo = mysql_get_table_object_from_cache(thd, dbname, tablename);
    //解决表已经删除，但后面又用到了，则直接判断这个标记
    //而不是重新从远程载入这个表对象，删除表的时候只打标记
    if (tableinfo && tableinfo->isdeleted)
    {
        //如果是建表语句的话，找不到表不能报错
        if (not_exist_report) 
        {
            my_error(ER_TABLE_NOT_EXISTED_ERROR, MYF(0), tablename);
            mysql_errmsg_append(thd);
        }

        return NULL;
    }

    if (tableinfo != NULL)
        return tableinfo;

    tableinfo = mysql_query_table_from_source(thd, thd->get_audit_connection(), 
                dbname, tablename, not_exist_report);
    if (tableinfo != NULL)
    {
        mysql_add_table_object(thd, tableinfo);
        mysql_alloc_record(tableinfo, thd->get_audit_connection());
    }

    return tableinfo;
}

void
mysql_check_ddldml_coexisted(
    THD*            thd,
    table_info_t*   table_info,
    int             dmlddlflag
)
{
    //只有在执行的时候才报这个错误
    if (table_info == NULL)
        return;

    if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE)
    {
        if (table_info->dmlddl <= (MYSQLDDL | MYSQLDML))
            table_info->dmlddl |= dmlddlflag;
        if (table_info->dmlddl & MYSQLDDL && table_info->dmlddl & MYSQLDML)
        {
            //同一个表只报一个错误，多了就不报了
            table_info->dmlddl = 4;
            my_error(ER_DDL_DML_COEXIST, MYF(0), thd->lex->query_tables->table_name);
            mysql_errmsg_append(thd);
        }
    }
}

field_info_t*
mysql_get_table_field(
    THD*  thd,
    char*  dbname,
    char*  tablename,
    char* field_name
)
{
    field_info_t* fieldinfo = NULL;
    table_info_t*   tableinfo = NULL;

    if ((tableinfo = mysql_get_table_object(thd, dbname, tablename, TRUE)) == NULL)
        return NULL;

    fieldinfo = LIST_GET_FIRST(tableinfo->field_lst);
    while (fieldinfo != NULL) {
        if (strcasecmp(fieldinfo->field_name, field_name) == 0) {
            return fieldinfo;
        }

        fieldinfo = LIST_GET_NEXT(link, fieldinfo);
    }

    return fieldinfo;
}

int
mysql_check_fields_valid(
    THD *thd,
    table_info_t* table_info,
    List<Item> &fields
)
{
    List_iterator<Item> it(fields);
    reg2 Item *item;
    field_info_t* field_node;

    DBUG_ENTER("mysql_check_fields_valid");

    if (fields.elements == 0)
        DBUG_RETURN(0);

    while ((item= it++))
    {
        // mysql_check_item(thd,  item, &thd->lex->select_lex);
        field_node = LIST_GET_FIRST(table_info->field_lst);
        while (field_node != NULL)
        {
            if (strcasecmp(field_node->field_name, item->full_name()) == 0)
            {
                if (field_node->fixed == true)
                {
                    my_error(ER_FIELD_SPECIFIED_TWICE, MYF(0), item->full_name(), table_info->table_name);
                    mysql_errmsg_append(thd);
                    field_node->fixed = 99999;
                }
                else if (field_node->fixed == false)
                {
                    field_node->fixed = true;
                }

                break;
            }

            field_node = LIST_GET_NEXT(link, field_node);
        }

        if (field_node == NULL)
        {
            my_error(ER_BAD_FIELD_ERROR, MYF(0), item->full_name(), table_info->table_name);
            mysql_errmsg_append(thd);
        }
    }

    field_node = LIST_GET_FIRST(table_info->field_lst);
    while (field_node != NULL)
    {
        field_node->fixed = false;
        field_node = LIST_GET_NEXT(link, field_node);
    }

    DBUG_RETURN(0);
}

int 
mysql_load_insert_tables(
    THD *thd,
    table_info_t* table_info
)
{
    check_rt_t*     rt;
    table_rt_t*           tablert;

    if (!thd->rt_lst)
        thd->rt_lst = (rt_lst_t*)my_malloc(sizeof(rt_lst_t), MY_ZEROFILL);

    rt = (check_rt_t*)my_malloc(sizeof(check_rt_t), MY_ZEROFILL);
    rt->select_lex = &thd->lex->select_lex;

    if (table_info)
    {
        tablert = (table_rt_t*)my_malloc(sizeof(table_rt_t), MY_ZEROFILL);
        tablert->table_info = table_info;
        if (thd->lex->query_tables->alias)
            strcpy(tablert->alias, thd->lex->query_tables->alias);
        LIST_ADD_LAST(link, rt->table_rt_lst, tablert);
    }

    LIST_ADD_LAST(link, *thd->rt_lst, rt);
    return 0;
}

int
mysql_check_insert_fields(
    THD *thd,
    table_info_t* table_info,
    List<Item> &fields,
    List<List_item> &values_list
)
{
    Name_resolution_context_state ctx_state;
    List_iterator<Item> it(fields);
    List_item *values;
    reg2 Item *item;
    reg2 Item *item2;//for values list
    field_info_t* field_node;
    List_iterator_fast<List_item> its(values_list);
    int count=0;

    DBUG_ENTER("mysql_check_insert_fields");

    if (fields.elements == 0)
    {
        my_error(ER_WITH_INSERT_FIELD, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (values_list.elements == 0)
    {
        my_error(ER_WITH_INSERT_VALUES, MYF(0));
        mysql_errmsg_append(thd);
    }

    mysql_check_fields_valid(thd, table_info, fields);
    mysql_load_insert_tables(thd, table_info);
    while ((values = its++))
    {
        List_iterator<Item> it(*values);
        while ((item= it++))
            mysql_check_item(thd,  item, &thd->lex->select_lex);

        count++;
        if ((fields.elements == 0 && LIST_GET_LEN(table_info->field_lst) != values->elements) ||
            (fields.elements != 0 && fields.elements != values->elements))
        {
            my_error(ER_WRONG_VALUE_COUNT_ON_ROW, MYF(0), count);
            mysql_errmsg_append(thd);
        }

        it.rewind();
        List_iterator<Item> vit(*values);
        while ((item= it++) && (item2 = vit++))
        {
            field_node = LIST_GET_FIRST(table_info->field_lst);
            while (field_node != NULL)
            {
                if (strcasecmp(field_node->field_name, item->full_name()) == 0)
                {
                    if (!field_node->nullable && 
                        dynamic_cast<Item_null*>(item2) != NULL && 
                        item2->is_null())
                    {
                        my_error(ER_BAD_NULL_ERROR, MYF(0), field_node->field_name, count);
                        mysql_errmsg_append(thd);
                    }

                    break;
                }

                field_node = LIST_GET_NEXT(link, field_node);
            }
        }
    }

    thd->affected_rows = count;

    DBUG_RETURN(0);
}


int mysql_add_new_one_cache_node(THD* thd,
    split_cache_t*      split_cache,
    char* dbname,
    char* tablename,
    int sqltype,
    enum_sql_command sql_command
)
{
    split_table_t*      split_table;
    split_table_t*      split_table_next;

    split_cache_node_t* split_node;

    //free old table node
    split_table = LIST_GET_FIRST(split_cache->table_lst);
    while (split_table) {
        split_table_next = LIST_GET_NEXT(link, split_table);
        LIST_REMOVE(link, split_cache->table_lst, split_table);
        my_free(split_table);

        split_table = split_table_next;
    }

    split_node = (split_cache_node_t*)my_malloc(sizeof(split_cache_node_t), MY_ZEROFILL);
    str_init(&split_node->sql_statements);

    //每次新建节点时，都将最新的 set names...及 use db 加在前面
    if (thd->lex->sql_command != SQLCOM_SET_OPTION) {
        if (str_get_len(&thd->setnames)) {
            str_append(&split_node->sql_statements, str_get(&thd->setnames));
            str_append(&split_node->sql_statements, ";\n");
        }
    }

    if (thd->lex->sql_command != SQLCOM_CHANGE_DB) {
        if (str_get_len(&thd->usedb)) {
            str_append(&split_node->sql_statements, str_get(&thd->usedb));
            str_append(&split_node->sql_statements, ";\n");
        }
    }
    str_append_with_length(&split_node->sql_statements, thd->query(), thd->query_length());
    str_append(&split_node->sql_statements, ";\n");
    LIST_ADD_LAST(link, split_cache->field_lst, split_node);

    split_table = (split_table_t*)my_malloc(sizeof(split_table_t), MY_ZEROFILL);

    if (dbname)
        strcpy(split_table->dbname, dbname);
    else
        strcpy(split_table->dbname, "");

    if (tablename)
        strcpy(split_table->tablename, tablename);
    else
        strcpy(split_table->tablename, "");

    //if current split have alter table statement, then set it true
    if (sql_command == SQLCOM_ALTER_TABLE || sql_command == SQLCOM_DROP_TABLE)
        split_node->ddlflag = 1;

    split_table->sqltype = sqltype;
    LIST_ADD_LAST(link, split_cache->table_lst, split_table);

    return  false;
}

int mysql_add_split_sql_node(
    THD* thd, 
    char* dbname, 
    char* tablename, 
    int sqltype, 
    enum_sql_command sql_command
)
{
    split_cache_t*      split_cache;
    split_table_t*      split_table;
    split_cache_node_t* split_last;

    split_cache = thd->split_cache;
    if (LIST_GET_LEN(split_cache->field_lst) == 0 /*|| tablename == NULL*/) {
        //create new one
        mysql_add_new_one_cache_node(thd, split_cache, dbname, tablename, sqltype, sql_command);
        return false;
    }

    split_table = LIST_GET_FIRST(split_cache->table_lst);
    while (split_table) {
        if ((!dbname || !tablename) || 
            (dbname && strcasecmp(split_table->dbname, dbname) != 0) ||
            (tablename && strcasecmp(split_table->tablename, tablename) != 0)) {
            split_table = LIST_GET_NEXT(link, split_table);
            continue;
        }

        if (sqltype != split_table->sqltype) {
            //add new one
            mysql_add_new_one_cache_node(thd, split_cache, dbname, tablename,sqltype, sql_command);
            return false;
        }

        split_table = LIST_GET_NEXT(link, split_table);
    }

    split_last = LIST_GET_LAST(split_cache->field_lst);
    //append to the last node
    if (thd->setnamesflag) {
        if (str_get_len(&thd->setnames)) {
            str_append(&split_last->sql_statements, str_get(&thd->setnames));
            str_append(&split_last->sql_statements, ";\n");
        }
        thd->setnamesflag = 0;
    }

    if (thd->useflag) {
        if (str_get_len(&thd->usedb)) {
            str_append(&split_last->sql_statements, str_get(&thd->usedb));
            str_append(&split_last->sql_statements, ";\n");
        }

        thd->useflag = 0;
    }

    str_append_with_length(&split_last->sql_statements, thd->query(), thd->query_length());
    str_append(&split_last->sql_statements, ";\n");

    split_table = (split_table_t*)my_malloc(sizeof(split_table_t), MY_ZEROFILL);
    if (dbname)
        strcpy(split_table->dbname, dbname);
    if (tablename)
        strcpy(split_table->tablename, tablename);

    //if current split have alter table statement, then set it true
    if (sql_command == SQLCOM_ALTER_TABLE)
        split_last->ddlflag = 1;
    split_table->sqltype = sqltype;
    LIST_ADD_LAST(link, split_cache->table_lst, split_table);

    return false;
}

int mysql_check_insert(THD *thd)
{
    table_info_t* table_info;

    DBUG_ENTER("mysql_check_insert");

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT){
        mysql_add_split_sql_node(thd, thd->lex->query_tables->db,
                                 thd->lex->query_tables->table_name, MYSQLDML, 
                                 thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(FALSE);

    mysql_check_ddldml_coexisted(thd, table_info, MYSQLDML);
    mysql_check_insert_fields(thd, table_info, thd->lex->field_list, thd->lex->many_values);

    DBUG_RETURN(FALSE);
}

int mysql_check_version_56(THD* thd)
{
    MYSQL* mysql;
    mysql = thd->get_audit_connection();
    if (!mysql)
        return false;

    if (mysql && strncmp(mysql->server_version, "5.6", 3) < 0)
        return false;

    return true;
}

int mysql_check_insert_select_ex(THD *thd, table_info_t* table_info)
{
    ORDER*   order;
    DBUG_ENTER("mysql_check_insert_select_ex");
    int found_where = false;
    explain_info_t* explain;
    char*           sql_statement;
    char*           sql_p;
    str_t*          str_select;
    str_t           str;
    List<Item> fields = thd->lex->field_list;
    List_iterator<Item> it(fields);
    MYSQL*          mysql;

    if (thd->lex->field_list.elements == 0)
    {
        my_error(ER_WITH_INSERT_FIELD, MYF(0));
        mysql_errmsg_append(thd);
    }

    mysql_check_fields_valid(thd, table_info, fields);

    if ((thd->lex->select_lex.with_wild == 0 &&
            ((thd->lex->field_list.elements != thd->lex->current_select->item_list.elements &&
              thd->lex->field_list.elements != 0) ||
             (thd->lex->field_list.elements == 0 &&
              LIST_GET_LEN(table_info->field_lst) !=
              thd->lex->current_select->item_list.elements))) ||
            (thd->lex->select_lex.with_wild && 
            LIST_GET_LEN(table_info->field_lst) != 
            thd->lex->current_select->item_list.elements))
    {
        my_error(ER_WRONG_VALUE_COUNT_ON_ROW, MYF(0), 1L);
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.where == NULL)
    {
        my_error(ER_NO_WHERE_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.with_wild != 0)
    {
        my_error(ER_SELECT_ONLY_STAR, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.select_limit != NULL)
    {
        my_error(ER_WITH_LIMIT_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }


    if (thd->lex->select_lex.order_list.elements != 0)
    {
        for (order= thd->lex->select_lex.order_list.first ; order; order= order->next)
        {
            if (dynamic_cast <Item_func_rand*>(*order->item))
            {
                my_error(ER_ORDERY_BY_RAND, MYF(0));
                mysql_errmsg_append(thd);
            }
        }
    }

    mysql_check_subselect_item(thd, &thd->lex->select_lex, false);

    mysql = thd->get_audit_connection();
    if (mysql && !table_info->new_cache && !table_info->new_column_cache)
    {
        str_select = str_init(&str);
        sql_statement = thd_query_with_length(thd);
        sql_p = sql_statement;
        if (!mysql_check_version_56(thd))
        {
            while (*sql_p)
            {
                if (strnicmp(sql_p, "select", 6) == 0)
                {
                    found_where = true;
                    break;
                }
                sql_p++;
            }
        }

        str_append(str_select, "EXPLAIN ");
        str_append(str_select, sql_p);
        my_free(sql_statement);
        if (mysql_get_explain_info(thd, mysql, str_get(str_select), &explain, TRUE, table_info->db_name))
        {
            str_deinit(str_select);
            DBUG_RETURN(FALSE);
        }

        mysql_anlyze_explain(thd, explain);
        str_deinit(str_select);
    }

    DBUG_RETURN(FALSE);
}

int mysql_check_insert_select(THD *thd)
{
    table_info_t* table_info;

    DBUG_ENTER("mysql_check_insert_select");

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT){
        mysql_add_split_sql_node(thd, thd->lex->query_tables->db,
                                 thd->lex->query_tables->table_name, MYSQLDML, 
                                 thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(FALSE);

    mysql_check_ddldml_coexisted(thd, table_info, MYSQLDML);
    mysql_check_insert_select_ex(thd, table_info);

    DBUG_RETURN(FALSE);
}

int
mysql_make_select_sql(THD *thd, table_info_t* tableinfo, str_t* str_select)
{
    str_t   str_s;
    str_t*   str;
    field_info_t* field_node;
    int    have_key = false;
    List_iterator<Item> updit(thd->lex->current_select->item_list);
    reg2 Item *item;
    char*   sql_p;
    char*           sql_statement;
    int    found_where = false;
    int    first_col = true;

    DBUG_ENTER("mysql_make_select_sql");

    str = str_init(&str_s);

    field_node = LIST_GET_FIRST(tableinfo->field_lst);
    while (field_node != NULL)
    {
        if (field_node->primary_key)
        {
            if (!first_col)
                str_append(str, ",");

            first_col = false;
            str_append(str, field_node->field_name);
            have_key = true;
        }

        field_node = LIST_GET_NEXT(link, field_node);
    }

    if (thd->lex->sql_command == SQLCOM_UPDATE)
    {
        if (have_key == true)
            str_append(str, ",");

        while ((item = updit++))
        {
            str_append(str, item->full_name());
            str_append(str, ",");
        }

        str_append(str, "1");
    }
    else if (have_key == false)
    {
        str_append(str, "*");
    }

    str_append(str, " ");

    //find the where from sql

    sql_statement = thd_query_with_length(thd);
    sql_p = sql_statement;
    while (*sql_p)
    {
        if (strnicmp(sql_p, "where", 5) == 0)
        {
            found_where = true;
            break;
        }

        sql_p++;
    }

    if (found_where == false)
    {
        str_deinit(str);
        my_free(sql_statement);

        DBUG_RETURN(-1);
    }

    str_append(str_select, "EXPLAIN ");
    str_append(str_select, "SELECT ");
    str_append(str_select, str_get(str));
    str_append(str_select, "FROM ");
    str_append(str_select, tableinfo->db_name);
    str_append(str_select, ".");
    str_append(str_select, tableinfo->table_name);
    str_append(str_select, "\t");
    if (thd->lex->query_tables->alias)
        str_append(str_select, thd->lex->query_tables->alias);
    str_append(str_select, "\t");
    str_append(str_select, sql_p);
    str_append(str_select, ";");

    str_deinit(str);
    my_free(sql_statement);

    DBUG_RETURN(0);
}

int
mysql_select_type_name_to_int(
    char*  select_type
)
{
    if (strcasecmp(select_type, "SIMPLE") == 0)
    {
        return st_select_lex::SLT_SIMPLE;
    }
    else if (strcasecmp(select_type, "PRIMARY") == 0)
    {
        return st_select_lex::SLT_PRIMARY;
    }
    else if (strcasecmp(select_type, "UNION") == 0)
    {
        return st_select_lex::SLT_UNION;
    }
    else if (strcasecmp(select_type, "DEPENDENT UNION") == 0)
    {
        return st_select_lex::SLT_UNION;
    }
    else if (strcasecmp(select_type, "UNION RESULT") == 0)
    {
        return st_select_lex::SLT_UNION_RESULT;
    }
    else if (strcasecmp(select_type, "SUBQUERY") == 0)
    {
        return st_select_lex::SLT_SUBQUERY;
    }
    else if (strcasecmp(select_type, "DEPENDENT SUBQUERY") == 0)
    {
        return st_select_lex::SLT_SUBQUERY;
    }
    else if (strcasecmp(select_type, "DERIVED") == 0)
    {
        return st_select_lex::SLT_DERIVED;
    }
    else if (strcasecmp(select_type, "MATERIALIZED") == 0)
    {
        return st_select_lex::SLT_MATERIALIZED;
    }
    else if (strcasecmp(select_type, "UNCACHEABLE SUBQUERY") == 0)
    {
        return st_select_lex::SLT_SUBQUERY;
    }
    else if (strcasecmp(select_type, "UNCACHEABLE UNION") == 0)
    {
        return st_select_lex::SLT_UNION;
    }

    return st_select_lex::SLT_NONE;
}

char**
mysql_parse_possible_keys(
    char*  possible_keys
)
{
    char*  p;
    int   count = 0;
    char**  keys;
    int   i = 0;

    DBUG_ENTER("mysql_parse_possible_keys");

    p = possible_keys;
    while (*p)
    {
        if (*p == ',')
        {
            count++;
        }

        p++;
    }

    keys = (char**)malloc(sizeof(char*) * (count + 1 + 1));
    memset(keys, 0, sizeof(char*) * (count + 1 + 1));
    p = strtok(possible_keys, ",");
    if (p)
    {
        keys[i] = (char*)malloc(strlen(p) + 1);
        strcpy(keys[i], p);
        i++;
    }

    while ((p = strtok(NULL, ",")))
    {
        keys[i] = (char*)malloc(strlen(p) + 1);
        strcpy(keys[i], p);
        i++;
    }

    DBUG_RETURN(keys);
}

uint
mysql_get_explain_info(
    THD*        thd,
    MYSQL*  mysql,
    char*  select_sql,
    explain_info_t** explain_ret,
    int     report_err,
    char* dbname
)
{
    explain_info_t*  explain = NULL;
    MYSQL_RES *   source_res;
    MYSQL_ROW   source_row;
    MYSQL_FIELD*  field;
    select_info_t*  select_info;
    char*    field_value;
    uint    i;
    char                usedb[100];

    DBUG_ENTER("mysql_get_explain_info");

    if (mysql == NULL)
        DBUG_RETURN(TRUE);

    explain = (explain_info_t*)my_malloc(sizeof(explain_info_t), MYF(MY_ZEROFILL));
    *explain_ret = explain;
    if (explain == NULL)
    {
        if (report_err) {
            my_error(ER_OUTOFMEMORY, MYF(0));
            mysql_errmsg_append(thd);
        }

        DBUG_RETURN(0);
    }

    LIST_INIT(explain->field_lst);

    sprintf(usedb, "use `%s`", dbname);
    if (mysql_real_query(mysql, usedb, strlen(usedb)))
    {
        if (report_err) {
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
            mysql_errmsg_append(thd);
        }

        DBUG_RETURN(FALSE);
    }

    if (mysql_real_query(mysql, select_sql, strlen(select_sql)))
    {
        if (report_err) {
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
            mysql_errmsg_append(thd);
        }
        DBUG_RETURN(FALSE);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        if (report_err) {
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
            mysql_errmsg_append(thd);
        }
        DBUG_RETURN(FALSE);
    }

    while ((source_row = mysql_fetch_row(source_res)))
    {
        //free memory
        select_info = (select_info_t*)my_malloc(sizeof(select_info_t), MYF(MY_ZEROFILL));
        for(i = 0; i < source_res->field_count; i++)
        {
            field_value = source_row[i];
            if (field_value != NULL)
            {
                field = &source_res->fields[i];
                if (strcmpi(field->name, "id") == 0)
                {
                    if (field_value == NULL)
                        select_info->id = 0;
                    else
                        select_info->id = atoi(field_value);
                }
                else if (strcmpi(field->name, "select_type") == 0)
                {
                    select_info->select_type = mysql_select_type_name_to_int(field_value);
                }
                else if (strcmpi(field->name, "table") == 0)
                {
                    strcpy(select_info->table, field_value);
                }
                else if (strcmpi(field->name, "type") == 0)
                {
                    strcpy(select_info->join_type, field_value);
                }
                else if (strcmpi(field->name, "possible_keys") == 0)
                {
                    select_info->possible_keys = mysql_parse_possible_keys(field_value);
                }
                else if (strcmpi(field->name, "key") == 0)
                {
                    strcpy(select_info->key, field_value);
                }
                else if (strcmpi(field->name, "key_len") == 0)
                {
                    select_info->key_len = atoi(field_value);
                }
                else if (strcmpi(field->name, "ref") == 0)
                {
                    strcpy(select_info->key, field_value);
                }
                else if (strcmpi(field->name, "rows") == 0)
                {
                    select_info->rows = atoi(field_value);
                }
                else if (strcmpi(field->name, "Extra") == 0)
                {
                    select_info->extra = (char*)malloc(strlen(field_value) + 1);
                    strcpy(select_info->extra, field_value);
                }
            }
        }

        LIST_ADD_LAST(link, explain->field_lst, select_info);
    }

    mysql_free_result(source_res);

    DBUG_RETURN(0);
}

void mysql_free_explain_info(explain_info_t* explain)
{
    select_info_t* select_info;
    select_info_t* select_info_next;
    int    i = 0;

    DBUG_ENTER("mysql_free_explain_info");

    if (explain == NULL)
        DBUG_VOID_RETURN;

    select_info = LIST_GET_FIRST(explain->field_lst);
    while (select_info != NULL)
    {
        i = 0;
        select_info_next = LIST_GET_NEXT(link, select_info);
        if (select_info->extra != NULL)
        {
            free(select_info->extra);
        }

        if (select_info->possible_keys != NULL)
        {
            while (select_info->possible_keys[i])
            {
                free(select_info->possible_keys[i++]);
            }
        }

        my_free(select_info);
        select_info = select_info_next;
    }

    my_free(explain);
    DBUG_VOID_RETURN;
}

int mysql_anlyze_explain(
    THD*   thd,
    explain_info_t* explain
)
{
    int    err = 0;
    int    select_count;
    select_info_t* select_node;

    DBUG_ENTER("mysql_anlyze_explain");

    select_count = LIST_GET_LEN(explain->field_lst);

    select_node = LIST_GET_FIRST(explain->field_lst);
    if (select_node != NULL)
        thd->affected_rows = select_node->rows;

    while (select_node != NULL)
    {
        if ((thd->lex->sql_command == SQLCOM_DELETE ||
              thd->lex->sql_command == SQLCOM_UPDATE) && 
              select_node->rows >= (int)inception_max_update_rows)
        {
            my_error(ER_UDPATE_TOO_MUCH_ROWS, MYF(0), inception_max_update_rows);
            DBUG_RETURN(TRUE);
        }
        select_node = LIST_GET_NEXT(link, select_node);
    }

    DBUG_RETURN(err);
}

int mysql_explain_or_analyze_statement(
    THD*    thd,
    table_info_t* table_info
)
{
    str_t  str;
    str_t*  str_select;
    explain_info_t* explain = NULL;
    Item* item;

    DBUG_ENTER("mysql_explain_or_analyze_statement");

    mysql_check_subselect_item(thd, &thd->lex->select_lex, false);
    List_iterator<Item> it(thd->lex->value_list);
    while ((item= it++))
        mysql_check_item(thd,  item, &thd->lex->select_lex);

    //如果表和列都是已经存在的，则到线上做一次EXPLAIN验证一次
    //并且返回一些可用的信息供分析
    if (!table_info->new_cache && !table_info->new_column_cache)
    {
        MYSQL*  mysql;
        char*   sql_statement;
        mysql = thd->get_audit_connection();
        str_select = str_init(&str);
        //如果是5.6版本的，则直接做一次EXPLAIN即可，而如果是5.6之下的，则需要拼成查询语句
        //但有时候不一定能完全转换
        if (mysql_check_version_56(thd))
        {
            sql_statement = thd_query_with_length(thd);
            str_append(str_select, "EXPLAIN ");
            str_append(str_select, sql_statement);
            mysql_get_explain_info(thd, mysql, str_get(str_select), &explain, TRUE, table_info->db_name);
            my_free(sql_statement);
            str_deinit(str_select);
        }
        else
        {
            if (mysql_make_select_sql(thd, table_info, str_select))
            {
                str_deinit(str_select);
                goto err2;
            }

            mysql_get_explain_info(thd, mysql, str_get(str_select), &explain, FALSE, table_info->db_name);
            str_deinit(str_select);
        }

        mysql_anlyze_explain(thd, explain);
    }

err2:
    mysql_errmsg_append(thd);
    mysql_free_explain_info(explain);
    DBUG_RETURN(false);
}

int mysql_check_delete(THD *thd)
{
    table_info_t* table_info;
    int tablenotexisted = false;
    TABLE_LIST *table;

    DBUG_ENTER("mysql_check_delete");

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT){
        mysql_add_split_sql_node(thd, thd->lex->query_tables->db,
                                 thd->lex->query_tables->table_name, MYSQLDML, 
                                 thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    if (thd->lex->sql_command == SQLCOM_DELETE_MULTI)
    {
        for (table=thd->lex->query_tables; table; table=table->next_global)
        {
            table_info = mysql_get_table_object(thd, table->db, table->table_name, TRUE);
            if (table_info == NULL) {
                tablenotexisted=true;
            }
        }
    }

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (tablenotexisted || table_info == NULL)
        DBUG_RETURN(FALSE);

    mysql_check_ddldml_coexisted(thd, table_info, MYSQLDML);
    if (thd->lex->select_lex.where == NULL)
    {
        my_error(ER_NO_WHERE_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.select_limit != NULL)
    {
        my_error(ER_WITH_LIMIT_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.order_list.elements != 0)
    {
        my_error(ER_WITH_ORDERBY_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }

    mysql_explain_or_analyze_statement(thd, table_info);

    DBUG_RETURN(FALSE);
}

int mysql_inception_local_show(THD* thd)
{
    return mysql_local_show_variables(thd, false);
}

int mysql_inception_local_showall(THD* thd)
{
    return mysql_local_show_variables(thd, true);
}

int mysql_execute_inception_osc_abort(THD* thd)
{
    DBUG_ENTER("mysql_execute_inception_osc_abort");
    int res= 0;
    LEX *lex= thd->lex;
    const char *wild= lex->wild ? lex->wild->ptr() : NullS;
    osc_percent_cache_t* osc_percent_node;

    mysql_mutex_lock(&osc_mutex); 
    osc_percent_node = LIST_GET_FIRST(global_osc_cache.osc_lst);
    while(osc_percent_node)
    {
        if (!strcasecmp(osc_percent_node->sqlsha1, wild))
            break;
        osc_percent_node = LIST_GET_NEXT(link, osc_percent_node);        
    }

    if (osc_percent_node && osc_percent_node->proc && osc_percent_node->percent != 100)
    {
        osc_percent_node->killed= 1;
        osc_percent_node->proc->killpid();
    }
    else
        my_error(ER_OSC_KILL_FAILED, MYF(0));

    mysql_mutex_unlock(&osc_mutex);
    DBUG_RETURN(res);
}

int mysql_execute_inception_processlist(THD *thd,bool verbose)
{
    List<Item> field_list;
    Mem_root_array<thread_info*, true> thread_infos(thd->mem_root);
    ulong max_query_length= (verbose ? thd->variables.max_allowed_packet : PROCESS_LIST_WIDTH);
    Protocol *protocol= thd->protocol;
    DBUG_ENTER("mysql_execute_inception_processlist");

    field_list.push_back(new Item_int(NAME_STRING("Id"), 0, MY_INT64_NUM_DECIMAL_DIGITS));
    field_list.push_back(new Item_empty_string("dest_user",16));//目标数据库用户名
    field_list.push_back(new Item_empty_string("dest_host",FN_REFLEN));//目标主机
    field_list.push_back(new Item_return_int("dest_port",20, MYSQL_TYPE_LONG));//目标端口
    field_list.push_back(new Item_empty_string("from_host",FN_REFLEN));//连接来源主机
    field_list.push_back(new Item_empty_string("Command",16));//操作类型
    field_list.push_back(new Item_empty_string("STATE",16));//操作类型
    field_list.push_back(new Item_return_int("Time",20, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("Info",max_query_length));
    if (protocol->send_result_set_metadata(&field_list,
        Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
        DBUG_RETURN(false);

    if (!thd->killed)
    {
        mysql_mutex_lock(&LOCK_thread_count);
        thread_infos.reserve(get_thread_count());
        Thread_iterator it= global_thread_list_begin();
        Thread_iterator end= global_thread_list_end();
        for (; it != end; ++it)
        {
            THD *tmp= *it;
            Security_context *tmp_sctx= tmp->security_ctx;
            thread_info *thd_info= new thread_info;

            //id
            thd_info->thread_id=tmp->thread_id;
            //from host
            if (tmp->peer_port && (tmp_sctx->host || tmp_sctx->ip) &&
                thd->security_ctx->host_or_ip[0])
            {
                if ((thd_info->host= (char*) thd->alloc(LIST_PROCESS_HOST_LEN+1)))
                    my_snprintf((char *) thd_info->host, LIST_PROCESS_HOST_LEN,
                        "%s:%u", tmp_sctx->host_or_ip, tmp->peer_port);
            }
            else
                thd_info->host= thd->strdup(tmp_sctx->host_or_ip[0] ? 
                    tmp_sctx->host_or_ip : tmp_sctx->host ? tmp_sctx->host : "");
            //command 
            if (tmp->thd_sinfo)
            {
                thd_info->command=(int) tmp->thd_sinfo->optype;
                thd_info->dest_port = (int)tmp->thd_sinfo->port;
                thd_info->dest_host = tmp->thd_sinfo->host;
                thd_info->dest_user= tmp->thd_sinfo->user;
            }
            
            thd_info->state = tmp->thread_state;
            //info
            if (tmp->query())
            {
                uint length= min<uint>(max_query_length, tmp->query_length());
                char *q= thd->strmake(tmp->query(),length);
                thd_info->query_string= CSET_STRING(q, q ? length : 0, tmp->query_charset());
            }
            mysql_mutex_unlock(&tmp->LOCK_thd_data);
            thd_info->start_time= tmp->start_time.tv_sec;
            thread_infos.push_back(thd_info);
        }
        mysql_mutex_unlock(&LOCK_thread_count);
    }

    // Return list sorted by thread_id.
    std::sort(thread_infos.begin(), thread_infos.end(), thread_info_compare());

    time_t now= my_time(0);
    for (size_t ix= 0; ix < thread_infos.size(); ++ix)
    {
        thread_info *thd_info= thread_infos.at(ix);
        protocol->prepare_for_resend();
        protocol->store((ulonglong) thd_info->thread_id);
        protocol->store(thd_info->dest_user, system_charset_info);
        protocol->store(thd_info->dest_host, system_charset_info);
        protocol->store_long (thd_info->dest_port);
        protocol->store(thd_info->host, system_charset_info);
        //command
        if (thd_info->command == INCEPTION_TYPE_CHECK)
            protocol->store("CHECK", system_charset_info);
        else if (thd_info->command == INCEPTION_TYPE_EXECUTE)
            protocol->store("EXECUTE", system_charset_info);
        else if (thd_info->command == INCEPTION_TYPE_SPLIT)
            protocol->store("SPLIT", system_charset_info);
        else if (thd_info->command == INCEPTION_TYPE_PRINT)
            protocol->store("PRINT", system_charset_info);
        else 
            protocol->store("LOCAL", system_charset_info);

        //state
        if (thd_info->state == INCEPTION_STATE_INIT)
            protocol->store("INIT", system_charset_info);
        else if (thd_info->state == INCEPTION_STATE_CHECKING)
            protocol->store("CHECKING", system_charset_info);
        else if (thd_info->state == INCEPTION_STATE_EXECUTING)
            protocol->store("EXECUTING", system_charset_info);
        else if (thd_info->state == INCEPTION_STATE_DEINIT)
            protocol->store("DEINIT", system_charset_info);
        else if (thd_info->state == INCEPTION_STATE_BACKUP)
            protocol->store("BACKUP", system_charset_info);

        //time
        if (thd_info->start_time)
            protocol->store_long ((longlong) (now - thd_info->start_time));
        else
            protocol->store_null();

        //info
        protocol->store(thd_info->query_string.str(), thd_info->query_string.charset());
        if (protocol->write())
            break; /* purecov: inspected */
    }
    my_eof(thd);
    DBUG_RETURN(false);
}

int mysql_execute_inception_osc_processlist(THD* thd)
{
    DBUG_ENTER("mysql_execute_inception_osc_processlist");
    int res= 0;
    osc_percent_cache_t* osc_percent_node;
    List<Item>    field_list;
    Protocol *    protocol= thd->protocol;

    field_list.push_back(new Item_empty_string("DBNAME", FN_REFLEN));
    field_list.push_back(new Item_empty_string("TABLENAME", FN_REFLEN));
    field_list.push_back(new Item_empty_string("COMMAND", FN_REFLEN));
    field_list.push_back(new Item_empty_string("SQLSHA1", FN_REFLEN));
    field_list.push_back(new Item_return_int("PERCENT", 20, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("REMAINTIME", FN_REFLEN));
    field_list.push_back(new Item_empty_string("INFOMATION", FN_REFLEN));

    if (protocol->send_result_set_metadata(&field_list,
          Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
        DBUG_RETURN(true);

    mysql_mutex_lock(&osc_mutex); 

    osc_percent_node = LIST_GET_FIRST(global_osc_cache.osc_lst);
    while(osc_percent_node)
    {
        protocol->prepare_for_resend();
        protocol->store(osc_percent_node->dbname, system_charset_info);
        protocol->store(osc_percent_node->tablename, system_charset_info);
        protocol->store(osc_percent_node->sql_cache_node->sql_statement, system_charset_info);
        protocol->store(osc_percent_node->sqlsha1, system_charset_info);
        protocol->store(osc_percent_node->percent);
        protocol->store(osc_percent_node->remaintime, system_charset_info);
        protocol->store(str_get(osc_percent_node->sql_cache_node->oscoutput), system_charset_info);

        protocol->write();

        osc_percent_node = LIST_GET_NEXT(link, osc_percent_node);        
    }

    mysql_mutex_unlock(&osc_mutex);
    my_eof(thd);
    DBUG_RETURN(res);
}

int mysql_execute_inception_osc_show(THD* thd)
{
    DBUG_ENTER("mysql_execute_inception_osc_show");
    int res= 0;
    LEX *lex= thd->lex;
    const char *wild= lex->wild ? lex->wild->ptr() : NullS;
    osc_percent_cache_t* osc_percent_node;
    List<Item>    field_list;
    Protocol *    protocol= thd->protocol;

    mysql_mutex_lock(&osc_mutex); 
    osc_percent_node = LIST_GET_FIRST(global_osc_cache.osc_lst);
    while(osc_percent_node)
    {
        if (!strcasecmp(osc_percent_node->sqlsha1, wild))
            break;

        osc_percent_node = LIST_GET_NEXT(link, osc_percent_node);        
    }
    mysql_mutex_unlock(&osc_mutex);

    if (osc_percent_node == NULL)
        DBUG_RETURN(res);

    field_list.push_back(new Item_empty_string("DBNAME", FN_REFLEN));
    field_list.push_back(new Item_empty_string("TABLENAME", FN_REFLEN));
    field_list.push_back(new Item_empty_string("SQLSHA1", FN_REFLEN));
    field_list.push_back(new Item_return_int("PERCENT", 20, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("REMAINTIME", FN_REFLEN));
    field_list.push_back(new Item_empty_string("INFOMATION", FN_REFLEN));

    if (protocol->send_result_set_metadata(&field_list,
          Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    {
        DBUG_RETURN(true);
    }

    if (osc_percent_node)
    {
        mysql_mutex_lock(&osc_mutex); 
        protocol->prepare_for_resend();
        protocol->store(osc_percent_node->dbname, system_charset_info);
        protocol->store(osc_percent_node->tablename, system_charset_info);
        protocol->store(osc_percent_node->sqlsha1, system_charset_info);
        protocol->store(osc_percent_node->percent);
        protocol->store(osc_percent_node->remaintime, system_charset_info);
        protocol->store(str_get(osc_percent_node->sql_cache_node->oscoutput), system_charset_info);
        mysql_mutex_unlock(&osc_mutex);

        protocol->write();
    }

    my_eof(thd);
    DBUG_RETURN(res);
}

int mysql_inception_remote_show(THD* thd)
{
    char sql[100];
    char* exesql;
    MYSQL*  mysql;
    MYSQL_ROW       source_row;
    int             n_fields;
    MYSQL_RES *     source_res;
    int i;

    DBUG_ENTER("mysql_inception_remote_show");

    exesql = thd_query_with_length(thd);

    str_truncate(thd->show_result, str_get_len(thd->show_result));

    mysql= thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        my_free(exesql);
        DBUG_RETURN(TRUE);
    }

    if (thd->thd_sinfo->db[0] != '\0')
    {
        sprintf(sql, "USE `%s`", thd->thd_sinfo->db);
        if (mysql_real_query(mysql, sql, strlen(sql)))
        {
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
            mysql_errmsg_append(thd);
            my_free(exesql);
            DBUG_RETURN(TRUE);
        }
    }

    if (mysql_real_query(mysql, exesql + strlen("inception")/*skip inception*/, 
          thd->query_length() - strlen("inception")))
    {
      my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
      mysql_errmsg_append(thd);
      my_free(exesql);
      DBUG_RETURN(TRUE);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(thd);
        my_free(exesql);
        DBUG_RETURN(TRUE);
    }

    source_row = mysql_fetch_row(source_res);
    n_fields = mysql_num_fields(source_res);
    while (source_row != NULL)
    {
        for (i = 0; i < n_fields; i ++)
        {
            str_append(thd->show_result, source_row[i] == NULL ? "NULL": source_row[i]);
            if (i != n_fields - 1)
                str_append(thd->show_result, " | ");
        }

        str_append(thd->show_result, "\n");
        source_row = mysql_fetch_row(source_res);
    }

    mysql_free_result(source_res);
    my_free(exesql);
    DBUG_RETURN(FALSE);
}

int mysql_execute_inception_set_command(THD* thd)
{
    int error;

    DBUG_ENTER("mysql_execute_inception_set_command");

    List_iterator_fast<set_var_base> it(thd->lex->var_list);

    set_var_base *var;
    while ((var=it++))
    {
        if ((error= var->check(thd)))
        {
            my_error(ER_WRONG_ARGUMENTS,MYF(0),"SET");
            DBUG_RETURN(FALSE);
        }

        if ((error = var->update(thd)))        // Returns 0, -1 or 1
        {
            my_error(ER_WRONG_ARGUMENTS,MYF(0),"SET");
            DBUG_RETURN(FALSE);
        }
    }

    my_ok(thd);
    DBUG_RETURN(FALSE);
}

int mysql_execute_inception_command(THD* thd)
{
    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        return false;
    }

    if (thd->lex->inception_cmd_type == INCEPTION_COMMAND_REMOTE_SHOW)
      return mysql_inception_remote_show(thd);

    if (thd->have_begin)
        return false;

    if (thd->lex->inception_cmd_type == INCEPTION_COMMAND_LOCAL_SHOWALL)
      return mysql_inception_local_showall(thd);

    if (thd->lex->inception_cmd_type == INCEPTION_COMMAND_LOCAL_SHOW)
      return mysql_inception_local_show(thd);
      
    if (thd->lex->inception_cmd_type == INCEPTION_COMMAND_LOCAL_SET)
      return mysql_execute_inception_set_command(thd);

    if (thd->lex->inception_cmd_type == INCEPTION_COMMAND_OSC_SHOW)
      return mysql_execute_inception_osc_show(thd);

    if (thd->lex->inception_cmd_type == INCEPTION_COMMAND_OSC_PROCESSLIST)
      return mysql_execute_inception_osc_processlist(thd);

    if (thd->lex->inception_cmd_type == INCEPTION_COMMAND_PROCESSLIST)
      return mysql_execute_inception_processlist(thd, thd->lex->verbose);

    if (thd->lex->inception_cmd_type == INCEPTION_COMMAND_OSC_ABORT)
      return mysql_execute_inception_osc_abort(thd);

    return false;
}

int mysql_check_update(THD *thd)
{
    table_info_t* table_info;
    int tablenotexisted=false;
    TABLE_LIST *table;

    DBUG_ENTER("mysql_check_update");

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        mysql_add_split_sql_node(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, MYSQLDML, 
            thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    if (thd->lex->sql_command == SQLCOM_UPDATE_MULTI)
    {
        for (table=thd->lex->query_tables; table; table=table->next_global)
        {
            table_info = mysql_get_table_object(thd, table->db, table->table_name, TRUE);
            if (table_info == NULL) {
                tablenotexisted=true;
            }
        }
    }

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (tablenotexisted || table_info == NULL)
        DBUG_RETURN(FALSE);

    mysql_check_ddldml_coexisted(thd, table_info, MYSQLDML);
    if (thd->lex->select_lex.where == NULL)
    {
        my_error(ER_NO_WHERE_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.select_limit != NULL)
    {
        my_error(ER_WITH_LIMIT_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.order_list.elements != 0)
    {
        my_error(ER_WITH_ORDERBY_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }

    mysql_explain_or_analyze_statement(thd, table_info);

    DBUG_RETURN(FALSE);
}

int mysql_check_table_existed(THD* thd)
{
    int nr=0;
    LEX  *lex= thd->lex;
    TABLE_LIST *all_tables;
    all_tables= lex->query_tables;
    TABLE_LIST *table;
    table_info_t* table_info;

    for (table=all_tables; table; table=table->next_global, nr++)
    {
        table_info = mysql_get_table_object_from_cache(thd, table->db, table->table_name);
        if (table_info == NULL) {
            my_error(ER_TABLE_NOT_EXISTED_ERROR, MYF(0), table->table_name);
            mysql_errmsg_append(thd);
        }
    }

    return false;
}

int mysql_check_table_new_cache(THD* thd)
{
    int nr=0;
    LEX  *lex= thd->lex;
    TABLE_LIST *all_tables;
    all_tables= lex->query_tables;
    TABLE_LIST *table;
    table_info_t* table_info;

    for (table=all_tables; table; table=table->next_global, nr++)
    {
        table_info = mysql_get_table_object(thd, table->db, table->table_name, FALSE);
        if (table_info != NULL && table_info->new_cache) {
            return true;
        }
    }

    return false;
}

int mysql_check_select(THD *thd)
{
    explain_info_t* explain = NULL;
    ORDER*   order;
    char*   explain_str=NULL;
    char*           sql = NULL;

    DBUG_ENTER("mysql_check_select");

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        DBUG_RETURN(false);
    }

    if (thd->lex->select_lex.where == NULL)
    {
        if (thd->lex->current_select->item_list.elements == 1)
        {
            Item *m_expr_item;
            m_expr_item= thd->lex->select_lex.item_list.head();
            if (dynamic_cast<Item_func_database*>(m_expr_item))
            {
                DBUG_RETURN(FALSE);
            }

        }

        my_error(ER_NO_WHERE_CONDITION, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.with_wild != 0)
    {
        my_error(ER_SELECT_ONLY_STAR, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (thd->lex->select_lex.order_list.elements != 0)
    {
        for (order= thd->lex->select_lex.order_list.first ; order; order= order->next)
        {
            if (dynamic_cast <Item_func_rand*>(*order->item))
            {
                my_error(ER_ORDERY_BY_RAND, MYF(0));
                mysql_errmsg_append(thd);
            }
        }
    }

    mysql_free_explain_info(explain);
    my_free(explain_str);
    my_free(sql);
    DBUG_RETURN(FALSE);
}

void
mysql_set_cache_new_column_type(field_info_t* field_info, Create_field*   field)
{
    switch(field->sql_type)
    {
    case MYSQL_TYPE_DECIMAL:
    case MYSQL_TYPE_NEWDECIMAL:
        char coltype[30];
        sprintf(coltype, "decimal(%d, %d)", my_decimal_length_to_precision(field->length,
                            field->decimals, field->flags & UNSIGNED_FLAG), field->decimals);
        strcpy(field_info->data_type, coltype);
        break;
    case MYSQL_TYPE_INT24:
    case MYSQL_TYPE_LONG:
        strcpy(field_info->data_type, "INT");
        break;
    case MYSQL_TYPE_TINY:
        strcpy(field_info->data_type, "TINYINT");
        break;
    case MYSQL_TYPE_SHORT:
        strcpy(field_info->data_type, "SMALLINT");
        break;
    case MYSQL_TYPE_DOUBLE:
    case MYSQL_TYPE_FLOAT:
        strcpy(field_info->data_type, "DOUBLE");
        break;
    case MYSQL_TYPE_TIMESTAMP:
    case MYSQL_TYPE_TIMESTAMP2:
        strcpy(field_info->data_type, "TIMESTAMP");
        break;
    case MYSQL_TYPE_LONGLONG:
        strcpy(field_info->data_type, "BIGINT");
        break;
    case MYSQL_TYPE_DATE:
        strcpy(field_info->data_type, "DATE");
        break;
    case MYSQL_TYPE_TIME:
    case MYSQL_TYPE_TIME2:
        strcpy(field_info->data_type, "TIME");
        break;
    case MYSQL_TYPE_DATETIME2:
    case MYSQL_TYPE_DATETIME:
        strcpy(field_info->data_type, "DATETIME");
        break;
    case MYSQL_TYPE_VARCHAR:
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_STRING:
        {
            char coltype[20];
            sprintf(coltype, "VARCHAR(%d)", (int)field->length);
            strcpy(field_info->data_type, coltype);
            break;
        }
    case MYSQL_TYPE_TINY_BLOB:
        strcpy(field_info->data_type, "TINYBLOB");
        break;
    case MYSQL_TYPE_MEDIUM_BLOB:
        strcpy(field_info->data_type, "MEDIUMBLOB");
        break;
    case MYSQL_TYPE_LONG_BLOB:
        strcpy(field_info->data_type, "LONGBLOB");
        break;
    case MYSQL_TYPE_BLOB:
        strcpy(field_info->data_type, "BLOB");
        break;
    default:
        strcpy(field_info->data_type, "UNKNOWN");
        break;
    }
}

field_info_t* mysql_cache_new_column(table_info_t* table_info, Create_field*   field)
{
    field_info_t* field_info;

    field_info = (field_info_t*)malloc(sizeof(field_info_t));

    memset(field_info, 0, sizeof(field_info_t));
    strcpy(field_info->field_name, field->field_name);
    field_info->nullable = (field->flags & NOT_NULL_FLAG) ? FALSE : TRUE;

    field_info->primary_key = FALSE;
    field_info->max_length = field->length;
    table_info->new_column_cache = TRUE;
    field_info->auto_increment = FALSE;
    field_info->real_type = field->sql_type;
    field_info->charset = (CHARSET_INFO*)field->charset;
    mysql_set_cache_new_column_type(field_info,field);

    LIST_ADD_LAST(link, table_info->field_lst, field_info);
    return field_info;
}


int mysql_cache_new_table(THD *thd, Alter_info* alter_info_ptr)
{
    SELECT_LEX *select_lex= &thd->lex->select_lex;
    TABLE_LIST *create_table= select_lex->table_list.first;

    Create_field *sql_field;
    table_info_t*   table_info;

    DBUG_ENTER("mysql_cache_new_table");

    //check if table is deleted, if yes, then delete it
    table_info = mysql_get_table_object_from_cache(thd, 
                create_table->db, create_table->table_name);
    if (table_info && table_info->isdeleted)
    {
        LIST_REMOVE(link, thd->tablecache.tablecache_lst, table_info);
        mysql_table_info_free(table_info);
    }

    //free memory
    table_info = (table_info_t*)malloc(sizeof(table_info_t));
    memset(table_info, 0, sizeof(table_info_t));
    LIST_INIT(table_info->field_lst);

    strcpy(table_info->table_name, create_table->table_name);
    strcpy(table_info->db_name, create_table->db);

    List_iterator<Create_field> it(alter_info_ptr->create_list);
    it.rewind();
    while ((sql_field=it++))
    {
        mysql_cache_new_column(table_info, sql_field);
    }

    mysql_add_table_object(thd, table_info);

    table_info->new_cache = true;

    DBUG_RETURN(FALSE);
}

int mysql_show_create_table(THD* thd, char*  dbname, char* tablename, str_t* create_str)
{
    char        tmp_buf[256];
    MYSQL*          mysql;
    MYSQL_RES *     source_res;
    MYSQL_ROW       source_row;

    sprintf(tmp_buf, "SHOW CREATE TABLE `%s`.`%s`;", dbname, tablename);

    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        return false;
    }

    if (mysql_real_query(mysql, tmp_buf, strlen(tmp_buf)))
        return false;

    if ((source_res = mysql_store_result(mysql)) == NULL)
        return 0;

    if (create_str != NULL && (source_row = mysql_fetch_row(source_res)) != NULL)
        str_append(create_str, source_row[1]); 

    str_append(create_str, ";"); 
    mysql_free_result(source_res);
    return true;
}

int mysql_table_is_existed(THD* thd, char*  dbname, char* tablename)
{
    char        tmp_buf[256];
    MYSQL*          mysql;
    MYSQL_RES *     source_res;

    sprintf(tmp_buf, "DESC `%s`.`%s`;", dbname, tablename);

    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        return false;
    }

    if (mysql_real_query(mysql, tmp_buf, strlen(tmp_buf)))
        return false;

    if ((source_res = mysql_store_result(mysql)) == NULL)
        return 0;

    mysql_free_result(source_res);
    return true;
}

int mysql_check_charset(const char* charsetname)
{
    char*   strToken;
    char*   charset;
    int     ret= true;

    if (inception_support_charset == NULL)
        return true;
    
    charset = (char*)my_malloc(strlen (inception_support_charset) + 1, MY_ZEROFILL);
    strcpy(charset, inception_support_charset);
    if ((strToken = strtok(charset, ",")) == NULL)
    {
        ret = true;
        goto err;
    }

    while (strToken && strcasecmp(charsetname, strToken))
        strToken=strtok(NULL, ",");

    if (strToken == NULL)
    {
        ret = false;
        goto err;
    }

err:
    my_free(charset);
    return ret;
}

int mysql_check_db_existed(
    THD *  thd,
    char*  db_name
)
{
    char  desc_sql[256];
    MYSQL_RES * source_res;
    MYSQL_ROW source_row;
    MYSQL*  mysql;
    int   found=FALSE;
    dbinfo_t* dbinfo;

    DBUG_ENTER("mysql_check_db_existed");

    dbinfo = LIST_GET_FIRST(thd->dbcache.dbcache_lst);
    while (dbinfo != NULL)
    {
        if (!strcasecmp(dbinfo->dbname, db_name))
            DBUG_RETURN(FALSE);

        dbinfo = LIST_GET_NEXT(link, dbinfo);
    }

    sprintf(desc_sql, "show databases;");

    if ((mysql = thd->get_audit_connection()) == NULL)
        DBUG_RETURN(true);

    if (mysql_real_query(mysql, desc_sql, strlen(desc_sql)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    source_row = mysql_fetch_row(source_res);
    while (source_row != NULL)
    {
        if (strcasecmp(source_row[0], db_name) == 0)
        {
            found = TRUE;
            break;
        }

        source_row = mysql_fetch_row(source_res);
    }

    mysql_free_result(source_res);
    DBUG_RETURN(!found);
}

int mysql_check_create_table(THD *thd)
{
    uint db_options= 0; /* not used */
    KEY *key_info_buffer= NULL;
    uint key_count;
    char    tmp_buf[256];

    DBUG_ENTER("mysql_check_create_table");

    SELECT_LEX *select_lex= &thd->lex->select_lex;

    TABLE_LIST *create_table= select_lex->table_list.first;

    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    HA_CREATE_INFO* create_info_ptr = &create_info;
    thd->timestamp_count = 0;

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        mysql_add_split_sql_node(thd, create_table->db, create_table->table_name, MYSQLDDL, 
            thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    //only when execute, generate the rollback sql statement
    if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE)
    {
        sprintf(tmp_buf, "DROP TABLE `%s`.`%s`;", create_table->db, create_table->table_name);
        str_append(&thd->ddl_rollback, tmp_buf);
    }

    //用来检查类似使用create table db.table的语句来创建表时
    //在db本身不存在的情况下，没有报错的情况，因为下面只检查
    //db.table是不是存在，所以没有检查库是不是存在
    if (mysql_check_db_existed(thd, create_table->db))
    {
        my_error(ER_DB_NOT_EXISTED_ERROR, MYF(0), create_table->db);
        mysql_errmsg_append(thd);
    }
    
    if (mysql_get_table_object(thd, create_table->db, create_table->table_name, FALSE))
    {
        my_error(ER_TABLE_EXISTS_ERROR, MYF(0), create_table->table_name);
        mysql_errmsg_append(thd);
    }

    //to do: cache the new table object, so that inception can find this table when insert
    if (create_info_ptr->options & HA_LEX_CREATE_TABLE_LIKE)
    {
        table_info_t* table_info = mysql_get_table_object(thd, create_table->next_global->db, 
              create_table->next_global->table_name, TRUE);
        if (!table_info)
        {
            mysql_errmsg_append(thd);
            DBUG_RETURN(TRUE);
        }

        table_info = mysql_copy_table_info(table_info);
        strcpy(table_info->db_name, create_table->db);
        strcpy(table_info->table_name, create_table->table_name);
        mysql_add_table_object(thd, table_info);
        DBUG_RETURN(FALSE);
    }

    if (check_column_name(create_table->table_name, 0))
    {
        my_error(ER_WRONG_DB_NAME, MYF(0), create_table->table_name);
        mysql_errmsg_append(thd);
    }

    if (create_info_ptr->options & HA_LEX_CREATE_TMP_TABLE)
    {
        if (strncmp("tmp", create_table->table_name, 3) != 0)
        {
            my_error(ER_TEMP_TABLE_TMP_PREFIX, MYF(0));
            mysql_errmsg_append(thd);
        }
    }

    if (create_info_ptr->db_type != (handlerton *)DB_TYPE_INNODB)
    {
        my_error(ER_TABLE_MUST_INNODB, MYF(0), create_table->table_name);
        mysql_errmsg_append(thd);
    }

    if (create_info_ptr->default_table_charset == NULL ||
        !mysql_check_charset(create_info_ptr->default_table_charset->csname))
    {
        my_error(ER_TABLE_CHARSET_MUST_UTF8, MYF(0), 
            inception_support_charset, create_table->table_name);
        mysql_errmsg_append(thd);
    }

    if (create_info_ptr->comment.length == 0)
    {
        my_error(ER_TABLE_MUST_HAVE_COMMENT, MYF(0), create_table->table_name);
        mysql_errmsg_append(thd);
    }

    if(thd->lex->part_info != NULL)
    {
        my_error(ER_PARTITION_NOT_ALLOWED, MYF(0));
        mysql_errmsg_append(thd);
    }

    if (mysql_prepare_create_table(thd, &create_info,
        &alter_info,
        (create_info_ptr->options & HA_LEX_CREATE_TMP_TABLE),
        &db_options,
        NULL, &key_info_buffer,
        &key_count, 0))
        DBUG_RETURN(true);

    mysql_cache_new_table(thd, &alter_info);
    DBUG_RETURN(FALSE);
}

void
mysql_check_index_attribute(
    THD *           thd,
    Key*            key,
    char*           table_name
)
{
    if (key->type == Key::PRIMARY)
        return;

    if (key->name.str == NULL)
    {
        my_error(ER_WRONG_NAME_FOR_INDEX, MYF(0), "NULL", table_name);
        mysql_errmsg_append(thd);
    }

    if (key->name.str  && (key->type != Key::PRIMARY) &&
        !my_strcasecmp(system_charset_info, key->name.str, primary_key_name))
    {
        my_error(ER_WRONG_NAME_FOR_INDEX, MYF(0), key->name.str, table_name);
        mysql_errmsg_append(thd);
    }

    if (key->name.str && check_column_name(key->name.str, 0))
    {
        my_error(ER_WRONG_NAME_FOR_INDEX, MYF(0), key->name.str, table_name);
        mysql_errmsg_append(thd);
    }

    if (key->name.str)
    {
        if (key->type == Key::FOREIGN_KEY)
        {
            my_error(ER_FOREIGN_KEY, MYF(0), table_name);
            mysql_errmsg_append(thd);
        }
        else if (key->type == Key::UNIQUE)
        {
            if (strncasecmp(key->name.str, "uniq_", 5) != 0)
            {
                my_error(ER_INDEX_NAME_UNIQ_PREFIX, MYF(0), key->name.str, table_name);
                mysql_errmsg_append(thd);
            }
        }
        else if (key->type != Key::PRIMARY)
        {
            if (strncasecmp(key->name.str, "idx_", 4) != 0)
            {
                my_error(ER_INDEX_NAME_IDX_PREFIX, MYF(0), key->name.str, table_name);
                mysql_errmsg_append(thd);
            }
        }
    }

    if (key->columns.elements > inception_max_key_parts)
    {
        my_error(ER_TOO_MANY_KEY_PARTS, MYF(0), key->name.str, 
            table_name, inception_max_key_parts);
        mysql_errmsg_append(thd);
    }
}

int mysql_field_is_blob(
    enum enum_field_types real_type
)
{
    if (real_type== MYSQL_TYPE_BLOB ||
      real_type== MYSQL_TYPE_TINY_BLOB ||
      real_type== MYSQL_TYPE_MEDIUM_BLOB ||
      real_type== MYSQL_TYPE_LONG_BLOB)
    {
        return TRUE;
    }

    return FALSE;
}

int mysql_check_create_index(THD *thd)
{
    Key*   key;
    Key_part_spec * col1;
    field_info_t*   field_node;
    table_info_t*   table_info;
    int             found;
    char            tmp_buf[256];
    MYSQL*          mysql;
    MYSQL_RES *     source_res;
    char            sql[1024];
    MYSQL_ROW       source_row;

    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    Alter_info* alter_info_ptr = &alter_info;

    List_iterator<Key> key_iterator(alter_info_ptr->key_list);

    DBUG_ENTER("mysql_check_create_index");

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    mysql= thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);
    }

    if (!table_info->new_cache)
    {
        sprintf(sql, "SHOW INDEX FROM `%s`.`%s`;", thd->lex->query_tables->db,
                thd->lex->query_tables->table_name);
        if (mysql_real_query(mysql, sql, strlen(sql)))
        {
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
            mysql_errmsg_append(thd);
        }

        if ((source_res = mysql_store_result(mysql)) == NULL)
        {
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
            mysql_errmsg_append(thd);
        }
    }

    while ((key=key_iterator++))
    {
        List_iterator<Key_part_spec> col_it(key->columns);

        uint keymaxlen=0;
        mysql_check_index_attribute(thd, key, table_info->table_name);
        while ((col1= col_it++))
        {
            found = 0;
            field_node = LIST_GET_FIRST(table_info->field_lst);
            while (field_node != NULL)
            {
                if (!strcasecmp(field_node->field_name, col1->field_name.str))
                {
                    if (field_node->charset && col1->length)
                    {
                        CHARSET_INFO* charset;
                        charset= get_charset(field_node->charsetnr, MYF(0));
                        if (!charset)
                            charset= get_charset(field_node->charset->number, MYF(0));
                          
                        keymaxlen += min(field_node->max_length, col1->length * charset->mbmaxlen);
                    }
                    else
                    {
                        keymaxlen += field_node->max_length;
                    }

                    found = TRUE;
                    break;
                }

                field_node = LIST_GET_NEXT(link, field_node);
            }

            if (!found)
            {
                my_error(ER_COLUMN_NOT_EXISTED, MYF(0), col1->field_name.str);
                mysql_errmsg_append(thd);
            } 
            else if (mysql_field_is_blob(field_node->real_type))
            {
                my_error(ER_BLOB_USED_AS_KEY, MYF(0), col1->field_name.str);
                mysql_errmsg_append(thd);
            }
        }

        if (keymaxlen > MAX_KEY_LENGTH)
        {
            my_error(ER_TOO_LONG_KEY,MYF(0),key->name.str, MAX_KEY_LENGTH); 
            mysql_errmsg_append(thd);
        }

        if (!table_info->new_cache)
        {
            source_row = mysql_fetch_row(source_res);
            while (source_row)
            {
                if (key->name.str &&
                        ((Key::PRIMARY != key->type && !strcasecmp(source_row[2], key->name.str)) ||
                         (Key::PRIMARY == key->type && !strcasecmp(source_row[2], "PRIMARY"))))
                {
                    my_error(ER_DUP_INDEX, MYF(0), source_row[2],
                            table_info->db_name, table_info->table_name);
                    mysql_errmsg_append(thd);
                    //找到之后，当前索引扫描就结束了，因为show出来的结果中
                    //如果有多个列的索引，则出现多次
                    break;
                }

                source_row = mysql_fetch_row(source_res);
            }
            //reset source_res to start
            mysql_data_seek2(source_res, 0);
        }

        if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE && key->name.str != NULL)
        {
            sprintf(tmp_buf, "DROP INDEX `%s`", key->name.str);
            str_append(&thd->ddl_rollback, tmp_buf);
            str_append(&thd->ddl_rollback, ",");
        }
    }

    if (!table_info->new_cache)
        mysql_free_result(source_res);
    DBUG_RETURN(FALSE);
}

int mysql_check_column_default(
    THD* thd,
    Item *default_value,
    uint flags,
    field_info_t* field_info,
    const char*   field_name,
    enum enum_field_types real_type
)
{
    if (default_value && field_name)
    {
        if (default_value->type() != Item::NULL_ITEM)
        {
            if (mysql_field_is_blob(real_type))
            {
                my_error(ER_BLOB_CANT_HAVE_DEFAULT, MYF(0), field_name);
                mysql_errmsg_append(thd);
            }
        }

        if (!mysql_check_version_56(thd))
        {
            if ((real_type == MYSQL_TYPE_DATETIME2 || real_type == MYSQL_TYPE_DATETIME)  && 
                default_value->type() == Item::FUNC_ITEM &&
                (static_cast<Item_func*>(default_value)->functype() == Item_func::NOW_FUNC))
            {
                my_error(ER_INVALID_DEFAULT, MYF(0), field_name);
                mysql_errmsg_append(thd);
            }
        }
        
        if ((flags & NOT_NULL_FLAG) && default_value->type() == Item::NULL_ITEM)
        {
            my_error(ER_INVALID_DEFAULT, MYF(0), field_name);
            mysql_errmsg_append(thd);
        }

        if (default_value->type() == Item::FUNC_ITEM &&
            (static_cast<Item_func*>(default_value)->functype() !=
            Item_func::NOW_FUNC))
        {
            my_error(ER_INVALID_DEFAULT, MYF(0), field_name);
            mysql_errmsg_append(thd);
        }
        else if (field_info && default_value->type() == Item::NULL_ITEM)
        {
            if (!field_info->nullable || field_info->primary_key || 
                (flags & (NOT_NULL_FLAG | AUTO_INCREMENT_FLAG)) == NOT_NULL_FLAG)
            {
                my_error(ER_INVALID_DEFAULT, MYF(0), field_name);
                mysql_errmsg_append(thd);
            }
        }
        else if (field_info && (field_info->auto_increment || flags & AUTO_INCREMENT_FLAG))
        {
            my_error(ER_INVALID_DEFAULT, MYF(0), field_name);
            mysql_errmsg_append(thd);
        }

        //检查非法时间值
        if ((default_value->type() == Item::INT_ITEM ||
            default_value->type() == Item::STRING_ITEM ||
            default_value->type() == Item::DECIMAL_ITEM) &&
           (real_type == MYSQL_TYPE_TIMESTAMP2 || 
            real_type == MYSQL_TYPE_DATETIME ||
            real_type == MYSQL_TYPE_DATETIME2 ||
            real_type == MYSQL_TYPE_DATE||
            real_type == MYSQL_TYPE_TIME||
            real_type == MYSQL_TYPE_TIME2 ||
            real_type == MYSQL_TYPE_NEWDATE||
            real_type == MYSQL_TYPE_TIMESTAMP))
        {
            MYSQL_TIME ltime;
            MYSQL_TIME_STATUS status={0};
            MYSQL_TIME_STATUS status2={0};
            uchar buff[MAX_FIELD_WIDTH];
            String buffer((char*) buff,sizeof(buff),&my_charset_bin);
            Item_string* itemstr;
            itemstr = (Item_string*)default_value;
            String *res = itemstr->val_str(&buffer);
            struct timeval tm;
        
            if (real_type == MYSQL_TYPE_TIME ||
                real_type == MYSQL_TYPE_TIME2)
                str_to_time(system_charset_info, res->ptr(), res->length(), &ltime, 0, &status);
            else
                str_to_datetime(system_charset_info, res->ptr(), res->length(), &ltime, 
                    MODE_NO_ZERO_DATE|MODE_NO_ZERO_IN_DATE, &status);
            //在上面没有检查出来的情况下，还需要对范围溢出做检查
            if (status.warnings == 0)
            {
                if (real_type == MYSQL_TYPE_TIMESTAMP || 
                    real_type == MYSQL_TYPE_TIMESTAMP2)
                    datetime_with_no_zero_in_date_to_timeval(thd, &ltime, &tm, &status2.warnings);
                if ((real_type == MYSQL_TYPE_DATE||
                    real_type == MYSQL_TYPE_NEWDATE) && non_zero_time(&ltime))
                    status2.warnings|= MYSQL_TIME_NOTE_TRUNCATED;
                if ((real_type == MYSQL_TYPE_TIME ||
                    real_type == MYSQL_TYPE_TIME2) && non_zero_date(&ltime))
                    status2.warnings|= MYSQL_TIME_NOTE_TRUNCATED;
            }

            //这里只要有警告，就是非法值，直接报警
            if (status.warnings > 0 || status2.warnings > 0)
            {
                my_error(ER_INVALID_DEFAULT, MYF(0), field_name);
                mysql_errmsg_append(thd);
            }
        }
    }

    return false;
}

int mysql_check_identified(THD* thd, char* name, int len)
{
    char*     p;
    p = name;
    int i=0;
    while (p && i < len)
    {
        if ((*p > 'Z' || *p < 'A') &&
            (*p > 'z' || *p < 'a') &&
            (*p > '9' || *p < '0') && 
            *p != '_')
        {
            my_error(ER_INVALID_IDENT, MYF(0), name);
            mysql_errmsg_append(thd);
            return 0;
        }
        i++;
        p++;
    }

    return 0;
}

int mysql_field_check(THD* thd, Create_field* field, char* table_name)
{
    if (field->sql_type == MYSQL_TYPE_SET ||
        field->sql_type == MYSQL_TYPE_ENUM ||
        field->sql_type == MYSQL_TYPE_BIT)
    {
        my_error(ER_INVALID_DATA_TYPE, MYF(0), field->field_name);
        mysql_errmsg_append(thd);
    }

    if (field->comment.length == 0)
    {
        my_error(ER_COLUMN_HAVE_NO_COMMENT, MYF(0), field->field_name, table_name);
        mysql_errmsg_append(thd);
    }

    if (field->sql_type == MYSQL_TYPE_STRING && field->length > inception_max_char_length)
    {
        my_error(ER_CHAR_TO_VARCHAR_LEN, MYF(0), field->field_name);
        mysql_errmsg_append(thd);
    }

    if (mysql_field_is_blob(field->sql_type))
    {
        my_error(ER_USE_TEXT_OR_BLOB, MYF(0), field->field_name);
        mysql_errmsg_append(thd);
    }

    field->create_length_to_internal_length();
    prepare_blob_field(thd, field);

    if (!(field->flags & NOT_NULL_FLAG) && !mysql_field_is_blob(field->sql_type))
    {
        my_error(ER_NOT_ALLOWED_NULLABLE, MYF(0), field->field_name, table_name);
        mysql_errmsg_append(thd);
    }

    if ((field->flags & NOT_NULL_FLAG) && mysql_field_is_blob(field->sql_type))
    {
        my_error(ER_TEXT_NOT_NULLABLE_ERROR, MYF(0), field->field_name, table_name);
        mysql_errmsg_append(thd);
    }

    if (check_column_name(field->field_name, 0))
    {
        my_error(ER_WRONG_COLUMN_NAME, MYF(0), field->field_name);
        mysql_errmsg_append(thd);
    }

    if ((field->flags & AUTO_INCREMENT_FLAG) != 0)
    {
        if ((field->flags & UNSIGNED_FLAG) == 0)
        {
            my_error(ER_AUTOINC_UNSIGNED, MYF(0), table_name);
            mysql_errmsg_append(thd);
        }
        if (field->pack_length < 4)
        {
            my_error(ER_SET_DATA_TYPE_INT_BIGINT, MYF(0));
            mysql_errmsg_append(thd);
        }
    }

    if (field->sql_type == MYSQL_TYPE_TIMESTAMP2 || field->sql_type == MYSQL_TYPE_TIMESTAMP)
    {
        if (field->unireg_check != Field::NONE)
            thd->timestamp_count++;
        if (field->def == NULL && (field->unireg_check == Field::NONE || 
              field->unireg_check == Field::TIMESTAMP_UN_FIELD))
        {
            my_error(ER_TIMESTAMP_DEFAULT, MYF(0), field->field_name);
            mysql_errmsg_append(thd);
        }
    }

    if (!mysql_check_version_56(thd))
    {
        if (thd->timestamp_count > 1)
        {
            my_error(ER_TOO_MUCH_AUTO_TIMESTAMP_COLS, MYF(0));
            mysql_errmsg_append(thd);
        }
        
        if (field->sql_type == MYSQL_TYPE_DATETIME ||
            field->sql_type == MYSQL_TYPE_DATETIME2)
        {
            if (Field::TIMESTAMP_UN_FIELD == field->unireg_check)
            {
                my_error(ER_INVALID_ON_UPDATE, MYF(0), field->field_name);
                mysql_errmsg_append(thd);
            }

            if (Field::TIMESTAMP_DN_FIELD == field->unireg_check || 
                Field::TIMESTAMP_DNUN_FIELD == field->unireg_check)
            {
                my_error(ER_INVALID_DEFAULT, MYF(0), field->field_name);
                mysql_errmsg_append(thd);
            }
        }
    }

    //must set the default value 
    if (!field->def && field->unireg_check != Field::TIMESTAMP_DN_FIELD && 
        field->unireg_check != Field::TIMESTAMP_DNUN_FIELD && 
        !mysql_field_is_blob(field->sql_type) && 
        (field->flags & AUTO_INCREMENT_FLAG) == 0 &&
        (field->flags & PRI_KEY_FLAG) == 0)
    {
        my_error(ER_WITH_DEFAULT_ADD_COLUMN, MYF(0), field->field_name,
            thd->lex->select_lex.table_list.first->table_name);
        mysql_errmsg_append(thd);
    }

    if (thd->variables.sql_mode & MODE_NO_ZERO_DATE &&
        is_timestamp_type(field->sql_type) && !field->def &&
        (field->flags & NOT_NULL_FLAG) &&
        (field->unireg_check == Field::NONE || 
         field->unireg_check == Field::TIMESTAMP_UN_FIELD))
    {
        my_error(ER_INVALID_DEFAULT, MYF(0), field->field_name);
        mysql_errmsg_append(thd);
    }

    return false;
}

int mysql_check_add_column(THD *thd)
{
    table_info_t* table_info;
    Create_field* field;
    field_info_t* field_info;
    field_info_t* field_info_new;
    int             found=FALSE;
    char            tmp_buf[256];

    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    Alter_info* alter_info_ptr = &alter_info;

    List_iterator<Create_field> fields(alter_info_ptr->create_list);
    List_iterator<Key> key_iterator(alter_info_ptr->key_list);

    DBUG_ENTER("mysql_check_add_column");

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    while ((field=fields++))
    {
        if (field->change != NULL)
            continue;

        found = FALSE;
        field_info = LIST_GET_FIRST(table_info->field_lst);
        while (field_info)
        {
            if (strcasecmp(field_info->field_name, field->field_name) == 0)
            {
                my_error(ER_COLUMN_EXISTED, MYF(0), field->field_name);
                mysql_errmsg_append(thd);
            }

            field_info = LIST_GET_NEXT(link, field_info);
        }

        field_info_new = mysql_cache_new_column(table_info, field);
        if (field->after)
        {
            field_info = LIST_GET_FIRST(table_info->field_lst);
            while (field_info)
            {
                if (strcasecmp(field_info->field_name, field->after) == 0)
                {
                    found=TRUE;
                    break;
                }

                field_info = LIST_GET_NEXT(link, field_info);
            }

            if (!found)
            {
                my_error(ER_COLUMN_NOT_EXISTED, MYF(0), field->after);
                mysql_errmsg_append(thd);
            }
        }

        if (field->charset && !mysql_field_is_blob(field->sql_type))
        {
            my_error(ER_CHARSET_ON_COLUMN, MYF(0), field->field_name,
                thd->lex->select_lex.table_list.first->table_name);
            mysql_errmsg_append(thd);
        }

        field->charset = system_charset_info;
        mysql_field_check(thd, field, table_info->table_name);
        mysql_check_column_default(thd, field->def, field->flags, 
            field_info_new, field->field_name, field->sql_type);
        if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE )
        {
            sprintf(tmp_buf, "DROP COLUMN `%s`", field->field_name);
            str_append(&thd->ddl_rollback, tmp_buf);
            str_append(&thd->ddl_rollback, ",");
        }
    }

    DBUG_RETURN(FALSE);
}

int mysql_check_rename_table(THD *thd)
{
    table_info_t* table_info;
    char            tmp_buf[256];
    DBUG_ENTER("mysql_check_rename_table");

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    //new table is existed, then report error message
    if (mysql_table_is_existed(thd, thd->lex->select_lex.db, thd->lex->name.str))
    {
        my_error(ER_TABLE_EXISTS_ERROR, MYF(0), thd->lex->name.str);
        mysql_errmsg_append(thd);
    }

    if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE )
    {
        sprintf(tmp_buf, "RENAME TO `%s`.`%s`",
                thd->lex->query_tables->db, thd->lex->query_tables->table_name);
        str_append(&thd->ddl_rollback, tmp_buf);
        str_append(&thd->ddl_rollback, ",");
    }

    //标志删除，然后复制一个新的出来，不然逻辑会有问题
    //再次获取这个表，然后再改名，原来的设置为已删除
    table_info->isdeleted = 1;
    table_info = mysql_copy_table_info(table_info);
    table_info->new_cache = TRUE;
    strcpy(table_info->db_name, thd->lex->select_lex.db);
    strcpy(table_info->table_name, thd->lex->name.str);
    mysql_add_table_object(thd, table_info);

    DBUG_RETURN(FALSE);
}

int mysql_drop_column_rollback(THD* thd, table_info_t* table_info, char* columnname)
{
    char        tmp_buf[256];
    MYSQL_RES *     source_res;
    MYSQL_ROW       source_row;
    MYSQL*          mysql;

    if (inception_get_type(thd) == INCEPTION_TYPE_CHECK)
        return 0;

    sprintf(tmp_buf, "SHOW FULL FIELDS FROM `%s`.`%s` where field='%s';",
            table_info->db_name, table_info->table_name, columnname);

    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        return 0;
    }

    if (mysql_real_query(mysql, tmp_buf, strlen(tmp_buf)))
        return 0;

    if ((source_res = mysql_store_result(mysql)) == NULL)
        return 0;

    //only one record
    if ((source_row = mysql_fetch_row(source_res)) != NULL)
    {
        char*       notnull = (char*)"";
        char*       defaults = NULL;
        char*       comment = NULL;

        if (source_row[3] != NULL && !strcasecmp(source_row[3], "NO"))
            notnull = (char*)"NOT NULL";

        if (source_row[5] != NULL)
            defaults = source_row[5];

        if (source_row[8] != NULL)
            comment = source_row[8];

        if (defaults && comment)
            sprintf(tmp_buf, "ADD COLUMN `%s` %s %s DEFAULT '%s' COMMENT '%s' ", columnname,
                    source_row[1], notnull, defaults, comment);
        else if (defaults && !comment)
            sprintf(tmp_buf, "ADD COLUMN `%s` %s %s DEFAULT '%s'", columnname,
                    source_row[1], notnull, defaults);
        else if (!defaults && comment)
            sprintf(tmp_buf, "ADD COLUMN `%s` %s %s COMMENT '%s'", columnname,
                    source_row[1], notnull, comment);
        str_append(&thd->ddl_rollback, tmp_buf);
        str_append(&thd->ddl_rollback, ",");
    }

    mysql_free_result(source_res);
    return 0;
}

int mysql_check_drop_column(THD *thd)
{
    table_info_t* table_info;
    Alter_drop*  field;
    field_info_t* field_info;
    int    found = FALSE;

    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    Alter_info* alter_info_ptr = &alter_info;

    List_iterator<Alter_drop> fields(alter_info_ptr->drop_list);

    DBUG_ENTER("mysql_check_drop_column");

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    while ((field=fields++))
    {
        if (field->type != Alter_drop::COLUMN)
            continue;

        found = FALSE;
        field_info = LIST_GET_FIRST(table_info->field_lst);
        while (field_info)
        {
            if (strcasecmp(field_info->field_name, field->name) == 0)
            {
                found = TRUE;
                break;
            }

            field_info = LIST_GET_NEXT(link, field_info);
        }

        if (found == FALSE)
        {
            my_error(ER_COLUMN_NOT_EXISTED, MYF(0), field->name);
            mysql_errmsg_append(thd);
        }

        mysql_drop_column_rollback(thd, table_info, (char*)field->name);
    }

    DBUG_RETURN(FALSE);
}

int mysql_change_column_rollback(THD* thd, table_info_t* table_info, char* columnname)
{
    char*           tmp_buf;
    char            buff_space[4096];
    MYSQL_RES *     source_res;
    MYSQL_ROW       source_row;
    MYSQL*          mysql;
    tmp_buf = (char*)&buff_space;

    if (inception_get_type(thd) == INCEPTION_TYPE_CHECK)
        return 0;

    sprintf(tmp_buf, "SHOW FULL FIELDS FROM `%s`.`%s` where field='%s';",
            table_info->db_name, table_info->table_name, columnname);

    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        return 0;
    }

    if (mysql_real_query(mysql, tmp_buf, strlen(tmp_buf)))
        return 0;

    if ((source_res = mysql_store_result(mysql)) == NULL)
        return 0;

    //only one record
    if ((source_row = mysql_fetch_row(source_res)) != NULL)
    {
        char*       notnull = (char*)"";
        char*       defaults = NULL;
        char*       comment = NULL;
        int         maxlen;

        if (source_row[3] != NULL && !strcasecmp(source_row[3], "NO"))
            notnull = (char*)"NOT NULL";

        if (source_row[5] != NULL)
            defaults = source_row[5];

        if (source_row[8] != NULL)
            comment = source_row[8];

        maxlen = (defaults ? strlen(defaults) : 0) + strlen(source_row[1]) +
            (comment ? strlen(comment) : 0) + strlen(notnull) + 512;

        if (maxlen > 4096)
            tmp_buf= (char*)my_malloc(maxlen, MYF(MY_ZEROFILL));

        if (defaults && comment)
            sprintf(tmp_buf, "CHANGE COLUMN `%s` `%s` %s %s DEFAULT '%s' COMMENT '%s' ",
                    columnname, columnname, source_row[1], notnull, defaults, comment);
        else if (defaults && !comment)
            sprintf(tmp_buf, "CHANGE COLUMN `%s` `%s` %s %s DEFAULT '%s'",
                    columnname, columnname, source_row[1], notnull, defaults);
        else if (!defaults && comment)
            sprintf(tmp_buf, "CHANGE COLUMN `%s` `%s` %s %s COMMENT '%s'",
                    columnname, columnname, source_row[1], notnull, comment);
        str_append(&thd->ddl_rollback, tmp_buf);
        str_append(&thd->ddl_rollback, ",");
        if (tmp_buf != buff_space)
            my_free(tmp_buf);
    }

    mysql_free_result(source_res);
    return 0;
}

int mysql_check_change_column(THD *thd)
{
    table_info_t* table_info;
    Create_field* field;
    field_info_t* field_info;
    int    found = FALSE;

    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    Alter_info* alter_info_ptr = &alter_info;

    List_iterator<Create_field> fields(alter_info_ptr->create_list);

    DBUG_ENTER("mysql_check_change_column");

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    while ((field=fields++))
    {
        if (field->change == NULL)
            continue;

        found = FALSE;
        field_info = LIST_GET_FIRST(table_info->field_lst);
        while (field_info)
        {
            if (strcasecmp(field_info->field_name, field->change) == 0)
            {
                found = TRUE;
                break;
            }

            field_info = LIST_GET_NEXT(link, field_info);
        }

        if (found == FALSE)
        {
            my_error(ER_COLUMN_NOT_EXISTED, MYF(0), field->change);
            mysql_errmsg_append(thd);
        }
        else
        {
            if (field->charset && !mysql_field_is_blob(field->sql_type))
            {
                my_error(ER_CHARSET_ON_COLUMN, MYF(0), field->field_name,
                    thd->lex->select_lex.table_list.first->table_name);
                mysql_errmsg_append(thd);
            }

            //update field info
            mysql_set_cache_new_column_type(field_info, field);
            strcpy(field_info->field_name, field->field_name);
            field_info->nullable = field->flags & NOT_NULL_FLAG ? 0 : 1;
            field_info->auto_increment = field->flags & AUTO_INCREMENT_FLAG ? 1 : 0;
            field_info->primary_key= field->flags & PRI_KEY_FLAG ? 1 : 0;
            
            field->charset = system_charset_info;
            mysql_field_check(thd, field, table_info->table_name);
            mysql_check_column_default(thd, field->def, field->flags, 
                field_info, field->field_name, field->sql_type);
            mysql_change_column_rollback(thd, table_info, (char*)field->field_name);
        }
    }

    DBUG_RETURN(FALSE);
}

my_ulonglong mysql_affected_rows(MYSQL *mysql)
{
    return (mysql->affected_rows == ~(my_ulonglong) 0) ? 0 : mysql->affected_rows;
}

int mysql_check_drop_index(THD *thd)
{
    MYSQL*          mysql;
    MYSQL_RES *     source_res;
    char            sql[1024];
    MYSQL_ROW       source_row;
    MYSQL_ROW       source_row_next;
    Alter_drop*     field;
    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    Alter_info* alter_info_ptr = &alter_info;
    char            tmp_buf[256];

    List_iterator<Alter_drop> fields(alter_info_ptr->drop_list);

    DBUG_ENTER("mysql_check_drop_index");

    mysql= thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);
    }

    while ((field = fields++))
    {
        if (field->type == Alter_drop::KEY)
        {
            sprintf(sql, "SHOW INDEX FROM `%s`.`%s` where \
                Key_name= '%s';", thd->lex->query_tables->db,
                thd->lex->query_tables->table_name, field->name);
            if (mysql_real_query(mysql, sql, strlen(sql)))
            {
                my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
                mysql_errmsg_append(thd);
                continue;
            }

            if ((source_res = mysql_store_result(mysql)) == NULL)
            {
                my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
                mysql_errmsg_append(thd);
                continue;
            }

            source_row = mysql_fetch_row(source_res);
            if (source_row == NULL)
            {
                my_error(ER_CANT_DROP_FIELD_OR_KEY, MYF(0), field->name);
                mysql_errmsg_append(thd);
                continue;
            }

            if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE )
            {
                int first = true;
                sprintf(tmp_buf, "ADD INDEX `%s` (", field->name);
                str_append(&thd->ddl_rollback, tmp_buf);
                mysql_data_seek2(source_res, 0);
                source_row = mysql_fetch_row(source_res);
                while (source_row)
                {
                    if (!first)
                        str_append(&thd->ddl_rollback, ",");
                    source_row_next = mysql_fetch_row(source_res);
                    str_append(&thd->ddl_rollback, source_row[4]);
                    source_row = source_row_next;
                    first = false;
                }

                str_append(&thd->ddl_rollback, "),");
            }
        }
    }

    mysql_free_result(source_res);
    DBUG_RETURN(FALSE);
}

int mysql_change_column_default_rollback(THD* thd, table_info_t* table_info, char* columnname)
{
    char        tmp_buf[256];
    MYSQL_RES *     source_res;
    MYSQL_ROW       source_row;
    MYSQL*          mysql;

    if (inception_get_type(thd) == INCEPTION_TYPE_CHECK)
        return 0;

    sprintf(tmp_buf, "SHOW FULL FIELDS FROM `%s`.`%s` where field='%s';",
            table_info->db_name, table_info->table_name, columnname);

    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        return 0;
    }
    if (mysql_real_query(mysql, tmp_buf, strlen(tmp_buf)))
        return 0;

    if ((source_res = mysql_store_result(mysql)) == NULL)
        return 0;

    //only one record
    if ((source_row = mysql_fetch_row(source_res)) != NULL)
    {
        char*       defaults = NULL;

        if (source_row[5] != NULL)
            defaults = source_row[5];

        if (defaults)
            sprintf(tmp_buf, "ALTER COLUMN `%s` SET DEFAULT '%s'", columnname, defaults);
        else
            sprintf(tmp_buf, "ALTER COLUMN `%s` DROP DEFAULT", columnname);

        str_append(&thd->ddl_rollback, tmp_buf);
        str_append(&thd->ddl_rollback, ",");
    }

    mysql_free_result(source_res);
    return 0;
}

int mysql_check_change_column_default(THD *thd)
{
    table_info_t* table_info;
    Alter_column* field;
    field_info_t* field_info;
    int    found = FALSE;

    DBUG_ENTER("mysql_check_change_column_default");

    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    Alter_info* alter_info_ptr = &alter_info;

    List_iterator<Alter_column> fields(alter_info_ptr->alter_list);

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db,
            thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    while ((field=fields++))
    {
        found = FALSE;
        field_info = LIST_GET_FIRST(table_info->field_lst);
        while (field_info)
        {
            if (strcasecmp(field_info->field_name, field->name) == 0)
            {
                found = TRUE;
                break;
            }

            field_info = LIST_GET_NEXT(link, field_info);
        }

        if (found == FALSE)
        {
            my_error(ER_COLUMN_NOT_EXISTED, MYF(0), field->name);
            mysql_errmsg_append(thd);
        }
        else
        {
            mysql_check_column_default(thd, field->def, 0, field_info, 
                field_info->field_name, field_info->real_type);
        }

        mysql_change_column_default_rollback(thd, table_info, (char*)field->name);
    }

    DBUG_RETURN(FALSE);
}

int mysql_get_table_size(THD *thd, table_info_t* table_info)
{
    char showsql[1000];
    MYSQL_RES * source_res;
    MYSQL_ROW   source_row;
    MYSQL*      mysql;

    DBUG_ENTER("mysql_get_table_size");

    //表大小已经取过了，就不再取了
    if (table_info->new_cache || table_info->table_size)
        DBUG_RETURN(FALSE);

    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        DBUG_RETURN(FALSE);
    }

    // sprintf(showsql, "set global innodb_stats_on_metadata=off");
    // if (mysql_real_query(mysql, showsql, strlen(showsql)))
    // {
    //     my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
    //     mysql_errmsg_append(thd);
    //     DBUG_RETURN(TRUE);
    // }

    sprintf(showsql, "select (DATA_LENGTH + INDEX_LENGTH)/1024/1024 from \
        information_schema.tables where table_schema = '%s' and \
        table_name = '%s'", table_info->db_name, table_info->table_name);
    if (mysql_real_query(mysql, showsql, strlen(showsql)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);
    }

    if ((source_row = mysql_fetch_row(source_res)) != NULL)
        table_info->table_size = atoi(source_row[0]);

    mysql_free_result(source_res);
    DBUG_RETURN(FALSE);
}

int mysql_show_table_status(THD *thd, table_info_t* table_info)
{
    char showsql[1000];
    MYSQL_RES * source_res;
    MYSQL_ROW   source_row;
    MYSQL*      mysql;

    DBUG_ENTER("mysql_show_table_status");

    if (table_info->new_cache)
        DBUG_RETURN(FALSE);

    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        mysql_errmsg_append(thd);
        DBUG_RETURN(FALSE);
    }
    sprintf(showsql, "show table status from `%s` where name = \'%s\'",
            table_info->db_name, table_info->table_name);
    if (mysql_real_query(mysql, showsql, strlen(showsql)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);
    }

    if ((source_row = mysql_fetch_row(source_res)) != NULL)
        thd->affected_rows = atoi(source_row[4]);

    mysql_free_result(source_res);
    DBUG_RETURN(FALSE);
}

int mysql_check_alter_use_osc(
    THD*            thd,
    table_info_t*   table_info
)
{
    //如果inception_osc_min_table_size设置为0，或者表大小大于
    //这个参数，就用OSC，如果直接设置为0的话，下面2个参数都满足，但为了
    //代码上看起来清楚，还是写了第二个条件
    if (inception_osc_on && 
        (table_info->table_size >= (int)thd->variables.inception_osc_min_table_size ||
        !thd->variables.inception_osc_min_table_size))
        thd->use_osc = TRUE;
    else
        thd->use_osc = FALSE; 
       
    return FALSE;
}

int mysql_check_alter_option(THD *thd)
{
    DBUG_ENTER("mysql_check_alter_option");
    HA_CREATE_INFO create_info(thd->lex->create_info);
    while(create_info.used_fields)
    {
        if (create_info.used_fields & HA_CREATE_USED_ENGINE)
        {
            if (create_info.db_type != (handlerton *)DB_TYPE_INNODB)
            {
                my_error(ER_TABLE_MUST_INNODB, MYF(0), thd->lex->query_tables->table_name);
                mysql_errmsg_append(thd);
            }

            create_info.used_fields &= ~HA_CREATE_USED_ENGINE;
        }
        else if (create_info.used_fields & HA_CREATE_USED_COMMENT)
        {
            create_info.used_fields &= ~HA_CREATE_USED_COMMENT;
        }
        else if (create_info.used_fields & HA_CREATE_USED_AUTO)
        {
            create_info.used_fields &= ~HA_CREATE_USED_AUTO;
        }
        else if (create_info.used_fields & HA_CREATE_USED_DEFAULT_CHARSET)
        {
            if (create_info.default_table_charset == NULL ||
                !mysql_check_charset(create_info.default_table_charset->csname))
            {
                my_error(ER_TABLE_CHARSET_MUST_UTF8, MYF(0), 
                    inception_support_charset, thd->lex->query_tables->table_name);
                mysql_errmsg_append(thd);
            }
            create_info.used_fields &= ~HA_CREATE_USED_DEFAULT_CHARSET;
        }
        else
        {
            if ((create_info.used_fields & HA_CREATE_USED_CHARSET) != HA_CREATE_USED_CHARSET)
            {
                my_error(ER_NOT_SUPPORTED_ALTER_OPTION, MYF(0));
                mysql_errmsg_append(thd);
            }
            break;
        }
    }

    DBUG_RETURN(FALSE);
}

int mysql_check_alter_convert(THD *thd)
{
    DBUG_ENTER("mysql_check_alter_convert");
    HA_CREATE_INFO create_info(thd->lex->create_info);
    if (create_info.used_fields & HA_CREATE_USED_CHARSET)
    {
        if (create_info.default_table_charset == NULL ||
            !mysql_check_charset(create_info.default_table_charset->csname))
        {
            my_error(ER_TABLE_CHARSET_MUST_UTF8, MYF(0), 
                inception_support_charset, thd->lex->query_tables->table_name);
            mysql_errmsg_append(thd);
        }
    }

    create_info.used_fields &= ~HA_CREATE_USED_CHARSET;
    DBUG_RETURN(FALSE);
}

int mysql_check_alter_table(THD *thd)
{
    int err;
    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    Alter_info* alter_info_ptr = &alter_info;
    table_info_t*   table_info;
    char        tmp_buf[256];
    DBUG_ENTER("mysql_check_alter_table");

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        mysql_add_split_sql_node(thd, thd->lex->query_tables->db,
                                 thd->lex->query_tables->table_name, MYSQLDDL, 
                                 thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db, 
        thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    mysql_check_ddldml_coexisted(thd, table_info, MYSQLDDL);
    if (++table_info->alter_count > 1)
    {
        my_error(ER_ALTER_TABLE_ONCE, MYF(0), thd->lex->query_tables->table_name);
        mysql_errmsg_append(thd);
    }

    mysql_show_table_status(thd, table_info);
    mysql_get_table_size(thd, table_info);

    if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE )
    {
        if (!(alter_info_ptr->flags & Alter_info::ALTER_RENAME))
        {
            sprintf(tmp_buf, "ALTER TABLE `%s`.`%s` ", thd->lex->query_tables->db,
                    thd->lex->query_tables->table_name);
            str_append(&thd->ddl_rollback, tmp_buf);
        }
        else
        {
            sprintf(tmp_buf, "ALTER TABLE `%s`.`%s` ",
                    thd->lex->select_lex.db, thd->lex->name.str);
            str_append(&thd->ddl_rollback, tmp_buf);
        }
    }

    mysql_check_alter_use_osc(thd, table_info);
    while (alter_info_ptr->flags)
    {
        if (alter_info_ptr->flags & Alter_info::ALTER_ADD_COLUMN ||
            alter_info_ptr->flags & Alter_info::ALTER_COLUMN_ORDER)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_ADD_COLUMN);
            if ((err = mysql_check_add_column(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_ADD_COLUMN;
            alter_info_ptr->flags &= ~Alter_info::ALTER_COLUMN_ORDER;
        }
        else if (alter_info_ptr->flags & Alter_info::ALTER_ADD_INDEX)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_ADD_INDEX);
            if ((err = mysql_check_create_index(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_ADD_INDEX;
        }
        else if (alter_info_ptr->flags & Alter_info::ALTER_DROP_COLUMN)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_DROP_COLUMN);
            if((err = mysql_check_drop_column(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_DROP_COLUMN;
        }
        else if (alter_info_ptr->flags & Alter_info::ALTER_RENAME)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_RENAME);
            if((err = mysql_check_rename_table(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_RENAME;
        }
        else if (alter_info_ptr->flags & Alter_info::ALTER_CHANGE_COLUMN)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_CHANGE_COLUMN);
            if ((err = mysql_check_change_column(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_CHANGE_COLUMN;
        }
        else if (alter_info_ptr->flags & Alter_info::ALTER_DROP_INDEX)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_DROP_INDEX);
            if ((err = mysql_check_drop_index(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_DROP_INDEX;
        }
        else if (alter_info_ptr->flags & Alter_info::ALTER_CHANGE_COLUMN_DEFAULT)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_CHANGE_COLUMN_DEFAULT);
            if ((err = mysql_check_change_column_default(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_CHANGE_COLUMN_DEFAULT;
        }
        else if (alter_info_ptr->flags & Alter_info::ALTER_OPTIONS)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_OPTIONS);
            if ((err = mysql_check_alter_option(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_OPTIONS;
        }
        else if (alter_info_ptr->flags & Alter_info::ALTER_CONVERT)
        {
            thd_sql_statistic_increment(thd, Alter_info::ALTER_CONVERT);
            if ((err = mysql_check_alter_convert(thd)))
                DBUG_RETURN(err);
            alter_info_ptr->flags &= ~Alter_info::ALTER_CONVERT;
        }
        else
        {
            my_error(ER_NOT_SUPPORTED_YET, MYF(0));
            mysql_errmsg_append(thd);
            break;
        }

        if (alter_info_ptr->flags == 0)
        {
            str_truncate(&thd->ddl_rollback, 1);
            str_append(&thd->ddl_rollback, ";");
        }
    }

    DBUG_RETURN(FALSE);
}

int mysql_set_option_check(THD* thd)
{
    int error;

    DBUG_ENTER("mysql_set_option_check");

    List_iterator_fast<set_var_base> it(thd->lex->var_list);

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        str_truncate(&thd->setnames, str_get_len(&thd->setnames));
        str_append_with_length(&thd->setnames, thd->query(), thd->query_length());
        mysql_add_split_sql_node(thd, NULL, NULL, MYSQLDML, thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    set_var_base *var;
    while ((var=it++))
    {
        //DBA执行的语句，需要设置的，只支持set names ...语句
        if (dynamic_cast <set_var_collation_client*> (var))
        {
            if ((error= var->check(thd)))
            {
                my_error(ER_WRONG_ARGUMENTS,MYF(0),"SET");
                mysql_errmsg_append(thd);
            }

            if ((error = var->update(thd)))        // Returns 0, -1 or 1
            {
                my_error(ER_WRONG_ARGUMENTS,MYF(0),"SET");
                mysql_errmsg_append(thd);
            }
        }
        else
        {
            my_error(ER_WRONG_ARGUMENTS,MYF(0),"SET");
            mysql_errmsg_append(thd);
        }
    }

    DBUG_RETURN(FALSE);
}

int mysql_check_create_db(THD *thd)
{
    dbinfo_t*   dbinfo;
    char        tmp_buf[256];

    DBUG_ENTER("mysql_check_create_db");

    HA_CREATE_INFO create_info(thd->lex->create_info);
    HA_CREATE_INFO* create_info_ptr = &create_info;

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        mysql_add_split_sql_node(thd, thd->lex->name.str, NULL, MYSQLDML, thd->lex->sql_command);
    }

    if (create_info_ptr->default_table_charset == NULL ||
        !mysql_check_charset(create_info_ptr->default_table_charset->csname))
    {
        my_error(ER_TABLE_CHARSET_MUST_UTF8, MYF(0), 
            inception_support_charset, thd->lex->name.str);
        mysql_errmsg_append(thd);
    }

    dbinfo = (dbinfo_t*)my_malloc(sizeof(dbinfo_t), MYF(MY_ZEROFILL));
    sprintf(dbinfo->dbname, "%s", thd->lex->name.str);
    LIST_ADD_LAST(link, thd->dbcache.dbcache_lst, dbinfo);

    if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE )
    {
        sprintf(tmp_buf, "DROP DATABASE `%s`;", dbinfo->dbname);
        str_append(&thd->ddl_rollback, tmp_buf);
    }

    DBUG_RETURN(FALSE);
}

int mysql_check_change_db(THD* thd)
{
    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        str_truncate(&thd->usedb, str_get_len(&thd->usedb));
        str_append_with_length(&thd->usedb, thd->query(), thd->query_length());
        mysql_add_split_sql_node(thd, NULL, NULL, MYSQLDML, thd->lex->sql_command);
    }

    LEX_STRING db_str= { (char *) thd->lex->select_lex.db, strlen(thd->lex->select_lex.db) };
    return mysql_change_db(thd, &db_str, FALSE);
}

int mysql_check_truncate_table(THD *thd)
{
    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    table_info_t*   table_info;
    DBUG_ENTER("mysql_check_truncate_table");

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        mysql_add_split_sql_node(thd, thd->lex->query_tables->db,
                                 thd->lex->query_tables->table_name, MYSQLDML,
                                 thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db, 
        thd->lex->query_tables->table_name, TRUE);
    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    mysql_show_table_status(thd, table_info);
    DBUG_RETURN(FALSE);
}

int mysql_check_drop_table(THD *thd)
{
    HA_CREATE_INFO create_info(thd->lex->create_info);
    Alter_info alter_info(thd->lex->alter_info, thd->mem_root);
    table_info_t*   table_info;
    DBUG_ENTER("mysql_check_drop_table");

    //在切分时，DROP TABLE和谁也不能共容，只有
    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        mysql_add_split_sql_node(thd, thd->lex->query_tables->db,
                                 thd->lex->query_tables->table_name, MYSQLDDL, 
                                 thd->lex->sql_command);
        DBUG_RETURN(FALSE);
    }

    table_info = mysql_get_table_object(thd, thd->lex->query_tables->db, 
        thd->lex->query_tables->table_name, !thd->lex->drop_if_exists);
    //drop table t if existed
    //如果表不存在，存在if existed，则直接啥都不做返回即可，不报错了
    if (thd->lex->drop_if_exists && !table_info)
    {
        DBUG_RETURN(FALSE);
    }

    if (table_info == NULL)
        DBUG_RETURN(TRUE);

    mysql_check_ddldml_coexisted(thd, table_info, MYSQLDDL);
    mysql_show_table_status(thd, table_info);
    if (!table_info->new_cache && inception_get_type(thd) == INCEPTION_TYPE_EXECUTE)
    {
        //生成回滚语句
        mysql_show_create_table(thd, thd->lex->query_tables->db, 
          thd->lex->query_tables->table_name, &thd->ddl_rollback);
    }
    
    //这里删除缓存对象没有用
    //LIST_REMOVE(link, thd->tablecache.tablecache_lst, table_info);
    //mysql_remove_table_object(thd, table_info);
    //todo:从缓存中将表对象删除，不过这个可以不做
    table_info->isdeleted = 1;
    DBUG_RETURN(FALSE);
}

int mysql_print_tables(
    THD* thd, 
    query_print_cache_node_t*   query_node, 
    st_select_lex *select_lex,
    str_t* print_str, 
    TABLE_LIST* tables,
    char* table_type
)
{
    char tablename[FN_LEN];
    char tabletype[FN_LEN];
    TABLE_LIST* table;
    Item    *join_cond;
    bool have_join_on = false;
    if (tables)
    {
        sprintf(tabletype, "\"%s\":[", table_type);
        str_append(print_str, tabletype);
        for (table= tables; table; table= table->next_local)
        {
            str_append(print_str, "{");
            str_append(print_str, "\"db\":");
            sprintf(tablename, "\"%s\",", table->db);
            str_append(print_str, tablename);

            str_append(print_str, "\"table\":");
            sprintf(tablename, "\"%s\"", table->table_name);
            str_append(print_str, tablename);
            str_append(print_str, "}");
            str_append(print_str, ",");
            join_cond = table->join_cond();
            if (join_cond)
                have_join_on=true;
        }
        str_truncate(print_str, 1);
        str_append(print_str, "]");
    }

    if (have_join_on)
    {
        str_append(print_str, ",");
        str_append(print_str, "\"join_on\":[");
        for (table= tables; table; table= table->next_local)
        {
            join_cond = table->join_cond();
            if (join_cond)
            {
                // str_append(print_str, "{");
                print_item(thd, query_node, print_str, join_cond, select_lex);
                // str_append(print_str, "}");
                str_append(print_str, ",");
            }
        }

        str_truncate(print_str, 1);
        str_append(print_str, "]");
    }

    return 0;
}

int 
mysql_load_tables(
    THD* thd, 
    rt_lst_t* rt_lst,
    st_select_lex *select_lex
)
{
    SQL_I_List<TABLE_LIST> * tables;
    TABLE_LIST* table;
    table_info_t* tableinfo;
    check_rt_t*     rt;
    table_rt_t*           tablert;

    rt = (check_rt_t*)my_malloc(sizeof(check_rt_t), MY_ZEROFILL);
    rt->select_lex = select_lex;

    tables = &select_lex->table_list;

    for (table= tables->first; table; table= table->next_local)
    {
        tableinfo = mysql_get_table_object(thd, table->db, table->table_name, TRUE);
        //如果有自连接，或者在不同层次使用了同一个表，那么以上层主准
        if (tableinfo)
        {
            tablert = (table_rt_t*)my_malloc(sizeof(table_rt_t), MY_ZEROFILL);
            tablert->table_info = tableinfo;
            if (table->alias)
                strcpy(tablert->alias, table->alias);
            LIST_ADD_LAST(link, rt->table_rt_lst, tablert);
        }
    }

    LIST_ADD_LAST(link, *rt_lst, rt);
    return 0;
}

table_rt_t* 
mysql_find_field_from_all_tables(
    THD* thd, 
    rt_lst_t* rt_lst, 
    st_select_lex *select_lex_in,
    const char* dbname,
    const char* tablename,
    const char* field_name
)
{
    table_info_t* tableinfo = NULL;
    field_info_t* fieldinfo = NULL;
    st_select_lex *select_lex;
    check_rt_t*   rt;
    table_rt_t*         tablert;
    table_rt_t*         ret_tablert = NULL;

    select_lex = select_lex_in;
retry:
    rt = LIST_GET_FIRST(*rt_lst);
    while (rt != NULL)
    {
        if ((st_select_lex*)rt->select_lex == select_lex)
        {
            tablert = LIST_GET_FIRST(rt->table_rt_lst); 
            while(tablert)
            {
                ret_tablert = NULL;
                tableinfo = tablert->table_info;
                fieldinfo = LIST_GET_FIRST(tableinfo->field_lst);
                while (fieldinfo != NULL) {
                    if (strcasecmp(fieldinfo->field_name, field_name) == 0) {
                        ret_tablert = tablert;
                        break;
                    }

                    fieldinfo = LIST_GET_NEXT(link, fieldinfo);
                }

                if (ret_tablert)
                {
                    //指定库表，那就没有别名的情况了
                    if (tablename && dbname)
                    {
                        tableinfo = ret_tablert->table_info;
                        if (!strcasecmp(tableinfo->table_name, tablename) && 
                            !strcasecmp(tableinfo->db_name, dbname))
                        {
                            return ret_tablert;
                        }
                    }
                    else if (tablename)//有可能是别名，有可能是实际表名
                    {
                        tableinfo = ret_tablert->table_info;
                        if (!strcasecmp(tableinfo->table_name, tablename) ||
                            !strcasecmp(ret_tablert->alias, tablename))
                        {
                            return ret_tablert;
                        }
                    }
                    else //没有指定任何标识ID
                    {
                        return ret_tablert;
                    }
                }

                tablert = LIST_GET_NEXT(link, tablert);
            }
        }

        rt = LIST_GET_NEXT(link, rt);
    }

    //not found
    if (select_lex->context.outer_context)
    {
        select_lex = select_lex->context.outer_context->select_lex;
        goto retry;
    }
    else
    {
        char name[1024];
        name[0] = '\0';
        if (dbname)
        {
            strcat(name, dbname);
            strcat(name, ".");
        }
        if (tablename)
        {
            strcat(name, tablename);
            strcat(name, ".");
        }
        if (field_name)
        {
            strcat(name, field_name);
        }
        my_error(ER_COLUMN_NOT_EXISTED, MYF(0), name);
        mysql_errmsg_append(thd);
        return NULL;
    }
}

int mysql_print_select_condition(
    THD* thd, 
    query_print_cache_node_t*   query_node, 
    str_t* print_str, 
    st_select_lex *select_lex
)
{
    ORDER*   order;
    if (select_lex->where)
    {
        str_append(print_str, ",");
        str_append(print_str, "\"where\":[");
        print_item(thd, query_node, print_str, select_lex->where, select_lex);
        str_append(print_str, "]");
    }

    if (select_lex->group_list.elements != 0)
    {
        str_append(print_str, ",");
        str_append(print_str, "\"GroupBy\":[");
        for (order= thd->lex->select_lex.group_list.first ; order; order= order->next)
        {
            print_item(thd, query_node, print_str, *order->item, select_lex);
            str_append(print_str, ",");
        }
        str_truncate(print_str, 1);
        str_append(print_str, "]");
    }

    if (select_lex->having)
    {
        str_append(print_str, ",");
        str_append(print_str, "\"Having\":[");
        print_item(thd, query_node, print_str, select_lex->having, select_lex);
        str_append(print_str, "]");
    }

    if (select_lex->order_list.elements != 0)
    {
        str_append(print_str, ",");
        str_append(print_str, "\"OrderBy\":[");
        for (order= thd->lex->select_lex.order_list.first ; order; order= order->next)
        {
            print_item(thd, query_node, print_str, *order->item, select_lex);
            str_append(print_str, ",");
        }
        str_truncate(print_str, 1);
        str_append(print_str, "]");
    }

    if (select_lex->select_limit)
    {
        str_append(print_str, ",");
        str_append(print_str, "\"limit\":{");
        str_append(print_str, "\"limit\":[");
        print_item(thd, query_node, print_str, select_lex->select_limit, select_lex);
        str_append(print_str, "]");
        if (select_lex->offset_limit)
        {
            str_append(print_str, ",");
            str_append(print_str, "\"limit_offset\":[");
            print_item(thd, query_node, print_str, select_lex->offset_limit, select_lex);
            str_append(print_str, "]");
        }
        str_append(print_str, "}");
    }

    return 0;
}

int mysql_print_subselect(
    THD* thd, 
    query_print_cache_node_t*   query_node, 
    str_t* print_str, 
    st_select_lex *select_lex, 
    bool top
)
{
    Item* item;
    ORDER*   order;
    TABLE_LIST* tables;

    if (mysql_load_tables(thd, &query_node->rt_lst, select_lex))
        return true;
    if (!top)
    {
        str_append(print_str, "\"subselect\":");
        str_append(print_str, "{");
    }
    str_append(print_str, "\"select_list\":[");
    List_iterator<Item> it(select_lex->item_list);
    while ((item= it++))
    {
        print_item(thd, query_node, print_str, item, select_lex);
        str_append(print_str, ",");
    }
    str_truncate(print_str, 1);
    str_append(print_str, "]");

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
        str_append(print_str, ",");
        mysql_print_tables(thd, query_node, select_lex, print_str, tables, (char*)"table_ref");
    }

    mysql_print_select_condition(thd, query_node, print_str, select_lex);
    if (!top)
        str_append(print_str, "}");

    return 0;
}

int print_func_item(
    THD* thd, 
    query_print_cache_node_t*   query_node, 
    str_t* print_str, 
    Item* item, 
    st_select_lex *select_lex
)
{
    if (!item)
        return 0;
    switch(((Item_func *)item)->functype())
    {
    case Item_func::EQ_FUNC:
    case Item_func::NE_FUNC:
    case Item_func::LT_FUNC:
    case Item_func::LE_FUNC:
    case Item_func::GE_FUNC:
    case Item_func::GT_FUNC:
        {
            if (((Item_func *)item)->functype() == Item_func::EQ_FUNC)
                str_append(print_str, "\"func\":\"=\"");
            else if (((Item_func *)item)->functype() == Item_func::NE_FUNC)
                str_append(print_str, "\"func\":\"!=\"");
            else if (((Item_func *)item)->functype() == Item_func::LT_FUNC)
                str_append(print_str, "\"func\":\">\"");
            else if (((Item_func *)item)->functype() == Item_func::LE_FUNC)
                str_append(print_str, "\"func\":\"<=\"");
            else if (((Item_func *)item)->functype() == Item_func::GE_FUNC)
                str_append(print_str, "\"func\":\">=\"");
            else if (((Item_func *)item)->functype() == Item_func::GT_FUNC)
                str_append(print_str, "\"func\":\">\"");
            str_append(print_str, ", \"args\":[");
            Item *left_item= ((Item_func*) item)->arguments()[0];
            print_item(thd, query_node, print_str, left_item, select_lex);
            str_append(print_str, ",");
            Item *right_item= ((Item_func*) item)->arguments()[1];
            print_item(thd, query_node, print_str, right_item, select_lex);
            str_append(print_str, "]");
        }
        break;

    case Item_func::COND_OR_FUNC:
    case Item_func::COND_AND_FUNC:
        {
            List<Item> *args= ((Item_cond*) item)->argument_list();
            List_iterator<Item> li(*args);
            Item *item_arg;
            if (((Item_func *)item)->functype() == Item_func::COND_AND_FUNC)
                str_append(print_str, "\"func\":\"AND\",");
            else if (((Item_func *)item)->functype() == Item_func::COND_OR_FUNC)
                str_append(print_str, "\"func\":\"OR\",");
            str_append(print_str, "\"args\":[");
            while ((item_arg= li++))
            {
                print_item(thd, query_node, print_str, item_arg, select_lex);
                str_append(print_str, ",");
            }
            str_truncate(print_str, 1);
            str_append(print_str, "]");
        }
        break;
    case Item_func::ISNULL_FUNC:
    case Item_func::ISNOTNULL_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            if (((Item_func *)item)->functype() == Item_func::ISNULL_FUNC)
                str_append(print_str, "\"func\":\"ISNULL\",");
            else
                str_append(print_str, "\"func\":\"ISNOTNULL\",");
            str_append(print_str, "\"args\":[");
            print_item(thd, query_node, print_str, left_item, select_lex);
            str_append(print_str, "]");
        }
        break;
    case Item_func::LIKE_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            Item *right_item= ((Item_func*) item)->arguments()[1];
            str_append(print_str, "\"func\":\"LIKE\",");
            str_append(print_str, "\"args\":[");
            print_item(thd, query_node, print_str, left_item, select_lex);
            str_append(print_str, ",");
            print_item(thd, query_node, print_str, right_item, select_lex);
            str_append(print_str, "]");
        }
        break;
    case Item_func::BETWEEN:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            Item *right_item1= ((Item_func*) item)->arguments()[1];
            Item *right_item2= ((Item_func*) item)->arguments()[2];
            str_append(print_str, "\"func\":\"BETWEEN\",");
            str_append(print_str, "\"args\":[");
            print_item(thd, query_node, print_str, left_item, select_lex);
            str_append(print_str, ",");
            print_item(thd, query_node, print_str, right_item1, select_lex);
            str_append(print_str, ",");
            print_item(thd, query_node, print_str, right_item2, select_lex);
            str_append(print_str, "]");
        }
        break;
    case Item_func::IN_FUNC:
    case Item_func::MULT_EQUAL_FUNC:
        {
            if (((Item_func *)item)->functype() == Item_func::IN_FUNC)
                str_append(print_str, "\"func\":\"IN\",");
            else if (((Item_func *)item)->functype() == Item_func::MULT_EQUAL_FUNC)
                str_append(print_str, "\"func\":\"MULT_EQUAL\",");

            str_append(print_str, "\"args\":[");
            for (uint i=0; i < ((Item_func*) item)->argument_count();i++)
            {
                Item *right_item= ((Item_func*) item)->arguments()[i];
                print_item(thd, query_node, print_str, right_item, select_lex);
                str_append(print_str, ",");
            }

            str_truncate(print_str, 1);
            str_append(print_str, "]");
        }
        break;
    case Item_func::NOT_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            str_append(print_str, "\"func\":\"NOT\",");
            str_append(print_str, "\"args\":[");
            print_item(thd, query_node, print_str, left_item, select_lex);
            str_append(print_str, "]");
        }
        break;
    case Item_func::NOW_FUNC:
        {
            str_append(print_str, "\"func\":\"NOW\"");
        }
        break;
    case Item_func::EXTRACT_FUNC:
        {
            str_append(print_str, "\"func\":\"EXTRACT\",");
            str_append(print_str, "\"args\":[");
            Item *left_item= ((Item_func*) item)->arguments()[0];
            print_item(thd, query_node, print_str, left_item, select_lex);
            str_append(print_str, "]");
        }
        break;
    case Item_func::FUNC_SP:
    case Item_func::UNKNOWN_FUNC:
        {
            char funcname[128];
            str_append(print_str, "\"func\":\"OTHERS\",");
            str_append(print_str, "\"name\":");
            sprintf(funcname, "\"%s\",", ((Item_func*) item)->func_name());
            str_append(print_str, funcname);
            str_append(print_str, "\"args\":[");
            for (uint i=0; i < ((Item_func*) item)->argument_count();i++)
            {
                Item *right_item= ((Item_func*) item)->arguments()[i];
                print_item(thd, query_node, print_str, right_item, select_lex);
                str_append(print_str, ",");
            }

            str_truncate(print_str, 1);
            str_append(print_str, "]");
        }
        break;

    default:
        break;
    }

    return 0;
}

int 
print_sum_item(
    THD* thd, 
    query_print_cache_node_t*   query_node, 
    str_t* print_str, 
    Item* item, 
    st_select_lex *select_lex
)
{
    Item_sum *item_sum= (((Item_sum*) item));
    switch(item_sum->sum_func())
    {
    case Item_sum::COUNT_FUNC:
    case Item_sum::COUNT_DISTINCT_FUNC:
    case Item_sum::SUM_FUNC:
    case Item_sum::SUM_DISTINCT_FUNC:
    case Item_sum::AVG_FUNC:
    case Item_sum::AVG_DISTINCT_FUNC:
    case Item_sum::MIN_FUNC:
    case Item_sum::MAX_FUNC:
    case Item_sum::STD_FUNC:
    case Item_sum::VARIANCE_FUNC:
    case Item_sum::SUM_BIT_FUNC:
    case Item_sum::UDF_SUM_FUNC:
    case Item_sum::GROUP_CONCAT_FUNC:
        {
            str_append(print_str, "\"type\":\"aggregate\",");
            if (item_sum->sum_func() == Item_sum::SUM_FUNC)
                str_append(print_str, "\"agg_type\":\"sum\",");
            else if (item_sum->sum_func() == Item_sum::AVG_FUNC)
                str_append(print_str, "\"agg_type\":\"avg\",");
            else if (item_sum->sum_func() == Item_sum::COUNT_FUNC)
                str_append(print_str, "\"agg_type\":\"count\",");
            else if (item_sum->sum_func() == Item_sum::COUNT_DISTINCT_FUNC)
                str_append(print_str, "\"agg_type\":\"count(distinct)\",");
            else if (item_sum->sum_func() == Item_sum::SUM_DISTINCT_FUNC)
                str_append(print_str, "\"agg_type\":\"sum(distinct)\",");
            else if (item_sum->sum_func() == Item_sum::AVG_DISTINCT_FUNC)
                str_append(print_str, "\"agg_type\":\"avg(distinct)\",");
            else if (item_sum->sum_func() == Item_sum::MIN_FUNC)
                str_append(print_str, "\"agg_type\":\"min\",");
            else if (item_sum->sum_func() == Item_sum::MAX_FUNC)
                str_append(print_str, "\"agg_type\":\"max\",");
            else if (item_sum->sum_func() == Item_sum::STD_FUNC)
                str_append(print_str, "\"agg_type\":\"std\",");
            else if (item_sum->sum_func() == Item_sum::GROUP_CONCAT_FUNC)
                str_append(print_str, "\"agg_type\":\"group_concat\",");
            else if (item_sum->sum_func() == Item_sum::VARIANCE_FUNC)
                str_append(print_str, "\"agg_type\":\"variance\",");
            else if (item_sum->sum_func() == Item_sum::SUM_BIT_FUNC)
                str_append(print_str, "\"agg_type\":\"sumbit\",");
            else if (item_sum->sum_func() == Item_sum::UDF_SUM_FUNC)
                str_append(print_str, "\"agg_type\":\"udfsum\",");
            str_append(print_str, "\"aggregate\":");
            Item* item_count = ((Item_sum_count*) item)->get_arg(0);
            print_item(thd, query_node, print_str, item_count, select_lex);
        }
        break;

    default:
        break;
    }

    return 0;
}

int
print_item(
    THD* thd, 
    query_print_cache_node_t*   query_node,
    str_t* print_str, 
    Item* item, 
    st_select_lex *select_lex
)
{
    if (!item)
        return 0;
    switch (item->type()) {
    case Item::STRING_ITEM:
        {
            String* stringval;
            String tmp;
            char* fieldname;
            str_append(print_str, "{");
            stringval = ((Item_string*) item)->val_str(&tmp);
            fieldname= (char*)my_malloc(stringval->length() + 10, MY_ZEROFILL);
            sprintf(fieldname, "\"%s\"", stringval->ptr());
            str_append(print_str, "\"type\":\"STRING_ITEM\",");
            str_append(print_str, "\"value\":");
            str_append(print_str, fieldname);
            str_append(print_str, "}");
        }
        break;
    case Item::FIELD_ITEM:
        {
            table_info_t* tableinfo;
            table_rt_t* tablert;
            char fieldname[FN_LEN];
            char dbname[FN_LEN];
            char tablename[FN_LEN];
            dbname[0]=fieldname[0]=tablename[0] = '\0';
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"FIELD_ITEM\",");
            if (strcasecmp(((Item_field*)item)->field_name, "*"))
            {
                if (((Item_field*)item)->db_name)
                    sprintf(dbname, "\"%s\",", ((Item_field*)item)->db_name);
                if (((Item_field*)item)->table_name)
                    sprintf(tablename, "\"%s\",", ((Item_field*)item)->table_name);
                tablert = mysql_find_field_from_all_tables(
                    thd, &query_node->rt_lst, select_lex, ((Item_field*)item)->db_name, 
                    ((Item_field*)item)->table_name, ((Item_field*)item)->field_name); 
                if (tablert)
                {
                    tableinfo = tablert->table_info;
                    sprintf(fieldname, "\"%s\",", tableinfo->table_name);
                    if (dbname[0] == '\0')
                        sprintf(dbname, "\"%s\",", tableinfo->db_name);
                    if (fieldname[0] == '\0')
                        sprintf(fieldname, "\"%s\",", tableinfo->table_name);
                }

                str_append(print_str, "\"db\":");
                str_append(print_str, dbname);
                str_append(print_str, "\"table\":");
                str_append(print_str, fieldname);
            }

            str_append(print_str, "\"field\":");
            sprintf(fieldname, "\"%s\"", ((Item_field*)item)->field_name);
            str_append(print_str, fieldname);
            str_append(print_str, "}");
        }
        break;
    case Item::FUNC_ITEM:
        {
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"FUNC_ITEM\",");
            print_func_item(thd, query_node, print_str, item, select_lex);
            str_append(print_str, "}");
        }
        break;
    case Item::INT_ITEM:
        {
            char fieldname[FN_LEN];
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"INT_ITEM\",");
            str_append(print_str, "\"value\":");
            sprintf(fieldname, "\"%lld\"", ((Item_int*) item)->val_int());
            str_append(print_str, fieldname);
            str_append(print_str, "}");
        }
        break;
    case Item::REAL_ITEM:
        {
            char fieldname[FN_LEN];
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"REAL_ITEM\",");
            str_append(print_str, "\"value\":");
            sprintf(fieldname, "\"%f\"", ((Item_int*) item)->val_real());
            str_append(print_str, fieldname);
            str_append(print_str, "}");
        }
        break;
    case Item::NULL_ITEM:
        {
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"NULL_ITEM\",");
            str_append(print_str, "\"value\":\"NULL\"");
            str_append(print_str, "}");
        }
        break;
    case Item::COND_ITEM:
        {
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"COND_ITEM\",");
            print_func_item(thd, query_node, print_str, item, select_lex);
            str_append(print_str, "}");
        }
        break;
    case Item::SUBSELECT_ITEM:
        {
            st_select_lex *select_lex_new;
            subselect_single_select_engine* real_engine;
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"SUBSELECT_ITEM\",");
            const subselect_engine *engine = ((Item_subselect*)item)->get_engine_for_explain();
            subselect_single_select_engine::enum_engine_type engine_type = engine->engine_type();

            if (engine_type == subselect_engine::SINGLE_SELECT_ENGINE)
            {
                str_append(print_str, "\"engine\":\"single_select\",");
                real_engine = (subselect_single_select_engine*)engine;
                select_lex_new = real_engine->get_st_select_lex();
                if (mysql_print_subselect(thd, query_node, print_str, select_lex_new, false))
                    return true;
            }

            str_append(print_str, "}");
        }
        break;
    case Item::SUM_FUNC_ITEM:
        {
            str_append(print_str, "{");
            print_sum_item(thd, query_node, print_str, item, select_lex);
            str_append(print_str, "}");
        }
        break;
    case Item::ROW_ITEM:
        {
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"ROW_ITEM\",");
            str_append(print_str, "\"ROW\":[");
            for (uint i=0; i < ((Item_row*)item)->cols();i++)
            {
                Item *right_item= ((Item_row*)item)->element_index(i);
                print_item(thd, query_node, print_str, right_item, select_lex);
                str_append(print_str, ",");
            }
            str_truncate(print_str, 1);
            str_append(print_str, "]");
            str_append(print_str, "}");
        }
        break;
    case Item::DECIMAL_ITEM:
        {
            String* stringval;
            String tmp;
            char* fieldname;
            str_append(print_str, "{");
            str_append(print_str, "\"type\":\"DECIMAL_ITEM\",");
            stringval = ((Item_string*) item)->val_str(&tmp);
            fieldname= (char*)my_malloc(stringval->length(), MY_ZEROFILL);
            sprintf(fieldname, "\"%s\"", stringval->ptr());
            str_append(print_str, "\"value\":");
            str_append(print_str, fieldname);
            str_append(print_str, "}");
        }
        break;
    default:
        break;
    }

    return 0;
}

int mysql_print_select(THD* thd)
{
    query_print_cache_node_t*   query_node;
    query_print_cache_t*        query_cache;
    check_rt_t*           rt;
    SELECT_LEX* select_lex = &thd->lex->select_lex;

    query_cache = thd->query_print_cache;

    query_node = (query_print_cache_node_t*)my_malloc(sizeof(query_print_cache_node_t), MY_ZEROFILL);
    query_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    query_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(query_node->query_tree);
    str_init(query_node->sql_statements);
    str_append_with_length(query_node->sql_statements, thd->query(), thd->query_length());
    str_append(query_node->query_tree, "{");

    str_append(query_node->query_tree, "\"command\":\"select\",");
    if (mysql_print_subselect(thd, query_node, query_node->query_tree, select_lex, true))
        return true;
    str_append(query_node->query_tree, "}");
    if (thd->errmsg != NULL)
    {
        query_node->errlevel= 1;
        query_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }

    LIST_ADD_LAST(link, query_cache->field_lst, query_node);
    return false;
}

int mysql_print_insert(THD* thd)
{
    query_print_cache_node_t*   query_node;
    query_print_cache_t*        query_cache;
    SELECT_LEX* select_lex = &thd->lex->select_lex;
    Item* item;
    List_item *values;
    char tablename[FN_LEN];

    query_cache = thd->query_print_cache;

    query_node = (query_print_cache_node_t*)my_malloc(sizeof(query_print_cache_node_t), MY_ZEROFILL);
    query_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    query_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(query_node->query_tree);
    str_init(query_node->sql_statements);
    str_append_with_length(query_node->sql_statements, thd->query(), thd->query_length());
    mysql_load_tables(thd, &query_node->rt_lst, select_lex);
    str_append(query_node->query_tree, "{");

    str_append(query_node->query_tree, "\"command\":\"insert\",");
    str_append(query_node->query_tree, "\"table_object\":");
    str_append(query_node->query_tree, "{");
    str_append(query_node->query_tree, "\"db\":");
    sprintf(tablename, "\"%s\",", thd->lex->query_tables->db);
    str_append(query_node->query_tree, tablename);

    str_append(query_node->query_tree, "\"table\":");
    sprintf(tablename, "\"%s\"", thd->lex->query_tables->table_name);
    str_append(query_node->query_tree, tablename);
    str_append(query_node->query_tree, "}");
    if (thd->lex->field_list.elements > 0)
    {
        str_append(query_node->query_tree, ",");
        str_append(query_node->query_tree, "\"fields\":[");
        List_iterator<Item> it(thd->lex->field_list);
        while ((item= it++))
        {
            print_item(thd, query_node, query_node->query_tree, item, &thd->lex->select_lex);
            str_append(query_node->query_tree, ",");
        }

        str_truncate(query_node->query_tree, 1);
        str_append(query_node->query_tree, "]");
    }

    if (thd->lex->sql_command != SQLCOM_INSERT_SELECT)
    {
        str_append(query_node->query_tree, ",");
        str_append(query_node->query_tree, "\"many_values\":[");
        List<List_item> &values_list = thd->lex->many_values;
        List_iterator_fast<List_item> its(values_list);
        while ((values = its++))
        {
            str_append(query_node->query_tree, "{");
            str_append(query_node->query_tree, "\"values\":[");
            List_iterator<Item> it(*values);
            while ((item= it++))
            {
                print_item(thd, query_node, query_node->query_tree, item, &thd->lex->select_lex);
                str_append(query_node->query_tree, ",");
            }
            str_truncate(query_node->query_tree, 1);
            str_append(query_node->query_tree, "]}");
            str_append(query_node->query_tree, ",");
        }
        str_truncate(query_node->query_tree, 1);
        str_append(query_node->query_tree, "]");
    }
    else
    {
        str_append(query_node->query_tree, ",");
        str_append(query_node->query_tree, "\"select_insert_values\":{");
        if (mysql_print_subselect(thd, query_node, query_node->query_tree, select_lex, true))
            return true;
        str_append(query_node->query_tree, "}");
    }

    str_append(query_node->query_tree, "}");
    if (thd->errmsg != NULL)
    {
        query_node->errlevel= 1;
        query_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }

    LIST_ADD_LAST(link, query_cache->field_lst, query_node);
    return false;
}

int mysql_print_delete(THD* thd)
{
    query_print_cache_node_t*   query_node;
    query_print_cache_t*        query_cache;
    SELECT_LEX* select_lex = &thd->lex->select_lex;

    query_cache = thd->query_print_cache;

    query_node = (query_print_cache_node_t*)my_malloc(sizeof(query_print_cache_node_t), MY_ZEROFILL);
    query_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    query_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(query_node->query_tree);
    str_init(query_node->sql_statements);
    str_append_with_length(query_node->sql_statements, thd->query(), thd->query_length());
    mysql_load_tables(thd, &query_node->rt_lst, select_lex);
    str_append(query_node->query_tree, "{");

    str_append(query_node->query_tree, "\"command\":\"delete\",");
    if (thd->lex->auxiliary_table_list.first)
    {
        mysql_print_tables(thd, query_node, select_lex, query_node->query_tree, 
            thd->lex->auxiliary_table_list.first, (char*)"table_object");
        str_append(query_node->query_tree, ",");
        mysql_print_tables(thd, query_node, select_lex, query_node->query_tree, 
            thd->lex->query_tables, (char*)"table_ref");
    }
    else
        mysql_print_tables(thd, query_node, select_lex, query_node->query_tree, 
            thd->lex->query_tables, (char*)"table_object");

    mysql_print_select_condition(thd, query_node, query_node->query_tree, select_lex);
    // if (select_lex->where)
    // {
    //     str_append(query_node->query_tree, ",");
    //     str_append(query_node->query_tree, "\"where\":[");
    //     print_item(thd, query_node, query_node->query_tree, select_lex->where, select_lex);
    //     str_append(query_node->query_tree, "]");
    // }

    str_append(query_node->query_tree, "}");
    if (thd->errmsg != NULL)
    {
        query_node->errlevel= 1;
        query_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }

    LIST_ADD_LAST(link, query_cache->field_lst, query_node);
    return false;
}

int mysql_print_update(THD* thd)
{
    query_print_cache_node_t*   query_node;
    query_print_cache_t*        query_cache;
    SELECT_LEX* select_lex = &thd->lex->select_lex;
    Item* item;

    query_cache = thd->query_print_cache;

    query_node = (query_print_cache_node_t*)my_malloc(sizeof(query_print_cache_node_t), MY_ZEROFILL);
    query_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    query_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(query_node->query_tree);
    str_init(query_node->sql_statements);
    str_append_with_length(query_node->sql_statements, thd->query(), thd->query_length());
    mysql_load_tables(thd, &query_node->rt_lst, select_lex);
    str_append(query_node->query_tree, "{");

    str_append(query_node->query_tree, "\"command\":\"update\",");
    str_append(query_node->query_tree, "\"set_fields\":{");
    str_append(query_node->query_tree, "\"fields\":[");
    List_iterator<Item> it(thd->lex->select_lex.item_list);
    while ((item= it++))
    {
        print_item(thd, query_node, query_node->query_tree, item, &thd->lex->select_lex);
        str_append(query_node->query_tree, ",");
    }

    str_truncate(query_node->query_tree, 1);
    str_append(query_node->query_tree, "]");
    str_append(query_node->query_tree, ",");
    str_append(query_node->query_tree, "\"values\":[");
    List_iterator<Item> vit(thd->lex->value_list);
    while ((item= vit++))
    {
        print_item(thd, query_node, query_node->query_tree, item, &thd->lex->select_lex);
        str_append(query_node->query_tree, ",");
    }
    str_truncate(query_node->query_tree, 1);
    str_append(query_node->query_tree, "]");
    str_append(query_node->query_tree, "}");

    str_append(query_node->query_tree, ",");
    mysql_print_tables(thd, query_node, select_lex, query_node->query_tree, 
        thd->lex->query_tables, (char*)"table_ref");

    mysql_print_select_condition(thd, query_node, query_node->query_tree, select_lex);

    str_append(query_node->query_tree, "}");
    if (thd->errmsg != NULL)
    {
        query_node->errlevel= 1;
        query_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }

    LIST_ADD_LAST(link, query_cache->field_lst, query_node);
    return false;
}

int mysql_print_not_support(THD* thd)
{
    query_print_cache_node_t*   query_node;
    query_print_cache_t*        query_cache;

    query_cache = thd->query_print_cache;

    query_node = (query_print_cache_node_t*)my_malloc(sizeof(query_print_cache_node_t), MY_ZEROFILL);
    query_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    query_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(query_node->query_tree);
    str_init(query_node->sql_statements);
    str_append_with_length(query_node->sql_statements, thd->query(), thd->query_length());

    my_error(ER_NOT_SUPPORTED_YET, MYF(0));
    mysql_errmsg_append(thd);
    if (thd->errmsg != NULL)
    {
        query_node->errlevel= 1;
        query_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }

    LIST_ADD_LAST(link, query_cache->field_lst, query_node);
    return false;
}

int mysql_print_command(THD *thd)
{
    thd->thread_state = INCEPTION_STATE_EXECUTING;
    int err;
    switch (thd->lex->sql_command)
    {
    case SQLCOM_CHANGE_DB:
        err = mysql_check_change_db(thd);
        break;

    case SQLCOM_INSERT:
    case SQLCOM_INSERT_SELECT:
        err = mysql_print_insert(thd);
        break;

    case SQLCOM_DELETE:
    case SQLCOM_DELETE_MULTI:
        err = mysql_print_delete(thd);
        break;

    case SQLCOM_UPDATE:
    case SQLCOM_UPDATE_MULTI:
        err = mysql_print_update(thd);
        break;

    case SQLCOM_SELECT:
        err = mysql_print_select(thd);
        break;

    default:
        mysql_print_not_support(thd);
        break;
    }

    return 0;
}

int mysql_check_subselect_item(
    THD* thd, 
    st_select_lex *select_lex, 
    bool top
)
{
    Item* item;
    ORDER*   order;

    if (!thd->rt_lst)
        thd->rt_lst = (rt_lst_t*)my_malloc(sizeof(rt_lst_t), MY_ZEROFILL);

    if (mysql_load_tables(thd, thd->rt_lst, select_lex))
        return true;
    List_iterator<Item> it(select_lex->item_list);
    while ((item= it++))
    {
        mysql_check_item(thd,  item, select_lex);
    }
    if (select_lex->where)
    {
        mysql_check_item(thd,  select_lex->where, select_lex);
    }

    if (select_lex->group_list.elements != 0)
    {
        for (order= thd->lex->select_lex.group_list.first ; order; order= order->next)
        {
            mysql_check_item(thd,  *order->item, select_lex);
        }
    }

    if (select_lex->having)
    {
        mysql_check_item(thd,  select_lex->having, select_lex);
    }

    if (select_lex->order_list.elements != 0)
    {
        for (order= thd->lex->select_lex.order_list.first ; order; order= order->next)
        {
            mysql_check_item(thd,  *order->item, select_lex);
        }
    }

    return 0;
}

int mysql_check_func_item(
    THD* thd, 
    Item* item, 
    st_select_lex *select_lex
)
{
    Item_func::Functype type;
    if (!item)
        return 0;
    type = ((Item_func *)item)->functype();
    switch(type)
    {
    case Item_func::EQ_FUNC:
    case Item_func::NE_FUNC:
    case Item_func::LT_FUNC:
    case Item_func::LE_FUNC:
    case Item_func::GE_FUNC:
    case Item_func::GT_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            mysql_check_item(thd,  left_item, select_lex);
            Item *right_item= ((Item_func*) item)->arguments()[1];
            mysql_check_item(thd,  right_item, select_lex);
        }
        break;

    case Item_func::COND_OR_FUNC:
    case Item_func::COND_AND_FUNC:
        {
            List<Item> *args= ((Item_cond*) item)->argument_list();
            List_iterator<Item> li(*args);
            Item *item_arg;
            while ((item_arg= li++))
            {
                mysql_check_item(thd,  item_arg, select_lex);
            }
        }
        break;
    case Item_func::ISNULL_FUNC:
    case Item_func::ISNOTNULL_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            mysql_check_item(thd,  left_item, select_lex);
        }
        break;
    case Item_func::LIKE_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            Item *right_item= ((Item_func*) item)->arguments()[1];
            mysql_check_item(thd,  left_item, select_lex);
            mysql_check_item(thd,  right_item, select_lex);
        }
        break;
    case Item_func::BETWEEN:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            Item *right_item1= ((Item_func*) item)->arguments()[1];
            Item *right_item2= ((Item_func*) item)->arguments()[2];
            mysql_check_item(thd,  left_item, select_lex);
            mysql_check_item(thd,  right_item1, select_lex);
            mysql_check_item(thd,  right_item2, select_lex);
        }
        break;
    case Item_func::IN_FUNC:
    case Item_func::MULT_EQUAL_FUNC:
        {
            for (uint i=0; i < ((Item_func*) item)->argument_count();i++)
            {
                Item *right_item= ((Item_func*) item)->arguments()[i];
                mysql_check_item(thd,  right_item, select_lex);
            }
        }
        break;
    case Item_func::NOT_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            mysql_check_item(thd,  left_item, select_lex);
        }
        break;
    case Item_func::NOW_FUNC:
        break;
    case Item_func::EXTRACT_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            mysql_check_item(thd,  left_item, select_lex);
        }
        break;
    case Item_func::FUNC_SP:
    case Item_func::UNKNOWN_FUNC:
        {
            for (uint i=0; i < ((Item_func*) item)->argument_count();i++)
            {
                Item *right_item= ((Item_func*) item)->arguments()[i];
                mysql_check_item(thd,  right_item, select_lex);
            }
        }
        break;
    default:
        break;
    }

    return 0;
}

int 
mysql_check_sum_item(
    THD* thd, 
    Item* item, 
    st_select_lex *select_lex
)
{
    Item_sum *item_sum= (((Item_sum*) item));
    switch(item_sum->sum_func())
    {
    case Item_sum::COUNT_FUNC:
    case Item_sum::COUNT_DISTINCT_FUNC:
    case Item_sum::SUM_FUNC:
    case Item_sum::SUM_DISTINCT_FUNC:
    case Item_sum::AVG_FUNC:
    case Item_sum::AVG_DISTINCT_FUNC:
    case Item_sum::MIN_FUNC:
    case Item_sum::MAX_FUNC:
    case Item_sum::STD_FUNC:
    case Item_sum::VARIANCE_FUNC:
    case Item_sum::SUM_BIT_FUNC:
    case Item_sum::UDF_SUM_FUNC:
    case Item_sum::GROUP_CONCAT_FUNC:
        {
            Item* item_count = ((Item_sum_count*) item)->get_arg(0);
            mysql_check_item(thd,  item_count, select_lex);
        }
        break;

    default:
        break;
    }

    return 0;
}

int
mysql_check_item(
    THD* thd, 
    Item* item, 
    st_select_lex *select_lex
)
{
    if (!item)
        return 0;
    switch (item->type()) {
    case Item::STRING_ITEM:
        {
            String* stringval;
            String tmp;
            char* fieldname;
            stringval = ((Item_string*) item)->val_str(&tmp);
            fieldname= (char*)my_malloc(stringval->length() + 10, MY_ZEROFILL);
            sprintf(fieldname, "\"%s\"", stringval->ptr());
        }
        break;
    case Item::FIELD_ITEM:
        {
            table_info_t* tableinfo;
            table_rt_t* tablert;
            if (strcasecmp(((Item_field*)item)->field_name, "*"))
            {
                tablert = mysql_find_field_from_all_tables(
                    thd, thd->rt_lst, select_lex, ((Item_field*)item)->db_name, 
                    ((Item_field*)item)->table_name, ((Item_field*)item)->field_name); 
                if (tablert)
                {
                    tableinfo = tablert->table_info;
                }
            }
        }
        break;
    case Item::FUNC_ITEM:
        {
            mysql_check_func_item(thd,  item, select_lex);
        }
        break;
    case Item::INT_ITEM:
        {
            char fieldname[FN_LEN];
            sprintf(fieldname, "\"%lld\"", ((Item_int*) item)->val_int());
        }
        break;
    case Item::REAL_ITEM:
        {
            char fieldname[FN_LEN];
            sprintf(fieldname, "\"%f\"", ((Item_int*) item)->val_real());
        }
        break;
    case Item::NULL_ITEM:
        break;
    case Item::COND_ITEM:
        {
            mysql_check_func_item(thd,  item, select_lex);
        }
        break;
    case Item::SUBSELECT_ITEM:
        {
            st_select_lex *select_lex_new;
            subselect_single_select_engine* real_engine;
            const subselect_engine *engine = ((Item_subselect*)item)->get_engine_for_explain();
            subselect_single_select_engine::enum_engine_type engine_type = engine->engine_type();
            if (engine_type == subselect_engine::SINGLE_SELECT_ENGINE)
            {
                real_engine = (subselect_single_select_engine*)engine;
                select_lex_new = real_engine->get_st_select_lex();
                if (mysql_check_subselect_item(thd,  select_lex_new, false))
                    return true;
            }
        }
        break;
    case Item::SUM_FUNC_ITEM:
        {
            mysql_check_sum_item(thd,  item, select_lex);
        }
        break;
    case Item::ROW_ITEM:
        {
            for (uint i=0; i < ((Item_row*)item)->cols();i++)
            {
                Item *right_item= ((Item_row*)item)->element_index(i);
                mysql_check_item(thd,  right_item, select_lex);
            }
        }
        break;
    case Item::DECIMAL_ITEM:
        {
            String* stringval;
            String tmp;
            char* fieldname;
            stringval = ((Item_string*) item)->val_str(&tmp);
            fieldname= (char*)my_malloc(stringval->length(), MY_ZEROFILL);
        }
        break;
    default:
        break;
    }

    return 0;
}

int mysql_check_command(THD *thd)
{
    int err;
    LEX  *lex= thd->lex;
    SELECT_LEX *select_lex= &lex->select_lex;
    TABLE_LIST *first_table= select_lex->table_list.first;
    
    thd->thread_state = INCEPTION_STATE_CHECKING;
    DBUG_ENTER("mysql_check_command");

    select_lex->context.resolve_in_table_list_only(select_lex->table_list.first);
    lex->first_lists_tables_same();
    thd->timestamp_count=0;
    
    if (!mysql_not_need_data_source(thd))
    {
        if (thd->lex->sql_command == SQLCOM_INSERT || 
            thd->lex->sql_command == SQLCOM_INSERT_SELECT) {
            /* Skip first table, which is the table we are inserting in */
            TABLE_LIST *second_table= first_table->next_local;
            select_lex->table_list.first= second_table;
            select_lex->context.table_list=
              select_lex->context.first_name_resolution_table= second_table;
        }

        //clear
        str_truncate(&thd->ddl_rollback, str_get_len(&thd->ddl_rollback));
    }

    thd_sql_statistic_increment(thd, 0);
    switch (thd->lex->sql_command)
    {
    case SQLCOM_CHANGE_DB:
        err = mysql_check_change_db(thd);
        break;

    case SQLCOM_SET_OPTION:
        err = mysql_set_option_check(thd);
        break;

    case SQLCOM_CREATE_DB:
        err = mysql_check_create_db(thd);
        break;

    case SQLCOM_INSERT:
        err = mysql_check_insert(thd);
        break;

    case SQLCOM_DELETE:
    case SQLCOM_DELETE_MULTI:
        err = mysql_check_delete(thd);
        break;

    case SQLCOM_UPDATE:
    case SQLCOM_UPDATE_MULTI:
        err = mysql_check_update(thd);
        break;

    case SQLCOM_SELECT:
        err = mysql_check_select(thd);
        break;

    case SQLCOM_CREATE_TABLE:
        err = mysql_check_create_table(thd);
        break;

    case SQLCOM_ALTER_TABLE:
        err = mysql_check_alter_table(thd);
        break;

    case SQLCOM_INSERT_SELECT:
        err = mysql_check_insert_select(thd);
        break;

    case SQLCOM_INCEPTION:
        err = mysql_execute_inception_command(thd);
        break;

    case SQLCOM_CREATE_INDEX:
    case SQLCOM_RENAME_TABLE:
    case SQLCOM_DROP_INDEX:
        my_error(ER_INDEX_USE_ALTER_TABLE, MYF(0));
        mysql_errmsg_append(thd);
        err = 1;
        break;

    case SQLCOM_TRUNCATE:
        err = mysql_check_truncate_table(thd);
        break;

    case SQLCOM_DROP_TABLE:
        err = mysql_check_drop_table(thd);
        break;

    default:
        my_error(ER_NOT_SUPPORTED_YET, MYF(0));
        mysql_errmsg_append(thd);
        err = 1;
    }

    DBUG_RETURN(err);
}

int mysql_table_is_not_exist(
    THD* thd,
    char* dbname,
    char* tablename
)
{
    char  desc_sql_space[256];
    char*  desc_sql;
    int   err;
    MYSQL*  mysql;
    MYSQL_RES * source_res;

    DBUG_ENTER("mysql_table_is_not_exist");

    desc_sql = desc_sql_space;
    sprintf(desc_sql, "desc `%s`.`%s`;", dbname, tablename);

    mysql= thd->get_backup_connection();
    if (mysql == NULL)
    {
        DBUG_RETURN(-1);
    }

    err = mysql_real_query(mysql, desc_sql, strlen(desc_sql));
    if (err)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(-1);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        if (mysql_errno(mysql) == ER_NO_SUCH_TABLE)
        {
            DBUG_RETURN(true);
        }

        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(-1);
    }

    mysql_free_result(source_res);
    DBUG_RETURN(false);
}

int mysql_get_create_sql_backup_table(
    char*   dbname,
    String*   create_sql
)
{
    char   sql_tmp[100];

    sprintf(sql_tmp, "`%s`.`%s`", dbname, REMOTE_BACKUP_TABLE);
    create_sql->append("create table ");
    create_sql->append(sql_tmp);
    create_sql->append("(");

    create_sql->append("opid_time varchar(50),");
    create_sql->append("start_binlog_file varchar(512),");
    create_sql->append("start_binlog_pos int,");
    create_sql->append("end_binlog_file varchar(512),");
    create_sql->append("end_binlog_pos int,");
    create_sql->append("sql_statement text,");
    create_sql->append("host VARCHAR(64),");
    create_sql->append("dbname VARCHAR(64),");
    create_sql->append("tablename VARCHAR(64),");
    create_sql->append("port INT,");
    create_sql->append("time TIMESTAMP,");
    create_sql->append("type VARCHAR(20)");

    create_sql->append(")ENGINE INNODB DEFAULT CHARSET UTF8;");

    return 0;
}

int mysql_get_create_sql_from_table_info(
    char*   dbname,
    table_info_t* table_info,
    String*   create_sql
)
{
    char   sql_tmp[100];

    create_sql->truncate();
    sprintf(sql_tmp, "`%s`.`%s`", dbname, table_info->table_name);
    create_sql->append("create table ");
    create_sql->append(sql_tmp);
    create_sql->append("(");

    create_sql->append("id bigint auto_increment primary key, ");
    create_sql->append("rollback_statement mediumtext, ");
    create_sql->append("opid_time varchar(50)");

    create_sql->append(") ENGINE INNODB DEFAULT CHARSET UTF8;");

    return 0;
}

int
mysql_sql_cache_is_valid_for_ddl(
    sql_cache_node_t* sql_cache_node
)
{
    if ((sql_cache_node->optype == SQLCOM_CREATE_TABLE ||
        sql_cache_node->optype == SQLCOM_DROP_TABLE ||
        sql_cache_node->optype == SQLCOM_ALTER_TABLE)
        && sql_cache_node->exe_complete)
    {
        return TRUE;
    }

    return FALSE;
}

int
mysql_sql_cache_is_valid(
    sql_cache_node_t* sql_cache_node
)
{
    if ((
        sql_cache_node->optype == SQLCOM_INSERT ||
        sql_cache_node->optype == SQLCOM_DELETE ||
        sql_cache_node->optype == SQLCOM_INSERT_SELECT ||
        sql_cache_node->optype == SQLCOM_UPDATE)
        && sql_cache_node->exe_complete)
    {
        return TRUE;
    }

    return FALSE;
}

int mysql_get_statistic_table_sql(
    String*   create_sql
)
{
    char   sql_tmp[100];

    create_sql->truncate();
    create_sql->append("create table ");
    create_sql->append("inception.statistic");
    create_sql->append("(");

    create_sql->append("id bigint auto_increment primary key, ");
    create_sql->append("optime timestamp not null default current_timestamp, ");
    create_sql->append("usedb int not null default 0, ");
    create_sql->append("deleting int not null default 0, ");
    create_sql->append("inserting int not null default 0, ");
    create_sql->append("updating int not null default 0, ");
    create_sql->append("selecting int not null default 0, ");
    create_sql->append("altertable int not null default 0, ");
    create_sql->append("renaming int not null default 0, ");
    create_sql->append("createindex int not null default 0, ");
    create_sql->append("dropindex int not null default 0, ");
    create_sql->append("addcolumn int not null default 0, ");
    create_sql->append("dropcolumn int not null default 0, ");
    create_sql->append("changecolumn int not null default 0, ");
    create_sql->append("alteroption int not null default 0, ");
    create_sql->append("alterconvert int not null default 0, ");
    create_sql->append("createtable int not null default 0, ");
    create_sql->append("droptable int not null default 0, ");
    create_sql->append("createdb int not null default 0, ");
    create_sql->append("truncating int not null default 0 ");

    create_sql->append(") ENGINE INNODB DEFAULT CHARSET UTF8;");

    return 0;
}

int mysql_make_sure_statistic_table_exist(THD *thd)
{
    char  desc_sql[256];
    MYSQL*  mysql_remote;
    String  create_sql;
    String  create_info_sql;

    DBUG_ENTER("mysql_make_sure_backupdb_table_exist");

    if ((mysql_remote= thd->get_backup_connection()) == NULL)
        DBUG_RETURN(TRUE);

    sprintf(desc_sql, "create database inception;");
    if (mysql_real_query(mysql_remote, desc_sql, strlen(desc_sql)))
    {
        if (mysql_errno(mysql_remote) != 1007/*ER_DB_CREATE_EXISTS*/)
        {
            my_message(mysql_errno(mysql_remote), mysql_error(mysql_remote), MYF(0));
            DBUG_RETURN(true);
        }

        thd->clear_error();
    }

    mysql_get_statistic_table_sql(&create_sql);

    if (mysql_real_query(mysql_remote, create_sql.ptr(), create_sql.length()))
    {
        if (mysql_errno(mysql_remote) != 1050/*ER_TABLE_EXISTS_ERROR*/)
        {
            my_message(mysql_errno(mysql_remote), mysql_error(mysql_remote), MYF(0));
            DBUG_RETURN(true);
        }

        thd->clear_error();
    }

    DBUG_RETURN(false);
}

int mysql_get_statistic_table_insert_sql(
    THD* thd,
    String*   create_sql
)
{
    char   sql_tmp[100];

    create_sql->truncate();
    create_sql->append("INSERT INTO ");
    create_sql->append("inception.statistic");
    create_sql->append("(");
    create_sql->append("usedb, ");
    create_sql->append("deleting, ");
    create_sql->append("inserting, ");
    create_sql->append("updating, ");
    create_sql->append("selecting, ");
    create_sql->append("altertable, ");
    create_sql->append("renaming, ");
    create_sql->append("createindex, ");
    create_sql->append("dropindex, ");
    create_sql->append("addcolumn, ");
    create_sql->append("dropcolumn, ");
    create_sql->append("changecolumn, ");
    create_sql->append("alteroption, ");
    create_sql->append("alterconvert, ");
    create_sql->append("createtable, ");
    create_sql->append("droptable, ");
    create_sql->append("createdb, ");
    create_sql->append("truncating ");
    create_sql->append(") VALUES");
    create_sql->append("(");
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.usedb);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.deleting);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.insert);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.update);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.select);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.altertable);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.rename);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.createindex);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.dropindex);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.addcolumn);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.dropcolumn);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.changecolumn);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.alteroption);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.alterconvert);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.createtable);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.droptable);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d, ", thd->sql_statistic.createdb);
    create_sql->append(sql_tmp);
    sprintf(sql_tmp, "%d", thd->sql_statistic.truncate);
    create_sql->append(sql_tmp);
    create_sql->append(")");

    return 0;
}

int mysql_execute_remote_backup_sql(
    THD*  thd,
    char*  sql
)
{
    MYSQL*  mysql;

    DBUG_ENTER("mysql_execute_remote_backup_sql");

    if ((mysql= thd->get_backup_connection()) == NULL)
        DBUG_RETURN(TRUE);

    if (mysql_real_query(mysql, sql, strlen(sql)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    DBUG_RETURN(false);
}

int mysql_operation_statistic(THD* thd)
{
    if (!inception_enable_sql_statistic)
        return true;

    String  create_sql;
    mysql_make_sure_statistic_table_exist(thd);
    mysql_get_statistic_table_insert_sql(thd, &create_sql);
    mysql_execute_remote_backup_sql(thd, create_sql.c_ptr());
    return false;
}


int mysql_make_sure_backupdb_table_exist(THD *thd, sql_cache_node_t* sql_cache_node)
{
    char  dbname[NAME_CHAR_LEN + 1];
    char  desc_sql[256];
    MYSQL*  mysql_remote;
    String  create_sql;
    String  create_info_sql;

    DBUG_ENTER("mysql_make_sure_backupdb_table_exist");

    if (sql_cache_node->table_info->remote_existed)
        DBUG_RETURN(FALSE);

    if (mysql_get_remote_backup_dbname(thd->thd_sinfo->host, thd->thd_sinfo->port,
        sql_cache_node->dbname, dbname))
        DBUG_RETURN(TRUE);

    if ((mysql_remote= thd->get_backup_connection()) == NULL)
        DBUG_RETURN(TRUE);

    sprintf(desc_sql, "create database `%s`;", dbname);
    if (mysql_real_query(mysql_remote, desc_sql, strlen(desc_sql)))
    {
        if (mysql_errno(mysql_remote) != 1007/*ER_DB_CREATE_EXISTS*/)
        {
            my_message(mysql_errno(mysql_remote), mysql_error(mysql_remote), MYF(0));
            DBUG_RETURN(true);
        }

        thd->clear_error();
    }

    mysql_get_create_sql_from_table_info(dbname, sql_cache_node->table_info, &create_sql);

    if (mysql_real_query(mysql_remote, create_sql.ptr(), create_sql.length()))
    {
        if (mysql_errno(mysql_remote) != 1050/*ER_TABLE_EXISTS_ERROR*/)
        {
            my_message(mysql_errno(mysql_remote), mysql_error(mysql_remote), MYF(0));
            DBUG_RETURN(true);
        }

        thd->clear_error();
    }

    mysql_get_create_sql_backup_table(dbname, &create_info_sql);
    if (mysql_real_query(mysql_remote, create_info_sql.ptr(), create_info_sql.length()))
    {
        if (mysql_errno(mysql_remote) != 1050/*ER_TABLE_EXISTS_ERROR*/)
        {
            my_message(mysql_errno(mysql_remote), mysql_error(mysql_remote), MYF(0));
            DBUG_RETURN(true);
        }

        thd->clear_error();
    }

    sql_cache_node->table_info->remote_existed = TRUE;
    DBUG_RETURN(false);
}

void mysql_change_db_impl(THD *thd,
    LEX_STRING *new_db_name,
    ulong new_db_access,
    const CHARSET_INFO *new_db_charset)
{
    /* 1. Change current database in THD. */

    if (new_db_name == NULL)
    {
        /*
        THD::set_db() does all the job -- it frees previous database name and
        sets the new one.
        */

        thd->set_db(NULL, 0);
    }
    else if (new_db_name == &INFORMATION_SCHEMA_NAME)
    {
        /*
        Here we must use THD::set_db(), because we want to copy
        INFORMATION_SCHEMA_NAME constant.
        */

        thd->set_db(INFORMATION_SCHEMA_NAME.str, INFORMATION_SCHEMA_NAME.length);
    }
    else
    {
        /*
        Here we already have a copy of database name to be used in THD. So,
        we just call THD::reset_db(). Since THD::reset_db() does not releases
        the previous database name, we should do it explicitly.
        */
        my_free(thd->db);

        thd->reset_db(new_db_name->str, new_db_name->length);
    }

    /* 2. Update security context. */

#ifndef NO_EMBEDDED_ACCESS_CHECKS
    thd->security_ctx->db_access= new_db_access;
#endif

    /* 3. Update db-charset environment variables. */

    thd->db_charset= new_db_charset;
    thd->variables.collation_database= new_db_charset;
}


bool mysql_change_db(THD *thd, const LEX_STRING *new_db_name, bool force_switch)
{
    LEX_STRING new_db_file_name;

    Security_context *sctx= thd->security_ctx;
    ulong db_access= sctx->db_access;
    const CHARSET_INFO *db_default_cl;

    DBUG_ENTER("mysql_change_db");
    DBUG_PRINT("enter",("name: '%s'", new_db_name->str));

    if (new_db_name == NULL ||
        new_db_name->length == 0)
    {
        if (force_switch)
        {
            /*
            This can happen only if we're switching the current database back
            after loading stored program. The thing is that loading of stored
            program can happen when there is no current database.

            TODO: actually, new_db_name and new_db_name->str seem to be always
            non-NULL. In case of stored program, new_db_name->str == "" and
            new_db_name->length == 0.
            */

            mysql_change_db_impl(thd, NULL, 0, thd->variables.collation_server);

            DBUG_RETURN(FALSE);
        }
        else
        {
            my_message(ER_NO_DB_ERROR, ER(ER_NO_DB_ERROR), MYF(0));
            mysql_errmsg_append(thd);
            DBUG_RETURN(TRUE);
        }
    }

    if (is_infoschema_db(new_db_name->str, new_db_name->length))
    {
        /* Switch the current database to INFORMATION_SCHEMA. */

        mysql_change_db_impl(thd, &INFORMATION_SCHEMA_NAME, SELECT_ACL,
            system_charset_info);

        DBUG_RETURN(FALSE);
    }

    new_db_file_name.str= my_strndup(new_db_name->str, new_db_name->length,
        MYF(MY_WME));
    new_db_file_name.length= new_db_name->length;

    if (new_db_file_name.str == NULL)
    {
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);                             /* the error is set */
    }

    if (check_and_convert_db_name(&new_db_file_name, FALSE) != IDENT_NAME_OK)
    {
        my_free(new_db_file_name.str);

        if (force_switch)
            mysql_change_db_impl(thd, NULL, 0, thd->variables.collation_server);
        DBUG_RETURN(TRUE);
    }

    //to do ...做DB缓存，不然创建库然后马上使用会有问题
    if (thd->have_begin && mysql_check_db_existed(thd, new_db_file_name.str))
    {
        my_error(ER_DB_NOT_EXISTED_ERROR, MYF(0), new_db_file_name.str);
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);
    }

    db_default_cl= get_default_db_collation(thd, new_db_file_name.str);
    mysql_change_db_impl(thd, &new_db_file_name, db_access, db_default_cl);

    strcpy(thd->thd_sinfo->db, thd->db);

    DBUG_RETURN(FALSE);
}


int mysql_fetch_master_binlog_position(
    THD *  thd,
    MYSQL*  mysql,
    char*  file_name,
    int*  binlog_pos
)
{
    char  desc_sql[256];
    int   err;
    MYSQL_RES * source_res;
    MYSQL_ROW   source_row;

    DBUG_ENTER("mysql_fetch_master_binlog_position");

    sprintf(desc_sql, "show master status;");

    err = mysql_real_query(mysql, desc_sql, strlen(desc_sql));
    if (err)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(-1);
    }

    source_row = mysql_fetch_row(source_res);
    strcpy(file_name, source_row[0]);
    *binlog_pos = atoi(source_row[1]);
    mysql_free_result(source_res);
    DBUG_RETURN(0);
}

int mysql_execute_sql_single(
    THD*  thd,
    char*  sql
)
{
    MYSQL*  mysql;

    DBUG_ENTER("mysql_execute_sql_single");

    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        DBUG_RETURN(TRUE);
    }

    if (mysql_real_query(mysql, sql, strlen(sql)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    DBUG_RETURN(false);
}

int register_slave_on_master(MYSQL* mysql,
    bool *suppress_warnings)
{
    uchar buf[1024], *pos= buf;
    DBUG_ENTER("register_slave_on_master");

    *suppress_warnings= FALSE;

    int4store(pos, server_id); pos+= 4;
    pos= net_store_data(pos, (uchar*) 0, 0);
    pos= net_store_data(pos, (uchar*) 0, 0);
    pos= net_store_data(pos, (uchar*) 0, 0);
    int2store(pos, (uint16) report_port); pos+= 2;

    int4store(pos, /* rpl_recovery_rank */ 0);    pos+= 4;
    /* The master will fill in master_id */
    int4store(pos, 0);                    pos+= 4;

    if (simple_command(mysql, COM_REGISTER_SLAVE, buf, (size_t) (pos- buf), 0))
    {
        if (mysql_errno(mysql) == ER_NET_READ_INTERRUPTED)
            *suppress_warnings= TRUE;                 // Suppress reconnect warning
        else
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(1);
    }

    DBUG_RETURN(0);
}

ulong mysql_read_event(MYSQL* mysql)
{
    ulong len;
    DBUG_ENTER("mysql_read_event");

    len = cli_safe_read(mysql);
    if (len == packet_error || (long) len < 1)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(packet_error);
    }

    /* Check if eof packet */
    if (len < 8 && mysql->net.read_pos[0] == 254)
    {
        DBUG_RETURN(0);
    }

    DBUG_RETURN(len - 1);
}

int mysql_request_binlog_dump(
    MYSQL*  mysql,
    char*  file_name,
    int   binlog_pos
)
{
    const int BINLOG_NAME_INFO_SIZE= strlen(file_name);
    size_t command_size= 0;
    enum_server_command command= COM_BINLOG_DUMP;
    uchar* command_buffer= NULL;
    ushort binlog_flags= 0;
    uchar* ptr_buffer = NULL;

    DBUG_ENTER("mysql_request_binlog_dump");

    size_t allocation_size= ::BINLOG_POS_OLD_INFO_SIZE +
        BINLOG_NAME_INFO_SIZE + ::BINLOG_FLAGS_INFO_SIZE +
        ::BINLOG_SERVER_ID_INFO_SIZE + 1;
    if (!(command_buffer= (uchar *) my_malloc(allocation_size, MYF(MY_WME))))
        DBUG_RETURN(TRUE);

    ptr_buffer= command_buffer;

    int4store(ptr_buffer, binlog_pos);
    ptr_buffer+= ::BINLOG_POS_OLD_INFO_SIZE;
    // See comment regarding binlog_flags above.
    int2store(ptr_buffer, binlog_flags);
    ptr_buffer+= ::BINLOG_FLAGS_INFO_SIZE;
    int4store(ptr_buffer, server_id);
    ptr_buffer+= ::BINLOG_SERVER_ID_INFO_SIZE;
    memcpy(ptr_buffer, file_name, BINLOG_NAME_INFO_SIZE);
    ptr_buffer+= BINLOG_NAME_INFO_SIZE;

    command_size= ptr_buffer - command_buffer;
    DBUG_ASSERT(command_size == (allocation_size - 1));

    if (simple_command(mysql, command, command_buffer, command_size, 1))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        my_free(command_buffer);
        DBUG_RETURN(TRUE);
    }

    my_free(command_buffer);
    DBUG_RETURN(FALSE);
}

Log_event* mysql_read_log_event(
    const char* buf,
    uint event_len,
    char **error,
    const Format_description_log_event *description_event
)
{
    Log_event* ev;
    uint8 alg;
    DBUG_ENTER("mysql_read_log_event");

    /* Check the integrity */
    if (event_len < EVENT_LEN_OFFSET ||
        buf[EVENT_TYPE_OFFSET] >= ENUM_END_EVENT ||
        (uint) event_len != uint4korr(buf+EVENT_LEN_OFFSET))
    {
        DBUG_RETURN(NULL); // general sanity check - will fail on a partial read
    }

    uint event_type= buf[EVENT_TYPE_OFFSET];

    alg= (event_type != FORMAT_DESCRIPTION_EVENT) ?
        description_event->checksum_alg : get_checksum_alg(buf, event_len);

    if (alg != BINLOG_CHECKSUM_ALG_UNDEF &&
        (event_type == FORMAT_DESCRIPTION_EVENT ||
        alg != BINLOG_CHECKSUM_ALG_OFF))
        event_len= event_len - BINLOG_CHECKSUM_LEN;

    switch(event_type) {
    case QUERY_EVENT:
        ev  = new Query_log_event(buf, event_len, description_event, QUERY_EVENT);
        break;
    case FORMAT_DESCRIPTION_EVENT:
        ev = new Format_description_log_event(buf, event_len, description_event);
        break;
    case WRITE_ROWS_EVENT_V1:
        ev = new Write_rows_log_event(buf, event_len, description_event);
        break;
    case UPDATE_ROWS_EVENT_V1:
        ev = new Update_rows_log_event(buf, event_len, description_event);
        break;
    case DELETE_ROWS_EVENT_V1:
        ev = new Delete_rows_log_event(buf, event_len, description_event);
        break;
    case TABLE_MAP_EVENT:
        ev = new Table_map_log_event(buf, event_len, description_event);
        break;
    case WRITE_ROWS_EVENT:
        ev = new Write_rows_log_event(buf, event_len, description_event);
        break;
    case UPDATE_ROWS_EVENT:
        ev = new Update_rows_log_event(buf, event_len, description_event);
        break;
    case DELETE_ROWS_EVENT:
        ev = new Delete_rows_log_event(buf, event_len, description_event);
        break;
    default:
        ev = new Ignorable_log_event(buf, description_event);
        break;
    }

    if (ev)
    {
        ev->checksum_alg= alg;
        if (ev->checksum_alg != BINLOG_CHECKSUM_ALG_OFF &&
            ev->checksum_alg != BINLOG_CHECKSUM_ALG_UNDEF)
            ev->crc= uint4korr(buf + (event_len));
    }

    if (!ev || !ev->is_valid() || (event_type == SLAVE_EVENT))
    {
        delete ev;
        DBUG_RETURN(0);
    }

    DBUG_RETURN(ev);
}

int process_io_rotate(Master_info *mi, Rotate_log_event *rev)
{
    DBUG_ENTER("process_io_rotate");

    if (unlikely(!rev->is_valid()))
        DBUG_RETURN(1);

    /* Safe copy as 'rev' has been "sanitized" in Rotate_log_event's ctor */
    memcpy(const_cast<char *>(mi->get_master_log_name()),
        rev->new_log_ident, rev->ident_len + 1);
    mi->set_master_log_pos(rev->pos);

    Format_description_log_event *old_fdle= mi->get_mi_description_event();
    if (old_fdle->binlog_version >= 4)
    {
        Format_description_log_event *new_fdle= new
            Format_description_log_event(3);
        new_fdle->checksum_alg= mi->relay_log_checksum_alg;
        mi->set_mi_description_event(new_fdle);
    }

    DBUG_RETURN(false);
}

int mysql_process_event(Master_info* mi,const char* buf, ulong event_len, Log_event** evlog)
{
    String error_msg;
    ulong inc_pos= 0;
    char*   error_desc;

    uint8 checksum_alg= mi->checksum_alg_before_fd != BINLOG_CHECKSUM_ALG_UNDEF ?
        mi->checksum_alg_before_fd : mi->relay_log_checksum_alg;

    Log_event_type event_type= (Log_event_type)buf[EVENT_TYPE_OFFSET];

    DBUG_ASSERT(checksum_alg == BINLOG_CHECKSUM_ALG_OFF ||
        checksum_alg == BINLOG_CHECKSUM_ALG_UNDEF ||
        checksum_alg == BINLOG_CHECKSUM_ALG_CRC32);

    DBUG_ENTER("mysql_process_event");
    /*
    FD_queue checksum alg description does not apply in a case of
    FD itself. The one carries both parts of the checksum data.
    */
    if (event_type == FORMAT_DESCRIPTION_EVENT)
    {
        checksum_alg= get_checksum_alg(buf, event_len);
    }
    else if (event_type == START_EVENT_V3)
    {
        // checksum behaviour is similar to the pre-checksum FD handling
        mi->checksum_alg_before_fd= BINLOG_CHECKSUM_ALG_UNDEF;
        mi->get_mi_description_event()->checksum_alg=
            mi->relay_log_checksum_alg= checksum_alg=
            BINLOG_CHECKSUM_ALG_OFF;
    }

    if (event_checksum_test((uchar *) buf, event_len, checksum_alg))
    {
        my_error(ER_NETWORK_READ_EVENT_CHECKSUM_FAILURE, MYF(0));
        DBUG_RETURN(true);
    }

    if (mi->get_mi_description_event()->binlog_version < 4 &&
        event_type != FORMAT_DESCRIPTION_EVENT /* a way to escape */)
    {
        my_error(ER_NETWORK_READ_EVENT_CHECKSUM_FAILURE, MYF(0));
        DBUG_RETURN(true);
    }

    switch (event_type) {
    case ROTATE_EVENT:
        {
            Rotate_log_event rev(buf, checksum_alg != BINLOG_CHECKSUM_ALG_OFF ?
                event_len - BINLOG_CHECKSUM_LEN : event_len,
                mi->get_mi_description_event());

            if (unlikely(process_io_rotate(mi, &rev)))
            {
                my_error(ER_SLAVE_RELAY_LOG_WRITE_FAILURE, MYF(0));
                DBUG_RETURN(true);
            }
        }

        break;

    case FORMAT_DESCRIPTION_EVENT:
        {
            /*
            Create an event, and save it (when we rotate the relay log, we will have
            to write this event again).
            */
            /*
            We are the only thread which reads/writes mi_description_event.
            The relay_log struct does not move (though some members of it can
            change), so we needn't any lock (no rli->data_lock, no log lock).
            */
            const char* errmsg;
            // mark it as undefined that is irrelevant anymore
            mi->checksum_alg_before_fd= BINLOG_CHECKSUM_ALG_UNDEF;
            Format_description_log_event *new_fdle=
                (Format_description_log_event*)
                Log_event::read_log_event(buf, event_len, &errmsg,
                mi->get_mi_description_event(), 1);
            if (new_fdle == NULL)
            {
                my_error(ER_SLAVE_RELAY_LOG_WRITE_FAILURE, MYF(0));
                DBUG_RETURN(true);
            }
            if (new_fdle->checksum_alg == BINLOG_CHECKSUM_ALG_UNDEF)
                new_fdle->checksum_alg= BINLOG_CHECKSUM_ALG_OFF;
            mi->set_mi_description_event(new_fdle);

            /* installing new value of checksum Alg for relay log */
            mi->relay_log_checksum_alg= new_fdle->checksum_alg;

            inc_pos= uint4korr(buf+LOG_POS_OFFSET) ? event_len : 0;
        }
        break;

    default:
        inc_pos= event_len;
        break;
    }

    *evlog = mysql_read_log_event(buf, event_len,
        &error_desc, mi->get_mi_description_event());
    if (!*evlog)
    {
        my_message(10000, "Binlog read error", MYF(0));
        DBUG_RETURN(true);
    }

    DBUG_RETURN(false);
}


int mysql_get_master_version(MYSQL* mysql, Master_info* mi)
{
    char err_buff[MAX_SLAVE_ERRMSG];
    const char* errmsg= 0;
    int err_code= 0;
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
    DBUG_ASSERT(mi->relay_log_checksum_alg !=BINLOG_CHECKSUM_ALG_UNDEF);


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

    if (mysql_real_query(mysql, "SET @master_binlog_checksum='NONE'",
                         strlen("SET @master_binlog_checksum='NONE'")))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(mi->thd);
    }

    DBUG_RETURN(0);
}


enum_tbl_map_status
    check_table_map(Master_info* mi, RPL_TABLE_LIST *table_list)
{
    DBUG_ENTER("check_table_map");
    enum_tbl_map_status res= OK_TO_PROCESS;
    RPL_TABLE_LIST *ptr= static_cast<RPL_TABLE_LIST*>(mi->tables_to_lock);
    for(uint i=0 ; ptr && (i< mi->tables_to_lock_count);
        ptr= static_cast<RPL_TABLE_LIST*>(ptr->next_local), i++)
    {
        if (ptr->table_id == table_list->table_id)
        {
            if (strcasecmp(ptr->db, table_list->db) ||
                strcasecmp(ptr->alias, table_list->table_name) ||
                ptr->lock_type != TL_WRITE) // the ::do_apply_event always sets TL_WRITE
                res= SAME_ID_MAPPING_DIFFERENT_TABLE;
            else
                res= SAME_ID_MAPPING_SAME_TABLE;

            break;
        }
    }

    DBUG_RETURN(res);
}

int mysql_parse_table_map_log_event(Master_info *mi, Log_event* ev)
{
    RPL_TABLE_LIST *table_list;
    char *db_mem, *tname_mem;
    void *memory;
    Table_map_log_event* tab_map_ev;

    DBUG_ENTER("mysql_parse_table_map_log_event");

    if (!(memory= my_multi_malloc(MYF(MY_WME),
        &table_list, (uint) sizeof(RPL_TABLE_LIST),
        &db_mem, (uint) NAME_LEN + 1,
        &tname_mem, (uint) NAME_LEN + 1,
        NullS)))
        DBUG_RETURN(HA_ERR_OUT_OF_MEM);

    tab_map_ev = (Table_map_log_event*)ev;

    strmov(db_mem, tab_map_ev->get_db());
    strmov(tname_mem, tab_map_ev->get_table_name());

    table_list->init_one_table(db_mem, strlen(db_mem),
        tname_mem, strlen(tname_mem),
        tname_mem, TL_WRITE);

    table_list->table_id= tab_map_ev->get_table_id();
    table_list->updating= 1;

    enum_tbl_map_status tblmap_status= check_table_map(mi, table_list);
    if (tblmap_status == OK_TO_PROCESS)
    {
        new (&table_list->m_tabledef)
            table_def(tab_map_ev->m_coltype, tab_map_ev->m_colcnt,
            tab_map_ev->m_field_metadata, tab_map_ev->m_field_metadata_size,
            tab_map_ev->m_null_bits, tab_map_ev->m_flags);
        table_list->m_tabledef_valid= TRUE;
        table_list->m_conv_table= NULL;
        table_list->open_type= OT_BASE_ONLY;

        /*
        We record in the slave's information that the table should be
        locked by linking the table into the list of tables to lock.
        */
        table_list->next_global= table_list->next_local= mi->tables_to_lock;
        mi->tables_to_lock= table_list;
        mi->tables_to_lock_count++;
        /* 'memory' is freed in clear_tables_to_lock */
    }
    else  // FILTERED_OUT, SAME_ID_MAPPING_*
    {
        my_free(memory);
    }

    DBUG_RETURN(tblmap_status == SAME_ID_MAPPING_DIFFERENT_TABLE);
}

uchar *
mysql_field_unpack(uchar* to, uchar *from, uint param_data,
    bool low_byte_first, uint length, enum_field_types real_type)
{
    int from_type= 0;
    /*
    If from length is > 255, it has encoded data in the upper bits. Need
    to mask it out.
    */
    if (param_data > 255)
    {
        from_type= (param_data & 0xff00) >> 8U;  // real_type.
        param_data= param_data & 0x00ff;        // length.
    }

    if ((param_data == 0) ||
        (length == param_data) ||
        (from_type != real_type))
    {
        memcpy(to, from, length);
        return from+length;
    }

    uint len= (param_data && (param_data < length)) ?
param_data : length;

    memcpy(to, from, param_data > length ? length : len);
    return from+len;
}

bool mysql_get_table_data(Master_info* mi, table_def **tabledef_var, TABLE **conv_table_var)
{
    DBUG_ENTER("mysql_get_table_data");

    for (RPL_TABLE_LIST *ptr= mi->tables_to_lock ; ptr != NULL ; 
        ptr= static_cast<RPL_TABLE_LIST*>(ptr->next_global))
    {
        if (strcasecmp(ptr->db, mi->table_info->db_name) == 0
          && strcasecmp(ptr->table_name , mi->table_info->table_name) == 0)
        {
            TABLE *conv_table = NULL;
            *tabledef_var= &static_cast<RPL_TABLE_LIST*>(ptr)->m_tabledef;
            *conv_table_var= static_cast<RPL_TABLE_LIST*>(ptr)->m_conv_table;

            if (!(static_cast<RPL_TABLE_LIST*>(ptr)->m_conv_table) && 
                !ptr->m_tabledef.compatible_with(mi->thd, NULL, 
                mi->table_info, &conv_table, mi->get_lock_tables_mem_root()))
            {
                DBUG_RETURN(FALSE);
            }

            if (conv_table)
                ptr->m_conv_table= conv_table;
            *tabledef_var= &static_cast<RPL_TABLE_LIST*>(ptr)->m_tabledef;
            *conv_table_var= static_cast<RPL_TABLE_LIST*>(ptr)->m_conv_table;
            DBUG_RETURN(TRUE);
        }
    }

    DBUG_RETURN(FALSE);
}

int
mysql_unpack_row(
    Master_info* mi,
    uchar const *const row_data,
    MY_BITMAP const *cols,
    uchar const **const row_end,
    uchar const *const row_end_ptr)
{
    table_info_t*  table_info;
    field_info_t*  field_node;
    Field*    field;

    DBUG_ENTER("mysql_unpack_row");
    DBUG_ASSERT(row_data);

    size_t const master_null_byte_count= (bitmap_bits_set(cols) + 7) / 8;
    int error= 0;

    uchar const *null_ptr= row_data;
    uchar const *pack_ptr= row_data + master_null_byte_count;

    if (bitmap_is_clear_all(cols))
    {
        *row_end= pack_ptr;
        DBUG_RETURN(error);
    }

    table_info = mi->table_info;

    DBUG_ASSERT(null_ptr < row_data + master_null_byte_count);

    unsigned int null_mask= 1U;
    unsigned int null_bits= *null_ptr++;
    uint i= 0;
    table_def *tabledef= NULL;
    TABLE *conv_table= NULL;

    if (!mysql_get_table_data(mi, &tabledef, &conv_table))
    {
        my_error(ER_SLAVE_CORRUPT_EVENT, MYF(0));
        DBUG_RETURN(ER_SLAVE_CORRUPT_EVENT);
    }

    field_node = LIST_GET_FIRST(table_info->field_lst);
    while (field_node != NULL)
    {
        field = field_node->field;
        Field *conv_field= conv_table ? conv_table->field[i] : NULL;
        field = conv_field ? conv_field : field;
        field_node->conv_field = field;
        // field->field_index = field_node->field->field_index;

        if (bitmap_is_set(cols, i))
        {
            if ((null_mask & 0xFF) == 0)
            {
                DBUG_ASSERT(null_ptr < row_data + master_null_byte_count);
                null_mask= 1U;
                null_bits= *null_ptr++;
            }

            DBUG_ASSERT(null_mask & 0xFF); // One of the 8 LSB should be set
            DBUG_ASSERT(pack_ptr != NULL);
            if (null_bits & null_mask)
            {
                table_info->null_arr[i] = TRUE;
            }
            else
            {
                table_info->null_arr[i] = FALSE;
                uint16 const metadata= tabledef->field_metadata(i);
                pack_ptr= field->unpack(field->ptr, pack_ptr, metadata, TRUE);
            }

            null_mask <<= 1;
        }
        else
        {
            DBUG_RETURN(ER_BINLOG_CORRUPTED);
        }

        i++;
        field_node = LIST_GET_NEXT(link, field_node);
    }

    /*
    throw away master's extra fields
    */
    uint max_cols= min<ulong>(tabledef->size(), cols->n_bits);
    for (; i < max_cols; i++)
    {
        if (bitmap_is_set(cols, i))
        {
            if ((null_mask & 0xFF) == 0)
            {
                DBUG_ASSERT(null_ptr < row_data + master_null_byte_count);
                null_mask= 1U;
                null_bits= *null_ptr++;
            }
            DBUG_ASSERT(null_mask & 0xFF); // One of the 8 LSB should be set

            if (!((null_bits & null_mask) && tabledef->maybe_null(i))) {
                uint32 len= tabledef->calc_field_size(i, (uchar *) pack_ptr);
                pack_ptr+= len;
            }
            null_mask <<= 1;
        }
    }

    *row_end = pack_ptr;
    DBUG_RETURN(error);
}

void
mysql_dup_char(
    char* src,
    char* dest,
    char chr
)
{
    char* p = src;
    while (*src)
    {
        //对于存在转义的情况，则不做替换
        if (*src == chr && (p == src || *(src-1) != '\\'))
        {
            *dest=chr;
            *(++dest) = chr;
        }
        else
        {
            *dest = *src;
        }

        dest++;
        src++;
    }

}

int mysql_get_field_string(Field* field, String* backupsql, char* null_arr, int field_index)
{
    int result = 0;                       // Will be set if null_value == 0
    enum_field_types f_type;
    String *res;
    int qutor_end=0;
    int append_flag=1;
    uchar buff[MAX_FIELD_WIDTH];
    String buffer((char*) buff,sizeof(buff),&my_charset_bin);
    String buffer2((char*) buff,sizeof(buff),&my_charset_bin);
    char* dupcharfield;

    // backupsql->append(separated);

    if (null_arr[field_index])
    {
        backupsql->append("NULL");
        append_flag = FALSE;
    }
    else
    {
        switch ((f_type=field->real_type())) {
        default:
        case MYSQL_TYPE_NULL:
            backupsql->append("NULL");
            append_flag = FALSE;
            break;

        // case MYSQL_TYPE_GEOMETRY:
        case MYSQL_TYPE_ENUM:
        case MYSQL_TYPE_SET:
            res=field->val_str(&buffer);
            break;

        case MYSQL_TYPE_DECIMAL:
        case MYSQL_TYPE_TINY_BLOB://255
        case MYSQL_TYPE_MEDIUM_BLOB://16m
        case MYSQL_TYPE_LONG_BLOB://4G
        case MYSQL_TYPE_BLOB://65K
        case MYSQL_TYPE_STRING:
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_VARCHAR:
        case MYSQL_TYPE_BIT:
        case MYSQL_TYPE_NEWDECIMAL:
            {
                backupsql->append("\'");
                res=field->val_str(&buffer);
                dupcharfield = (char*)my_malloc(res->length() * 2 + 1, MY_ZEROFILL);
                memset(dupcharfield, 0, res->length() * 2 + 1);
                mysql_dup_char(res->c_ptr(), dupcharfield, '\'');
                backupsql->append(dupcharfield);
                my_free(dupcharfield);
                qutor_end =1;
                append_flag = FALSE;
                break;
            }
        case MYSQL_TYPE_TINY:
            {
                //    nr= field->val_int();
                res=field->val_str(&buffer);
                break;
            }
        case MYSQL_TYPE_SHORT:
        case MYSQL_TYPE_YEAR:
            {
                //    longlong nr;
                //    nr= field->val_int();
                res=field->val_str(&buffer);
                break;
            }
        case MYSQL_TYPE_INT24:
        case MYSQL_TYPE_LONG:
            {
                //    longlong nr;
                //    nr= field->val_int();
                res=field->val_str(&buffer);
                break;
            }
        case MYSQL_TYPE_LONGLONG:
            {
                //    longlong nr;
                //    nr= field->val_int();
                res=field->val_str(&buffer);
                break;
            }
        case MYSQL_TYPE_FLOAT:
            {
                //    float nr;
                //    nr= (float) field->val_real();
                res=field->val_str(&buffer);
                break;
            }
        case MYSQL_TYPE_DOUBLE:
            {
                res=field->val_str(&buffer);
                //    double nr= field->val_real();
                break;
            }
        case MYSQL_TYPE_DATETIME:
        case MYSQL_TYPE_DATETIME2:
        case MYSQL_TYPE_DATE:
        case MYSQL_TYPE_NEWDATE:
        case MYSQL_TYPE_TIMESTAMP:
        case MYSQL_TYPE_TIMESTAMP2:
            {
                backupsql->append("\'");
                res=field->val_str(&buffer);
                qutor_end =1;
                //    MYSQL_TIME tm;
                //    field->get_date(&tm, TIME_FUZZY_DATE);
                break;
            }
        case MYSQL_TYPE_TIME:
        case MYSQL_TYPE_TIME2:
            {
                backupsql->append("\'");
                res=field->val_str(&buffer);
                qutor_end =1;
                //    MYSQL_TIME tm;
                //    field->get_time(&tm);
                break;
            }
        }
    }

    if (append_flag)
        backupsql->append(res->ptr(), res->length(), 1024);

    if (qutor_end)
        backupsql->append("\'");


    return result;
}

int mysql_execute_backup_info_insert_sql(
    Master_info*  mi,
    sql_cache_node_t* sql_cache_node
)
{
    char*  dupcharsql;
    MYSQL*  mysql;
    String  backup_sql_space;
    String*  backup_sql = &backup_sql_space;
    char  tmp_buf[512];
    char  dbname[NAME_CHAR_LEN + 1];

    DBUG_ENTER("mysql_execute_backup_info_insert_sql");

    if (mysql_get_remote_backup_dbname(mi->thd->thd_sinfo->host,
        mi->thd->thd_sinfo->port, sql_cache_node->dbname, dbname))
        DBUG_RETURN(false);

    backup_sql->append("INSERT INTO ");
    sprintf(tmp_buf, "`%s`.`%s` VALUES (", dbname, REMOTE_BACKUP_TABLE);
    backup_sql->append(tmp_buf);

    sprintf(tmp_buf, "\'%ld_%d_%d\',", sql_cache_node->exec_time,
            (int)sql_cache_node->thread_id, (int)sql_cache_node->seqno);
    backup_sql->append(tmp_buf);
    sprintf(tmp_buf, "\'%s\',", sql_cache_node->start_binlog_file);
    backup_sql->append(tmp_buf);
    sprintf(tmp_buf, "%d,", sql_cache_node->start_binlog_pos);
    backup_sql->append(tmp_buf);
    sprintf(tmp_buf, "\'%s\',", sql_cache_node->end_binlog_file);
    backup_sql->append(tmp_buf);
    sprintf(tmp_buf, "%d,", sql_cache_node->end_binlog_pos);
    backup_sql->append(tmp_buf);

    dupcharsql = (char*)my_malloc(strlen(sql_cache_node->sql_statement) * 2 + 1, MYF(0));
    memset(dupcharsql, 0, strlen(sql_cache_node->sql_statement) * 2 + 1);
    mysql_dup_char(sql_cache_node->sql_statement, dupcharsql, '\'');
    backup_sql->append("\'");
    backup_sql->append(dupcharsql);
    backup_sql->append("\'");
    backup_sql->append(",");
    my_free(dupcharsql);

    sprintf(tmp_buf, "\'%s\',", mi->thd->thd_sinfo->host);
    backup_sql->append(tmp_buf);
    sprintf(tmp_buf, "\'%s\',", sql_cache_node->table_info->db_name);
    backup_sql->append(tmp_buf);
    sprintf(tmp_buf, "\'%s\',", sql_cache_node->table_info->table_name);
    backup_sql->append(tmp_buf);
    sprintf(tmp_buf, "%d,", mi->thd->thd_sinfo->port);
    backup_sql->append(tmp_buf);
    backup_sql->append("NOW(),");
    switch(sql_cache_node->optype)
    {
    case SQLCOM_INSERT:
    case SQLCOM_INSERT_SELECT:
        backup_sql->append("\'INSERT\'");
        break;
    case SQLCOM_DELETE:
        backup_sql->append("\'DELETE\'");
        break;
    case SQLCOM_UPDATE:
        backup_sql->append("\'UPDATE\'");
        break;
    case SQLCOM_CREATE_DB:
        backup_sql->append("\'CREATEDB\'");
        break;
    case SQLCOM_CREATE_TABLE:
        backup_sql->append("\'CREATETABLE\'");
        break;
    case SQLCOM_ALTER_TABLE:
        backup_sql->append("\'ALTERTABLE\'");
        break;
    case SQLCOM_DROP_TABLE:
        backup_sql->append("\'DROPTABLE\'");
        break;

    default:
        backup_sql->append("\'UNKNOWN\'");
        break;
    }

    backup_sql->append(");");

    if ((mysql= mi->thd->get_backup_connection()) == NULL)
        DBUG_RETURN(TRUE);

    if (mysql_real_query(mysql, backup_sql->c_ptr(), backup_sql->length()))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    DBUG_RETURN(false);
}

int mysql_generate_field_insert_values_for_rollback(
    Master_info* mi,
    int    optype,
    String*   backup_sql,
    char*       dbname,
    char*       tablename
)
{
    field_info_t* field_node;
    char   tmp_buf[256];
    int    err = 0;
    int    field_index=0;
    int    pkcount=0;

    if (optype == SQLCOM_INSERT)
    {
        sprintf(tmp_buf, "DELETE FROM `%s`.`%s` WHERE ", dbname, tablename);
        backup_sql->append(tmp_buf);
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            if (field_node->primary_key)
            {
                if (pkcount >= 1)
                    backup_sql->append(" AND ");

                sprintf(tmp_buf, "%s=", field_node->field_name);
                backup_sql->append(tmp_buf);

                err = mysql_get_field_string(field_node->conv_field,
                    backup_sql, mi->table_info->null_arr, field_index);
                pkcount++;
            }
            field_node = LIST_GET_NEXT(link, field_node);
            field_index++;
        }

        backup_sql->append(";");
    } else if (optype == SQLCOM_DELETE) {
        sprintf(tmp_buf, "INSERT INTO `%s`.`%s` ( ", dbname, tablename);
        backup_sql->append(tmp_buf);
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            backup_sql->append(field_node->field_name);
            if (LIST_GET_LAST(mi->table_info->field_lst) != field_node)
                backup_sql->append(",");
            field_node = LIST_GET_NEXT(link, field_node);
        }

        backup_sql->append(") values( ");
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            err = mysql_get_field_string(field_node->conv_field,
                    backup_sql, mi->table_info->null_arr, field_index);
            if (LIST_GET_LAST(mi->table_info->field_lst) != field_node)
                backup_sql->append(",");

            field_node = LIST_GET_NEXT(link, field_node);
            field_index++;
        }

        backup_sql->append(");");
    } else if (optype == SQLCOM_UPDATE) {
        sprintf(tmp_buf, "UPDATE `%s`.`%s` SET ", dbname, tablename);
        backup_sql->append(tmp_buf);
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            sprintf(tmp_buf, "%s=", field_node->field_name);
            backup_sql->append(tmp_buf);
            err = mysql_get_field_string(field_node->conv_field,
                    backup_sql, mi->table_info->null_arr, field_index);

            if (LIST_GET_LAST(mi->table_info->field_lst) != field_node)
                backup_sql->append(",");

            field_node = LIST_GET_NEXT(link, field_node);
            field_index++;
        }

        backup_sql->append(" WHERE ");
    } else if (optype == SQLCOM_UPDATE + 1000) {
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            if (field_node->primary_key)
            {
                if (pkcount >= 1)
                    backup_sql->append(" AND ");

                sprintf(tmp_buf, "%s=", field_node->field_name);
                backup_sql->append(tmp_buf);

                err = mysql_get_field_string(field_node->conv_field,
                    backup_sql, mi->table_info->null_arr, field_index);
                pkcount++;
            }
            field_node = LIST_GET_NEXT(link, field_node);
            field_index++;
        }

        backup_sql->append(";");
    }

    return 0;
}

int mysql_generate_field_insert_values(
    Master_info* mi,
    int    optype,
    String*   backup_sql,
    String*   rollback_sql
)
{
    char   tmp_buf[256];
    String   tmpsql;
    char* dupcharfield;

    /* field_node = LIST_GET_FIRST(mi->table_info->field_lst); */
    /* while (field_node != NULL) */
    /* { */
    /*     err = mysql_get_field_string(field_node->field, */
    /*             backup_sql, mi->table_info->null_arr, ","); */

    /*     field_node = LIST_GET_NEXT(link, field_node); */
    /* } */

    if (optype != SQLCOM_UPDATE)
    {
        mysql_generate_field_insert_values_for_rollback(mi, optype, &tmpsql,
                mi->table_info->db_name, mi->table_info->table_name);

        dupcharfield = (char*)my_malloc(tmpsql.length() * 2 + 1, MY_ZEROFILL);
        mysql_dup_char(tmpsql.c_ptr(), dupcharfield, '\'');
        backup_sql->append("'");
        backup_sql->append(dupcharfield);
    } else {
        dupcharfield = (char*)my_malloc(rollback_sql->length() * 2 + 1, MY_ZEROFILL);
        mysql_dup_char(rollback_sql->c_ptr(), dupcharfield, '\'');
        backup_sql->append("'");
        backup_sql->append(dupcharfield);
    }

    backup_sql->append("',");
    sprintf(tmp_buf, "\'%d_%d_%d\'", (int)mi->exec_time, (int)mi->thread_id, (int)mi->seqno);
    backup_sql->append(tmp_buf);

    return 0;
}

int mysql_generate_backup_sql_by_record_for_update_before(
    Master_info* mi,
    int    optype,
    String*   backup_sql
)
{
    char  dbname[NAME_CHAR_LEN + 1];
    sinfo_space_t* thd_sinfo;
    char   tmp_buf[256];

    DBUG_ENTER("mysql_generate_backup_sql_by_record_for_update_before");
    backup_sql->truncate();

    thd_sinfo = mi->thd->thd_sinfo;
    if (mysql_get_remote_backup_dbname(thd_sinfo->host, thd_sinfo->port,
        mi->table_info->db_name, dbname))
        DBUG_RETURN(true);

    backup_sql->append("INSERT INTO ");
    sprintf(tmp_buf, "`%s`.`%s` (rollback_statement, opid_time) VALUES (",
            dbname, mi->table_info->table_name);
    backup_sql->append(tmp_buf);

    /* field_node = LIST_GET_FIRST(mi->table_info->field_lst); */
    /* while (field_node != NULL) */
    /* { */
    /*    err = mysql_get_field_string(field_node->field, */
    /*         backup_sql, mi->table_info->null_arr, ", "); */

    /*     field_node = LIST_GET_NEXT(link, field_node); */
    /* } */

    DBUG_RETURN(false);
}

int mysql_generate_backup_sql_by_record_for_update_after(
    Master_info* mi,
    int    optype,
    String*   backup_sql,
    String*   rollback_sql
)
{
    char   tmp_buf[256];
    char*   dupcharfield;

    DBUG_ENTER("mysql_generate_backup_sql_by_record_for_update_after");

    dupcharfield = (char*)my_malloc(rollback_sql->length() * 2 + 1, MY_ZEROFILL);
    mysql_dup_char(rollback_sql->c_ptr(), dupcharfield, '\'');
    backup_sql->append("'");
    backup_sql->append(dupcharfield);
    backup_sql->append("',");

    sprintf(tmp_buf, "\'%d_%d_%d\'", (int)mi->exec_time, (int)mi->thread_id, (int)mi->seqno);
    backup_sql->append(tmp_buf);

    backup_sql->append(");");

    DBUG_RETURN(false);
}

int mysql_generate_backup_sql_by_record(
    Master_info* mi,
    int    optype,
    String*   backup_sql,
    String*   rollback_sql /*for update*/
)
{
    char  dbname[NAME_CHAR_LEN + 1];
    sinfo_space_t* thd_sinfo;
    char   tmp_buf[256];

    DBUG_ENTER("mysql_generate_backup_sql_by_record");
    backup_sql->truncate();

    thd_sinfo = mi->thd->thd_sinfo;
    if (mysql_get_remote_backup_dbname(thd_sinfo->host, thd_sinfo->port,
        mi->table_info->db_name, dbname))
        DBUG_RETURN(true);

    backup_sql->append("INSERT INTO ");
    sprintf(tmp_buf, "`%s`.`%s` (rollback_statement, opid_time) VALUES (", 
            dbname, mi->table_info->table_name);
    backup_sql->append(tmp_buf);
    mysql_generate_field_insert_values(mi, optype, backup_sql, rollback_sql);
    backup_sql->append(");");

    DBUG_RETURN(false);
}

int mysql_parse_write_row_log_event(Master_info *mi, Log_event* ev)
{
    Write_rows_log_event*  write_ev;
    int       error= 0;
    String backup_sql;

    DBUG_ENTER("mysql_parse_write_row_log_event");
    write_ev = (Write_rows_log_event*)ev;

    do
    {
        if (mysql_unpack_row(mi, write_ev->m_curr_row, write_ev->get_cols(),
            &write_ev->m_curr_row_end, write_ev->m_rows_end))
            DBUG_RETURN(true);

        //只有主键的情况下，才做备份
        if (mi->table_info->have_pk)
        {
            if (mysql_generate_backup_sql_by_record(mi, SQLCOM_INSERT, &backup_sql, NULL))
                DBUG_RETURN(true);

            if (mysql_execute_remote_backup_sql(mi->thd, backup_sql.c_ptr()))
                DBUG_RETURN(true);
        }

        write_ev->m_curr_row = write_ev->m_curr_row_end;
    }while(!error && write_ev->m_rows_end != write_ev->m_curr_row);

    DBUG_RETURN(false);
}

int mysql_parse_delete_row_log_event(Master_info *mi, Log_event* ev)
{
    Delete_rows_log_event*  write_ev;
    int       error= 0;
    String backup_sql;

    DBUG_ENTER("mysql_parse_delete_row_log_event");
    write_ev = (Delete_rows_log_event*)ev;

    do
    {
        if (mysql_unpack_row(mi, write_ev->m_curr_row, write_ev->get_cols(),
            &write_ev->m_curr_row_end, write_ev->m_rows_end))
            DBUG_RETURN(true);

        if (mi->table_info->have_pk)
        {
            if (mysql_generate_backup_sql_by_record(mi, SQLCOM_DELETE, &backup_sql, NULL))
                DBUG_RETURN(true);

            if (mysql_execute_remote_backup_sql(mi->thd, backup_sql.c_ptr()))
                DBUG_RETURN(true);
        }

        write_ev->m_curr_row = write_ev->m_curr_row_end;
    }while(!error && write_ev->m_rows_end != write_ev->m_curr_row);

    DBUG_RETURN(false);
}

int mysql_parse_update_row_log_event(Master_info *mi, Log_event* ev)
{
    Update_rows_log_event*  write_ev;
    int       error= 0;
    String backup_sql;
    String rollback_sql;

    DBUG_ENTER("mysql_parse_update_row_log_event");
    write_ev = (Update_rows_log_event*)ev;

    do
    {
        rollback_sql.truncate();
        if (mysql_unpack_row(mi, write_ev->m_curr_row, write_ev->get_cols(),
            &write_ev->m_curr_row_end, write_ev->m_rows_end))
            DBUG_RETURN(true);

        if (mi->table_info->have_pk)
        {
            if (mysql_generate_backup_sql_by_record_for_update_before(mi,
                        SQLCOM_UPDATE, &backup_sql))
                DBUG_RETURN(true);

            mysql_generate_field_insert_values_for_rollback(mi, SQLCOM_UPDATE, &rollback_sql,
                                        mi->table_info->db_name, mi->table_info->table_name);
        }

        write_ev->m_curr_row = write_ev->m_curr_row_end;

        if (mysql_unpack_row(mi, write_ev->m_curr_row, write_ev->get_cols(),
            &write_ev->m_curr_row_end, write_ev->m_rows_end))
            DBUG_RETURN(true);

        if (mi->table_info->have_pk)
        {
            mysql_generate_field_insert_values_for_rollback(mi, SQLCOM_UPDATE + 1000, &rollback_sql,
                                        mi->table_info->db_name, mi->table_info->table_name);

            if (mysql_generate_backup_sql_by_record_for_update_after(mi,
                        SQLCOM_UPDATE, &backup_sql, &rollback_sql))
                DBUG_RETURN(true);
            if (mysql_execute_remote_backup_sql(mi->thd, backup_sql.c_ptr()))
                DBUG_RETURN(true);
        }

        write_ev->m_curr_row = write_ev->m_curr_row_end;
    }while(!error && write_ev->m_rows_end != write_ev->m_curr_row);

    DBUG_RETURN(false);
}

int
mysql_parse_query_log_event(
    Master_info* mi,
    Log_event* ev,
    ulong thread_id,
    sql_cache_node_t* sql_cache_node,
    int* skip_trx
)
{
    Query_log_event*  query_log;

    DBUG_ENTER("mysql_parse_query_log_event");

    query_log = (Query_log_event*)ev;

    if (strcasecmp(query_log->query, "BEGIN") == 0)
    {
        if (ev->log_pos >= (my_off_t)sql_cache_node->end_binlog_pos ||
            ev->log_pos < (my_off_t)sql_cache_node->start_binlog_pos ||
            strcasecmp(sql_cache_node->end_binlog_file, mi->get_master_log_name()) != 0)
        {
            *skip_trx = TRUE;
            DBUG_RETURN(true);
        }

        if (query_log->thread_id != thread_id)
        {
            *skip_trx = TRUE;
            DBUG_RETURN(true);
        }

        *skip_trx = FALSE;
        DBUG_RETURN(false);
    }

    DBUG_RETURN(false);
}

int mysql_parse_event_and_backup(
    Master_info* mi,
    Log_event* ev,
    sql_cache_node_t* sql_cache_node,
    int* skip_trx
)
{
    int err = 0;

    DBUG_ENTER("mysql_parse_event_and_backup");

    if (ev == NULL)
        DBUG_RETURN(false);

    if (ev->get_type_code() == QUERY_EVENT)
        mysql_parse_query_log_event(mi, ev, mi->thread_id, sql_cache_node, skip_trx);

    if (*skip_trx)
        DBUG_RETURN(false);

    switch(ev->get_type_code())
    {
    case TABLE_MAP_EVENT:
        err = mysql_parse_table_map_log_event(mi, ev);
        break;

    case WRITE_ROWS_EVENT_V1:
    case WRITE_ROWS_EVENT:
        err = mysql_parse_write_row_log_event(mi, ev);
        break;

    case UPDATE_ROWS_EVENT:
    case UPDATE_ROWS_EVENT_V1:
        err = mysql_parse_update_row_log_event(mi, ev);
        break;

    case DELETE_ROWS_EVENT:
    case DELETE_ROWS_EVENT_V1:
        err = mysql_parse_delete_row_log_event(mi, ev);
        break;

    default:
        break;
    }

    DBUG_RETURN(err);
}

int mysql_fetch_thread_id(MYSQL *mysql, ulong* thread_id)
{
    char set_format[32];
    int  err;
    MYSQL_RES * source_res;
    MYSQL_ROW source_row;

    DBUG_ENTER("mysql_fetch_thread_id");

    sprintf(set_format, "select connection_id();");
    err = mysql_real_query(mysql, set_format, strlen(set_format));
    if (err)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    source_row = mysql_fetch_row(source_res);
    *thread_id = atoi(source_row[0]);
    mysql_free_result(source_res);
    DBUG_RETURN(false);
}

int mysql_prepare_field(
    field_info_t *sql_field
)
{
    uint pack_length = 0;
    CHARSET_INFO *charset;

    DBUG_ENTER("mysql_prepare_field");

    charset = get_charset(sql_field->charsetnr, MYF(0));
    if (f_is_blob(sql_field->pack_flag) ||
        f_is_enum(sql_field->pack_flag) ||
        sql_field->real_type == MYSQL_TYPE_SET)
    {
        pack_length = calc_pack_length(sql_field->real_type, sql_field->max_length);
    }

    switch (sql_field->real_type) {
    case MYSQL_TYPE_BLOB:
    case MYSQL_TYPE_MEDIUM_BLOB:
    case MYSQL_TYPE_TINY_BLOB:
    case MYSQL_TYPE_LONG_BLOB:
        sql_field->pack_flag=FIELDFLAG_BLOB |
            pack_length_to_packflag(pack_length - portable_sizeof_char_ptr);
        if (charset->state & MY_CS_BINSORT)
            sql_field->pack_flag|=FIELDFLAG_BINARY;
        sql_field->length=8;   // Unireg field length
        sql_field->unireg_check=Field::BLOB_FIELD;
        break;
    case MYSQL_TYPE_VARCHAR:
    case MYSQL_TYPE_VAR_STRING:
        /* fall through */
    case MYSQL_TYPE_STRING:
        sql_field->pack_flag=0;
        if (charset->state & MY_CS_BINSORT)
            sql_field->pack_flag|=FIELDFLAG_BINARY;
        break;
    case MYSQL_TYPE_ENUM:
        sql_field->pack_flag=pack_length_to_packflag(pack_length) |
            FIELDFLAG_INTERVAL;
        if (charset->state & MY_CS_BINSORT)
            sql_field->pack_flag|=FIELDFLAG_BINARY;
        sql_field->unireg_check=Field::INTERVAL_FIELD;
        break;
    case MYSQL_TYPE_SET:
        sql_field->pack_flag=pack_length_to_packflag(pack_length) |
            FIELDFLAG_BITFIELD;
        if (charset->state & MY_CS_BINSORT)
            sql_field->pack_flag|=FIELDFLAG_BINARY;
        sql_field->unireg_check=Field::BIT_FIELD;
        break;
    case MYSQL_TYPE_DATE:   // Rest of string types
    case MYSQL_TYPE_NEWDATE:
    case MYSQL_TYPE_TIME:
    case MYSQL_TYPE_DATETIME:
    case MYSQL_TYPE_TIME2:
    case MYSQL_TYPE_DATETIME2:
    case MYSQL_TYPE_NULL:
        sql_field->pack_flag=f_settype((uint) sql_field->real_type);
        break;
    case MYSQL_TYPE_BIT:
        break;
    case MYSQL_TYPE_NEWDECIMAL:
        sql_field->pack_flag=(FIELDFLAG_NUMBER |
            (sql_field->flags & UNSIGNED_FLAG ? 0 :
            FIELDFLAG_DECIMAL) |
            (sql_field->flags & ZEROFILL_FLAG ?
FIELDFLAG_ZEROFILL : 0) |
                     (sql_field->decimals << FIELDFLAG_DEC_SHIFT));
        break;
    case MYSQL_TYPE_TIMESTAMP:
    case MYSQL_TYPE_TIMESTAMP2:
        /* fall-through */
    default:
        sql_field->pack_flag=(FIELDFLAG_NUMBER |
            (sql_field->flags & UNSIGNED_FLAG ? 0 :
            FIELDFLAG_DECIMAL) |
            (sql_field->flags & ZEROFILL_FLAG ?
FIELDFLAG_ZEROFILL : 0) |
                     f_settype((uint) sql_field->real_type) |
                     (sql_field->decimals << FIELDFLAG_DEC_SHIFT));
        break;
    }
    if (!(sql_field->flags & NOT_NULL_FLAG))
        sql_field->pack_flag|= FIELDFLAG_MAYBE_NULL;
    if (sql_field->flags & NO_DEFAULT_VALUE_FLAG)
        sql_field->pack_flag|= FIELDFLAG_NO_DEFAULT;
    DBUG_RETURN(0);
}

int mysql_alloc_record(table_info_t* table_info, MYSQL *mysql)
{
    char   set_format[256];
    MYSQL_RES *  source_res;
    ulong    i;
    MYSQL_FIELD * field;
    int    max_length = 0;
    field_info_t* field_info;
    Field::geometry_type geom_type= Field::GEOM_GEOMETRY;
    Field *   field_def;

    DBUG_ENTER("mysql_alloc_record");

    if (mysql == NULL)
        DBUG_RETURN(true);

    if (table_info->record != NULL)
        DBUG_RETURN(false);

    sprintf(set_format, "select * from `%s`.`%s` limit 1;",
        table_info->db_name, table_info->table_name);
    if (mysql_real_query(mysql, set_format, strlen(set_format)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    DBUG_ASSERT(LIST_GET_LEN(table_info->field_lst) == source_res->field_count);
    field_info = LIST_GET_FIRST(table_info->field_lst);
    for (i=0; i < source_res->field_count; i++)
    {
        field = &source_res->fields[i];
        field_info->real_type = field->type;
        if (field_info->real_type == MYSQL_TYPE_DATE)
            field_info->real_type = MYSQL_TYPE_NEWDATE;
        field_info->flags = field->flags;
        field_info->decimals = field->decimals;

        field_info->charsetnr = field->charsetnr;
        field_info->max_length = calc_pack_length(field->type,field->length);

        //调整最大长度，根据表定义的字符集来调整
        if (field_info->charset)
        {
            CHARSET_INFO* charset;
            charset= get_charset(field_info->charsetnr, MYF(0));
            field_info->max_length = 
               field->length / charset->mbmaxlen * field_info->charset->mbmaxlen;
            field_info->charsetnr = field_info->charset->number;
        }

        max_length += calc_pack_length(field->type,field_info->max_length);
        mysql_prepare_field(field_info);

        field_info = LIST_GET_NEXT(link, field_info);
    }

    table_info->record = (uchar*)my_malloc(ALIGN_SIZE(max_length), MY_ZEROFILL);
    table_info->null_arr = (char*)my_malloc(mysql_num_fields(source_res) + 1, MY_ZEROFILL);

    max_length = 0;
    field_info = LIST_GET_FIRST(table_info->field_lst);
    for (i=0; i < source_res->field_count; i++)
    {
        field = &source_res->fields[i];
        field_info->field_ptr = table_info->record + max_length;
        max_length += calc_pack_length(field->type,field_info->max_length);
        field_info = LIST_GET_NEXT(link, field_info);
    }

    mysql_free_result(source_res);

    i=0;
    field_info = LIST_GET_FIRST(table_info->field_lst);
    while (field_info != NULL)
    {
        field_def = make_field(NULL, field_info->field_ptr, field_info->max_length,
            (uchar *)"Hello world", false, field_info->pack_flag,
            field_info->real_type, get_charset(field_info->charsetnr, MYF(0)),
            geom_type, Field::NONE, NULL, field_info->field_name, NULL);

        if (field_def != NULL)
        {
            field_def->field_index = i++;
            field_info->field = field_def;
        }

        field_info = LIST_GET_NEXT(link, field_info);
    }

    DBUG_RETURN(false);
}

int mysql_generate_backup_field_insert_values_for_ddl(
    Master_info* mi,
    String*   backup_sql,
    sql_cache_node_t* sql_cache_node
)
{
    char   tmp_buf[256];
    String   tmpsql;
    char* dupcharfield;

    /* field_node = LIST_GET_FIRST(mi->table_info->field_lst); */
    /* while (field_node != NULL) */
    /* { */
    /*     backup_sql->append("NULL,"); */
    /*     field_node = LIST_GET_NEXT(link, field_node); */
    /* } */

    dupcharfield = (char*)my_malloc(str_get_len(sql_cache_node->ddl_rollback)* 2 + 1, MY_ZEROFILL);
    mysql_dup_char(str_get(sql_cache_node->ddl_rollback), dupcharfield, '\'');
    backup_sql->append("'");
    backup_sql->append(dupcharfield);

    backup_sql->append("',");
    sprintf(tmp_buf, "\'%d_%d_%d\'", (int)mi->exec_time, (int)mi->thread_id, (int)mi->seqno);
    backup_sql->append(tmp_buf);

    return 0;
}

int mysql_backup_sql_for_ddl(
    Master_info* mi,
    sql_cache_node_t* sql_cache_node
)
{
    char  dbname[NAME_CHAR_LEN + 1];
    sinfo_space_t* thd_sinfo;
    char   tmp_buf[256];
    String     backup_sql;

    DBUG_ENTER("mysql_backup_sql_for_ddl");
    backup_sql.truncate();

    //如果没有生成语句，则不备份
    if (str_get_len(sql_cache_node->ddl_rollback) == 0)
        DBUG_RETURN(false);
        
    thd_sinfo = mi->thd->thd_sinfo;
    if (mysql_get_remote_backup_dbname(thd_sinfo->host, thd_sinfo->port,
        mi->table_info->db_name, dbname))
        DBUG_RETURN(true);

    backup_sql.append("INSERT INTO ");
    sprintf(tmp_buf, "`%s`.`%s`(rollback_statement, opid_time) VALUES (", 
            dbname, mi->table_info->table_name);
    backup_sql.append(tmp_buf);
    mysql_generate_backup_field_insert_values_for_ddl(mi, &backup_sql, sql_cache_node);
    backup_sql.append(");");

    if (mysql_execute_remote_backup_sql(mi->thd, backup_sql.c_ptr()))
        DBUG_RETURN(true);

    DBUG_RETURN(false);
}

int mysql_backup_single_ddl_statement(
    THD *    thd,
    Master_info*  mi,
    MYSQL*    mysql,
    sql_cache_node_t* sql_cache_node
)
{
    DBUG_ENTER("mysql_backup_single_ddl_statement");

    mi->thread_id = sql_cache_node->thread_id;
    mi->exec_time = sql_cache_node->exec_time;
    mi->table_info = sql_cache_node->table_info;
    mi->seqno  = sql_cache_node->seqno;

    if (mysql_execute_backup_info_insert_sql(mi, sql_cache_node))
        goto error;

    if (mysql_backup_sql_for_ddl(mi, sql_cache_node))
        goto error;

    str_append(sql_cache_node->stagereport, "Backup successfully\n");
    DBUG_RETURN(FALSE);
error:
    str_append(sql_cache_node->stagereport, "Backup failed\n");
    DBUG_RETURN(TRUE);
}

int mysql_backup_single_statement(
    THD *    thd,
    Master_info*  mi,
    MYSQL*    mysql,
    sql_cache_node_t* sql_cache_node
)
{
    char*   event_buf;
    Log_event*  evlog;
    int    skip_trx = 0;
    my_off_t  log_pos;
    int     retrycount=0;

    DBUG_ENTER("mysql_backup_single_statement");

    mi->thread_id = sql_cache_node->thread_id;
    mi->exec_time = sql_cache_node->exec_time;
    mi->table_info = sql_cache_node->table_info;
    mi->seqno  = sql_cache_node->seqno;

    if (mysql_execute_backup_info_insert_sql(mi, sql_cache_node))
        goto error;

    //如果影响行数是0行，则不通过binlog备份了，只做上面的操作日志备份
    while (sql_cache_node->affected_rows)
    {
        ulong event_len;

        event_len = mysql_read_event(mysql);
        event_buf= (char*)mysql->net.read_pos + 1;

        if (event_len == 0)//end of packet
            break;

        if (event_len == packet_error)
        {
            if (mysql_errno(mysql) == CR_NET_PACKET_TOO_LARGE ||
                mysql_errno(mysql) == ER_MASTER_FATAL_ERROR_READING_BINLOG ||
                mysql_errno(mysql) == ER_OUT_OF_RESOURCES)
                goto error;

            if (retrycount++ <= 3)
            {
                //从当前语句BINLOG位置开始重试3次，如果3次都失败则退出
                if (mysql_request_binlog_dump(mysql, sql_cache_node->start_binlog_file,
                      sql_cache_node->start_binlog_pos))
                    goto error;
                continue;
            }
            
            goto error;
        }

        if (mysql_process_event(mi, event_buf, event_len, &evlog) || evlog == NULL)
            goto error;

        if (mysql_parse_event_and_backup(mi, evlog, sql_cache_node, &skip_trx))
            goto error;

        log_pos = evlog->log_pos;
        delete evlog;

        if (log_pos != 0 &&
            strcasecmp(sql_cache_node->end_binlog_file, mi->get_master_log_name()) == 0 &&
            log_pos >= (my_off_t)sql_cache_node->end_binlog_pos)
        {
            break;
        }
    }

    str_append(sql_cache_node->stagereport, "Backup successfully\n");
    DBUG_RETURN(FALSE);
error:
    str_append(sql_cache_node->stagereport, "Backup failed\n");
    DBUG_RETURN(TRUE);
}

int mysql_modify_binlog_format_row(MYSQL *mysql)
{
    char set_format[32];

    DBUG_ENTER("mysql_modify_binlog_format_row");

    sprintf(set_format, "set binlog_format=row;");
    if (mysql_real_query(mysql, set_format, strlen(set_format)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(true);
    }

    DBUG_RETURN(false);
}

char* mysql_get_alter_table_post_part(
    THD*  thd,
    char* statement,
    int ignore
)
{
    char* p;
    int tokencount=0;
    int spaceflag=1;
    int jincom = 0;
    int segcom = 0;

    DBUG_ENTER("mysql_get_alter_table_post_part");
    p = statement;
    while (*p)
    {
        if (!segcom)
        {
            if (p[0] == '#')
                jincom = 1;

            if (jincom == 1)
            {
                if (p[0] == '\n')
                {
                    jincom = 0;
                    spaceflag = 1;
                }
                if (p[0] == '\r' && p[1] == '\n')
                {
                    jincom = 0;
                    spaceflag = 1;
                    p++;//skip two byte
                }
                goto next;
            }
        }

        if (!jincom )
        {
            if (p[0] == '/' && p[1] == '*')
                segcom = 1;
            if (segcom == 1)
            {
                if (p[0] == '*' && p[1] == '/')
                {
                    segcom = 0;
                    spaceflag = 1;
                    p++;//skip two byte
                }
                goto next;
            }
        }

        if (!segcom && !jincom)
        {
            if (!my_isspace(thd->charset(), *p))
            {
                if(spaceflag)
                {
                    spaceflag = 0;
                    tokencount++;
                }
            }
            else
            {
                //如果后面也是空白字符，就跳过所有的
                while(my_isspace(thd->charset(), *(p+1)))
                    p++;
                spaceflag = 1;
                if ((tokencount == 4 && ignore) ||
                    (tokencount == 3 && !ignore))
                {
                    while(my_isspace(thd->charset(), *p))
                        p++;
                    DBUG_RETURN(p);
                }
            }
        }

next:
        p++;
    }

    DBUG_RETURN(NULL);
}

// get rid of trailing \n
static char* my_fgets (char* buf, size_t buf_len, FILE* stream)
{
   char* ret= fgets (buf, buf_len, stream);

   if (ret)
   {
       size_t len = strlen(ret);
       if (len > 0 && ret[len - 1] == '\n') ret[len - 1] = '\0';
   }

   return ret;
}

void mysql_free_osc_cache_node(char* sqlsha1)
{
    osc_percent_cache_t* osc_percent_node;

    mysql_mutex_lock(&osc_mutex); 
    osc_percent_node = LIST_GET_FIRST(global_osc_cache.osc_lst);
    while(osc_percent_node)
    {
        if (!strcasecmp(osc_percent_node->sqlsha1, sqlsha1))
        {
            LIST_REMOVE(link, global_osc_cache.osc_lst, osc_percent_node);
            my_free(osc_percent_node);
            break;
        }

        osc_percent_node = LIST_GET_NEXT(link, osc_percent_node);        
    }
    mysql_mutex_unlock(&osc_mutex);
}

int mysql_add_new_percent_cache_node(
    sql_cache_node_t* sql_cache_node, 
    process*  proc
)
{
    osc_percent_cache_t* osc_percent_node;

    DBUG_ENTER("mysql_add_new_percent_cache_node");
    mysql_mutex_lock(&osc_mutex); 
    osc_percent_node = (osc_percent_cache_t*)my_malloc(sizeof(osc_percent_cache_t), MY_ZEROFILL);
    osc_percent_node->percent = 0;
    osc_percent_node->proc = proc;
    strcpy(osc_percent_node->dbname, sql_cache_node->dbname);
    strcpy(osc_percent_node->tablename, sql_cache_node->tablename);
    strcpy(osc_percent_node->remaintime, "");
    strcpy(osc_percent_node->sqlsha1, sql_cache_node->sqlsha1);
    osc_percent_node->sql_cache_node = sql_cache_node;
    LIST_ADD_LAST(link, global_osc_cache.osc_lst, osc_percent_node);
    mysql_mutex_unlock(&osc_mutex);
    DBUG_RETURN(false);
}

int mysql_analyze_osc_output(
    THD* thd, 
    char* tmp, 
    sql_cache_node_t* sql_cache_node
)
{
    int percent = -1;
    char    timeremain[100];
    osc_percent_cache_t* osc_percent_node;
    char    Successfully[1024];

    DBUG_ENTER("mysql_analyze_osc_output");
    sprintf(Successfully, "Successfully altered `%s`.`%s`.", 
        sql_cache_node->dbname, sql_cache_node->tablename);

    if (!strcasecmp(Successfully, tmp))
    {
        percent = 100;
        strcpy(timeremain, "00:00");
        sql_cache_node->oscpercent = 100;
        sql_cache_node->oscoutput = str_append(sql_cache_node->oscoutput, tmp);
        sql_cache_node->oscoutput = str_append(sql_cache_node->oscoutput, "\n");
    }
    else 
    {
        sscanf(tmp, "Copying %*s %d%*s %s remain", &percent, timeremain);
        if (percent == -1)
        {
            //因为有了进度查询，所以输出中的进度就不再打印了
            sql_cache_node->oscoutput = str_append(sql_cache_node->oscoutput, tmp);
            sql_cache_node->oscoutput = str_append(sql_cache_node->oscoutput, "\n");
            DBUG_RETURN(false);
        }
    }
    
    mysql_mutex_lock(&osc_mutex); 
    osc_percent_node = LIST_GET_FIRST(global_osc_cache.osc_lst);
    while(osc_percent_node)
    {
        if (!strcasecmp(osc_percent_node->sqlsha1, sql_cache_node->sqlsha1))
        {
            osc_percent_node->percent = percent;
            strcpy(osc_percent_node->remaintime, timeremain);
            break;
        }

        osc_percent_node = LIST_GET_NEXT(link, osc_percent_node);        
    }

    if (osc_percent_node == NULL)
    {
        osc_percent_node = (osc_percent_cache_t*)my_malloc(sizeof(osc_percent_cache_t), MY_ZEROFILL);
        osc_percent_node->percent = percent;
        strcpy(osc_percent_node->dbname, sql_cache_node->dbname);
        strcpy(osc_percent_node->tablename, sql_cache_node->tablename);
        strcpy(osc_percent_node->remaintime, timeremain);
        strcpy(osc_percent_node->sqlsha1, sql_cache_node->sqlsha1);
        LIST_ADD_LAST(link, global_osc_cache.osc_lst, osc_percent_node);
    }
    mysql_mutex_unlock(&osc_mutex);

    DBUG_RETURN(false);
}

int mysql_osc_execute_abort_check(THD* thd, sql_cache_node_t* sql_cache_node)
{
    osc_percent_cache_t* osc_percent_node;

    DBUG_ENTER("mysql_osc_execute_abort_check");
    mysql_mutex_lock(&osc_mutex); 
    osc_percent_node = LIST_GET_FIRST(global_osc_cache.osc_lst);
    while(osc_percent_node)
    {
        if (!strcasecmp(osc_percent_node->sqlsha1, sql_cache_node->sqlsha1))
            break;

        osc_percent_node = LIST_GET_NEXT(link, osc_percent_node);        
    }

    //肯定可以找到
    if (osc_percent_node->killed)
    {
        const size_t  out_len = 1024;
        char          errmsg[out_len];
        sql_cache_node->stage=1;//not executed
        thd->killed = THD::KILL_CONNECTION;
        sprintf(errmsg, "Execute has been abort in percent: %d, remain time: %s", 
                osc_percent_node->percent, osc_percent_node->remaintime);
        mysql_errmsg_append_without_errno_osc(thd, sql_cache_node, errmsg);
    }
    else
    {
        //如果没有被ABORT，才会输出所有信息，否则就输出取消信息及百分比即可
        if (sql_cache_node->oscpercent != 100 || !inception_osc_print_none)
            mysql_errmsg_append_without_errno_osc(thd, sql_cache_node, 
                str_get(sql_cache_node->oscoutput));

        //没有执行完成，就算执行失败，后面就不继续执行了，返回TRUE
        if (sql_cache_node->oscpercent != 100)
        {
            mysql_mutex_unlock(&osc_mutex);
            DBUG_RETURN(true);
        }
        else
            sql_cache_node->exe_complete = TRUE;
    }

    mysql_mutex_unlock(&osc_mutex);
    DBUG_RETURN(false);
}

int mysql_execute_alter_table_osc(
    THD* thd,
    MYSQL* mysql,
    char* statement,
    sql_cache_node_t* sql_cache_node
)
{
    str_t       osc_cmd;
    str_t*      osc_cmd_ptr;
    char        cmd_line[100];
    int         ret;
    char*       oscargv[100];
    int         count=0;
    const size_t  out_len = 1024;
    char          errmsg[out_len];
    char          out[out_len];

    DBUG_ENTER("mysql_execute_alter_table_osc");
    osc_prepend_PATH(inception_osc_bin_dir, thd, sql_cache_node);
    osc_cmd_ptr = str_init(&osc_cmd);
    oscargv[count++] = strdup("pt-online-schema-change");
    oscargv[count++] = strdup("--alter");
    oscargv[count++] = strdup(mysql_get_alter_table_post_part(
                              thd, statement, sql_cache_node->ignore));
    if (inception_osc_print_sql)
        oscargv[count++] = strdup("--print");
    oscargv[count++] = strdup("--charset");
    oscargv[count++] = strdup("utf8");

    oscargv[count++] = strdup("--chunk-time");
    sprintf(cmd_line, "%f", thd->variables.inception_osc_chunk_time);
    oscargv[count++] = strdup(cmd_line);

    oscargv[count++] = strdup("--critical-load");
    sprintf(cmd_line, "Threads_connected:%lu,Threads_running:%lu", 
        thd->variables.inception_osc_critical_connected, 
        thd->variables.inception_osc_critical_running);
    oscargv[count++] = strdup(cmd_line);

    oscargv[count++] = strdup("--max-load");
    sprintf(cmd_line, "Threads_connected:%lu,Threads_running:%lu", 
        thd->variables.inception_osc_max_connected, 
        thd->variables.inception_osc_max_running);
    oscargv[count++] = strdup(cmd_line);

    oscargv[count++] = strdup("--check-replication-filters");
    oscargv[count++] = strdup("--check-alter");
    oscargv[count++] = strdup("--recurse=1");

    oscargv[count++] = strdup("--check-interval");
    sprintf(cmd_line, "%f", thd->variables.inception_osc_check_interval);
    oscargv[count++] = strdup(cmd_line);

    if (!thd->variables.inception_osc_drop_new_table)
        oscargv[count++] = strdup("--no-drop-new-table");
        
    if (!thd->variables.inception_osc_drop_old_table)
        oscargv[count++] = strdup("--no-drop-old-table");

    oscargv[count++] = strdup("--alter-foreign-keys-method=auto");
    oscargv[count++] = strdup("--execute");
    oscargv[count++] = strdup("--statistics");
    oscargv[count++] = strdup("--max-lag");
    sprintf(cmd_line, "%f", thd->variables.inception_osc_max_lag);
    oscargv[count++] = strdup(cmd_line);

    oscargv[count++] = strdup("--no-version-check");
    sprintf(cmd_line, "--recursion-method=%s", 
        osc_recursion_method[thd->variables.inception_osc_recursion_method]);
    oscargv[count++] = strdup(cmd_line);

    //这个参数就可以直接使用默认值
    // sprintf(cmd_line, "--set-vars innodb_lock_wait_timeout=%d ", 50);
    // osc_cmd_ptr = str_append(osc_cmd_ptr, cmd_line);

    oscargv[count++] = strdup("--progress");
    sprintf(cmd_line, "percentage,%d", 1);
    oscargv[count++] = strdup(cmd_line);

    sprintf(cmd_line, "--user=%s", thd->thd_sinfo->user);
    oscargv[count++] = strdup(cmd_line);
    sprintf(cmd_line, "--password=%s", thd->thd_sinfo->password);
    oscargv[count++] = strdup(cmd_line);
    sprintf(cmd_line, "--host=%s", thd->thd_sinfo->host);
    oscargv[count++] = strdup(cmd_line);
    sprintf(cmd_line, "--port=%d", thd->thd_sinfo->port);
    oscargv[count++] = strdup(cmd_line);
    sprintf(cmd_line, "D=%s,t=%s", sql_cache_node->dbname, sql_cache_node->tablename);
    oscargv[count++] = strdup(cmd_line);
    oscargv[count++] = NULL;

    sql_cache_node->oscoutput = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    sql_cache_node->oscoutput = str_init(sql_cache_node->oscoutput);
    sql_cache_node->oscpercent = 0;

    process proc (thd, sql_cache_node, oscargv, "r");
    mysql_add_new_percent_cache_node(sql_cache_node, &proc);
    if (NULL != proc.pipe() && !proc.error())
    {
        char* tmp;
        if (!(tmp = my_fgets (out, out_len, proc.pipe())))
            proc.wait();
        while(tmp && !proc.error() )
        {
            mysql_analyze_osc_output(thd, tmp, sql_cache_node);
            tmp = my_fgets (out, out_len, proc.pipe());
        }
    }

    for (int j=0; j<count-1; j++)
        free(oscargv[j]);

    if ((ret = proc.error()))
    {
        sprintf(errmsg, "'%s' failed: %d (%s)", "pt-online-schema-change", ret, strerror(ret));
        mysql_errmsg_append_without_errno_osc(thd, sql_cache_node, errmsg);
        DBUG_RETURN(true);
    }
        
    if(mysql_osc_execute_abort_check(thd, sql_cache_node))
        DBUG_RETURN(true);

    DBUG_RETURN(false);
}

static void print_warnings(
    THD* thd,
    MYSQL* mysql,
    sql_cache_node_t* sql_cache_node
)
{
    const char   *query;
    MYSQL_RES    *result;
    MYSQL_ROW    cur;
    my_ulonglong num_rows;
    char         errcode[64]; 
    uint error= mysql_errno(mysql);
    int count=1;

    //这两种语句类型不打印警告，因为它们不会产生自己的警告
    if (sql_cache_node->optype == SQLCOM_SET_OPTION || 
        sql_cache_node->optype == SQLCOM_CHANGE_DB)
        return;

    /* Get the warnings */
    query= "show warnings";
    if (mysql_real_query(mysql, query, strlen(query)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        return;
    }

    if ((result= mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        return;
    }

    /* Bail out when no warnings */
    if (!result || !(num_rows= mysql_num_rows(result)))
        goto end;

    cur= mysql_fetch_row(result);

    /*
      Don't print a duplicate of the current error.  It is possible for SHOW
      WARNINGS to return multiple errors with the same code, but different
      messages.  To be safe, skip printing the duplicate only if it is the only
      warning.
    */
    if (!cur || (num_rows == 1 && error == (uint) strtoul(cur[1], NULL, 10)))
        goto end;

    do
    {
      sprintf(errcode, "#%d Execute(Warning, Code %s):", count++, cur[1]);
      //error code
      mysql_errmsg_append_without_errno(thd, sql_cache_node, errcode);
      //error message
      mysql_errmsg_append_without_errno(thd, sql_cache_node, cur[2]);
      mysql_errmsg_append_without_errno(thd, sql_cache_node, (char*)"\n");
    } while ((cur= mysql_fetch_row(result)));
    
    //set to warnings
    sql_cache_node->errlevel = INCEPTION_RULES;

  end:
    mysql_free_result(result);
}

#if defined(__WIN__)
#include <time.h>
#else
#include <sys/times.h>
#ifdef _SC_CLK_TCK        // For mit-pthreads
#undef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC (sysconf(_SC_CLK_TCK))
#endif
#endif

static ulong start_timer(void)
{
#if defined(__WIN__)
    return clock();
#else
    struct tms tms_tmp;
    return times(&tms_tmp);
#endif
}

int mysql_execute_statement(
    THD* thd,
    MYSQL* mysql,
    char* statement,
    sql_cache_node_t* sql_cache_node
)
{
    ulong timer;
    DBUG_ENTER("mysql_execute_statement");
    timer=start_timer();

    if (sql_cache_node->use_osc)
    {
        if (mysql_execute_alter_table_osc(thd, mysql, statement, sql_cache_node))
        {
            sprintf(sql_cache_node->execute_time, "%.3f",
                (double)(start_timer() - timer) / CLOCKS_PER_SEC);
            DBUG_RETURN(true);
        }
    }
    else
    {
        if (mysql_real_query(mysql, statement, strlen(statement)))
        {
            sprintf(sql_cache_node->execute_time, "%.3f",
                (double)(start_timer() - timer) / CLOCKS_PER_SEC);
            my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
            DBUG_RETURN(true);
        }
        sql_cache_node->exe_complete = TRUE;
    }

    sprintf(sql_cache_node->execute_time, "%.3f",  
        (double)(start_timer() - timer) / CLOCKS_PER_SEC);

    sql_cache_node->affected_rows = mysql_affected_rows(mysql);

    print_warnings(thd, mysql, sql_cache_node);

    if (mysql_fetch_thread_id(mysql, &sql_cache_node->thread_id))
        DBUG_RETURN(true);

    time(&sql_cache_node->exec_time);

    if (sql_cache_node->dbname[0] != '\0' && 
        sql_cache_node->tablename[0] != '\0' && 
        !sql_cache_node->table_info)
    {
        sql_cache_node->table_info = mysql_get_table_object_from_cache(thd, 
          sql_cache_node->dbname, sql_cache_node->tablename);
    }

    DBUG_RETURN(false);
}

int mysql_execute_and_backup(THD *thd, MYSQL* mysql, sql_cache_node_t* sql_cache_node)
{
    char before_binlog_name[FN_REFLEN];
    char after_binlog_name[FN_REFLEN];
    int  before_binlog_pos;
    int  after_binlog_pos;

    DBUG_ENTER("mysql_execute_and_backup");

    if (thd->thd_sinfo->backup)
    {
        if (mysql_fetch_master_binlog_position(thd, mysql,
            before_binlog_name, &before_binlog_pos))
            DBUG_RETURN(TRUE);

        if (!mysql_check_binlog_format(thd, (char*)"ROW"))
            if (mysql_modify_binlog_format_row(mysql))
                DBUG_RETURN(TRUE);
    }

    if (mysql_execute_statement(thd, mysql, sql_cache_node->sql_statement, sql_cache_node))
        DBUG_RETURN(TRUE);

    if (thd->thd_sinfo->backup)
    {
        if (mysql_fetch_master_binlog_position(thd, mysql,
            after_binlog_name, &after_binlog_pos))
            DBUG_RETURN(TRUE);

        if (strcasecmp(after_binlog_name, before_binlog_name) == 0 &&
            after_binlog_pos == before_binlog_pos)
            DBUG_RETURN(false);

        strcpy(sql_cache_node->start_binlog_file, before_binlog_name);
        sql_cache_node->start_binlog_pos = before_binlog_pos;
        strcpy(sql_cache_node->end_binlog_file, after_binlog_name);
        sql_cache_node->end_binlog_pos = after_binlog_pos;
    }

    sql_cache_node->exe_complete = TRUE;

    DBUG_RETURN(false);
}

int mysql_remote_execute_command(
    THD *thd,
    MYSQL* mysql,
    sql_cache_node_t* sql_cache_node
)
{
    int err=0;

    DBUG_ENTER("mysql_remote_execute_command");

    sql_cache_node->stage = 2;//execute
    sql_cache_node->affected_rows = 0;

    if (!thd->thd_sinfo->force && thd->have_error_before)
    {
        my_error(ER_ERROR_EXIST_BEFORE, MYF(0));
        err = 1;
    }
    else
    {
        switch (sql_cache_node->optype)
        {
        case SQLCOM_INSERT:
        case SQLCOM_DELETE:
        case SQLCOM_DELETE_MULTI:
        case SQLCOM_UPDATE:
        case SQLCOM_UPDATE_MULTI:
        case SQLCOM_INSERT_SELECT:
            err = mysql_execute_and_backup(thd, mysql, sql_cache_node);
            break;

        case SQLCOM_ALTER_TABLE:
            err = mysql_execute_statement(thd, mysql,
                    sql_cache_node->sql_statement, sql_cache_node);
            break;

        case SQLCOM_DROP_TABLE:
        case SQLCOM_CHANGE_DB:
        case SQLCOM_CREATE_TABLE:
        case SQLCOM_SET_OPTION:
        case SQLCOM_TRUNCATE:
        case SQLCOM_CREATE_DB:
            err = mysql_execute_statement(thd, mysql,
                    sql_cache_node->sql_statement, sql_cache_node);
            break;

        default:
            my_error(ER_NOT_SUPPORTED_YET, MYF(0));
            err = TRUE;
        }
    }

    if (err)
    {
        mysql_sqlcachenode_errmsg_append(thd, sql_cache_node, INC_ERROR_EXECUTE_STAGE);
        if (sql_cache_node->err_stage == INC_ERROR_NONE_STAGE)
            sql_cache_node->err_stage = INC_ERROR_EXECUTE_STAGE;
        str_append(sql_cache_node->stagereport, "Execute failed\n");
        thd->have_error_before = TRUE;
        if (thd->thd_sinfo->force)
            DBUG_RETURN(FALSE);
        else
            DBUG_RETURN(TRUE);
    }

    if (sql_cache_node->stage==1)
        str_append(sql_cache_node->stagereport, "Execute Aborted\n");
    else
        str_append(sql_cache_node->stagereport, "Execute Successfully\n");

    DBUG_RETURN(FALSE);
}


int mysql_execute_all_statement(THD* thd)
{
    MYSQL*     mysql = NULL;
    sql_cache_node_t*  sql_cache_node;
    int      exe_err = FALSE;

    if ((mysql = thd->get_audit_connection()) == NULL)
        return TRUE;

    thd->thread_state = INCEPTION_STATE_EXECUTING;
    sql_cache_node = LIST_GET_FIRST(thd->sql_cache->field_lst);
    while (!thd->killed && sql_cache_node != NULL)
    {
        if (sql_cache_node->optype != SQLCOM_INCEPTION &&
            (exe_err = mysql_remote_execute_command(thd, mysql, sql_cache_node)) == TRUE)
            break;

        sql_cache_node = LIST_GET_NEXT(link, sql_cache_node);
    }

    return FALSE;
}

int mysql_create_backup_tables(THD* thd, sql_cache_node_t* sql_cache_node)
{
    if (mysql_make_sure_backupdb_table_exist(thd, sql_cache_node))
    {
        mysql_sqlcachenode_errmsg_append(thd, sql_cache_node, INC_ERROR_BACKUP_STAGE);
        if (sql_cache_node->err_stage == INC_ERROR_NONE_STAGE)
            sql_cache_node->err_stage = INC_ERROR_BACKUP_STAGE;//check

        if (sql_cache_node->errrno == 1130 || sql_cache_node->errrno == 2003)
            return TRUE;
    }

    return FALSE;
}

int
mysql_backup_sql(
    THD *    thd,
    Master_info*  mi,
    MYSQL*    mysql,
    sql_cache_node_t* sql_cache_node
)
{
    if (mysql_sql_cache_is_valid_for_ddl(sql_cache_node) &&
        mysql_backup_single_ddl_statement(thd, mi, mysql, sql_cache_node))
    {
        mysql_sqlcachenode_errmsg_append(thd, sql_cache_node, INC_ERROR_BACKUP_STAGE);
        if (sql_cache_node->err_stage == INC_ERROR_NONE_STAGE)
            sql_cache_node->err_stage = INC_ERROR_BACKUP_STAGE;//check
    }
    else if (mysql_sql_cache_is_valid(sql_cache_node) &&
            mysql_backup_single_statement(thd, mi, mysql, sql_cache_node))
    {
        //dml的binlog处理出错了，就重新去dump一次，不然直接读网络的话会造成阻塞
        mysql_sqlcachenode_errmsg_append(thd, sql_cache_node, INC_ERROR_BACKUP_STAGE);
        if (sql_cache_node->err_stage == INC_ERROR_NONE_STAGE)
            sql_cache_node->err_stage = INC_ERROR_BACKUP_STAGE;//check
        return TRUE;
    }

    return FALSE;
}

int mysql_alloc_cache_table_record(THD* thd, sql_cache_t* sql_cache)
{
    sql_cache_node_t*  sql_cache_node;

    sql_cache_node = LIST_GET_FIRST(sql_cache->field_lst);
    while (sql_cache_node != NULL)
    {
        if (mysql_sql_cache_is_valid(sql_cache_node) ||
            mysql_sql_cache_is_valid_for_ddl(sql_cache_node))
        {
            if (mysql_create_backup_tables(thd, sql_cache_node))
                return TRUE;

            if (mysql_sql_cache_is_valid(sql_cache_node))
                if(mysql_alloc_record(sql_cache_node->table_info, thd->get_audit_connection()))
                    return TRUE;
        }

        sql_cache_node = LIST_GET_NEXT(link, sql_cache_node);
    }

    return false;
}

int mysql_dump_binlog_from_first_statement(Master_info*   mi, MYSQL* mysql, sql_cache_t*   sql_cache)
{
    sql_cache_node_t*  sql_cache_node;
    sql_cache_node = LIST_GET_FIRST(sql_cache->field_lst);
    while (sql_cache_node != NULL)
    {
        if (sql_cache_node->start_binlog_pos != 0 &&
            mysql_sql_cache_is_valid(sql_cache_node))
        {
            mysql_get_master_version(mysql, mi);
            return mysql_request_binlog_dump(mysql,
                    sql_cache_node->start_binlog_file, sql_cache_node->start_binlog_pos);
        }

        sql_cache_node = LIST_GET_NEXT(link, sql_cache_node);
    }

    return false;
}

int mysql_execute_commit(THD *thd)
{
    sql_cache_node_t*  sql_cache_node;
    sql_cache_node_t*  next_sql_cache_node;
    sql_cache_t*   sql_cache;
    MYSQL*     mysql = NULL;
    int      err = TRUE;
    Master_info*   mi = NULL;

    DBUG_ENTER("mysql_execute_commit");

    //如果只是审核，或者是拆分，或者是只读的Inception服务，都提前返回
    if (inception_read_only ||
        inception_get_type(thd) == INCEPTION_TYPE_CHECK ||
        inception_get_type(thd) == INCEPTION_TYPE_SPLIT ||
        inception_get_type(thd) == INCEPTION_TYPE_PRINT)
    {
        mysql_send_all_results(thd);
        mysql_free_all_table_definition(thd);
        mysql_deinit_sql_cache(thd);

        thd->have_begin = FALSE;
        thd->thd_sinfo->host[0]='\0';
        thd->close_all_connections();
        DBUG_RETURN(false);
    }

    if (!thd->check_error_before || thd->thd_sinfo->ignore_warnings)
    {
        if (!mysql_execute_all_statement(thd))
        {
            if (thd->thd_sinfo->backup)
            {
                thd->thread_state = INCEPTION_STATE_BACKUP;
                mysql_operation_statistic(thd);
                mi = new Master_info(1);
                mi->thd = thd;
                sql_cache = thd->sql_cache;
                if (mysql_alloc_cache_table_record(thd, sql_cache))
                    goto error;

                if (mysql_dump_binlog_from_first_statement(
                        mi, thd->get_audit_connection(), sql_cache))
                    goto error;

                sql_cache_node = LIST_GET_FIRST(sql_cache->field_lst);
                while (sql_cache_node != NULL)
                {
                    next_sql_cache_node = LIST_GET_NEXT(link, sql_cache_node);
                    if ((mysql = thd->get_audit_connection()) == NULL)
                        goto error;

                    //如果一条语句备份失败了，则要重新请求一次，对下一条语句做备份
                    if(mysql_backup_sql(thd, mi, mysql, sql_cache_node) && next_sql_cache_node)
                        mysql_request_binlog_dump(mysql, next_sql_cache_node->start_binlog_file,
                          next_sql_cache_node->start_binlog_pos);

                    sql_cache_node = next_sql_cache_node;
                }

                err = FALSE;
            }
        }
        else
        {
            goto error;
        }
    }

    err = FALSE;
error:
    mysql_send_all_results(thd);
    thd->thread_state = INCEPTION_STATE_DEINIT;
    mysql_free_all_table_definition(thd);
    mysql_deinit_sql_cache(thd);
    delete mi;
    thd->have_begin = FALSE;
    thd->thd_sinfo->host[0]='\0';
    thd->close_all_connections();
    DBUG_RETURN(err);
}

static const char *sql_mode_names[]=
{
    "REAL_AS_FLOAT", "PIPES_AS_CONCAT", "ANSI_QUOTES", "IGNORE_SPACE", ",",
    "ONLY_FULL_GROUP_BY", "NO_UNSIGNED_SUBTRACTION", "NO_DIR_IN_CREATE",
    "POSTGRESQL", "ORACLE", "MSSQL", "DB2", "MAXDB", "NO_KEY_OPTIONS",
    "NO_TABLE_OPTIONS", "NO_FIELD_OPTIONS", "MYSQL323", "MYSQL40", "ANSI",
    "NO_AUTO_VALUE_ON_ZERO", "NO_BACKSLASH_ESCAPES", "STRICT_TRANS_TABLES",
    "STRICT_ALL_TABLES", "NO_ZERO_IN_DATE", "NO_ZERO_DATE",
    "ALLOW_INVALID_DATES", "ERROR_FOR_DIVISION_BY_ZERO", "TRADITIONAL",
    "NO_AUTO_CREATE_USER", "HIGH_NOT_PRECEDENCE", "NO_ENGINE_SUBSTITUTION",
    "PAD_CHAR_TO_FULL_LENGTH",
    0
};

static const unsigned int sql_mode_values[]=
{
    MODE_REAL_AS_FLOAT,
    MODE_PIPES_AS_CONCAT,
    MODE_ANSI_QUOTES,
    MODE_IGNORE_SPACE,
    MODE_NOT_USED,
    MODE_ONLY_FULL_GROUP_BY,
    MODE_NO_UNSIGNED_SUBTRACTION,
    MODE_NO_DIR_IN_CREATE,
    MODE_POSTGRESQL,
    MODE_ORACLE,
    MODE_MSSQL,
    MODE_DB2,
    MODE_MAXDB,
    MODE_NO_KEY_OPTIONS,
    MODE_NO_TABLE_OPTIONS,
    MODE_NO_FIELD_OPTIONS,
    MODE_MYSQL323,
    MODE_MYSQL40,
    MODE_ANSI,
    MODE_NO_AUTO_VALUE_ON_ZERO,
    MODE_NO_BACKSLASH_ESCAPES,
    MODE_STRICT_TRANS_TABLES,
    MODE_STRICT_ALL_TABLES,
    MODE_NO_ZERO_IN_DATE,
    MODE_NO_ZERO_DATE,
    MODE_INVALID_DATES,
    MODE_ERROR_FOR_DIVISION_BY_ZERO,
    MODE_TRADITIONAL,
    MODE_NO_AUTO_CREATE_USER,
    MODE_HIGH_NOT_PRECEDENCE,
    MODE_NO_ENGINE_SUBSTITUTION,
    MODE_PAD_CHAR_TO_FULL_LENGTH,
    0
};

int get_sql_mode_from_str(char* mode)
{
    unsigned int i = 0;
    while (sql_mode_names[i])
    {
        if (strcmp(mode, sql_mode_names[i])==0)
            return sql_mode_values[i];
        i++;
    }

    return 0;
}

int get_sql_mode(THD*  thd, char* sqlmode)
{
    char*   sql_mode;
    char*   strToken;
    int     ret;

    if (!strlen(sqlmode))
        return false; 

    sql_mode = (char*)my_malloc(strlen(sqlmode)+1, MY_ZEROFILL);
    strcpy(sql_mode, sqlmode);
    if ((strToken = strtok(sql_mode, ",")) == NULL)
    {
        ret = false;
        goto err;
    }

    while(strToken)
    {
        thd->variables.sql_mode |= get_sql_mode_from_str(strToken);
        strToken=strtok(NULL, ",");
    }

err:
    my_free(sql_mode);
    return false;
}
int mysql_get_remote_variables(THD* thd)
{
    char set_format[1024];
    MYSQL_RES * source_res;
    MYSQL_ROW source_row;
    MYSQL*  mysql;

    DBUG_ENTER("mysql_get_remote_variables");

    mysql= thd->get_audit_connection();
    if (mysql == NULL)
        DBUG_RETURN(ER_NO);

    sprintf(set_format, "show variables where \
        Variable_name in ('explicit_defaults_for_timestamp', 'sql_mode');");
    if (mysql_real_query(mysql, set_format, strlen(set_format)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(ER_NO);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(ER_NO);
    }

    source_row = mysql_fetch_row(source_res);
    while(source_row)
    {
        if (strcasecmp(source_row[0], "explicit_defaults_for_timestamp") == 0)
            thd->variables.explicit_defaults_for_timestamp=strcmp("OFF", source_row[1]) ? 1 : 0;
        else if (strcasecmp(source_row[0], "sql_mode") == 0)
            get_sql_mode(thd, source_row[1]);

        source_row = mysql_fetch_row(source_res);
    }

    mysql_free_result(source_res);
    DBUG_RETURN(false);
}

int mysql_check_binlog_format(THD* thd, char* binlogformat)
{
    char set_format[64];
    MYSQL_RES * source_res;
    MYSQL_ROW source_row;
    MYSQL*  mysql;

    DBUG_ENTER("mysql_check_binlog_format");

    mysql= thd->get_audit_connection();
    if (mysql == NULL)
        DBUG_RETURN(ER_NO);

    sprintf(set_format, "show variables like 'binlog_format';");
    if (mysql_real_query(mysql, set_format, strlen(set_format)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(ER_NO);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(ER_NO);
    }

    source_row = mysql_fetch_row(source_res);
    if (strcasecmp(source_row[1], binlogformat) == 0)
    {
        mysql_free_result(source_res);
        DBUG_RETURN(1);
    }

    mysql_free_result(source_res);
    DBUG_RETURN(false);
}

int mysql_check_binlog_is_on(THD* thd)
{
    char set_format[64];
    MYSQL_RES * source_res;
    MYSQL_ROW source_row;
    MYSQL*  mysql;

    DBUG_ENTER("mysql_check_binlog_is_on");

    mysql= thd->get_audit_connection();
    if (mysql == NULL)
        DBUG_RETURN(ER_NO);

    sprintf(set_format, "show variables like 'log_bin';");
    if (mysql_real_query(mysql, set_format, strlen(set_format)))
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(ER_NO);
    }

    if ((source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        DBUG_RETURN(ER_NO);
    }

    source_row = mysql_fetch_row(source_res);
    if (strcasecmp(source_row[1], "ON") == 0)
    {
        mysql_free_result(source_res);
        DBUG_RETURN(TRUE);
    }

    mysql_free_result(source_res);
    DBUG_RETURN(false);
}


int mysql_execute_select(THD *thd)
{
    DBUG_ENTER("mysql_execute_select");
    DBUG_RETURN(false);
}

int mysql_need_source_info(THD *thd)
{
    if (thd->lex->sql_command == SQLCOM_SHOW_WARNS ||
        thd->lex->sql_command == SQLCOM_SHOW_ERRORS ||
        thd->lex->sql_command == SQLCOM_SET_OPTION ||
        thd->lex->sql_command == SQLCOM_SHOW_PROCESSLIST)
    {
        return false;
    }

    return true;
}

int mysql_init_sql_cache(THD* thd)
{
    sql_cache_t*  sql_cache;
    int     is_stmt;
    int     is_on;
    split_cache_t*  split_cache;

    DBUG_ENTER("mysql_init_sql_cache");

    if (thd->have_begin)
    {
        my_error(ER_HAVE_BEGIN, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    thd->thread_state = INCEPTION_STATE_INIT;
    thd->have_begin = TRUE;
    thd->have_error_before = FALSE;
    thd->check_error_before = FALSE;
    thd->parse_error = FALSE;
    thd->errmsg = NULL;
    thd->show_result = NULL;
    thd->err_level = INCEPTION_NOERR;
    str_init(&thd->ddl_rollback);
    thd->affected_rows = 0;

    thd->show_result = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(thd->show_result);
    thd->query_print_cache = (query_print_cache_t*)my_malloc(
        sizeof(query_print_cache_t), MY_ZEROFILL);
    LIST_INIT(thd->query_print_cache->field_lst);

    LIST_INIT(thd->tablecache.tablecache_lst);
    LIST_INIT(thd->dbcache.dbcache_lst);
    thd->rt_lst = NULL;

    if (inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        split_cache = (split_cache_t*)my_malloc(sizeof(split_cache_t), MY_ZEROFILL);
        thd->split_cache = split_cache;
        if (split_cache == NULL)
        {
            my_error(ER_OUTOFMEMORY, MYF(0));
            DBUG_RETURN(ER_NO);
        }

        str_init(&thd->usedb);
        str_init(&thd->setnames);
        thd->useflag = 0;
        thd->setnamesflag = 0;
        DBUG_RETURN(FALSE);
    }

    DBUG_ASSERT(thd->sql_cache == NULL);
    sql_cache = (sql_cache_t*)my_malloc(sizeof(sql_cache_t), MY_ZEROFILL);
    thd->sql_cache = sql_cache;
    if (sql_cache == NULL)
    {
        my_error(ER_OUTOFMEMORY, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    mysql_get_remote_variables(thd);
    if (inception_get_type(thd) == INCEPTION_TYPE_EXECUTE)
    {
        if ((is_stmt = mysql_check_binlog_format(thd, (char*)"STATEMENT")) == ER_NO)
            DBUG_RETURN(ER_NO);

        if ((is_on = mysql_check_binlog_is_on(thd)) == ER_NO)
            DBUG_RETURN(ER_NO);

        if (!is_on || is_stmt)
            thd->thd_sinfo->backup = FALSE;
    }

    if (thd->thd_sinfo->backup && !inception_read_only && 
        inception_get_type(thd) == INCEPTION_TYPE_EXECUTE && 
        (remote_backup_host == NULL || remote_backup_port == 0 || 
        remote_system_user == NULL || remote_system_password == NULL || 
        remote_system_user[0] == '\0' || remote_system_password[0] == '\0'))
    {
        my_error(ER_INVALID_BACKUP_HOST_INFO, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    DBUG_RETURN(FALSE);
}

int mysql_deinit_sql_cache(THD* thd)
{
    sql_cache_node_t*  sql_cache_node;
    sql_cache_node_t*  sql_cache_node_next;
    split_cache_node_t* split_cache_node;
    split_cache_node_t* split_cache_node_next;
    split_table_t*      split_table;
    split_table_t*      split_table_next;
    check_rt_t*   query_rt;
    check_rt_t*   query_rt_next;
    query_print_cache_t* query_print_cache;
    query_print_cache_node_t * query_print_cache_node;
    query_print_cache_node_t * query_print_cache_node_next;
    table_rt_t*                 table_rt;
    table_rt_t*                 table_rt_next;

    DBUG_ENTER("mysql_deinit_sql_cache");

    if (thd->split_cache != NULL && inception_get_type(thd) == INCEPTION_TYPE_SPLIT) {
        split_cache_node = LIST_GET_FIRST(thd->split_cache->field_lst);
        while (split_cache_node) {

            split_cache_node_next = LIST_GET_NEXT(link, split_cache_node);
            LIST_REMOVE(link, thd->split_cache->field_lst, split_cache_node);
            my_free(split_cache_node);

            split_cache_node = split_cache_node_next;
        }

        split_table = LIST_GET_FIRST(thd->split_cache->table_lst);
        while (split_table) {

            split_table_next = LIST_GET_NEXT(link, split_table);
            LIST_REMOVE(link, thd->split_cache->table_lst, split_table);
            my_free(split_table);

            split_table = split_table_next;
        }

        my_free(thd->split_cache);
        thd->split_cache = NULL;
        str_deinit(&thd->usedb);
        str_deinit(&thd->setnames);
    }

    str_deinit(thd->errmsg);
    thd->errmsg = NULL;
    if (thd->sql_cache == NULL)
    {
        DBUG_RETURN(FALSE);
    }

    sql_cache_node = LIST_GET_FIRST(thd->sql_cache->field_lst);
    while (sql_cache_node != NULL)
    {
        sql_cache_node_next = LIST_GET_NEXT(link, sql_cache_node);
        if (sql_cache_node->sql_statement != NULL)
            my_free(sql_cache_node->sql_statement);

        str_deinit(sql_cache_node->errmsg);
        str_deinit(sql_cache_node->stagereport);
        str_deinit(sql_cache_node->ddl_rollback);

        if (sql_cache_node->sqlsha1[0] != '\0')
        {
            mysql_free_osc_cache_node(sql_cache_node->sqlsha1);
            str_deinit(sql_cache_node->oscoutput);
            my_free(sql_cache_node->oscoutput);
        }

        query_rt = sql_cache_node->rt_lst ? LIST_GET_FIRST(*sql_cache_node->rt_lst) : NULL;
        while(query_rt)
        {
            query_rt_next = LIST_GET_NEXT(link, query_rt);
            LIST_REMOVE(link, *sql_cache_node->rt_lst, query_rt);

            table_rt = LIST_GET_FIRST(query_rt->table_rt_lst);
            while(table_rt)
            {
                table_rt_next = LIST_GET_NEXT(link, table_rt);
                LIST_REMOVE(link, query_rt->table_rt_lst, table_rt);
                my_free(table_rt);
                table_rt = table_rt_next;
            }

            my_free(query_rt);
            query_rt = query_rt_next;
        }

        my_free(sql_cache_node);
        sql_cache_node = sql_cache_node_next;
    }

    my_free(thd->sql_cache);
    thd->sql_cache = NULL;

    str_deinit(thd->show_result);
    thd->show_result = NULL;
    query_print_cache_node = LIST_GET_FIRST(thd->query_print_cache->field_lst);
    while (query_print_cache_node != NULL)
    {
        query_print_cache_node_next = LIST_GET_NEXT(link, query_print_cache_node);
        str_deinit(query_print_cache_node->sql_statements);
        str_deinit(query_print_cache_node->query_tree);
        str_deinit(query_print_cache_node->errmsg);

        query_rt = LIST_GET_FIRST(query_print_cache_node->rt_lst);
        while(query_rt)
        {
            query_rt_next = LIST_GET_NEXT(link, query_rt);
            LIST_REMOVE(link, query_print_cache_node->rt_lst, query_rt);

            table_rt = LIST_GET_FIRST(query_rt->table_rt_lst);
            while(table_rt)
            {
                table_rt_next = LIST_GET_NEXT(link, table_rt);
                LIST_REMOVE(link, query_rt->table_rt_lst, table_rt);
                my_free(table_rt);
                table_rt = table_rt_next;
            }

            my_free(query_rt);
            query_rt = query_rt_next;
        }

        my_free(query_print_cache_node);
        query_print_cache_node = query_print_cache_node_next;
    }

    my_free(thd->query_print_cache);
    thd->query_print_cache= NULL;

    DBUG_RETURN(FALSE);
}


int mysql_show_print_and_execute_simple(THD *thd)
{
    int res = 0;

    DBUG_ENTER("mysql_show_print_and_execute_simple");

    switch(thd->lex->sql_command)
    {
    case SQLCOM_INCEPTION_START:
        res = mysql_init_sql_cache(thd);
        break;

    case SQLCOM_INCEPTION_COMMIT:
        res = mysql_execute_commit(thd);
        break;

    case SQLCOM_SET_OPTION:
        //用ER_WARNING错误码来告诉审核线程是不是要缓存语句
        //ER_WARNING表示不要缓存当前语句, 这里如果没有开始审核，这些
        //set语句都被忽略了，不检查，如果开始了，则就到mysql_set_option_check
        //中做检查了
        if (!thd->have_begin)
            res = FALSE;
        else
            res = ER_WARNING;
        break;

    default:
        res = ER_WARNING;
        break;
    }

    DBUG_RETURN(res);
}

int mysql_parse_and_check_valid(THD* thd, Parser_state *parser_state)
{
    int err;
    DBUG_ENTER("mysql_parse_and_check_valid");

    err = parse_sql(thd, parser_state, NULL);
    const char *found_semicolon= parser_state->m_lip.found_semicolon;

    if (!err)
    {
        if (found_semicolon && (ulong) (found_semicolon - thd->query()))
            thd->set_query_inner(thd->query(), (uint32)
            (found_semicolon - thd->query() - 1), thd->charset());

        //直接执行的命令不做这些操作了
        if (mysql_not_need_data_source(thd))
            DBUG_RETURN(FALSE);

        if (found_semicolon && thd->lex->sql_command == SQLCOM_INCEPTION_COMMIT)
        {
            my_error(ER_END_WITH_COMMIT, MYF(0));
            DBUG_RETURN(ER_NO);
        }

        if (!found_semicolon &&
            thd->lex->sql_command != SQLCOM_INCEPTION_COMMIT && thd->have_begin)
        {
            my_error(ER_END_WITH_COMMIT, MYF(0));
            DBUG_RETURN(ER_NO);
        }
    }
    else
    {
        thd->parse_error = TRUE;
        mysql_errmsg_append(thd);
        DBUG_RETURN(TRUE);
    }

    if ((sql_command_flags[thd->lex->sql_command] & CF_DIAGNOSTIC_STMT) != 0)
        thd->get_stmt_da()->set_warning_info_read_only(TRUE);
    else
        thd->get_stmt_da()->set_warning_info_read_only(FALSE);

    if (thd->lex->sql_command == SQLCOM_INCEPTION_START)
    {
        if (thd_parse_options(thd, thd->query()) == ER_NO)
            DBUG_RETURN(ER_NO);
    }

    DBUG_RETURN(FALSE);
}

int mysql_check_after_parse(THD* thd)
{
    DBUG_ENTER("mysql_check_after_parse");

    if (mysql_not_need_data_source(thd))
        DBUG_RETURN(FALSE);

    if (!thd->have_begin)
    {
        my_error(ER_START_AS_BEGIN, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    if (thd->thd_sinfo->host[0] == '\0')
    {
        my_error(ER_SQL_NO_SOURCE, MYF(0));
        DBUG_RETURN(ER_NO);
    }

    DBUG_RETURN(FALSE);
}

int mysql_process_command(THD *thd, Parser_state *parser_state)
{
    int err;

    DBUG_ENTER("mysql_process_command");

    if ((err = mysql_parse_and_check_valid(thd, parser_state)) != FALSE)
        DBUG_RETURN(err);

    if ((err = mysql_show_print_and_execute_simple(thd)) != ER_WARNING)
        DBUG_RETURN(ER_WARNING);

    if ((err = mysql_check_after_parse(thd)) != FALSE)
        DBUG_RETURN(err);
      
    if (inception_get_type(thd) == INCEPTION_TYPE_PRINT)
        DBUG_RETURN(mysql_print_command(thd));
        
    DBUG_RETURN(mysql_check_command(thd));
}

/*
When you modify mysql_parse(), you may need to mofify
mysql_test_parse_for_slave() in this same file.
*/

/**
Parse a query.

@param       thd     Current thread
@param       rawbuf  Begining of the query text
@param       length  Length of the query text
@param[out]  found_semicolon For multi queries, position of the character of
the next query in the query text.
*/

void mysql_parse(THD *thd, uint length, Parser_state *parser_state)
{
    int err;
    DBUG_ENTER("mysql_parse");

    DBUG_EXECUTE_IF("parser_debug", turn_parser_debug_on(););

    lex_start(thd);
    mysql_reset_thd_for_next_command(thd);

    err = mysql_process_command(thd, parser_state);
    if (err != ER_NO && err != ER_WARNING && 
        (inception_get_type(thd) == INCEPTION_TYPE_CHECK ||
        inception_get_type(thd) == INCEPTION_TYPE_EXECUTE))
        mysql_cache_one_sql(thd);

    thd->end_statement();
    thd->cleanup_after_query();

    DBUG_VOID_RETURN;
}


bool add_field_to_list(THD *thd, LEX_STRING *field_name, enum_field_types type,
    char *length, char *decimals,
    uint type_modifier,
    Item *default_value, Item *on_update_value,
    LEX_STRING *comment,
    char *change,
    List<String> *interval_list, const CHARSET_INFO *cs,
    uint uint_geom_type)
{
    register Create_field *new_field;
    LEX  *lex= thd->lex;
    uint8 datetime_precision= decimals ? atoi(decimals) : 0;
    DBUG_ENTER("add_field_to_list");

    if (check_string_char_length(field_name, "", NAME_CHAR_LEN,
        system_charset_info, 1))
    {
        my_error(ER_TOO_LONG_IDENT, MYF(0), field_name->str); /* purecov: inspected */
        DBUG_RETURN(1);    /* purecov: inspected */
    }
    if (type_modifier & PRI_KEY_FLAG)
    {
        Key *key;
        lex->col_list.push_back(new Key_part_spec(*field_name, 0));
        key= new Key(Key::PRIMARY, null_lex_str,
            &default_key_create_info,
            0, lex->col_list);
        lex->alter_info.key_list.push_back(key);
        lex->col_list.empty();
    }
    if (type_modifier & (UNIQUE_FLAG | UNIQUE_KEY_FLAG))
    {
        Key *key;
        lex->col_list.push_back(new Key_part_spec(*field_name, 0));
        key= new Key(Key::UNIQUE, null_lex_str,
            &default_key_create_info, 0,
            lex->col_list);
        lex->alter_info.key_list.push_back(key);
        lex->col_list.empty();
    }

    if (default_value)
    {
        /*
        Default value should be literal => basic constants =>
        no need fix_fields()

        We allow only CURRENT_TIMESTAMP as function default for the TIMESTAMP or
        DATETIME types.
        */
        // if (default_value->type() == Item::FUNC_ITEM &&
        //     (static_cast<Item_func*>(default_value)->functype() !=
        //     Item_func::NOW_FUNC ||
        //     (!real_type_with_now_as_default(type)) ||
        //     default_value->decimals != datetime_precision))
        // {
        //     my_error(ER_INVALID_DEFAULT, MYF(0), field_name->str);
        //     DBUG_RETURN(1);
        // }
        // else if (default_value->type() == Item::NULL_ITEM)
        // {
        //     default_value= 0;
        //     if ((type_modifier & (NOT_NULL_FLAG | AUTO_INCREMENT_FLAG)) ==
        //         NOT_NULL_FLAG)
        //     {
        //         my_error(ER_INVALID_DEFAULT, MYF(0), field_name->str);
        //         DBUG_RETURN(1);
        //     }
        // }
        // else if (type_modifier & AUTO_INCREMENT_FLAG)
        // {
        //     my_error(ER_INVALID_DEFAULT, MYF(0), field_name->str);
        //     DBUG_RETURN(1);
        // }
    }

    if (on_update_value &&
        (!real_type_with_now_on_update(type) ||
        on_update_value->decimals != datetime_precision))
    {
        my_error(ER_INVALID_ON_UPDATE, MYF(0), field_name->str);
        DBUG_RETURN(1);
    }

    if (!(new_field= new Create_field()) ||
        new_field->init(thd, field_name->str, type, length, decimals, type_modifier,
        default_value, on_update_value, comment, change,
        interval_list, cs, uint_geom_type))
        DBUG_RETURN(1);

    lex->alter_info.create_list.push_back(new_field);
    lex->last_field=new_field;
    DBUG_RETURN(0);
}


/** Store position for column in ALTER TABLE .. ADD column. */

void store_position_for_column(const char *name)
{
    current_thd->lex->last_field->after=(char*) (name);
}


/**
save order by and tables in own lists.
*/

bool add_to_list(THD *thd, SQL_I_List<ORDER> &list, Item *item,bool asc)
{
    ORDER *order;
    DBUG_ENTER("add_to_list");
    if (!(order = (ORDER *) thd->alloc(sizeof(ORDER))))
        DBUG_RETURN(1);
    order->item_ptr= item;
    order->item= &order->item_ptr;
    order->direction= (asc ? ORDER::ORDER_ASC : ORDER::ORDER_DESC);
    order->used_alias= false;
    order->used=0;
    order->counter_used= 0;
    list.link_in_list(order, &order->next);
    DBUG_RETURN(0);
}


/**
Add a table to list of used tables.

@param table  Table to add
@param alias  alias for table (or null if no alias)
@param table_options A set of the following bits:
- TL_OPTION_UPDATING : Table will be updated
- TL_OPTION_FORCE_INDEX : Force usage of index
- TL_OPTION_ALIAS : an alias in multi table DELETE
@param lock_type How table should be locked
@param mdl_type       Type of metadata lock to acquire on the table.
@param use_index List of indexed used in USE INDEX
@param ignore_index List of indexed used in IGNORE INDEX

@retval
0  Error
@retval
\# Pointer to TABLE_LIST element added to the total table list
*/

TABLE_LIST *st_select_lex::add_table_to_list(THD *thd,
    Table_ident *table,
    LEX_STRING *alias,
    ulong table_options,
    thr_lock_type lock_type,
    enum_mdl_type mdl_type,
    List<Index_hint> *index_hints_arg,
    List<String> *partition_names,
    LEX_STRING *option)
{
    register TABLE_LIST *ptr;
    TABLE_LIST *previous_table_ref; /* The table preceding the current one. */
    char *alias_str;
    LEX *lex= thd->lex;
    DBUG_ENTER("add_table_to_list");
    LINT_INIT(previous_table_ref);

    if (!table)
        DBUG_RETURN(0);    // End of memory
    alias_str= alias ? alias->str : table->table.str;
    if (table->db.str == NULL)
    {
        if (thd->thd_sinfo->db[0] != '\0')
        {
            table->db.str = thd->thd_sinfo->db;
            table->db.length = strlen(thd->thd_sinfo->db);
        }
        else
        {
            my_error(ER_NO_DB_ERROR, MYF(0));
            DBUG_RETURN(0);
        }
    }

    if (!test(table_options & TL_OPTION_ALIAS))
    {
        enum_ident_name_check ident_check_status=
            check_table_name(table->table.str, table->table.length, FALSE);
        if (ident_check_status == IDENT_NAME_WRONG)
        {
            my_error(ER_WRONG_TABLE_NAME, MYF(0), table->table.str);
            DBUG_RETURN(0);
        }
        else if (ident_check_status == IDENT_NAME_TOO_LONG)
        {
            my_error(ER_TOO_LONG_IDENT, MYF(0), table->table.str);
            DBUG_RETURN(0);
        }
    }
    if (table->is_derived_table() == FALSE && table->db.str &&
        (check_and_convert_db_name(&table->db, FALSE) != IDENT_NAME_OK))
        DBUG_RETURN(0);

    if (!alias)     /* Alias is case sensitive */
    {
        if (table->sel)
        {
            my_message(ER_DERIVED_MUST_HAVE_ALIAS,
                ER(ER_DERIVED_MUST_HAVE_ALIAS), MYF(0));
            DBUG_RETURN(0);
        }
        if (!(alias_str= (char*) thd->memdup(alias_str,table->table.length+1)))
            DBUG_RETURN(0);
    }
    if (!(ptr = (TABLE_LIST *) thd->calloc(sizeof(TABLE_LIST))))
        DBUG_RETURN(0);    /* purecov: inspected */
    if (table->db.str)
    {
        ptr->is_fqtn= TRUE;
        ptr->db= table->db.str;
        ptr->db_length= table->db.length;
    }
    else if (lex->copy_db_to(&ptr->db, &ptr->db_length))
        DBUG_RETURN(0);
    else
        ptr->is_fqtn= FALSE;

    ptr->alias= alias_str;
    ptr->is_alias= alias ? TRUE : FALSE;
    if (lower_case_table_names && table->table.length)
        table->table.length= my_casedn_str(files_charset_info, table->table.str);
    ptr->table_name=table->table.str;
    ptr->table_name_length=table->table.length;
    ptr->lock_type=   lock_type;
    ptr->updating=    test(table_options & TL_OPTION_UPDATING);
    /* TODO: remove TL_OPTION_FORCE_INDEX as it looks like it's not used */
    ptr->force_index= test(table_options & TL_OPTION_FORCE_INDEX);
    ptr->ignore_leaves= test(table_options & TL_OPTION_IGNORE_LEAVES);
    ptr->derived=     table->sel;
    ptr->select_lex=  lex->current_select;
    ptr->cacheable_table= 1;
    ptr->index_hints= index_hints_arg;
    ptr->option= option ? option->str : 0;
    /* check that used name is unique */
    if (lock_type != TL_IGNORE)
    {
        TABLE_LIST *first_table= table_list.first;
        if (lex->sql_command == SQLCOM_CREATE_VIEW)
            first_table= first_table ? first_table->next_local : NULL;
        for (TABLE_LIST *tables= first_table ;
            tables ;
            tables=tables->next_local)
        {
            if (!my_strcasecmp(table_alias_charset, alias_str, tables->alias) &&
                !strcasecmp(ptr->db, tables->db))
            {
                my_error(ER_NONUNIQ_TABLE, MYF(0), alias_str); /* purecov: tested */
                DBUG_RETURN(0);    /* purecov: tested */
            }
        }
    }
    /* Store the table reference preceding the current one. */
    if (table_list.elements > 0)
    {
        /*
        table_list.next points to the last inserted TABLE_LIST->next_local'
        element
        We don't use the offsetof() macro here to avoid warnings from gcc
        */
        previous_table_ref= (TABLE_LIST*) ((char*) table_list.next -
            ((char*) &(ptr->next_local) -
            (char*) ptr));
        /*
        Set next_name_resolution_table of the previous table reference to point
        to the current table reference. In effect the list
        TABLE_LIST::next_name_resolution_table coincides with
        TABLE_LIST::next_local. Later this may be changed in
        store_top_level_join_columns() for NATURAL/USING joins.
        */
        previous_table_ref->next_name_resolution_table= ptr;
    }

    /*
    Link the current table reference in a local list (list for current select).
    Notice that as a side effect here we set the next_local field of the
    previous table reference to 'ptr'. Here we also add one element to the
    list 'table_list'.
    */
    table_list.link_in_list(ptr, &ptr->next_local);
    ptr->next_name_resolution_table= NULL;
#ifdef WITH_PARTITION_STORAGE_ENGINE
    ptr->partition_names= partition_names;
#endif /* WITH_PARTITION_STORAGE_ENGINE */
    /* Link table in global list (all used tables) */
    lex->add_to_query_tables(ptr);

    // Pure table aliases do not need to be locked:
    if (!test(table_options & TL_OPTION_ALIAS))
    {
        ptr->mdl_request.init(MDL_key::TABLE, ptr->db, ptr->table_name, mdl_type,
            MDL_TRANSACTION);
    }
    if (table->is_derived_table())
    {
        ptr->effective_algorithm= DERIVED_ALGORITHM_TMPTABLE;
        ptr->derived_key_list.empty();
    }
    DBUG_RETURN(ptr);
}


/**
Initialize a new table list for a nested join.

The function initializes a structure of the TABLE_LIST type
for a nested join. It sets up its nested join list as empty.
The created structure is added to the front of the current
join list in the st_select_lex object. Then the function
changes the current nest level for joins to refer to the newly
created empty list after having saved the info on the old level
in the initialized structure.

@param thd         current thread

@retval
0   if success
@retval
1   otherwise
*/

bool st_select_lex::init_nested_join(THD *thd)
{
    TABLE_LIST *ptr;
    NESTED_JOIN *nested_join;
    DBUG_ENTER("init_nested_join");

    if (!(ptr= (TABLE_LIST*) thd->calloc(ALIGN_SIZE(sizeof(TABLE_LIST))+
        sizeof(NESTED_JOIN))))
        DBUG_RETURN(1);
    nested_join= ptr->nested_join=
        ((NESTED_JOIN*) ((uchar*) ptr + ALIGN_SIZE(sizeof(TABLE_LIST))));

    join_list->push_front(ptr);
    ptr->embedding= embedding;
    ptr->join_list= join_list;
    ptr->alias= (char*) "(nested_join)";
    embedding= ptr;
    join_list= &nested_join->join_list;
    join_list->empty();
    DBUG_RETURN(0);
}


/**
End a nested join table list.

The function returns to the previous join nest level.
If the current level contains only one member, the function
moves it one level up, eliminating the nest.

@param thd         current thread

@return
- Pointer to TABLE_LIST element added to the total table list, if success
- 0, otherwise
*/

TABLE_LIST *st_select_lex::end_nested_join(THD *thd)
{
    TABLE_LIST *ptr;
    NESTED_JOIN *nested_join;
    DBUG_ENTER("end_nested_join");

    DBUG_ASSERT(embedding);
    ptr= embedding;
    join_list= ptr->join_list;
    embedding= ptr->embedding;
    nested_join= ptr->nested_join;
    if (nested_join->join_list.elements == 1)
    {
        TABLE_LIST *embedded= nested_join->join_list.head();
        join_list->pop();
        embedded->join_list= join_list;
        embedded->embedding= embedding;
        join_list->push_front(embedded);
        ptr= embedded;
    }
    else if (nested_join->join_list.elements == 0)
    {
        join_list->pop();
        ptr= 0;                                     // return value
    }
    DBUG_RETURN(ptr);
}


/**
Nest last join operation.

The function nest last join operation as if it was enclosed in braces.

@param thd         current thread

@retval
0  Error
@retval
\#  Pointer to TABLE_LIST element created for the new nested join
*/

TABLE_LIST *st_select_lex::nest_last_join(THD *thd)
{
    TABLE_LIST *ptr;
    NESTED_JOIN *nested_join;
    List<TABLE_LIST> *embedded_list;
    DBUG_ENTER("nest_last_join");

    if (!(ptr= (TABLE_LIST*) thd->calloc(ALIGN_SIZE(sizeof(TABLE_LIST))+
        sizeof(NESTED_JOIN))))
        DBUG_RETURN(0);
    nested_join= ptr->nested_join=
        ((NESTED_JOIN*) ((uchar*) ptr + ALIGN_SIZE(sizeof(TABLE_LIST))));

    ptr->embedding= embedding;
    ptr->join_list= join_list;
    ptr->alias= (char*) "(nest_last_join)";
    embedded_list= &nested_join->join_list;
    embedded_list->empty();

    for (uint i=0; i < 2; i++)
    {
        TABLE_LIST *table= join_list->pop();
        table->join_list= embedded_list;
        table->embedding= ptr;
        embedded_list->push_back(table);
        if (table->natural_join)
        {
            ptr->is_natural_join= TRUE;
            /*
            If this is a JOIN ... USING, move the list of joined fields to the
            table reference that describes the join.
            */
            if (prev_join_using)
                ptr->join_using_fields= prev_join_using;
        }
    }
    join_list->push_front(ptr);
    nested_join->used_tables= nested_join->not_null_tables= (table_map) 0;
    DBUG_RETURN(ptr);
}


/**
Add a table to the current join list.

The function puts a table in front of the current join list
of st_select_lex object.
Thus, joined tables are put into this list in the reverse order
(the most outer join operation follows first).

@param table       the table to add

@return
None
*/

void st_select_lex::add_joined_table(TABLE_LIST *table)
{
    DBUG_ENTER("add_joined_table");
    join_list->push_front(table);
    table->join_list= join_list;
    table->embedding= embedding;
    DBUG_VOID_RETURN;
}


/**
Convert a right join into equivalent left join.

The function takes the current join list t[0],t[1] ... and
effectively converts it into the list t[1],t[0] ...
Although the outer_join flag for the new nested table contains
JOIN_TYPE_RIGHT, it will be handled as the inner table of a left join
operation.

EXAMPLES
@verbatim
SELECT * FROM t1 RIGHT JOIN t2 ON on_expr =>
SELECT * FROM t2 LEFT JOIN t1 ON on_expr

SELECT * FROM t1,t2 RIGHT JOIN t3 ON on_expr =>
SELECT * FROM t1,t3 LEFT JOIN t2 ON on_expr

SELECT * FROM t1,t2 RIGHT JOIN (t3,t4) ON on_expr =>
SELECT * FROM t1,(t3,t4) LEFT JOIN t2 ON on_expr

SELECT * FROM t1 LEFT JOIN t2 ON on_expr1 RIGHT JOIN t3  ON on_expr2 =>
SELECT * FROM t3 LEFT JOIN (t1 LEFT JOIN t2 ON on_expr2) ON on_expr1
@endverbatim

@param thd         current thread

@return
- Pointer to the table representing the inner table, if success
- 0, otherwise
*/

TABLE_LIST *st_select_lex::convert_right_join()
{
    TABLE_LIST *tab2= join_list->pop();
    TABLE_LIST *tab1= join_list->pop();
    DBUG_ENTER("convert_right_join");

    join_list->push_front(tab2);
    join_list->push_front(tab1);
    tab1->outer_join|= JOIN_TYPE_RIGHT;

    DBUG_RETURN(tab1);
}

/**
Set lock for all tables in current select level.

@param lock_type   Lock to set for tables

@note
If lock is a write lock, then tables->updating is set 1
This is to get tables_ok to know that the table is updated by the
query
*/

void st_select_lex::set_lock_for_tables(thr_lock_type lock_type)
{
    bool for_update= lock_type >= TL_READ_NO_INSERT;
    DBUG_ENTER("set_lock_for_tables");
    DBUG_PRINT("enter", ("lock_type: %d  for_update: %d", lock_type,
        for_update));
    for (TABLE_LIST *tables= table_list.first;
        tables;
        tables= tables->next_local)
    {
        tables->lock_type= lock_type;
        tables->updating=  for_update;
        tables->mdl_request.set_type((lock_type >= TL_WRITE_ALLOW_WRITE) ?
MDL_SHARED_WRITE : MDL_SHARED_READ);
    }
    DBUG_VOID_RETURN;
}


/**
Create a fake SELECT_LEX for a unit.

The method create a fake SELECT_LEX object for a unit.
This object is created for any union construct containing a union
operation and also for any single select union construct of the form
@verbatim
(SELECT ... ORDER BY order_list [LIMIT n]) ORDER BY ...
@endvarbatim
or of the form
@varbatim
(SELECT ... ORDER BY LIMIT n) ORDER BY ...
@endvarbatim

@param thd_arg     thread handle

@note
The object is used to retrieve rows from the temporary table
where the result on the union is obtained.

@retval
1     on failure to create the object
@retval
0     on success
*/

bool st_select_lex_unit::add_fake_select_lex(THD *thd_arg)
{
    SELECT_LEX *first_sl= first_select();
    DBUG_ENTER("add_fake_select_lex");
    DBUG_ASSERT(!fake_select_lex);

    if (!(fake_select_lex= new (thd_arg->mem_root) SELECT_LEX()))
        DBUG_RETURN(1);
    fake_select_lex->include_standalone(this,
        (SELECT_LEX_NODE**)&fake_select_lex);
    fake_select_lex->select_number= INT_MAX;
    fake_select_lex->parent_lex= thd_arg->lex; /* Used in init_query. */
    fake_select_lex->make_empty_select();
    fake_select_lex->linkage= GLOBAL_OPTIONS_TYPE;
    fake_select_lex->select_limit= 0;

    fake_select_lex->context.outer_context=first_sl->context.outer_context;
    /* allow item list resolving in fake select for ORDER BY */
    fake_select_lex->context.resolve_in_select_list= TRUE;
    fake_select_lex->context.select_lex= fake_select_lex;

    if (!is_union())
    {
        /*
        This works only for
        (SELECT ... ORDER BY list [LIMIT n]) ORDER BY order_list [LIMIT m],
        (SELECT ... LIMIT n) ORDER BY order_list [LIMIT m]
        just before the parser starts processing order_list
        */
        global_parameters= fake_select_lex;
        fake_select_lex->no_table_names_allowed= 1;
        thd_arg->lex->current_select= fake_select_lex;
    }
    thd_arg->lex->pop_context();
    DBUG_RETURN(0);
}


/**
Push a new name resolution context for a JOIN ... ON clause to the
context stack of a query block.

Create a new name resolution context for a JOIN ... ON clause,
set the first and last leaves of the list of table references
to be used for name resolution, and push the newly created
context to the stack of contexts of the query.

@param thd       pointer to current thread
@param left_op   left  operand of the JOIN
@param right_op  rigth operand of the JOIN

@retval
FALSE  if all is OK
@retval
TRUE   if a memory allocation error occured
*/

bool
    push_new_name_resolution_context(THD *thd,
    TABLE_LIST *left_op, TABLE_LIST *right_op)
{
    Name_resolution_context *on_context;
    if (!(on_context= new (thd->mem_root) Name_resolution_context))
        return TRUE;
    on_context->init();
    on_context->first_name_resolution_table=
        left_op->first_leaf_for_name_resolution();
    on_context->last_name_resolution_table=
        right_op->last_leaf_for_name_resolution();
    on_context->select_lex= thd->lex->current_select;
    return thd->lex->push_context(on_context);
}


/**
Add an ON condition to the second operand of a JOIN ... ON.

Add an ON condition to the right operand of a JOIN ... ON clause.

@param b     the second operand of a JOIN ... ON
@param expr  the condition to be added to the ON clause
*/

void add_join_on(TABLE_LIST *b, Item *expr)
{
    if (expr)
    {
        if (!b->join_cond())
            b->set_join_cond(expr);
        else
        {
            /*
            If called from the parser, this happens if you have both a
            right and left join. If called later, it happens if we add more
            than one condition to the ON clause.
            */
            b->set_join_cond(new Item_cond_and(b->join_cond(), expr));
        }
        b->join_cond()->top_level_item();
    }
}


/**
Mark that there is a NATURAL JOIN or JOIN ... USING between two
tables.

This function marks that table b should be joined with a either via
a NATURAL JOIN or via JOIN ... USING. Both join types are special
cases of each other, so we treat them together. The function
setup_conds() creates a list of equal condition between all fields
of the same name for NATURAL JOIN or the fields in 'using_fields'
for JOIN ... USING. The list of equality conditions is stored
either in b->join_cond(), or in JOIN::conds, depending on whether there
was an outer join.

EXAMPLE
@verbatim
SELECT * FROM t1 NATURAL LEFT JOIN t2
<=>
SELECT * FROM t1 LEFT JOIN t2 ON (t1.i=t2.i and t1.j=t2.j ... )

SELECT * FROM t1 NATURAL JOIN t2 WHERE <some_cond>
<=>
SELECT * FROM t1, t2 WHERE (t1.i=t2.i and t1.j=t2.j and <some_cond>)

SELECT * FROM t1 JOIN t2 USING(j) WHERE <some_cond>
<=>
SELECT * FROM t1, t2 WHERE (t1.j=t2.j and <some_cond>)
@endverbatim

@param a    Left join argument
@param b    Right join argument
@param using_fields    Field names from USING clause
*/

void add_join_natural(TABLE_LIST *a, TABLE_LIST *b, List<String> *using_fields,
    SELECT_LEX *lex)
{
    b->natural_join= a;
    lex->prev_join_using= using_fields;
}


/**
kill on thread.

@param thd   Thread class
@param id   Thread id
@param only_kill_query        Should it kill the query or the connection

@note
This is written such that we have a short lock on LOCK_thread_count
*/

uint kill_one_thread(THD *thd, ulong id, bool only_kill_query)
{
    THD *tmp= NULL;
    uint error=ER_NO_SUCH_THREAD;
    DBUG_ENTER("kill_one_thread");
    DBUG_PRINT("enter", ("id=%lu only_kill=%d", id, only_kill_query));

    mysql_mutex_lock(&LOCK_thread_count);
    Thread_iterator it= global_thread_list_begin();
    Thread_iterator end= global_thread_list_end();
    for (; it != end; ++it)
    {
        if ((*it)->get_command() == COM_DAEMON)
            continue;
        if ((*it)->thread_id == id)
        {
            tmp= *it;
            mysql_mutex_lock(&tmp->LOCK_thd_data);    // Lock from delete
            break;
        }
    }
    mysql_mutex_unlock(&LOCK_thread_count);
    if (tmp)
    {

        /*
        If we're SUPER, we can KILL anything, including system-threads.
        No further checks.

        KILLer: thd->security_ctx->user could in theory be NULL while
        we're still in "unauthenticated" state. This is a theoretical
        case (the code suggests this could happen, so we play it safe).

        KILLee: tmp->security_ctx->user will be NULL for system threads.
        We need to check so Jane Random User doesn't crash the server
        when trying to kill a) system threads or b) unauthenticated users'
        threads (Bug#43748).

        If user of both killer and killee are non-NULL, proceed with
        slayage if both are string-equal.
        */

        if ((thd->security_ctx->master_access & SUPER_ACL) ||
            thd->security_ctx->user_matches(tmp->security_ctx))
        {
            /* process the kill only if thread is not already undergoing any kill
            connection.
            */
            if (tmp->killed != THD::KILL_CONNECTION)
            {
                tmp->awake(only_kill_query ? THD::KILL_QUERY : THD::KILL_CONNECTION);
            }
            error= 0;
        }
        else
            error=ER_KILL_DENIED_ERROR;
        mysql_mutex_unlock(&tmp->LOCK_thd_data);
    }
    DBUG_PRINT("exit", ("%d", error));
    DBUG_RETURN(error);
}


/*
kills a thread and sends response

SYNOPSIS
sql_kill()
thd   Thread class
id   Thread id
only_kill_query     Should it kill the query or the connection
*/


/** If pointer is not a null pointer, append filename to it. */

bool append_file_to_dir(THD *thd, const char **filename_ptr,
    const char *table_name)
{
    char buff[FN_REFLEN],*ptr, *end;
    if (!*filename_ptr)
        return 0;     // nothing to do

    /* Check that the filename is not too long and it's a hard path */
    if (strlen(*filename_ptr)+strlen(table_name) >= FN_REFLEN-1 ||
        !test_if_hard_path(*filename_ptr))
    {
        my_error(ER_WRONG_TABLE_NAME, MYF(0), *filename_ptr);
        return 1;
    }
    /* Fix is using unix filename format on dos */
    strmov(buff,*filename_ptr);
    end=convert_dirname(buff, *filename_ptr, NullS);
    if (!(ptr= (char*) thd->alloc((size_t) (end-buff) + strlen(table_name)+1)))
        return 1;     // End of memory
    *filename_ptr=ptr;
    strxmov(ptr,buff,table_name,NullS);
    return 0;
}


/**
Check if the select is a simple select (not an union).

@retval
0 ok
@retval
1 error ; In this case the error messege is sent to the client
*/

bool check_simple_select()
{
    THD *thd= current_thd;
    LEX *lex= thd->lex;
    if (lex->current_select != &lex->select_lex)
    {
        char command[80];
        Lex_input_stream *lip= & thd->m_parser_state->m_lip;
        strmake(command, lip->yylval->symbol.str,
            min<size_t>(lip->yylval->symbol.length, sizeof(command)-1));
        my_error(ER_CANT_USE_OPTION_HERE, MYF(0), command);
        return 1;
    }
    return 0;
}


Comp_creator *comp_eq_creator(bool invert)
{
    return invert?(Comp_creator *)&ne_creator:(Comp_creator *)&eq_creator;
}


Comp_creator *comp_ge_creator(bool invert)
{
    return invert?(Comp_creator *)&lt_creator:(Comp_creator *)&ge_creator;
}


Comp_creator *comp_gt_creator(bool invert)
{
    return invert?(Comp_creator *)&le_creator:(Comp_creator *)&gt_creator;
}


Comp_creator *comp_le_creator(bool invert)
{
    return invert?(Comp_creator *)&gt_creator:(Comp_creator *)&le_creator;
}


Comp_creator *comp_lt_creator(bool invert)
{
    return invert?(Comp_creator *)&ge_creator:(Comp_creator *)&lt_creator;
}


Comp_creator *comp_ne_creator(bool invert)
{
    return invert?(Comp_creator *)&eq_creator:(Comp_creator *)&ne_creator;
}


/**
Construct ALL/ANY/SOME subquery Item.

@param left_expr   pointer to left expression
@param cmp         compare function creator
@param all         true if we create ALL subquery
@param select_lex  pointer on parsed subquery structure

@return
constructed Item (or 0 if out of memory)
*/
Item * all_any_subquery_creator(Item *left_expr,
    chooser_compare_func_creator cmp,
    bool all,
    SELECT_LEX *select_lex)
{
    if ((cmp == &comp_eq_creator) && !all)       //  = ANY <=> IN
        return new Item_in_subselect(left_expr, select_lex);

    if ((cmp == &comp_ne_creator) && all)        // <> ALL <=> NOT IN
        return new Item_func_not(new Item_in_subselect(left_expr, select_lex));

    Item_allany_subselect *it=
        new Item_allany_subselect(left_expr, cmp, select_lex, all);
    if (all)
        return it->upper_item= new Item_func_not_all(it); /* ALL */

    return it->upper_item= new Item_func_nop_all(it);      /* ANY/SOME */
}


/**
Multi update query pre-check.

@param thd  Thread handler
@param tables Global/local table list (have to be the same)

@retval
FALSE OK
@retval
TRUE  Error
*/

bool multi_update_precheck(THD *thd, TABLE_LIST *tables)
{
    const char *msg= 0;
    TABLE_LIST *table;
    LEX *lex= thd->lex;
    SELECT_LEX *select_lex= &lex->select_lex;
    DBUG_ENTER("multi_update_precheck");

    if (select_lex->item_list.elements != lex->value_list.elements)
    {
        my_message(ER_WRONG_VALUE_COUNT, ER(ER_WRONG_VALUE_COUNT), MYF(0));
        DBUG_RETURN(TRUE);
    }
    /*
    Ensure that we have UPDATE or SELECT privilege for each table
    The exact privilege is checked in mysql_multi_update()
    */
    for (table= tables; table; table= table->next_local)
    {
        //     if (table->derived)
        //       table->grant.privilege= SELECT_ACL;
        //     else if ((check_access(thd, UPDATE_ACL, table->db,
        //                            &table->grant.privilege,
        //                            &table->grant.m_internal,
        //                            0, 1) ||
        //               check_grant(thd, UPDATE_ACL, table, FALSE, 1, TRUE)) &&
        //              (check_access(thd, SELECT_ACL, table->db,
        //                            &table->grant.privilege,
        //                            &table->grant.m_internal,
        //                            0, 0) ||
        //               check_grant(thd, SELECT_ACL, table, FALSE, 1, FALSE)))
        //       DBUG_RETURN(TRUE);

        table->table_in_first_from_clause= 1;
    }
    /*
    Is there tables of subqueries?
    */
    if (select_lex->order_list.elements)
        msg= "ORDER BY";
    else if (select_lex->select_limit)
        msg= "LIMIT";
    if (msg)
    {
        my_error(ER_WRONG_USAGE, MYF(0), "UPDATE", msg);
        DBUG_RETURN(TRUE);
    }
    DBUG_RETURN(FALSE);
}

/**
Multi delete query pre-check.

@param thd   Thread handler
@param tables  Global/local table list

@retval
FALSE OK
@retval
TRUE  error
*/

bool multi_delete_precheck(THD *thd, TABLE_LIST *tables)
{
    SELECT_LEX *select_lex= &thd->lex->select_lex;
    TABLE_LIST *aux_tables= thd->lex->auxiliary_table_list.first;
    TABLE_LIST **save_query_tables_own_last= thd->lex->query_tables_own_last;
    DBUG_ENTER("multi_delete_precheck");

    /*
    Temporary tables are pre-opened in 'tables' list only. Here we need to
    initialize TABLE instances in 'aux_tables' list.
    */
    for (TABLE_LIST *tl= aux_tables; tl; tl= tl->next_global)
    {
        if (tl->table)
            continue;

        if (tl->correspondent_table)
            tl->table= tl->correspondent_table->table;
    }

    /* sql_yacc guarantees that tables and aux_tables are not zero */
    DBUG_ASSERT(aux_tables != 0);
    /*
    Since aux_tables list is not part of LEX::query_tables list we
    have to juggle with LEX::query_tables_own_last value to be able
    call check_table_access() safely.
    */
    thd->lex->query_tables_own_last= 0;
    thd->lex->query_tables_own_last= save_query_tables_own_last;

    if ((thd->variables.option_bits & OPTION_SAFE_UPDATES) && !select_lex->where)
    {
        my_message(ER_UPDATE_WITHOUT_KEY_IN_SAFE_MODE,
            ER(ER_UPDATE_WITHOUT_KEY_IN_SAFE_MODE), MYF(0));
        DBUG_RETURN(TRUE);
    }
    DBUG_RETURN(FALSE);
}


/*
Given a table in the source list, find a correspondent table in the
table references list.

@param lex Pointer to LEX representing multi-delete.
@param src Source table to match.
@param ref Table references list.

@remark The source table list (tables listed before the FROM clause
or tables listed in the FROM clause before the USING clause) may
contain table names or aliases that must match unambiguously one,
and only one, table in the target table list (table references list,
after FROM/USING clause).

@return Matching table, NULL otherwise.
*/

static TABLE_LIST *multi_delete_table_match(LEX *lex, TABLE_LIST *tbl,
    TABLE_LIST *tables)
{
    TABLE_LIST *match= NULL;
    DBUG_ENTER("multi_delete_table_match");

    for (TABLE_LIST *elem= tables; elem; elem= elem->next_local)
    {
        int cmp;

        if (tbl->is_fqtn && elem->is_alias)
            continue; /* no match */
        if (tbl->is_fqtn && elem->is_fqtn)
            cmp= my_strcasecmp(table_alias_charset, tbl->table_name, elem->table_name) ||
            strcmp(tbl->db, elem->db);
        else if (elem->is_alias)
            cmp= my_strcasecmp(table_alias_charset, tbl->alias, elem->alias);
        else
            cmp= my_strcasecmp(table_alias_charset, tbl->table_name, elem->table_name) ||
            strcmp(tbl->db, elem->db);

        if (cmp)
            continue;

        if (match)
        {
            my_error(ER_NONUNIQ_TABLE, MYF(0), elem->alias);
            DBUG_RETURN(NULL);
        }

        match= elem;
    }

    if (!match)
        my_error(ER_UNKNOWN_TABLE, MYF(0), tbl->table_name, "MULTI DELETE");

    DBUG_RETURN(match);
}


/**
Link tables in auxilary table list of multi-delete with corresponding
elements in main table list, and set proper locks for them.

@param lex   pointer to LEX representing multi-delete

@retval
FALSE   success
@retval
TRUE    error
*/

bool multi_delete_set_locks_and_link_aux_tables(LEX *lex)
{
    TABLE_LIST *tables= lex->select_lex.table_list.first;
    TABLE_LIST *target_tbl;
    DBUG_ENTER("multi_delete_set_locks_and_link_aux_tables");

    for (target_tbl= lex->auxiliary_table_list.first;
        target_tbl; target_tbl= target_tbl->next_local)
    {
        /* All tables in aux_tables must be found in FROM PART */
        TABLE_LIST *walk= multi_delete_table_match(lex, target_tbl, tables);
        if (!walk)
            DBUG_RETURN(TRUE);
        if (!walk->derived)
        {
            target_tbl->table_name= walk->table_name;
            target_tbl->table_name_length= walk->table_name_length;
        }
        walk->updating= target_tbl->updating;
        walk->lock_type= target_tbl->lock_type;
        /* We can assume that tables to be deleted from are locked for write. */
        DBUG_ASSERT(walk->lock_type >= TL_WRITE_ALLOW_WRITE);
        walk->mdl_request.set_type(MDL_SHARED_WRITE);
        target_tbl->correspondent_table= walk; // Remember corresponding table
    }
    DBUG_RETURN(FALSE);
}

/**
Set proper open mode and table type for element representing target table
of CREATE TABLE statement, also adjust statement table list if necessary.
*/

void create_table_set_open_action_and_adjust_tables(LEX *lex)
{
    TABLE_LIST *create_table= lex->query_tables;

    if (lex->create_info.options & HA_LEX_CREATE_TMP_TABLE)
        create_table->open_type= OT_TEMPORARY_ONLY;
    else
        create_table->open_type= OT_BASE_ONLY;

    if (!lex->select_lex.item_list.elements)
    {
        /*
        Avoid opening and locking target table for ordinary CREATE TABLE
        or CREATE TABLE LIKE for write (unlike in CREATE ... SELECT we
        won't do any insertions in it anyway). Not doing this causes
        problems when running CREATE TABLE IF NOT EXISTS for already
        existing log table.
        */
        create_table->lock_type= TL_READ;
    }
}

/**
negate given expression.

@param thd  thread handler
@param expr expression for negation

@return
negated expression
*/

Item *negate_expression(THD *thd, Item *expr)
{
    Item *negated;
    if (expr->type() == Item::FUNC_ITEM &&
        ((Item_func *) expr)->functype() == Item_func::NOT_FUNC)
    {
        /* it is NOT(NOT( ... )) */
        Item *arg= ((Item_func *) expr)->arguments()[0];
        enum_parsing_place place= thd->lex->current_select->parsing_place;
        if (arg->is_bool_func() || place == IN_WHERE || place == IN_HAVING)
            return arg;
        /*
        if it is not boolean function then we have to emulate value of
        not(not(a)), it will be a != 0
        */
        return new Item_func_ne(arg, new Item_int_0());
    }

    if ((negated= expr->neg_transformer(thd)) != 0)
        return negated;
    return new Item_func_not(expr);
}

/**
Set the specified definer to the default value, which is the
current user in the thread.

@param[in]  thd       thread handler
@param[out] definer   definer
*/

void get_default_definer(THD *thd, LEX_USER *definer)
{
    const Security_context *sctx= thd->security_ctx;

    definer->user.str= (char *) sctx->priv_user;
    definer->user.length= strlen(definer->user.str);

    definer->host.str= (char *) sctx->priv_host;
    definer->host.length= strlen(definer->host.str);

    definer->password= null_lex_str;
    definer->plugin= empty_lex_str;
    definer->auth= empty_lex_str;
    definer->uses_identified_with_clause= false;
    definer->uses_identified_by_clause= false;
    definer->uses_authentication_string_clause= false;
    definer->uses_identified_by_password_clause= false;
}


/**
Create default definer for the specified THD.

@param[in] thd         thread handler

@return
- On success, return a valid pointer to the created and initialized
LEX_USER, which contains definer information.
- On error, return 0.
*/

LEX_USER *create_default_definer(THD *thd)
{
    LEX_USER *definer;

    if (! (definer= (LEX_USER*) thd->alloc(sizeof(LEX_USER))))
        return 0;

    thd->get_definer(definer);

    return definer;
}


/**
Create definer with the given user and host names.

@param[in] thd          thread handler
@param[in] user_name    user name
@param[in] host_name    host name

@return
- On success, return a valid pointer to the created and initialized
LEX_USER, which contains definer information.
- On error, return 0.
*/

LEX_USER *create_definer(THD *thd, LEX_STRING *user_name, LEX_STRING *host_name)
{
    LEX_USER *definer;

    /* Create and initialize. */

    if (! (definer= (LEX_USER*) thd->alloc(sizeof(LEX_USER))))
        return 0;

    definer->user= *user_name;
    definer->host= *host_name;
    definer->password.str= NULL;
    definer->password.length= 0;
    definer->uses_authentication_string_clause= false;
    definer->uses_identified_by_clause= false;
    definer->uses_identified_by_password_clause= false;
    definer->uses_identified_with_clause= false;
    return definer;
}


/**
Retuns information about user or current user.

@param[in] thd          thread handler
@param[in] user         user

@return
- On success, return a valid pointer to initialized
LEX_USER, which contains user information.
- On error, return 0.
*/

LEX_USER *get_current_user(THD *thd, LEX_USER *user)
{
    if (!user->user.str)  // current_user
    {
        LEX_USER *default_definer= create_default_definer(thd);
        if (default_definer)
        {
            /*
            Inherit parser semantics from the statement in which the user parameter
            was used.
            This is needed because a st_lex_user is both used as a component in an
            AST and as a specifier for a particular user in the ACL subsystem.
            */
            default_definer->uses_authentication_string_clause=
                user->uses_authentication_string_clause;
            default_definer->uses_identified_by_clause=
                user->uses_identified_by_clause;
            default_definer->uses_identified_by_password_clause=
                user->uses_identified_by_password_clause;
            default_definer->uses_identified_with_clause=
                user->uses_identified_with_clause;
            default_definer->plugin.str= user->plugin.str;
            default_definer->plugin.length= user->plugin.length;
            default_definer->auth.str= user->auth.str;
            default_definer->auth.length= user->auth.length;
            return default_definer;
        }
    }

    return user;
}


/**
Check that byte length of a string does not exceed some limit.

@param str         string to be checked
@param err_msg     error message to be displayed if the string is too long
@param max_length  max length

@retval
FALSE   the passed string is not longer than max_length
@retval
TRUE    the passed string is longer than max_length

NOTE
The function is not used in existing code but can be useful later?
*/

bool check_string_byte_length(LEX_STRING *str, const char *err_msg,
    uint max_byte_length)
{
    if (str->length <= max_byte_length)
        return FALSE;

    my_error(ER_WRONG_STRING_LENGTH, MYF(0), str->str, err_msg, max_byte_length);

    return TRUE;
}


/*
Check that char length of a string does not exceed some limit.

SYNOPSIS
check_string_char_length()
str              string to be checked
err_msg          error message to be displayed if the string is too long
max_char_length  max length in symbols
cs               string charset

RETURN
FALSE   the passed string is not longer than max_char_length
TRUE    the passed string is longer than max_char_length
*/


bool check_string_char_length(LEX_STRING *str, const char *err_msg,
    uint max_char_length, const CHARSET_INFO *cs,
    bool no_error)
{
    int well_formed_error;
    uint res= cs->cset->well_formed_len(cs, str->str, str->str + str->length,
        max_char_length, &well_formed_error);

    if (!well_formed_error &&  str->length == res)
        return FALSE;

    if (!no_error)
    {
        ErrConvString err(str->str, str->length, cs);
        my_error(ER_WRONG_STRING_LENGTH, MYF(0), err.ptr(), err_msg, max_char_length);
    }
    return TRUE;
}

bool check_string_char_with_length(char* str, size_t length, const char *err_msg,
    uint max_char_length, const CHARSET_INFO *cs,
    bool no_error)
{
    int well_formed_error;
    uint res= cs->cset->well_formed_len(cs, str, str + length,
        max_char_length, &well_formed_error);

    if (!well_formed_error &&  length == res)
        return FALSE;

    if (!no_error)
    {
        ErrConvString err(str, length, cs);
        my_error(ER_WRONG_STRING_LENGTH, MYF(0), err.ptr(), err_msg, max_char_length);
    }
    return TRUE;
}


/**
Check that host name string is valid.

@param[in] str string to be checked

@return             Operation status
@retval  FALSE    host name is ok
@retval  TRUE     host name string is longer than max_length or
has invalid symbols
*/

bool check_host_name(LEX_STRING *str)
{
    const char *name= str->str;
    const char *end= str->str + str->length;
    if (check_string_byte_length(str, ER(ER_HOSTNAME), HOSTNAME_LENGTH))
        return TRUE;

    while (name != end)
    {
        if (*name == '@')
        {
            my_printf_error(ER_UNKNOWN_ERROR,
                "Malformed hostname (illegal symbol: '%c')", MYF(0),
                *name);
            return TRUE;
        }
        name++;
    }
    return FALSE;
}


extern int MYSQLparse(void *thd); // from sql_yacc.cc


/**
This is a wrapper of MYSQLparse(). All the code should call parse_sql()
instead of MYSQLparse().

@param thd Thread context.
@param parser_state Parser state.
@param creation_ctx Object creation context.

@return Error status.
@retval FALSE on success.
@retval TRUE on parsing error.
*/

bool parse_sql(THD *thd,
    Parser_state *parser_state,
    Object_creation_ctx *creation_ctx)
{
    bool ret_value;
    DBUG_ASSERT(thd->m_parser_state == NULL);
    DBUG_ASSERT(thd->lex->m_sql_cmd == NULL);

    MYSQL_QUERY_PARSE_START(thd->query());
    /* Backup creation context. */

    Object_creation_ctx *backup_ctx= NULL;

    if (creation_ctx)
        backup_ctx= creation_ctx->set_n_backup(thd);

    /* Set parser state. */

    thd->m_parser_state= parser_state;

#ifdef HAVE_PSI_STATEMENT_DIGEST_INTERFACE
    /* Start Digest */
    thd->m_parser_state->m_lip.m_digest_psi= MYSQL_DIGEST_START(thd->m_statement_psi);
#endif

    /* Parse the query. */

    bool mysql_parse_status= MYSQLparse(thd) != 0;

    /*
    Check that if MYSQLparse() failed either thd->is_error() is set, or an
    internal error handler is set.

    The assert will not catch a situation where parsing fails without an
    error reported if an error handler exists. The problem is that the
    error handler might have intercepted the error, so thd->is_error() is
    not set. However, there is no way to be 100% sure here (the error
    handler might be for other errors than parsing one).
    */

    DBUG_ASSERT(!mysql_parse_status ||
        (mysql_parse_status && thd->is_error()) ||
        (mysql_parse_status && thd->get_internal_handler()));

    if (mysql_parse_status &&
        strncasecmp(thd->m_parser_state->m_lip.get_tok_start(),
                    INCEPTION_COMMIT, INCEPTION_COMMIT_LEN) == 0)
    {
        thd->clear_error();
        my_error(ER_END_WITH_SEMICOLON, MYF(0));
    }

    /* Reset parser state. */
    thd->m_parser_state= NULL;

    if (creation_ctx)
        creation_ctx->restore_env(thd, backup_ctx);

    /* That's it. */

    ret_value= mysql_parse_status || thd->is_fatal_error;
    MYSQL_QUERY_PARSE_DONE(ret_value);
    return ret_value;
}

/**
@} (end of group Runtime_Environment)
*/



/**
Check and merge "CHARACTER SET cs [ COLLATE cl ]" clause

@param cs character set pointer.
@param cl collation pointer.

Check if collation "cl" is applicable to character set "cs".

If "cl" is NULL (e.g. when COLLATE clause is not specified),
then simply "cs" is returned.

@return Error status.
@retval NULL, if "cl" is not applicable to "cs".
@retval pointer to merged CHARSET_INFO on success.
*/


const CHARSET_INFO*
    merge_charset_and_collation(const CHARSET_INFO *cs, const CHARSET_INFO *cl)
{
    if (cl)
    {
        if (!my_charset_same(cs, cl))
        {
            my_error(ER_COLLATION_CHARSET_MISMATCH, MYF(0), cl->name, cs->csname);
            return NULL;
        }
        return cl;
    }
    return cs;
}

void append_definer(THD *thd, String *buffer, const LEX_STRING *definer_user,
    const LEX_STRING *definer_host)
{
    buffer->append(STRING_WITH_LEN("DEFINER="));
    append_identifier(thd, buffer, definer_user->str, definer_user->length);
    buffer->append('@');
    append_identifier(thd, buffer, definer_host->str, definer_host->length);
    buffer->append(' ');
}

static const char *require_quotes(const char *name, uint name_length)
{
    uint length;
    bool pure_digit= TRUE;
    const char *end= name + name_length;

    for (; name < end ; name++)
    {
        uchar chr= (uchar) *name;
        length= my_mbcharlen(system_charset_info, chr);
        if (length == 1 && !system_charset_info->ident_map[chr])
            return name;
        if (length == 1 && (chr < '0' || chr > '9'))
            pure_digit= FALSE;
    }
    if (pure_digit)
        return name;
    return 0;
}

int get_quote_char_for_identifier(THD *thd, const char *name, uint length)
{
    if (length &&
        !is_keyword(name,length) &&
        !require_quotes(name, length) &&
        !(thd->variables.option_bits & OPTION_QUOTE_SHOW_CREATE))
        return EOF;
    if (thd->variables.sql_mode & MODE_ANSI_QUOTES)
        return '"';
    return '`';
}

int wild_case_compare(CHARSET_INFO *cs, const char *str,const char *wildstr)
{
    reg3 int flag;
    DBUG_ENTER("wild_case_compare");
    DBUG_PRINT("enter",("str: '%s'  wildstr: '%s'",str,wildstr));
    while (*wildstr)
    {
        while (*wildstr && *wildstr != wild_many && *wildstr != wild_one)
        {
            if (*wildstr == wild_prefix && wildstr[1])
                wildstr++;
            if (my_toupper(cs, *wildstr++) !=
                my_toupper(cs, *str++)) DBUG_RETURN(1);
        }
        if (! *wildstr ) DBUG_RETURN (*str != 0);
        if (*wildstr++ == wild_one)
        {
            if (! *str++) DBUG_RETURN (1); /* One char; skip */
        }
        else
        {      /* Found '*' */
            if (!*wildstr) DBUG_RETURN(0);  /* '*' as last char: OK */
            flag=(*wildstr != wild_many && *wildstr != wild_one);
            do
            {
                if (flag)
                {
                    char cmp;
                    if ((cmp= *wildstr) == wild_prefix && wildstr[1])
                        cmp=wildstr[1];
                    cmp=my_toupper(cs, cmp);
                    while (*str && my_toupper(cs, *str) != cmp)
                        str++;
                    if (!*str) DBUG_RETURN (1);
                }
                if (wild_case_compare(cs, str,wildstr) == 0) DBUG_RETURN (0);
            } while (*str++);
            DBUG_RETURN(1);
        }
    }
    DBUG_RETURN (*str != '\0');
}

void mem_alloc_error(size_t size)
{
    my_error(ER_OUTOFMEMORY, MYF(0), static_cast<int>(size));
}

void append_identifier(THD *thd, String *packet, const char *name, uint length)
{
    const char *name_end;
    char quote_char;
    int q;
    q= thd ? get_quote_char_for_identifier(thd, name, length) : '`';

    if (q == EOF)
    {
        packet->append(name, length, packet->charset());
        return;
    }

    /*
    The identifier must be quoted as it includes a quote character or
    it's a keyword
    */

    (void) packet->reserve(length*2 + 2);
    quote_char= (char) q;
    packet->append(&quote_char, 1, system_charset_info);

    for (name_end= name+length ; name < name_end ; name+= length)
    {
        uchar chr= (uchar) *name;
        length= my_mbcharlen(system_charset_info, chr);
        /*
        my_mbcharlen can return 0 on a wrong multibyte
        sequence. It is possible when upgrading from 4.0,
        and identifier contains some accented characters.
        The manual says it does not work. So we'll just
        change length to 1 not to hang in the endless loop.
        */
        if (!length)
            length= 1;
        if (length == 1 && chr == (uchar) quote_char)
            packet->append(&quote_char, 1, system_charset_info);
        packet->append(name, length, system_charset_info);
    }
    packet->append(&quote_char, 1, system_charset_info);
}
