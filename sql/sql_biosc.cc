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

#include "my_global.h"
#include "sql_parse.h"
#include "mysqld.h"
#include <string.h>
#include "sql_db.h"
#include "sql_common.h"
#include "derror.h"
#include "mysys_err.h"
#include "item_subselect.h"
#include "sql_class.h"
#include "thr_alarm.h"
#include "errmsg.h"

#define LOCK_TIME_WAIT          60
#define RENAME_TIME_PERIOD      (LOCK_TIME_WAIT * 10000000)

int mysql_execute_sql_with_retry( THD* thd, MYSQL* mysql, char* tmp, my_ulonglong* affected_rows);
int inception_event_enqueue( THD*  thd, sql_cache_node_t* sql_cache_node);
pthread_handler_t inception_move_rows_thread(void* arg);
pthread_handler_t inception_catch_binlog_thread(void* arg);
int inception_get_master_status( THD* thd, sql_cache_node_t* sql_cache_node, int after);
int inception_catch_binlog( THD*  thd, sql_cache_node_t* sql_cache_node);
int inception_rename_table( THD*  thd, sql_cache_node_t* sql_cache_node);
str_t* inception_get_sql_execute_element( THD*  thd, sql_cache_node_t* sql_cache_node);
int inception_create_event_queue( THD*  thd, sql_cache_node_t* sql_cache_node);
MYSQL* inception_get_connection_with_retry( THD*  thd);
int inception_cleanup_biosc( THD*  thd, sql_cache_node_t* sql_cache_node);

int inception_stop_dump(
    THD* thd,
    sql_cache_node_t* sql_cache_node
)
{
    mysql_mutex_lock(&sql_cache_node->osc_lock);
    sql_cache_node->osc_complete = true;
    while (sql_cache_node->dump_on)                        // Should always be true
    {
        int error;
        DBUG_PRINT("loop", ("killing slave thread"));
     
        mysql_mutex_lock(&thd->LOCK_thd_data);
#ifndef DONT_USE_THR_ALARM
        int err __attribute__((unused))= pthread_kill(
            sql_cache_node->binlog_catch_threadid, thr_client_alarm);
        DBUG_ASSERT(err != EINVAL);
#endif
        thd->awake(THD::NOT_KILLED);
        mysql_mutex_unlock(&thd->LOCK_thd_data);
        struct timespec abstime;
        set_timespec(abstime,2);
        error= mysql_cond_timedwait(&sql_cache_node->stop_cond, 
            &sql_cache_node->osc_lock, &abstime);
        DBUG_ASSERT(error == ETIMEDOUT || error == 0);
    }

    mysql_mutex_unlock(&sql_cache_node->osc_lock);

    return false;
}

int mysql_analyze_biosc_output(
    THD* thd, 
    char* tmp, 
    sql_cache_node_t* sql_cache_node
)
{
    int percent = -1;
    char    timeremain[100];
    osc_percent_cache_t* osc_percent_node;

    DBUG_ENTER("mysql_analyze_biosc_output");

    mysql_mutex_lock(&osc_mutex); 

    osc_percent_node = LIST_GET_FIRST(global_osc_cache.osc_lst);
    while(osc_percent_node)
    {
        if (!strcasecmp(osc_percent_node->sqlsha1, sql_cache_node->sqlsha1))
        {
            osc_percent_node->percent = 0;
            strcpy(osc_percent_node->remaintime, "\0");
            sprintf(osc_percent_node->execute_time, "%.3f",
                (double)(start_timer() - osc_percent_node->start_timer) / CLOCKS_PER_SEC);
            break;
        }

        osc_percent_node = LIST_GET_NEXT(link, osc_percent_node);        
    }

    if (osc_percent_node == NULL)
    {
        osc_percent_node = (osc_percent_cache_t*)my_malloc(
            sizeof(osc_percent_cache_t), MY_ZEROFILL);
        osc_percent_node->percent = 0;
        osc_percent_node->start_timer = start_timer();
        strcpy(osc_percent_node->dbname, str_get(&sql_cache_node->tables.db_names));
        strcpy(osc_percent_node->tablename, str_get(&sql_cache_node->tables.table_names));
        strcpy(osc_percent_node->remaintime, "");
        strcpy(osc_percent_node->execute_time, "");
        strcpy(osc_percent_node->sqlsha1, sql_cache_node->sqlsha1);
        osc_percent_node->sql_cache_node = sql_cache_node;
        LIST_ADD_LAST(link, global_osc_cache.osc_lst, osc_percent_node);
    }

    if (sql_cache_node->osc_complete)
    {
        percent = 100;
        strcpy(timeremain, "00:00");
        sql_cache_node->oscpercent = 100;
    }
    //因为有了进度查询，所以输出中的进度就不再打印了
    sql_cache_node->oscoutput = str_append(sql_cache_node->oscoutput, tmp);
    sql_cache_node->oscoutput = str_append(sql_cache_node->oscoutput, "\n");
    mysql_mutex_unlock(&osc_mutex);
    DBUG_RETURN(false);
}

int mysql_execute_alter_table_biosc(
    THD* thd,
    MYSQL* mysql,
    char* statement,
    sql_cache_node_t* sql_cache_node
)
{
    str_t     new_sql;
    str_t     new_table_name;
    str_t     new_create_sql;
    char      new_tablename[1024];
    char      old_tablename[1024];
    char      timestamp[1024];
    time_t now= my_time(0);
    pthread_t threadid;

    /* sha1 compute from time+dbname+seqno */
    sql_cache_node->oscoutput = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    sql_cache_node->oscoutput = str_init(sql_cache_node->oscoutput);
    sql_cache_node->oscpercent = 0;

    str_init(&new_sql);
    str_init(&new_table_name);
    str_init(&new_create_sql);
    sprintf(timestamp, "%d", (int)now);
    str_append(&new_table_name, timestamp);
    str_append(&new_table_name, str_get(&sql_cache_node->tables.db_names));
    sprintf(timestamp, "%d", (int)sql_cache_node->seqno);
    str_append(&new_table_name, timestamp);
    my_make_scrambled_password_sha1(timestamp, 
        str_get(&new_table_name), str_get_len(&new_table_name));
    sprintf(new_tablename, "_%s_%s_new", timestamp + 33, 
        str_get(&sql_cache_node->tables.table_names));
    sprintf(old_tablename, "_%s_%s_old", timestamp + 33, 
        str_get(&sql_cache_node->tables.table_names));
    
    /* alter new table statement */
    str_append(&new_sql, "ALTER TABLE ");
    str_append(&new_sql, str_get(&sql_cache_node->tables.db_names));
    str_append(&new_sql, ".");
    str_append(&new_sql, new_tablename);
    str_append(&new_sql, " ");
    str_append(&new_sql, mysql_get_alter_table_post_part(
        thd, statement, sql_cache_node->ignore));

    /* create new table statement */
    str_append(&new_create_sql, "CREATE TABLE ");
    str_append(&new_create_sql, str_get(&sql_cache_node->tables.db_names));
    str_append(&new_create_sql, ".");
    str_append(&new_create_sql, new_tablename);
    str_append(&new_create_sql, " LIKE ");
    str_append(&new_create_sql, str_get(&sql_cache_node->tables.db_names));
    str_append(&new_create_sql, ".");
    str_append(&new_create_sql, str_get(&sql_cache_node->tables.table_names));

    /* create new table and then alter it */
    if (mysql_execute_sql_with_retry(thd, mysql, str_get(&new_create_sql), NULL) ||
        mysql_execute_sql_with_retry(thd, mysql, str_get(&new_sql), NULL))
        return true;

    sprintf(timestamp, "Create new table: %s.%s completely", 
        str_get(&sql_cache_node->tables.db_names), new_tablename);
    mysql_analyze_biosc_output(thd, timestamp, sql_cache_node);

    strcpy(sql_cache_node->biosc_new_tablename, new_tablename);
    strcpy(sql_cache_node->biosc_old_tablename, old_tablename);

    mysql_mutex_init(NULL, &sql_cache_node->osc_lock, MY_MUTEX_INIT_FAST);
    mysql_cond_init(NULL, &sql_cache_node->stop_cond, NULL);
    mysql_cond_init(NULL, &sql_cache_node->rename_ready_cond, NULL);
    mysql_cond_init(NULL, &sql_cache_node->alter_status, NULL);

    /* show MASTER STAUTS FIRST, and then copy rows */
    inception_get_master_status(thd, sql_cache_node, false);
    sprintf(timestamp, "Get the binary log position before copy rows: %s:%d", 
        sql_cache_node->start_binlog_file, sql_cache_node->start_binlog_pos);
    mysql_analyze_biosc_output(thd, timestamp, sql_cache_node);

    sql_cache_node->osc_complete = false;
    sql_cache_node->biosc_copy_complete = false;
    sql_cache_node->rename_timeout = false;

    inception_create_event_queue(thd, sql_cache_node);

    /* start to copy rows use one thread */
    /* start to catch binlog */
    mysql_analyze_biosc_output(thd, "Create copy rows thread completely", sql_cache_node);
    mysql_analyze_biosc_output(thd, "Create binary logs catch thread completely", sql_cache_node);
    if (mysql_thread_create(0, &threadid, &connection_attrib,
        inception_move_rows_thread, (void*)sql_cache_node) || 
        mysql_thread_create(0, &threadid, &connection_attrib,
        inception_catch_binlog_thread, (void*)sql_cache_node))
    {
        my_message(ER_CREATE_THREAD_ERROR, "Copy rows or binlog parse", MYF(0));
        mysql_errmsg_append(thd);
        return true;
    }

    sql_cache_node->binlog_catch_threadid = threadid;
    inception_rename_table(thd, sql_cache_node);
    inception_stop_dump(thd, sql_cache_node);
    inception_cleanup_biosc(thd, sql_cache_node);

    mysql_mutex_destroy(&sql_cache_node->osc_lock);
    mysql_cond_destroy(&sql_cache_node->stop_cond);
    mysql_cond_destroy(&sql_cache_node->rename_ready_cond);
    mysql_cond_destroy(&sql_cache_node->alter_status);
    str_deinit(&new_table_name);
    str_deinit(&new_create_sql);
    str_deinit(&new_sql);
    return false;
}

int
inception_get_master_status(
    THD*              thd, 
    sql_cache_node_t* sql_cache_node,
    int               after
)
{
    MYSQL_RES *source_res1;
    MYSQL_ROW  source_row;
    MYSQL* mysql;
    char    tmp[128];

    mysql = inception_get_connection_with_retry(thd);
    if (!mysql)
    {
        mysql_errmsg_append(thd);
        return true;
    }

    sprintf (tmp, "SHOW MASTER STATUS");
    if (mysql_real_query(mysql, tmp, strlen(tmp)) ||
       (source_res1 = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(thd);
        return true;
    }

    source_row = mysql_fetch_row(source_res1);
    if (source_row == NULL)
    {
        mysql_free_result(source_res1);
        return true;
    }

    if (!after)
    {
        strcpy(sql_cache_node->start_binlog_file, source_row[0]);
        sql_cache_node->start_binlog_pos = strtoul(source_row[1], 0, 10);
    }
    else
    {
        strcpy(sql_cache_node->end_binlog_file, source_row[0]);
        sql_cache_node->end_binlog_pos = strtoul(source_row[1], 0, 10);
    }

    mysql_free_result(source_res1);
    return false;
}

int inception_biosc_abort(THD* thd, sql_cache_node_t* sql_cache_node)
{
    if ((sql_cache_node->osc_complete || sql_cache_node->osc_abort
          || abort_loop || (thd != NULL && thd->killed)))
        return true;
    return false;
}

int inception_biosc_table_map_log_event(
    Master_info *mi, 
    Log_event* ev,
    sql_cache_node_t* sql_cache_node
)
{
    table_info_t*   table_info;
    Table_map_log_event* tab_map_ev;

    tab_map_ev = (Table_map_log_event*)ev;

    if (!strcasecmp((char*)tab_map_ev->get_db(), 
          str_get(&sql_cache_node->tables.db_names))
        && !strcasecmp((char*)tab_map_ev->get_table_name(), 
          str_get(&sql_cache_node->tables.table_names)))
    {
        table_info = mysql_get_table_object(mi->thd, (char*)tab_map_ev->get_db(), 
            (char*)tab_map_ev->get_table_name(), TRUE);
        if (table_info)
            return mysql_parse_table_map_log_event_low(mi, ev, table_info);
    }

    return false;
}

int inception_get_field_string(
    Field* field, 
    str_t* backup_sql, 
    char* null_arr, 
    int field_index, 
    int qutor_flag,
    int doublequtor_escape
)
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
    char* dupcharfieldforbackslash;

    // str_append(backup_sql, separated);

    if (null_arr[field_index])
    {
        str_append(backup_sql, "NULL");
        append_flag = FALSE;
    }
    else
    {
        switch ((f_type=field->real_type())) {
        default:
        case MYSQL_TYPE_NULL:
            str_append(backup_sql, "NULL");
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
                if (qutor_flag)
                    str_append(backup_sql, "\'");
                res=field->val_str(&buffer);
                dupcharfield = (char*)my_malloc(res->length() * 4 + 1, MY_ZEROFILL);

                if(mysql_dup_char(res->c_ptr(), dupcharfield, '\''))
                {
                    dupcharfieldforbackslash = (char*)my_malloc(
                        (res->length() * 4 + 1) * 2, MY_ZEROFILL);
                    mysql_dup_char(dupcharfield, dupcharfieldforbackslash, '\\');
                    str_append(backup_sql, dupcharfieldforbackslash);
                    my_free(dupcharfieldforbackslash);
                }
                else
                    str_append(backup_sql, dupcharfield);
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
                if (qutor_flag)
                    str_append(backup_sql, "\'");
                res=field->val_str(&buffer);
                qutor_end =1;
                //    MYSQL_TIME tm;
                //    field->get_date(&tm, TIME_FUZZY_DATE);
                break;
            }
        case MYSQL_TYPE_TIME:
        case MYSQL_TYPE_TIME2:
            {
                if (qutor_flag)
                    str_append(backup_sql, "\'");
                res=field->val_str(&buffer);
                qutor_end =1;
                //    MYSQL_TIME tm;
                //    field->get_time(&tm);
                break;
            }
        }
    }

    if (append_flag)
        str_append_with_length(backup_sql, res->ptr(), res->length());

    if (qutor_end && qutor_flag)
        str_append(backup_sql, "\'");

    return result;
}

int mysql_generate_biosc_increment_sql(
    Master_info* mi,
    int    optype,
    str_t*   backup_sql,
    sql_cache_node_t* sql_cache_node,
    int update_after
)
{
    field_info_t* field_node;
    char   tmp_buf[256];
    int    err = 0;
    int    field_index=0;
    int   first = true;

    if (optype == SQLCOM_DELETE)
    {
        sprintf(tmp_buf, "DELETE IGNORE FROM `%s`.`%s` WHERE ", 
            str_get(&sql_cache_node->tables.db_names), 
            sql_cache_node->biosc_new_tablename);
        first = true;
        str_append(backup_sql, tmp_buf);
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            if (field_node->primary_key)
            {
                if (!first)
                    str_append(backup_sql, " AND ");

                sprintf(tmp_buf, "%s=", field_node->field_name);
                str_append(backup_sql, tmp_buf);

                err = inception_get_field_string(
                update_after ? field_node->conv_field_after: field_node->conv_field,
                    backup_sql, mi->table_info->null_arr, field_index, TRUE, FALSE);
                first = false;
            }
            field_node = LIST_GET_NEXT(link, field_node);
            field_index++;
        }

        str_append(backup_sql, ";");
    } 
    else if (optype == SQLCOM_INSERT) 
    {
        first = true;
        sprintf(tmp_buf, "INSERT IGNORE INTO `%s`.`%s` (", 
            str_get(&sql_cache_node->tables.db_names), 
            sql_cache_node->biosc_new_tablename);

        str_append(backup_sql, tmp_buf);
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            if (!first)
                str_append(backup_sql, ",");
            str_append(backup_sql, field_node->field_name);
            first = false;
            field_node = LIST_GET_NEXT(link, field_node);
        }

        first = true;
        str_append(backup_sql, ") values(");
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            if (!first)
                str_append(backup_sql, ",");

            err = inception_get_field_string(
                update_after ? field_node->conv_field_after : field_node->conv_field,
                    backup_sql, mi->table_info->null_arr, field_index, TRUE, FALSE);

            first = false;
            field_node = LIST_GET_NEXT(link, field_node);
            field_index++;
        }

        str_append(backup_sql, ");");
    } 
    else if (optype == SQLCOM_UPDATE) 
    {
        first = true;
        sprintf(tmp_buf, "UPDATE `%s`.`%s` SET ", 
            str_get(&sql_cache_node->tables.db_names), 
            sql_cache_node->biosc_new_tablename);
        str_append(backup_sql, tmp_buf);
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            if (!first)
                str_append(backup_sql, ",");

            sprintf(tmp_buf, "%s=", field_node->field_name);
            str_append(backup_sql, tmp_buf);
            err = inception_get_field_string(
                update_after ? field_node->conv_field: field_node->conv_field_after,
                    backup_sql, mi->table_info->null_arr, field_index,TRUE, FALSE);

            first = false;
            field_node = LIST_GET_NEXT(link, field_node);
            field_index++;
        }

        str_append(backup_sql, " WHERE ");
    } 
    else if (optype == SQLCOM_UPDATE + 1000) 
    {
        first = true;
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            if (field_node->primary_key)
            {
                if (!first)
                    str_append(backup_sql, " AND ");

                sprintf(tmp_buf, "%s=", field_node->field_name);
                str_append(backup_sql, tmp_buf);

                inception_get_field_string(
                    update_after ? field_node->conv_field: field_node->conv_field_after,
                    backup_sql, mi->table_info->null_arr, field_index,TRUE, FALSE);
                first = false;
            }
            field_node = LIST_GET_NEXT(link, field_node);
            field_index++;
        }

        str_append(backup_sql, ";");
    }

    return 0;
}

int mysql_execute_sql_with_retry(
    THD* thd,
    MYSQL* mysql,
    char* tmp,
    my_ulonglong* affected_rows
)
{
    int retry_count=0;

retry:
    retry_count++;
    if (mysql_real_query(mysql, tmp, strlen(tmp)))
        goto error;

    if (affected_rows)
        *affected_rows = mysql_affected_rows(mysql);

    if (mysql_real_query(mysql, "COMMIT", strlen("COMMIT")))
        goto error;

    return false;
error:
    if (retry_count < 3)
        goto retry;

    my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
    mysql_errmsg_append(thd);

    return true;
}

int inception_biosc_write_row(
    Master_info *mi, 
    Log_event* ev,
    int optype,
    sql_cache_node_t* sql_cache_node
)
{
    Write_rows_log_event*   write_ev;
    int                     error= 0;
    str_t*                  backup_sql;
    table_info_t*           table_info;
    THD*                    thd;

    DBUG_ENTER("inception_biosc_write_row");
    write_ev = (Write_rows_log_event*)ev;
    thd = mi->thd;
    table_info = mysql_get_table_info_by_id(mi, write_ev->get_table_id());
    if (table_info == NULL)
        DBUG_RETURN(error);
        
    do
    {
        backup_sql = inception_get_sql_execute_element(thd, sql_cache_node);
        if (mysql_unpack_row(mi, write_ev->get_table_id(), write_ev->m_curr_row, 
              write_ev->get_cols(), &write_ev->m_curr_row_end, write_ev->m_rows_end, false))
        {
            error=true;
            goto error;
        }

        write_ev->m_curr_row = write_ev->m_curr_row_end;
        if (optype == SQLCOM_UPDATE)
        {
            if (mysql_unpack_row(mi, write_ev->get_table_id(), write_ev->m_curr_row, 
                  write_ev->get_cols(), &write_ev->m_curr_row_end, write_ev->m_rows_end, true))
            {
                error=true;
                goto error;
            }

            write_ev->m_curr_row = write_ev->m_curr_row_end;
        }

        str_truncate_0(backup_sql);
        if (mysql_generate_biosc_increment_sql(mi, optype, 
              backup_sql, sql_cache_node, false))
        {
            error=true;
            goto error;
        }

        if (optype == SQLCOM_UPDATE)
        {
            if (mysql_generate_biosc_increment_sql(mi, 
                  SQLCOM_UPDATE+1000, backup_sql, sql_cache_node, true))
            {
                error=true;
                goto error;
            }
        }

        inception_event_enqueue(thd, sql_cache_node);
    }while(!error && write_ev->m_rows_end != write_ev->m_curr_row);

error:
    DBUG_RETURN(error);
}

int inception_biosc_binlog_process(
    Master_info* mi,
    Log_event* ev,
    sql_cache_node_t* sql_cache_node
)
{
    int err = 0;
    THD* thd;

    DBUG_ENTER("inception_biosc_binlog_process");

    thd = mi->thd;
    if (ev == NULL)
        DBUG_RETURN(false);

    switch(ev->get_type_code())
    {
    case TABLE_MAP_EVENT:
        err = inception_biosc_table_map_log_event(mi, ev, sql_cache_node);
        break;

    case XID_EVENT:
        free_tables_to_lock(mi);
        break;

    case WRITE_ROWS_EVENT_V1:
    case WRITE_ROWS_EVENT:
        err = inception_biosc_write_row(mi, ev, SQLCOM_INSERT, sql_cache_node);
        break;

    case UPDATE_ROWS_EVENT:
    case UPDATE_ROWS_EVENT_V1:
        err = inception_biosc_write_row(mi, ev, SQLCOM_UPDATE, sql_cache_node);
        break;

    case DELETE_ROWS_EVENT:
    case DELETE_ROWS_EVENT_V1:
        err = inception_biosc_write_row(mi, ev, SQLCOM_DELETE, sql_cache_node);
        break;

    default:
        break;
    }

    DBUG_RETURN(err);
}

int inception_get_table_select_where_low(
    sql_cache_node_t* sql_cache_node,
    str_t*    next_where,
    MYSQL_ROW  source_row,
    int       col_count,
    int       gol
)
{
    int       i=0;
    int       first = true;

    for (i = 0; i < col_count; i ++)
    {
        if (!first)
            str_append(next_where, " AND ");
            
        str_append(next_where, sql_cache_node->primary_keys[i]);
        if (col_count - 1 == i)
        {
            if (gol)
                str_append(next_where, ">=");
            else
                str_append(next_where, "<=");
        }
        else
        {
            str_append(next_where, "=");
        }
        str_append(next_where, "\'");
        str_append(next_where, source_row[i]);
        str_append(next_where, "\'");
        first = false;
    }

    return false;
}

int inception_get_table_rows_copy_sql(
    THD*              thd,
    str_t*            copy_rows_sql,
    str_t*            select_prefix,
    str_t*            front_sql,
    str_t*            behind_sql
)
{
    str_append(copy_rows_sql, str_get(select_prefix));
    str_append(copy_rows_sql, " WHERE (");
    str_append(copy_rows_sql, str_get(front_sql));
    str_append(copy_rows_sql, ")");
    if (behind_sql)
    {
        str_append(copy_rows_sql, " AND (");
        str_append(copy_rows_sql, str_get(behind_sql));
        str_append(copy_rows_sql, ")");
    }

    str_append(copy_rows_sql, " LOCK IN SHARE MODE");
    
    return false;
}

int inception_get_table_select_where(
    THD*              thd,
    str_t*            select_sql,
    str_t*            front_sql,
    str_t*            behind_sql,
    sql_cache_node_t* sql_cache_node,
    int               first_time
)
{
    int           field_num;
    int           i;
    MYSQL_RES *source_res1;
    MYSQL_ROW  source_row;
    MYSQL*      mysql;

    mysql = inception_get_connection_with_retry(thd);
    if (!mysql)
    {
        mysql_errmsg_append(thd);
        return true;
    }

    if (mysql_real_query(mysql, str_get(select_sql), str_get_len(select_sql)) ||
       (source_res1 = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_errmsg_append(thd);
        return true;
    }

    field_num = mysql_num_fields(source_res1);
    source_row = mysql_fetch_row(source_res1);
    if (source_row)
    {
        /* first_time is only working for first row, because there
         * have no second row */
        for (i = 0; i < field_num; i ++)
        {
            if (i != 0)
                str_append(front_sql, " OR ");
            str_append(front_sql, " (");
            inception_get_table_select_where_low(sql_cache_node, 
                front_sql, source_row, i + 1, first_time ? true : false);
            str_append(front_sql, " )");
        }

        source_row = mysql_fetch_row(source_res1);
        for (i = 0; i < field_num && source_row; i ++)
        {
            if (i != 0)
                str_append(behind_sql, " OR ");
            str_append(behind_sql, " (");
            inception_get_table_select_where_low(sql_cache_node, 
                behind_sql, source_row, i + 1, true);
            str_append(behind_sql, " )");
        }
    }
    
    mysql_free_result(source_res1);

    return false;
}

int inception_get_table_primary_keys(
    THD* thd,
    sql_cache_node_t* sql_cache_node,
    str_t*            pkstring
)
{
    sql_table_t*  tables;
    table_rt_t*   table_rt;
    table_info_t* table_info;
    field_info_t* field_info;
    int           first = true;
    int           pkcount = 0;

    tables = &sql_cache_node->tables;
    table_rt = LIST_GET_FIRST(tables->table_lst);
    while (table_rt)
    {
        table_info = table_rt->table_info;
        field_info = LIST_GET_FIRST(table_info->field_lst);
        while (field_info)
        {
            if (field_info->primary_key)
            {
                if (!first)
                    str_append(pkstring, ", ");
                str_append(pkstring, field_info->field_name);
                first = false;
                pkcount++;
            }

            field_info = LIST_GET_NEXT(link, field_info);
        }
        
        sql_cache_node->primary_keys = (char**)my_malloc(sizeof(char*) * pkcount, MY_ZEROFILL);
        pkcount = 0;
        field_info = LIST_GET_FIRST(table_info->field_lst);
        while (field_info)
        {
            if (field_info->primary_key)
            {
                sql_cache_node->primary_keys[pkcount] = (char*)my_malloc(NAME_LEN, MY_ZEROFILL);
                strcpy(sql_cache_node->primary_keys[pkcount], field_info->field_name);
                pkcount++;
            }

            field_info = LIST_GET_NEXT(link, field_info);
        }

        /* only one table to alter */
        break;
        table_rt = LIST_GET_NEXT(link, table_rt);
    }

    return false;
}

int inception_get_insert_new_table_sql(
    str_t* select_sql,
    sql_cache_node_t* sql_cache_node
)
{
    sql_table_t*      tables;
    str_t             old_table_cols;
    table_info_t*     table_info;
    table_rt_t*       table_rt;
    field_info_t*     field_info;
    int               first=true;

    str_init(&old_table_cols);
    /* first batch start */
    str_append(select_sql, "INSERT LOW_PRIORITY IGNORE INTO ");
    str_append(select_sql, "`");
    str_append(select_sql, str_get(&sql_cache_node->tables.db_names));
    str_append(select_sql, "`.");
    str_append(select_sql, "`");
    str_append(select_sql, sql_cache_node->biosc_new_tablename);
    str_append(select_sql, "` ");

    tables = &sql_cache_node->tables;
    table_rt = LIST_GET_FIRST(tables->table_lst);
    if (table_rt)
    {
        table_info = table_rt->table_info;
        field_info = LIST_GET_FIRST(table_info->field_lst);
        while (field_info)
        {
            if (!first)
                str_append(&old_table_cols, ", ");
            str_append(&old_table_cols, field_info->field_name);
            first = false;

            field_info = LIST_GET_NEXT(link, field_info);
        }
    }

    str_append(select_sql, "(");
    str_append(select_sql, str_get(&old_table_cols));
    str_append(select_sql, ")");

    str_append(select_sql, " SELECT ");
    str_append(select_sql, str_get(&old_table_cols));

    str_append(select_sql, " FROM ");
    str_append(select_sql, "`");
    str_append(select_sql, str_get(&sql_cache_node->tables.db_names));
    str_append(select_sql, "`.");
    str_append(select_sql, "`");
    str_append(select_sql, str_get(&sql_cache_node->tables.table_names));
    str_append(select_sql, "` ");
    str_append(select_sql, " FORCE INDEX(`PRIMARY`) ");
    return false;
}

int inception_get_copy_rows_batch_sql_prefix(
    str_t* select_sql,
    str_t* primary_cols,
    sql_cache_node_t* sql_cache_node
)
{
    /* first batch start */
    str_append(select_sql, "SELECT /*!40001 SQL_NO_CACHE */ ");
    str_append(select_sql, str_get(primary_cols));
    str_append(select_sql, " FROM ");
    str_append(select_sql, str_get(&sql_cache_node->tables.db_names));
    str_append(select_sql, ".");
    str_append(select_sql, str_get(&sql_cache_node->tables.table_names));
    str_append(select_sql, " FORCE INDEX(`PRIMARY`) ");
    return false;
}

int inception_get_copy_rows_batch_sql(
    str_t* select_prefix,
    str_t* greater_cond_sql,
    str_t* primary_cols,
    str_t* select_sql,
    sql_cache_node_t* sql_cache_node,
    int   first_time
)
{
    /* first batch start */
    str_append(select_sql, str_get(select_prefix));
    if (first_time)
    {
        str_append(select_sql, " LIMIT 1");
    }
    else
    {
        str_append(select_sql, " WHERE ");
        str_append(select_sql, str_get(greater_cond_sql));
        str_append(select_sql, " ORDER BY ");
        str_append(select_sql, str_get(primary_cols));
        /* TODO: 将分片大小参数化，这里先认定2000 */
        str_append(select_sql, " LIMIT 200, 2");
    }

    return false;
}

int inception_swap_str(
    str_t**       str_1,
    str_t**       str_2 
)
{
    str_t*        tmp;

    tmp = *str_1;
    *str_1 = *str_2;
    *str_2 = tmp;
    return false;
}

pthread_handler_t inception_move_rows_thread(void* arg)
{
    THD *thd= NULL;
    THD *query_thd= NULL;
    MYSQL* mysql = NULL;
    char* binlog_file = NULL;
    int binlog_position = 0;
    int retrycount = 0;
    time_t skr;
    int   first_time = true;
    char  osc_output[1024];
    sql_cache_node_t* sql_cache_node;
    str_t       primary_cols;
    str_t       select_prefix;
    str_t       copy_rows_sql;
    str_t       front_sql;
    str_t       execute_sql;
    str_t       change_sql;
    str_t       behind_sql;
    str_t*      greater_cond_sql;
    str_t*      lesser_cond_sql;
    str_t*      change_cond_sql;
    str_t       insert_select_prefix;
    int         complete = false;
    my_ulonglong affected_rows = 0;
    my_ulonglong sum_affected_rows = 0;

    my_thread_init();

    sql_cache_node = (sql_cache_node_t*)arg;
    query_thd = sql_cache_node->thd;

    thd= new THD;
    thd->thread_stack= (char*) &thd;
    pthread_detach_this_thread();

    setup_connection_thread_globals(thd);
    inception_init_slave_thread(thd);

    thd->query_thd = NULL;
    binlog_file = sql_cache_node->start_binlog_file;
    binlog_position = sql_cache_node->start_binlog_pos;
    str_init(&primary_cols);
    str_init(&copy_rows_sql);
    str_init(&select_prefix);
    str_init(&execute_sql);

    str_init(&insert_select_prefix);
    str_init(&front_sql);
    str_init(&behind_sql);
    str_init(&change_sql);
    change_cond_sql = &change_sql;
    greater_cond_sql = &front_sql;
    lesser_cond_sql = &behind_sql;
    memcpy(thd->thd_sinfo, query_thd->thd_sinfo, sizeof (sinfo_space_t));

    sprintf(osc_output, "[Copy thread] Start to Copy rows, batch size: %d", 200);
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
reconnect:
    sprintf(osc_output, "[Copy thread] Start to get connection, retry: %d/3", retrycount++);
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    if (!(mysql = inception_get_connection_with_retry(thd)))
    {
        sprintf(osc_output, "[Copy thread] Can not get connection, error: %s", 
            thd->get_stmt_da()->message());
        mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
        sprintf(osc_output, "[Copy thread] Alter table abort");
        mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
        sql_cache_node->biosc_copy_complete = 2;
        mysql_errmsg_append(thd);
        goto error;
    }

    inception_get_table_primary_keys(query_thd, sql_cache_node, &primary_cols);
    inception_get_copy_rows_batch_sql_prefix(
        &select_prefix, &primary_cols, sql_cache_node);
    inception_get_insert_new_table_sql(&insert_select_prefix, sql_cache_node);

    /* 获取找到第一条记录的SQL语句 */
    inception_get_copy_rows_batch_sql(&select_prefix, NULL, &primary_cols, 
        &execute_sql, sql_cache_node, first_time);
    while(!complete && !inception_biosc_abort(query_thd, sql_cache_node))
    {
        if (inception_get_table_select_where(thd, &execute_sql, 
            lesser_cond_sql, greater_cond_sql, sql_cache_node, first_time))
        {
            sprintf(osc_output, "[Copy thread] Alter table abort");
            mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
            sql_cache_node->biosc_copy_complete = 2;
            goto error;
        }

        str_truncate_0(&execute_sql);
        str_truncate_0(&copy_rows_sql);

        if (!first_time && str_get_len(greater_cond_sql) > 0)
        {
            /*
             * 中间状态，每次取到的边界值都有2个，分别是本分片的最大值和
             * 下一个分片的最小值
             * 得到一个分片查询的语句,目标串为copy_rows_sql */
            inception_get_table_rows_copy_sql(thd, &copy_rows_sql, 
                &insert_select_prefix, change_cond_sql, lesser_cond_sql);

            /* 得到用来取得下一个分片的边界 */
            inception_get_copy_rows_batch_sql(&select_prefix, greater_cond_sql, 
                &primary_cols, &execute_sql, sql_cache_node, first_time);
            str_truncate_0(lesser_cond_sql);
            str_truncate_0(change_cond_sql);
            inception_swap_str(&change_cond_sql, &greater_cond_sql);
        }
        else if (first_time)
        {
            /* 第一次进来，这是第一行数据 */
            inception_swap_str(&change_cond_sql, &lesser_cond_sql);
            str_truncate_0(lesser_cond_sql);
            first_time = false;

            inception_get_copy_rows_batch_sql(&select_prefix, change_cond_sql, 
                &primary_cols, &execute_sql, sql_cache_node, first_time);
        }
        else if (!first_time)
        {
            /* 已经取到了最后，分两种情况，一种就是正好取了一条，还
             * 有一种情况就是一条都没有取到，分情况讨论 */
            /* 1. 正好取到一条，本分片的最大边界值 */
            if (str_get_len(lesser_cond_sql) > 0)
            {
                inception_get_table_rows_copy_sql(thd, &copy_rows_sql, 
                    &insert_select_prefix, change_cond_sql, lesser_cond_sql);
            }
            else
            {
                /* 没有取到边界，说明已经走到最后，需要处理最后一部分数据,
                 * 直接去掉这个边界的最大边界，只取最小边界即可
                 * 不过有隐患，如果此时正好插入大批数据，会导致这个分片一下子增大
                 * 这里需要处理，最好是取到最后一条数据，再插入进来也不需要管了
                 * 因为有Binlog做增量处理 */
                inception_get_table_rows_copy_sql(thd, &copy_rows_sql, 
                    &insert_select_prefix, change_cond_sql, NULL);
            }
            complete = true;
        }

        /*execute the copy_rows_sql to copy rows from old to new table*/
        if (str_get_len(&copy_rows_sql) > 0)
        {
            if (mysql_execute_sql_with_retry(thd, mysql, 
                  str_get(&copy_rows_sql), &affected_rows))
            {
                sprintf(osc_output, "[Copy thread] Alter table abort");
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                sql_cache_node->biosc_copy_complete = 2;
                goto error;
            }
            sum_affected_rows += affected_rows;
        }
    }

    sql_cache_node->biosc_copy_complete = true;
    sprintf(osc_output, "[Copy thread] Copy rows completely, copy rows: %lld", sum_affected_rows);
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    sprintf(osc_output, "[Copy thread] Copy thread exit");
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);

error:
    str_deinit(&primary_cols);
    str_deinit(&select_prefix);
    str_deinit(&copy_rows_sql);
    str_deinit(&front_sql);
    str_deinit(&execute_sql);
    str_deinit(&change_sql);
    str_deinit(&behind_sql);
    str_deinit(&insert_select_prefix);

    delete thd;
    my_thread_end();
    pthread_exit(0);
    return NULL;
}

int 
inception_event_enqueue(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
{
    mts_thread_queue_t* element;
    mts_thread_t* current_thread;

    current_thread = sql_cache_node->mts_queue;
    element = sql_cache_node->current_element;
    mysql_mutex_lock(&element->element_lock);
    element->valid = true;
    mysql_mutex_unlock(&element->element_lock);
    // mysql_cond_broadcast(&sql_cache_node->mts_cond);
    return false;
}

str_t*
inception_event_dequeue(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
{
    mts_thread_queue_t* element;
    mts_thread_t* mts_thread;
    str_t*        sql_buffer = NULL;

    mts_thread = sql_cache_node->mts_queue;
    if (mts_thread->dequeue_index != mts_thread->enqueue_index)
    {
        element = &mts_thread->thread_queue[mts_thread->dequeue_index];
        if (element->valid)
        {
            sql_buffer = &element->sql_buffer;
        }
        else
        {
            return NULL;
        }
    }

    return sql_buffer;
}

pthread_handler_t inception_catch_binlog_thread(void* arg)
{
    Master_info* mi;
    MYSQL* mysql = NULL;
    char*   event_buf;
    Log_event*  evlog;
    char* binlog_file = NULL;
    int binlog_position = 0;
    int retrycount = 0;
    bool suppress_warnings;
    time_t skr;
    THD*      query_thd;
    THD*      thd;
    char      osc_output[1024];

    my_thread_init();

    sql_cache_node_t* sql_cache_node;
    sql_cache_node = (sql_cache_node_t*)arg;
    query_thd = sql_cache_node->thd;

    thd= new THD;
    thd->thread_stack= (char*) &thd;

    pthread_detach_this_thread();
    setup_connection_thread_globals(thd);
    inception_init_slave_thread(thd);

    mi = new Master_info(1);
    mi->thd = thd;
    mi->info_thd = thd;

    binlog_file = sql_cache_node->start_binlog_file;
    binlog_position = sql_cache_node->start_binlog_pos;

    memcpy(thd->thd_sinfo, query_thd->thd_sinfo, sizeof (sinfo_space_t));

    sprintf(osc_output, "[Binlog thread] Binlog catch start with position: (%s:%d)", 
        binlog_file, binlog_position);
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);

    sprintf(osc_output, "[Binlog thread] Start to read the binlog "
        "events and produce the increament SQL");
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);

reconnect:
    sprintf(osc_output, "[Binlog thread] Get the connection and "
        "Dump binlog, retry: %d/3", retrycount);
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    if (++retrycount > 3)
    {
        sprintf(osc_output, "[Binlog thread] Alter table abort, error: %s",
            thd->get_stmt_da()->message());
        mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
        sql_cache_node->osc_abort = true;
        mysql_errmsg_append(thd);
        goto error;
    }

    mysql_close(mysql);
    if (!(mysql = inception_init_binlog_connection(thd->thd_sinfo->host, 
	          thd->thd_sinfo->port, thd->thd_sinfo->user, thd->thd_sinfo->password)))
        goto reconnect; 

    if (mysql_get_master_version(mysql, mi) || 
        register_slave_on_master(mysql, &suppress_warnings, server_id) ||
        mysql_request_binlog_dump(mysql, binlog_file, binlog_position, server_id))
        goto reconnect; 

    sql_cache_node->dump_on = true;
    while(!inception_biosc_abort(thd, sql_cache_node))
    {
        ulong event_len;

        event_len = mysql_read_event_for_transfer(mi, mysql);
        event_buf= (char*)mysql->net.read_pos + 1;
        if (event_len == packet_error)
        {
            if (mysql_errno(mysql) == CR_NET_PACKET_TOO_LARGE ||
                mysql_errno(mysql) == ER_MASTER_FATAL_ERROR_READING_BINLOG ||
                mysql_errno(mysql) == ER_OUT_OF_RESOURCES)
                goto error;
            if (inception_biosc_abort(thd, sql_cache_node))
                goto error;
            goto reconnect;
        }

        retrycount = 0;
        if (mysql_process_event(mi, event_buf, event_len, &evlog) || evlog == NULL)
        {
            sprintf(osc_output, "[Binlog thread] Alter table abort, error: %s",
                thd->get_stmt_da()->message());
            mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
            sql_cache_node->osc_abort = true;
            goto error;
        }

        mysql_mutex_lock(&sql_cache_node->osc_lock); 
        strcpy(sql_cache_node->current_binlog_file, (char*)mi->get_master_log_name());
        sql_cache_node->current_binlog_pos = mi->get_master_log_pos();
        mysql_mutex_unlock(&sql_cache_node->osc_lock); 

        if (inception_biosc_binlog_process(mi, evlog, sql_cache_node))
        {
            sprintf(osc_output, "[Binlog thread] Alter table abort, error: %s",
                thd->get_stmt_da()->message());
            mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
            sql_cache_node->osc_abort = true;
            delete evlog;
            goto error; 
        }
        delete  evlog;
    }

error:
    sprintf(osc_output, "[Binlog thread] Binlog catch thread exit");
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    sql_cache_node->dump_on = false;
    delete mi;
    delete thd;
    my_thread_end();
    pthread_exit(0);
    return false;
}

str_t*
inception_get_sql_execute_element(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
{
    mts_thread_t* mts_thread;
    mts_thread_queue_t* mts_queue;
    int dequeue_index;
    int enqueue_index;

    mts_thread = sql_cache_node->mts_queue;
    mts_thread->event_count += 1;
    
retry:
    //queue is not full
    dequeue_index = mts_thread->dequeue_index;
    enqueue_index = mts_thread->enqueue_index;
    if ((enqueue_index+1) % 1000 != dequeue_index)
    {
        mts_queue = &mts_thread->thread_queue[mts_thread->enqueue_index];
        sql_cache_node->current_element = mts_queue;
        mts_thread->enqueue_index = (enqueue_index + 1) % 1000;
        return &mts_queue->sql_buffer;
    }
    else
    {
        //queue is full, wait to consume
        if (inception_biosc_abort(thd, sql_cache_node))
            return NULL;
        // sleep(1);
        goto retry;
    }

    return NULL;
}

int 
inception_create_event_queue(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
{
    mts_thread_t* mts_thread;
    mts_thread_queue_t* mts_queue;
    int j;

    mts_thread = (mts_thread_t*)my_malloc(sizeof(mts_thread_t), MY_ZEROFILL);
    mts_thread->thread_queue = (mts_thread_queue_t*)my_malloc(
        sizeof(mts_thread_queue_t) * 1000, MY_ZEROFILL);
    mts_thread->dequeue_index = 0;
    mts_thread->enqueue_index = 0;
    mts_thread->last_tid = 0;
    mts_thread->last_eid = 0;
    mts_thread->datacenter = NULL;
    for (j = 0; j < 1000; j++)
    {
        mts_queue = &mts_thread->thread_queue[j];
        mysql_mutex_init(NULL, &mts_queue->element_lock, MY_MUTEX_INIT_FAST);
        mts_queue->valid = false;
        str_init(&mts_queue->sql_buffer);
        str_init(&mts_queue->commit_sql_buffer);
    }

    sql_cache_node->mts_queue = mts_thread;
    // mysql_mutex_init(NULL, &sql_cache_node->mts_lock, MY_MUTEX_INIT_FAST);
    // mysql_cond_init(NULL, &sql_cache_node->mts_cond, NULL);
    return false;
}

int 
inception_get_connection_id(
    THD*  thd,
    MYSQL* mysql,
    sql_cache_node_t* sql_cache_node
)
{
    MYSQL_RES *source_res1;
    MYSQL_ROW  source_row;
    char      osc_output[1024];
    char      connectionid[1024];
    sprintf(connectionid, "select connection_id()");

    if (mysql_real_query(mysql, connectionid, strlen(connectionid)) ||
       (source_res1 = mysql_store_result(mysql)) == NULL)
    {
        return true;
    }

    source_row = mysql_fetch_row(source_res1);
    if (source_row == NULL)
    {
        mysql_free_result(source_res1);
        return true;
    }

    sql_cache_node->rename_connectionid = strtoul(source_row[0], 0, 10);
    mysql_free_result(source_res1);
    sprintf(osc_output, "[rename thread] Rename table thread get connection_id: %d",
        sql_cache_node->rename_connectionid);
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    return false;
}

pthread_handler_t inception_rename_to_block_request_thread(void* arg)
{
    THD *thd= NULL;
    THD *query_thd= NULL;
    sql_cache_node_t* sql_cache_node;
    char      rename_sql[1024];
    char      set_var_sql[1024];
    char      osc_output[1024];
    MYSQL*    mysql;
    int       ret;
    struct timespec abstime;

    my_thread_init();
    thd= new THD;
    thd->thread_stack= (char*) &thd;

    sql_cache_node = (sql_cache_node_t*)arg;
    query_thd = sql_cache_node->thd;

    setup_connection_thread_globals(thd);

    /* TODO:
     * 将这两个参数参数化 */
    sprintf(set_var_sql, "set session lock_wait_timeout=%d," 
        "session innodb_lock_wait_timeout=%d;", LOCK_TIME_WAIT, 1);

    sprintf(rename_sql, "RENAME TABLE `%s`.`%s` TO `%s`.`%s`, `%s`.`%s` TO `%s`.`%s`", 
        str_get(&sql_cache_node->tables.db_names), str_get(&sql_cache_node->tables.table_names),
        str_get(&sql_cache_node->tables.db_names), sql_cache_node->biosc_old_tablename, 
        str_get(&sql_cache_node->tables.db_names), sql_cache_node->biosc_new_tablename, 
        str_get(&sql_cache_node->tables.db_names), str_get(&sql_cache_node->tables.table_names));

    while (!inception_biosc_abort(thd, sql_cache_node))
    {
        /* 注定是不能被执行成功的，开始执行前，必须要被主线程通知
         * 在inception_rename_table中通知，只有当原表被上锁之后
         * 这个RENAME才会被执行，然后这个执行操作会被阻塞，直到
         * 重命名表操作结束，那么这个语句就执行退出，或者超时 */

        /* waiting the master thread to lock the origin table and new table */
        sql_cache_node->rename_connectionid = 0;
        sprintf(osc_output, "[rename thread] Rename table thread start to waiting");
        mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
        mysql_mutex_lock(&sql_cache_node->osc_lock);
        mysql_cond_wait(&sql_cache_node->rename_ready_cond, &sql_cache_node->osc_lock);
        mysql_mutex_unlock(&sql_cache_node->osc_lock);
        sprintf(osc_output, "[rename thread] Rename table thread is awake");
        mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);

        if ((mysql = inception_init_binlog_connection(query_thd->thd_sinfo->host, 
                query_thd->thd_sinfo->port, query_thd->thd_sinfo->user, 
                query_thd->thd_sinfo->password)) != NULL)
        {
            if (inception_get_connection_id(thd, mysql, sql_cache_node) ||
                mysql_execute_sql_with_retry(thd, mysql, set_var_sql, NULL))
            {
                sprintf(osc_output, "[rename thread] Alter table abort");
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                sql_cache_node->osc_abort = true;
                break;
            }

            sprintf(osc_output, "[rename thread] Rename table start "
                "to blocking, timout: %d", LOCK_TIME_WAIT);
            mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
            if ((ret = mysql_execute_sql_with_retry(thd, mysql, rename_sql, NULL)) > 0)
            {
                if (ret == 1205/* ER_LOCK_WAIT_TIMEOUT */)
                {
                    sprintf(osc_output, "[rename thread] Table rename timeout(%d)", 
                        LOCK_TIME_WAIT);
                    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                    sql_cache_node->rename_timeout = true;
                }
                else
                {
                    sprintf(osc_output, "[rename thread] Alter table abort");
                    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                    sql_cache_node->osc_abort = true;
                    break;
                }
            }
            else
            {
                sprintf(osc_output, "[rename thread] Successfully altered `%s`.`%s`.", 
                    str_get(&sql_cache_node->tables.db_names), 
                    str_get(&sql_cache_node->tables.table_names));
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                sql_cache_node->osc_complete = true;

                sprintf(osc_output, "[Master thread] Increament SQL consume over, "
                    "exactly %d rows, including %d insert(s), %d update(s), %d delete(s)", 
                    sql_cache_node->mts_queue->event_count, 0, 0, 0);
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);

                sprintf(osc_output, "[rename thread] Locked table for %lld(ms)", 
                    (my_getsystime() - sql_cache_node->start_lock_time)/10000);
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
            }
        }
        
        mysql_cond_signal(&sql_cache_node->alter_status);
    }

    sprintf(osc_output, "[rename thread] Rename thread exit");
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    delete thd;
    my_thread_end();
    pthread_exit(0);
    return NULL;
}

MYSQL* inception_get_connection_with_retry(
    THD*  thd
)
{
    MYSQL*  mysql;
    int       retry_count = 0;

retry:
    mysql = thd->get_audit_connection();
    if (!mysql)
    {
        if (retry_count < 3)
        {
            retry_count++;
            goto retry;
        }

        return NULL;
    }

    return mysql;
}

int inception_catch_rename_blocked_in_processlist(
    THD*  thd,
    sql_cache_node_t* sql_cache_node,
    int   not_found
)
{
    char      processlist[1024];
    MYSQL_RES *source_res1;
    MYSQL_ROW  source_row;
    MYSQL*    mysql;
    int       rows;
    struct timespec abstime;
    int       first_time = true;
    char      osc_output[1024];

    /* SLEEP 100ms and then retry */
    set_timespec_nsec(abstime, 100 * 1000000ULL);

    sprintf(osc_output, "[Master thread] try to catch connection_id");
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
retry:
    while(!inception_biosc_abort(thd, sql_cache_node))
    {
        if (sql_cache_node->rename_timeout)
            return 2;

        if (sql_cache_node->rename_connectionid)
        {
            if (first_time)
            {
                sprintf(osc_output, "[Master thread] get the rename connection_id: %d", 
                    sql_cache_node->rename_connectionid);
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                first_time = false;
            }

            if (!(mysql = inception_get_connection_with_retry(thd)))
            {
                mysql_errmsg_append(thd);
                return 1;
            }

            sprintf(processlist, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID=%d "
                "AND COMMAND ='Query' AND STATE LIKE 'Waiting for table metadata lock%%'", 
                sql_cache_node->rename_connectionid);
            if (mysql_real_query(mysql, processlist, strlen(processlist)) ||
               (source_res1 = mysql_store_result(mysql)) == NULL)
            {
                my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
                mysql_errmsg_append(thd);
                return 1;
            }

            source_row = mysql_fetch_row(source_res1);
            if (!not_found && strtoul(source_row[0], 0, 10) == 1)
            {
                sprintf(osc_output, "[Master thread] Found the blocked rename table thread");
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                mysql_free_result(source_res1);
                return 0;
            }

            if (not_found && strtoul(source_row[0], 0, 10) == 0)
            {
                sprintf(osc_output, "[Master thread] Found the blocked rename table thread");
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                mysql_free_result(source_res1);
                return 0;
            }

            mysql_free_result(source_res1);
        }

        mysql_mutex_lock(&thd->sleep_lock);
        mysql_cond_timedwait(&thd->sleep_cond, &thd->sleep_lock, &abstime);
        mysql_mutex_unlock(&thd->sleep_lock);
    }

    /* 中止了 */
    return 1;
}

int inception_finish_event_queue(
    THD*              thd,
    MYSQL*            mysql,
    sql_cache_node_t* sql_cache_node
)
{
    str_t*    execute_sql;
    execute_sql = inception_event_dequeue(thd, sql_cache_node);
    while (execute_sql)
    {
        if (mysql_execute_sql_with_retry(thd, mysql, str_get(execute_sql), NULL))
        {
            return true;
            break;
        }

        sql_cache_node->mts_queue->dequeue_index = 
          (sql_cache_node->mts_queue->dequeue_index+1) % 1000;
        execute_sql = inception_event_dequeue(thd, sql_cache_node);
    }

    return false;
}

/*
 * return values:
 * 0. 改表成功
 * 1. 出错了，放弃改表
 * 2. 可以继续改，重新来过
 * */
int inception_catch_blocked_rename(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
{
    int ret;
    int not_found = false;
    int retry_count =  0;
    char      osc_output[1024];

retry:
    if (inception_biosc_abort(thd, sql_cache_node) || retry_count++ > 3)
        return 1;

    /* 出错了，这里有两种可能：
     * 1. 已经阻塞，但这个函数失败了，出错了，或者连不上
     * 2. 已经超时返回了，所以没有找到
     * */
    if ((ret = inception_catch_rename_blocked_in_processlist(thd, 
          sql_cache_node, not_found)) == 2)
    {
        sql_cache_node->rename_timeout = false;
        return 2;
    }
    else if (ret == 0 && !not_found)
    {
        /* 这里还不能完全肯定表已经被改完，而必须是在RENAME
         * 成功返回0的时候才表示表已经改完，所以不能在这里标记 
         * 原因是，假设这里标志了，但正要解锁的时候，RENAME
         * TIMEOUT了，那么表就不会被改完，则还需要继续重来*/
        return 0;
    }
    else if (ret == 0 && not_found)
    {
        /* 说明已经超时，可以得新来过 */
        sprintf(osc_output, "[Master thread] Blocked rename thread have disappeared, retry");
        mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
        return 2;
    }
    else 
    {
        /* inception_catch_rename_blocked_in_processlist 本身出错了
         * 解决办法是等待超时，然后放弃改表 */
        not_found = true;
        goto retry;
    }

    /* impossible come here */
    return false;
}

int inception_cleanup_biosc(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
{
    return false;
}

int inception_wait_biosc_complete(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
{
    struct    timespec abstime;
    set_timespec_nsec(abstime, 200 * 1000000ULL);
    while (true)
    {
        mysql_mutex_lock(&sql_cache_node->osc_lock);
        mysql_cond_timedwait(&sql_cache_node->alter_status, 
            &sql_cache_node->osc_lock, &abstime);
        mysql_mutex_unlock(&sql_cache_node->osc_lock);
        if (inception_biosc_abort(thd, sql_cache_node))
            return true;

        if (sql_cache_node->rename_timeout)
            return false;
    }

    return false;
}


int inception_rename_table(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
{
    MYSQL*    mysql = NULL;
    char      lock_sql[1024];
    char      new_table_lock_sql[1024];
    char      set_var_sql[1024];
    int       locked = false;
    int       ret;
    struct    timespec abstime;
    char      unlock_tables[1024];
    ulonglong start_lock_time = 0;
    str_t*    execute_sql;
    pthread_t threadid;
    int       lock_count = 0;
    char      osc_output[1024];

    sprintf(lock_sql, "LOCK TABLES `%s`.`%s` WRITE, `%s`.`%s` WRITE", 
        str_get(&sql_cache_node->tables.db_names), 
        str_get(&sql_cache_node->tables.table_names),
        str_get(&sql_cache_node->tables.db_names), 
        sql_cache_node->biosc_new_tablename);
    sprintf(unlock_tables, "UNLOCK TABLES");

    sprintf(osc_output, "[Master thread] Create the rename table thread");
    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    if (mysql_thread_create(0, &threadid, &connection_attrib,
        inception_rename_to_block_request_thread, (void*)sql_cache_node))
    {
        my_message(ER_CREATE_THREAD_ERROR, "rename table", MYF(0));
        mysql_errmsg_append(thd);
        sql_cache_node->osc_abort = true;
        goto error;
    }

    /* TODO:
     * 将这两个参数参数化 */
    sprintf(set_var_sql, "set session lock_wait_timeout=%d," 
        "session innodb_lock_wait_timeout=%d;", LOCK_TIME_WAIT, 1);

    sprintf(osc_output, "[Master thread] Start to consume the increament SQL");
reconnect:
    if (!(mysql = inception_get_connection_with_retry(thd)))
    {
        mysql_errmsg_append(thd);
        sql_cache_node->osc_abort = true;
        goto error;
    }

    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    while(!inception_biosc_abort(thd, sql_cache_node))
    {
        /* 如果COPY数据已经完成，则处理换表名的事儿 */
        if (!sql_cache_node->biosc_copy_complete)
        {
            execute_sql = inception_event_dequeue(thd, sql_cache_node);
            if (execute_sql)
            {
                if (mysql_execute_sql_with_retry(thd, mysql, str_get(execute_sql), NULL))
                    goto reconnect;
                sql_cache_node->mts_queue->dequeue_index = 
                  (sql_cache_node->mts_queue->dequeue_index+1) % 1000;
            }
        }
        else if (sql_cache_node->biosc_copy_complete == true)
        {
            if (mysql_execute_sql_with_retry(thd, mysql, set_var_sql, NULL))
                goto reconnect;
            /* TODO: 判断有没有延迟，如果延迟比较长的话，还不能去锁表 */
            if (!locked)
            {
                /* 如果没有上锁成功，则需要重新再来 */
                sprintf(osc_output, "[Master thread] Lock origin table and new table, "
                    "retry: %d", lock_count++);
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                if (mysql_execute_sql_with_retry(thd, mysql, lock_sql, NULL))
                    goto reconnect;

                inception_get_master_status(thd, sql_cache_node, true);
                sprintf(osc_output, "[Master thread] The end binlog position is (%s:%d)", 
                    sql_cache_node->end_binlog_file, sql_cache_node->end_binlog_pos);
                mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                start_lock_time = my_getsystime();
                sql_cache_node->start_lock_time = start_lock_time;
                locked = true;
            }
            else
            {
                /* 如果当前Binlog位置已经大于上锁之后的位置了，则说明
                 * 这个位置之后，再不会有这个表的Binlog了，则可以做RENAME了 */
                if (inception_finish_event_queue(thd, mysql, sql_cache_node))
                    goto reconnect;

                mysql_mutex_lock(&sql_cache_node->osc_lock); 
                ret = mysql_binlog_position_compare(
                    sql_cache_node->current_binlog_file, sql_cache_node->current_binlog_pos, 
                      sql_cache_node->end_binlog_file, sql_cache_node->end_binlog_pos);
                mysql_mutex_unlock(&sql_cache_node->osc_lock); 

                /* 如果一直没有找到上锁之后的位置，则通过参数计时，超过这个时间
                 * 需要再解锁，保证不影响线上 */
                if (my_getsystime() - start_lock_time > RENAME_TIME_PERIOD)
                {
                    sprintf(osc_output, "[Master thread] Table locked timeout, "
                        "unlock them and retry");
                    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
                    if (mysql_execute_sql_with_retry(thd, mysql, unlock_tables, NULL))
                        goto reconnect;
                    locked = false;
                }

                /* 这里如果返回值大于等于0，则说明Binlog已经追上了，此时就可以
                 * 做重命名表的工作了，但即使已经追上了，但此时已经锁表，时间
                 * 如果超过设置时间，就不能去RENAME了，需要重新等机会 */
                if (my_getsystime() - start_lock_time < RENAME_TIME_PERIOD && ret >= 0)
                {
                    /* make sure all events are finished */
                    if (inception_finish_event_queue(thd, mysql, sql_cache_node))
                        goto reconnect;

                    sprintf(osc_output, "[Master thread] Notify the rename thread to start work");
                    mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);

                    /* 通知RENAME线程去做RENAME TABLE操作 */
                    sql_cache_node->rename_connectionid = 0;
                    mysql_cond_signal(&sql_cache_node->rename_ready_cond);
                    /* 然后等待PROCESSLIST 出现被阻塞的RENAME语句，如果有了
                     * 则就可以做两个表的非原子ALTER TABLE RENAME TO了 */
                    if ((ret = inception_catch_blocked_rename(thd, sql_cache_node)) == 1)
                    {
                        sql_cache_node->osc_abort = true;
                        break;
                    }
                    else
                    {
                        /* 两种可能：成功改表及需要重来，不管哪种，都需要将表锁释放掉*/
                        locked = false;
                        /* 下面的解锁操作，不管成功还是失败，结果都是一样的，通过等待
                         * RENAME线程的结果来判断得新来还是放弃改表，或者成功改表 */
                        mysql_execute_sql_with_retry(thd, mysql, unlock_tables, NULL);
                        /* 如果已经完成，则这里就结束了，否则就重新来过 */
                        if (inception_wait_biosc_complete(thd, sql_cache_node))
                            break;
                        else
                            goto reconnect;
                    }
                }
            }
        }
        else /* sql_cache_node->biosc_copy_complete == 2: error abort */
        {
            sql_cache_node->osc_abort = true;
            break;
        }
    }

error:
    if (sql_cache_node->osc_abort)
    {
        sprintf(osc_output, "[Master thread] Alter table abort");
        mysql_analyze_biosc_output(thd, osc_output, sql_cache_node);
    }

    /* notify the rename thread to exit */
    mysql_cond_signal(&sql_cache_node->rename_ready_cond);
    return false;
}

