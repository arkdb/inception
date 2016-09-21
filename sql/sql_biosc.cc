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
#include "errmsg.h"

pthread_handler_t inception_move_rows_thread(void* arg);
int inception_get_master_status( THD* thd, sql_cache_node_t* sql_cache_node);
int inception_catch_binlog( THD*  thd, sql_cache_node_t* sql_cache_node);

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
    str_append(&new_sql, mysql_get_alter_table_post_part(
        thd, statement, sql_cache_node->ignore));

    /* create new table statement */
    str_append(&new_create_sql, "CREATE TABLE ");
    str_append(&new_create_sql, str_get(&sql_cache_node->tables.db_names));
    str_append(&new_sql, ".");
    str_append(&new_sql, new_tablename);
    str_append(&new_sql, "LIKE ");
    str_append(&new_create_sql, str_get(&sql_cache_node->tables.db_names));
    str_append(&new_sql, ".");
    str_append(&new_sql, str_get(&sql_cache_node->tables.table_names));

    strcpy(sql_cache_node->biosc_new_tablename, new_tablename);
    strcpy(sql_cache_node->biosc_old_tablename, old_tablename);

    /* show MASTER STAUTS FIRST, and then copy rows */
    inception_get_master_status(thd, sql_cache_node);

    /* start to catch binlog */
    if (mysql_thread_create(0, &threadid, &connection_attrib,
        inception_move_rows_thread, (void*)sql_cache_node))
    {
        return true;
    }

    inception_catch_binlog(thd, sql_cache_node);

    str_deinit(&new_table_name);
    str_deinit(&new_create_sql);
    str_deinit(&new_sql);
    return false;
}

int
inception_get_master_status(
    THD* thd, 
    sql_cache_node_t* sql_cache_node
)
{
    MYSQL_RES *source_res1;
    MYSQL_ROW  source_row;
    MYSQL* mysql;
    char    tmp[128];

    mysql = thd->get_audit_connection();

    sprintf (tmp, "SHOW MASTER STATUS");
    if (mysql_real_query(mysql, tmp, strlen(tmp)) ||
       (source_res1 = mysql_store_result(mysql)) == NULL)
        return true;

    source_row = mysql_fetch_row(source_res1);
    if (source_row == NULL)
    {
        mysql_free_result(source_res1);
        return true;
    }

    strcpy(sql_cache_node->start_binlog_file, source_row[0]);
    sql_cache_node->start_binlog_pos = strtoul(source_row[1], 0, 10);
    mysql_free_result(source_res1);
    return false;
}

int inception_biosc_abort(THD* thd)
{
    if ((!abort_loop || (thd != NULL && thd->killed)))
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
                    dupcharfieldforbackslash = (char*)my_malloc((res->length() * 4 + 1) * 2, MY_ZEROFILL);
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
            str_get(&sql_cache_node->tables.table_names));
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
                update_after ? field_node->conv_field_after : field_node->conv_field,
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
            str_get(&sql_cache_node->tables.table_names));

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
            str_get(&sql_cache_node->tables.table_names));
        str_append(backup_sql, tmp_buf);
        field_node = LIST_GET_FIRST(mi->table_info->field_lst);
        while (field_node != NULL)
        {
            if (!first)
                str_append(backup_sql, ",");

            sprintf(tmp_buf, "%s=", field_node->field_name);
            str_append(backup_sql, tmp_buf);
            err = inception_get_field_string(
                update_after ? field_node->conv_field_after : field_node->conv_field,
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
                    update_after ? field_node->conv_field_after : field_node->conv_field,
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

int inception_execute_sql_with_retry(
    THD* thd, 
    char* tmp
)
{
    MYSQL* mysql;
    int retry_count=0;

retry:
    retry_count++;
    mysql = thd->get_audit_connection();
    if (mysql == NULL)
        goto error;

    if (mysql_real_query(mysql, tmp, strlen(tmp)))
    {
        goto error;
    }

    return false;

error:
    if (retry_count < 3)
        goto retry;

    return true;
}

int inception_biosc_write_row(
    Master_info *mi, 
    Log_event* ev,
    int optype,
    sql_cache_node_t* sql_cache_node
)
{
    Write_rows_log_event*  write_ev;
    int       error= 0;
    str_t* backup_sql;
    str_t backup_sql_buf;
    str_t   pk_string;
    table_info_t* table_info;

    DBUG_ENTER("inception_biosc_write_row");
    write_ev = (Write_rows_log_event*)ev;

    str_init(&pk_string);
    str_init(&backup_sql_buf);
    backup_sql = &backup_sql_buf;

    table_info = mysql_get_table_info_by_id(mi, write_ev->get_table_id());
    if (table_info == NULL)
        DBUG_RETURN(error);
        
    do
    {
        str_truncate_0(&pk_string);
        if (mysql_unpack_row(mi, write_ev->get_table_id(), write_ev->m_curr_row, 
              write_ev->get_cols(), &write_ev->m_curr_row_end, write_ev->m_rows_end, false))
        {
            error=true;
            goto error;
        }

        write_ev->m_curr_row = write_ev->m_curr_row_end;

        // inception_transfer_make_one_row_primary_key(mi, &pk_string, false);
        if (optype == SQLCOM_UPDATE)
        {
            if (mysql_unpack_row(mi, write_ev->get_table_id(), write_ev->m_curr_row, 
                  write_ev->get_cols(), &write_ev->m_curr_row_end, write_ev->m_rows_end, true))
            {
                error=true;
                goto error;
            }

            write_ev->m_curr_row = write_ev->m_curr_row_end;
            // inception_transfer_make_one_row_primary_key(mi, &pk_string, true);
        }

        str_truncate_0(backup_sql);
        if (mysql_generate_biosc_increment_sql(mi, optype, 
              backup_sql, sql_cache_node, false))
        {
            error=true;
            goto error;
        }

        if (optype != SQLCOM_UPDATE)
        {
            if (inception_execute_sql_with_retry(mi->thd, str_get(backup_sql)))
            {
                error=true;
                goto error;
            }
        }
        else /*(optype == SQLCOM_UPDATE)*/
        {
            if (mysql_generate_biosc_increment_sql(mi, 
                  SQLCOM_UPDATE+1000, backup_sql, sql_cache_node, true))
            {
                error=true;
                goto error;
            }

            if (inception_execute_sql_with_retry(mi->thd, str_get(backup_sql)))
            {
                error=true;
                goto error;
            }
        }
    }while(!error && write_ev->m_rows_end != write_ev->m_curr_row);

    str_deinit(&pk_string);
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
    MYSQL_RES *source_res1,
    MYSQL_ROW  source_row,
    int       col_count,
    int       gol
)
{
    int       i=0;
    int       field_num;

    mysql_data_seek2(source_res1, 0);
    source_row = mysql_fetch_row(source_res1);
    field_num = mysql_num_fields(source_res1);
    while (source_row)
    {
        for (i = 0; i < col_count; i ++)
        {
            str_append(next_where, sql_cache_node->primary_keys[i]);
            if (col_count - 1 == col_count)
            {
                if (gol)
                    str_append(next_where, ">");
                else
                    str_append(next_where, "<");
            }
            else
            {
                str_append(next_where, "=");
            }
            str_append(next_where, "\'");
            str_append(next_where, source_row[i]);
            str_append(next_where, "\'");
        }

        source_row = mysql_fetch_row(source_res1);
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
    str_append(copy_rows_sql, ") AND (");
    str_append(copy_rows_sql, str_get(behind_sql));
    str_append(copy_rows_sql, ") LOCK IN SHARE MODE");
    
    return false;
}

int inception_get_table_select_where(
    THD*              thd,
    str_t*            select_sql,
    str_t*            front_sql,
    str_t*            behind_sql,
    sql_cache_node_t* sql_cache_node
)
{
    int           field_num;
    int           i;
    MYSQL_RES *source_res1;
    MYSQL_ROW  source_row;
    MYSQL*      mysql;

    mysql = thd->get_audit_connection();
    if (mysql_real_query(mysql, str_get(select_sql), str_get_len(select_sql)) ||
       (source_res1 = mysql_store_result(mysql)) == NULL)
        return true;

    field_num = mysql_num_fields(source_res1);

    source_row = mysql_fetch_row(source_res1);
    for (i = 0; i < field_num; i ++)
    {
        if (i != 0)
            str_append(front_sql, " OR ");
        inception_get_table_select_where_low(sql_cache_node, front_sql, source_res1, source_row, i, false);
    }

    source_row = mysql_fetch_row(source_res1);
    for (i = 0; i < field_num && source_row; i ++)
    {
        if (i != 0)
            str_append(behind_sql, " OR ");
        inception_get_table_select_where_low(sql_cache_node, behind_sql, source_res1, source_row, i, true);
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
        
        sql_cache_node->primary_keys = (char**)my_malloc(pkcount, MY_ZEROFILL);
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
        str_append(select_sql, " WHERE");
        str_append(select_sql, str_get(greater_cond_sql));
        str_append(select_sql, " ORDER BY ");
        str_append(select_sql, str_get(primary_cols));
        /* TODO: 将分片大小参数化，这里先认定2000 */
        str_append(select_sql, " LIMIT 2000, 2");
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
    Master_info* mi;
    MYSQL* mysql = NULL;
    char* binlog_file = NULL;
    int binlog_position = 0;
    int retrycount = 0;
    time_t skr;
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

    my_thread_init();

    thd= new THD;

    sql_cache_node = (sql_cache_node_t*)arg;
    mi = new Master_info(1);
    mi->thd = thd;
    thd->thread_stack= (char*) &thd;

    pthread_detach_this_thread();
    mi->info_thd = thd;

    setup_connection_thread_globals(thd);
    inception_init_slave_thread(thd);

    thd->query_thd = NULL;
    binlog_file = sql_cache_node->start_binlog_file;
    binlog_position = sql_cache_node->start_binlog_pos;
    sql_print_information("transfer started, start position: %s : %d", 
        binlog_file, binlog_position);
    str_init(&primary_cols);
    str_init(&copy_rows_sql);
    str_init(&select_prefix);
    str_init(&execute_sql);
    str_init(&change_sql);
    change_cond_sql = &change_sql;
    greater_cond_sql = &front_sql;
    lesser_cond_sql = &behind_sql;

reconnect:
    mysql_close(mysql);
    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        if (!inception_biosc_abort(thd) && retrycount++ < 3)
        {
            sql_print_information("Forcing to reconnect master");
            goto reconnect;
        }
        goto error; 
    }


    inception_get_table_primary_keys(thd, sql_cache_node, &primary_cols);
    inception_get_copy_rows_batch_sql_prefix(
        &select_prefix, &primary_cols, sql_cache_node);

    inception_get_copy_rows_batch_sql(&select_prefix, NULL, &primary_cols, 
        &execute_sql, sql_cache_node, true);
    while(!inception_biosc_abort(thd))
    {
        inception_get_table_select_where(thd, &execute_sql, 
            lesser_cond_sql, greater_cond_sql, sql_cache_node);

        if (str_get_len(greater_cond_sql) > 0)
        {
            /* 得到一个分片查询的语句,目标串为copy_rows_sql */
            inception_get_table_rows_copy_sql(thd, &copy_rows_sql, 
                &select_prefix, change_cond_sql, lesser_cond_sql);
            /* 得到用来取得下一个分片的边界 */
            inception_get_copy_rows_batch_sql(&select_prefix, greater_cond_sql, 
                &primary_cols, &execute_sql, sql_cache_node, false);
            str_truncate_0(lesser_cond_sql);
            str_truncate_0(change_cond_sql);
            inception_swap_str(&change_cond_sql, &greater_cond_sql);
        }
        else
        {
            inception_swap_str(&change_cond_sql, &lesser_cond_sql);
            str_truncate_0(lesser_cond_sql);
        }
    }

error:
    sql_print_information("Copy rows complete");
    skr= my_time(0);
    delete mi;
    delete thd;
    my_thread_end();
    pthread_exit(0);
    return NULL;
}

int inception_catch_binlog(
    THD*  thd,
    sql_cache_node_t* sql_cache_node
)
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

    mi = new Master_info(1);
    mi->thd = thd;
    mi->info_thd = thd;

    binlog_file = sql_cache_node->start_binlog_file;
    binlog_position = sql_cache_node->start_binlog_pos;
    sql_print_information("transfer started, start position: %s : %d", 
        binlog_file, binlog_position);

reconnect:
    mysql_close(mysql);
    mysql = thd->get_audit_connection();
    if (mysql == NULL)
    {
        if (!inception_biosc_abort(thd) && retrycount++ < 3)
        {
            sql_print_information("Forcing to reconnect master");
            goto reconnect;
        }
        goto error; 
    }

    if (mysql_get_master_version(mysql, mi) || 
        register_slave_on_master(mysql, &suppress_warnings, server_id) ||
        mysql_request_binlog_dump(mysql, binlog_file, binlog_position, server_id))
    {
        if (!inception_biosc_abort(thd) && retrycount++ < 3)
        {
            sql_print_information("Forcing to reconnect master");
            goto reconnect;
        }
        goto error; 
    }

    while(!inception_biosc_abort(thd))
    {
        ulong event_len;

        event_len = mysql_read_event_for_transfer(mi, mysql);
        event_buf= (char*)mysql->net.read_pos + 1;
        if (event_len == packet_error)
        {
            if (mysql_errno(mysql) == CR_NET_PACKET_TOO_LARGE ||
                mysql_errno(mysql) == ER_MASTER_FATAL_ERROR_READING_BINLOG ||
                mysql_errno(mysql) == ER_OUT_OF_RESOURCES)
            {
                goto error;
            }

            if (!inception_biosc_abort(thd) && retrycount++ < 3)
                goto reconnect;
        }

        retrycount = 0;
        if (mysql_process_event(mi, event_buf, event_len, &evlog) || evlog == NULL)
            goto error;

        binlog_file = (char*)mi->get_master_log_name();
        binlog_position = mi->get_master_log_pos();
        if (inception_biosc_binlog_process(mi, evlog, sql_cache_node))
        {
            delete evlog;
            goto error; 
        }
        delete  evlog;
    }

error:
    sql_print_information("transfer stopped");
    skr= my_time(0);
    delete mi;
    return false;
}

