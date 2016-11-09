/* Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include "sql_parse.h"
#include "mysqld.h"
#include <string.h>
#include "sql_db.h"
#include "sql_common.h"
#include "derror.h"
#include "mysys_err.h"
#include "item_subselect.h"
#include "set_var.h"
#include "sql_connect.h"

#define PROGRESS_ALL_STARTED  (char*)"started"
#define PROGRESS_ALL_RUNNING  (char*)"running"
#define PROGRESS_ALL_STOPED   (char*)"stoped"
#define PROGRESS_ALL_FINISHED (char*)"finished"

#define PROGRESS_DETAIL_RUNNING    (char*)"running"
#define PROGRESS_DETAIL_FAILED     (char*)"failed"
#define PROGRESS_DETAIL_STOPED     (char*)"stoped"
#define PROGRESS_DETAIL_FINISHED   (char*)"finished"

#define TABLE_ID_STEPS                100
#define CACHE_QUEUE_LENGTH            1000

#define COLLECTOR_RULE_ALL            0
#define COLLECTOR_RULE_CARDINALITY    1

#define FIELD_VALUE_FORE                  0
#define FIELD_VALUE_TMP                   1
#define FIELD_VALUE_HIND                  2

#define THREAD_SLEEP_NSEC                 1

extern collector_t global_collector_cache;
extern mysql_mutex_t collector_cache_mutex;
extern mysql_mutex_t collector_idle_mutex;
extern bool inception_collector_on;
extern int inception_collector_idle;
extern int inception_collector_running_worker;
extern int inception_collector_rule;//按位标志性---0:all; 1:cardinality

void str_replace(char* str_src, char* str_find, char* str_replace)
{
    while (*str_src != '\0')
    {
        if (*str_src == *str_find)
        {
            if (strncmp(str_src, str_find, strlen(str_find)) == 0)
            {
                int i = strlen(str_find);
                char* q = str_src+i;
                char* p = q;//p、q均指向剩余字符串的首地址
                char* repl = str_replace;
                int lastLen = 0;
                while (*q++ != '\0')
                    lastLen++;
                char* temp = new char[lastLen+1];//临时开辟一段内存保存剩下的字符串,防止内存覆盖
                for (int k = 0; k < lastLen; k++)
                {
                    *(temp+k) = *(p+k);
                }
                *(temp+lastLen) = '\0';
                while (*repl != '\0')
                {
                    *str_src++ = *repl++;
                }
                p = str_src;
                char* pTemp = temp;//回收动态开辟内存
                while (*pTemp != '\0')
                {
                    *p++ = *pTemp++;
                }
                delete[] temp;
                *p = '\0';
            }
            else
                str_src++;
        }
        else
            str_src++;
    }
}

int init_mysql_connection(MYSQL* conn, char* host, uint port, char* user, char* password, char* db)
{
    MYSQL* mysql = conn;
    ulong client_flag= CLIENT_REMEMBER_OPTIONS ;
    uint net_timeout= 3600*24;
    bool reconnect= TRUE;
    
    mysql_init(mysql);
    mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (char *) &net_timeout);
    mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, (char *) &net_timeout);
    mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, (char *) &net_timeout);
    mysql_options(mysql, MYSQL_SET_CHARSET_NAME, "utf8mb4");
    mysql_options(mysql, MYSQL_SET_CHARSET_DIR, (char *) charsets_dir);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, (bool*)&reconnect);
    
    if (mysql_real_connect(mysql, host, user,
                           password, db, port, NULL, client_flag) == 0)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        mysql_close(mysql);
        return FALSE;
    }

    return TRUE;
}

int get_mysql_connection(MYSQL* conn, char* host, uint port, char* user, char* password, char* db)
{
    if (port== 0 ||
        user== NULL || user[0] == '\0' ||
        host== NULL || host[0] == '\0' ||
        password== NULL || password[0] == '\0')
    {
        my_error(ER_INVALID_TRANSFER_INFO, MYF(0));
        return NULL;
    }
    if (init_mysql_connection(conn, host, port, user, password, db) == FALSE)
        return NULL;
    else
        return FALSE;
}

MYSQL_RES* get_mysql_res(MYSQL* conn, char* sql)
{
    if (mysql_real_query(conn, sql, strlen(sql)))
    {
        if (mysql_errno(conn) != 1050 && mysql_errno(conn) != 1007/*ER_TABLE_EXISTS_ERROR*/)
        {
            sql_print_information(mysql_error(conn));
            return NULL;
        }
    }
    return mysql_store_result(conn);
}

int clear_collector_cache()
{
    while (global_collector_cache.table_list.count)
    {
        collector_table_t* table_info =
               LIST_GET_FIRST(global_collector_cache.table_list);
        LIST_REMOVE(link, global_collector_cache.table_list, table_info);
        my_free(table_info);
    }
    
    return FALSE;
}

int mark_progress_all(MYSQL* conn,double progress,char* state)
{
    char tmp[512];
    
    if (inception_collector_rule == COLLECTOR_RULE_ALL
        || inception_collector_rule & COLLECTOR_RULE_CARDINALITY)
    {
        if (strcasecmp("started", state) == 0)
            sprintf (tmp, "insert into collector_data.progress_all(rule,state,progress) \
                     values('%s','%s',%lf) \
                     ON DUPLICATE KEY UPDATE start_time =now(), state='%s',progress=%lf",
                     "cardinality", state, progress, state, progress);
        else
            sprintf (tmp, "insert into collector_data.progress_all(rule,state,progress) \
                     values('%s','%s',%lf) \
                     ON DUPLICATE KEY UPDATE state='%s',progress=%lf",
                     "cardinality", state, progress, state, progress);
        
        if (get_mysql_res(conn, tmp))
            return TRUE;
    }
    
    return FALSE;
    
}

int mark_progress_detail(MYSQL* conn, collector_table_t* table_info, char* state,
                         char* info, ulong thread_id, int sum_no, int current_no)
{
    char tmp[1024];
    char replace_sql[512];
    
    if (inception_collector_rule == COLLECTOR_RULE_ALL
        || inception_collector_rule & COLLECTOR_RULE_CARDINALITY)
    {
        if (table_info == NULL)
            sprintf (tmp, "insert into collector_data.progress_detail(thread_id,rule,state, info) \
                     values(%ld,'cardinality','%s','') ON DUPLICATE KEY UPDATE state='%s', start_time=now(),\
                     info=''",
                     thread_id, state, state);
        else
        {
            strcpy(replace_sql, info);
            str_replace(replace_sql, (char*)"'", (char*)"''");
            sprintf (tmp, "insert into collector_data.progress_detail(thread_id, table_id, dest_host,\
                     dest_port, dest_db, dest_tname, rule, state, sum_no, current_no, info) values(%ld, \
                     %ld, '%s', %d, '%s', '%s', 'cardinality','%s', %d, %d, '%s') ON DUPLICATE KEY UPDATE \
                     table_id = %ld, dest_host='%s',dest_port=%d, dest_db='%s', dest_tname='%s',\
                     state='%s', sum_no=%d, current_no=%d , start_time=now(), info='%s'",\
                     thread_id, table_info->table_id,
                     table_info->host, table_info->port, table_info->db,table_info->tname,
                     state, sum_no, current_no, replace_sql, table_info->table_id, table_info->host,table_info->port,
                     table_info->db, table_info->tname, state, sum_no, current_no, replace_sql);
        }
        
        if (get_mysql_res(conn, tmp))
            return TRUE;
    }
    
    return FALSE;
}

int create_db_table(MYSQL* conn_dc, collector_table_t* table_info)
{
    MYSQL_RES* res_dc = NULL;
    char tmp[512];
    char host_[30];

    strcpy(host_, table_info->host);
    str_replace(host_, ".", "_");

    //创建采样信息存放实例的库
    sprintf (tmp, "create database collector_data_%s_%d", host_, table_info->port);
    if (get_mysql_res(conn_dc, tmp))
    {
        mysql_free_result(res_dc);
        res_dc = NULL;
        return TRUE;
    }
    //创建采样信息存放的表
    sprintf (tmp, "create table collector_data_%s_%d.cardinality_%s_%s(\
             id bigint unsigned  not null primary key auto_increment comment '主键',\
             variable varchar(32) not null default '' comment '列名', \
             value int unsigned not null default 0 comment '选择度', \
             UNIQUE KEY `uniq_variable` (`variable`) \
             )engine=innodb default charset=utf8 comment='cardinality';", host_, table_info->port,
             table_info->db, table_info->tname);
    if (get_mysql_res(conn_dc, tmp))
    {
        mysql_free_result(res_dc);
        res_dc = NULL;
        return TRUE;
    }

    return FALSE;
}

int insert_cardinality(MYSQL* mysql_dc, collector_table_t* table_info, char* var, int value)
{
    MYSQL_RES* res_dc = NULL;
    char tmp[512];
    char host_[30];
    
    strcpy(host_, table_info->host);
    str_replace(host_, ".", "_");

    sprintf (tmp, "insert into collector_data_%s_%d.cardinality_%s_%s(variable,value) values('%s',%d) \
             ON DUPLICATE KEY UPDATE value=%d;",
             host_, table_info->port,table_info->db, table_info->tname,var, value, value);
    if (get_mysql_res(mysql_dc, tmp))
    {
        mysql_free_result(res_dc);
        res_dc = NULL;
        return TRUE;
    }
    
    res_dc = NULL;
    return FALSE;
}

int need_quotation(collector_field_t* field)
{
    if (strcasecmp("bit", field->type) == 0
        || strcasecmp("tinyint", field->type) == 0
        || strcasecmp("smallint", field->type) == 0
        || strcasecmp("mediumint", field->type) == 0
        || strcasecmp("int", field->type) == 0
        || strcasecmp("bigint", field->type) == 0
        || strcasecmp("decimal", field->type) == 0
        || strcasecmp("float", field->type) == 0
        || strcasecmp("double", field->type) == 0)
        return FALSE;
    else
        return TRUE;
}

int get_field_value(collector_field_list_t* field_list, char* name, char* value, char* sign, int is_fore)
{
    collector_field_t* field = LIST_GET_FIRST(field_list->field_list);
    char field_value[256];
    while (field)
    {
        strcpy(field_value, is_fore?field->value_fore:field->value_hind);

        if (strcasecmp(name, field->name) == 0
            && strcasecmp("NULL", field_value))
        {
            if (need_quotation(field))
                sprintf(value, "%s %s ''%s''",
                        field->name, sign, field_value);
            else
                sprintf(value, "%s %s %s",
                        field->name, sign, field_value);
            return FALSE;
        }
        field = LIST_GET_NEXT(link, field);
    }
    return TRUE;
}

int set_field_value(collector_field_list_t* field_list, char* name, char* value, int type)
{
    collector_field_t* field = LIST_GET_FIRST(field_list->field_list);
    while (field)
    {
        if (strcasecmp(name, field->name) == 0)
        {
            if (type == FIELD_VALUE_FORE)
                strcpy(field->value_fore, value);
            else if (type == FIELD_VALUE_HIND)
                strcpy(field->value_hind, value);
            else
                strcpy(field->value_tmp, value);
        }
        field = LIST_GET_NEXT(link, field);
    }
    return FALSE;
}

int exchange_field_fore_and_tmp(collector_field_list_t* field_list)
{
    collector_field_t* field = LIST_GET_FIRST(field_list->field_list);
    while (field)
    {
        if (strcmp("PRI", field->key) == 0)
        {
            strcpy(field->value_fore, field->value_tmp);
            strcpy(field->value_tmp, "NULL");
            strcpy(field->value_hind, "NULL");
            if (strcasecmp("NULL", field->value_fore));
        }
        field = LIST_GET_NEXT(link, field);
    }
    return FALSE;
}

int clean_field_value(collector_field_list_t* field_list)
{
    collector_field_t* field = LIST_GET_FIRST(field_list->field_list);
    while (field)
    {
        if (strcmp("PRI", field->key) == 0)
        {
            strcpy(field->value_fore, "NULL");
            strcpy(field->value_tmp, "NULL");
            strcpy(field->value_hind, "NULL");
        }
        field = LIST_GET_NEXT(link, field);
    }
    return FALSE;
}

int assemble_fields_value(MYSQL* mysql, collector_table_t* table_info,
                          collector_field_list_t* field_list, collector_field_t* field_t, int is_first)
{
    MYSQL_RES* res = NULL;
    MYSQL_ROW row;
    char tmp[512];
    char keys[256][256];
    int count = 0;
    strcpy(tmp, "select ");
    memset(keys, 0, 256*256);
    collector_field_t* field = LIST_GET_FIRST(field_list->field_list);
    while (field)
    {
        if (strcmp("PRI", field->key) == 0)
        {
            int index = field->seq_in_index-1;
            strcpy(keys[index], field->name);
            count++;
        }
        field = LIST_GET_NEXT(link, field);
    }
    for (int i=0; i < count; ++i)
    {
        sprintf(tmp, "%s %s%s", tmp, keys[i], i+1==count?"":",");
    }
    sprintf(tmp, "%s from %s.%s force index(primary) ", tmp, table_info->db, table_info->tname);

    if (is_first)
        sprintf(tmp, "%s limit 1", tmp);
    else
    {
        sprintf(tmp, "%s where 1=1 and ", tmp);
        
        for (int j = count; j > 0; --j)
        {
            sprintf(tmp, "%s ( ", tmp);
            for (int i = 0; i< j; ++i)
            {
                char value[256];
                if (i+1 == j)
                {
                    if (get_field_value(field_list, keys[i], value, (char*)">=", true))
                    {
                        field_t->done = true;
                        return TRUE;
                    }
                    sprintf(tmp, "%s %s and", tmp, value);
                }
                else
                {
                    if (get_field_value(field_list, keys[i], value, (char*)"=", true))
                    {
                        field_t->done = true;
                        return TRUE;
                    }
                    sprintf(tmp, "%s %s and ", tmp, value);
                }
            }
            sprintf(tmp, "%s 1=1 ) ", tmp);
            if (j-1 != 0)
                sprintf(tmp, "%s or ", tmp);
        }
        sprintf(tmp, "%s limit %d, 2", tmp, table_info->steps-1);
    }
    
    res = get_mysql_res(mysql, tmp);
    row = mysql_fetch_row(res);
    if (row == NULL)
    {
        if (is_first)
        {
            field_t->done = true;
            mysql_free_result(res);
            res = NULL;
            return TRUE;
        }
    }
    else
    {
        for (int i = 0; i < count; ++i)
            set_field_value(field_list, keys[i], row[i], is_first?FIELD_VALUE_FORE:FIELD_VALUE_HIND);
    }
    row = mysql_fetch_row(res);
    if (row != NULL)
        for (int i = 0; i < count; ++i)
            set_field_value(field_list, keys[i], row[i], FIELD_VALUE_TMP);
    mysql_free_result(res);
    return FALSE;
}

int count_every_field(MYSQL* mysql, MYSQL* mysql_dc, MYSQL* mysql_collector,
                      collector_table_t* table_info, collector_field_list_t* field_list,
                      char keys[][256], int key_count, ulong thread_id)
{
    char tmp[512];
    MYSQL_RES* res = NULL;
    MYSQL_ROW row;
    collector_field_t* field = LIST_GET_FIRST(field_list->field_list);
    int current_no = 0;
next_field:
    if (field != NULL)
        assemble_fields_value(mysql, table_info, field_list, field, true);
    current_no++;
    while (field && inception_collector_on)
    {
        while (!field->done)
        {
            assemble_fields_value(mysql, table_info, field_list, field, false);
            if (field->done)
                break;
            
            int limits = table_info->steps * table_info->sample_percent;
            sprintf(tmp, "select count(*) from (select count(*) from %s.%s force index(primary) \
                    where 1=1 and ", table_info->db, table_info->tname);
            for (int j = key_count; j > 0; --j)
            {
                sprintf(tmp, "%s ( ", tmp);
                for (int i = 0; i< j; ++i)
                {
                    char value[256];
                    if (i+1 == j)
                    {
                        if (!get_field_value(field_list, keys[i], value, (char*)">=", true))
                            sprintf(tmp, "%s %s and", tmp, value);
                        if (!get_field_value(field_list, keys[i], value, (char*)"<=", false))
                            sprintf(tmp, "%s %s and", tmp, value);
                    }
                    else
                    {
                        if (!get_field_value(field_list, keys[i], value, (char*)"=", true))
                            sprintf(tmp, "%s %s and", tmp, value);
                        if (!get_field_value(field_list, keys[i], value, (char*)"=", false))
                            sprintf(tmp, "%s %s and", tmp, value);
                    }
                }
                sprintf(tmp, "%s 1=1 ) ", tmp);
                if (j-1 != 0)
                    sprintf(tmp, "%s or ", tmp);
            }
            sprintf(tmp, "%s group by %s limit %d) tmp", tmp, field->name, limits);
            mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_RUNNING,
                                 tmp, thread_id, field_list->field_list.count, current_no);
            res = get_mysql_res(mysql, tmp);
            if (res == NULL)
            {
                mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_FAILED,
                                     tmp, thread_id, field_list->field_list.count, current_no);
                return TRUE;
            }
            row = mysql_fetch_row(res);
            int count = 0;
            if (row != NULL)
                count = atoi(row[0]);
            else
            {
                mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_FAILED,
                                     tmp, thread_id, field_list->field_list.count, current_no);
                mysql_free_result(res);
                return TRUE;
            }
            mysql_free_result(res);
            
            if (count > 15 || field->cardinality > 256)
                field->cardinality += count;
            else
            {
                sprintf(tmp, "select %s from %s.%s force index(primary) where 1=1 and ",
                        field->name, table_info->db, table_info->tname);
                for (int j = key_count; j > 0; --j)
                {
                    sprintf(tmp, "%s ( ", tmp);
                    for (int i = 0; i< j; ++i)
                    {
                        char value[256];
                        if (i+1 == j)
                        {
                            if (!get_field_value(field_list, keys[i], value, (char*)">=", true))
                                sprintf(tmp, "%s %s and", tmp, value);
                            if (!get_field_value(field_list, keys[i], value, (char*)"<=", false))
                                sprintf(tmp, "%s %s and", tmp, value);
                        }
                        else
                        {
                            if (!get_field_value(field_list, keys[i], value, (char*)"=", true))
                                sprintf(tmp, "%s %s and", tmp, value);
                            if (!get_field_value(field_list, keys[i], value, (char*)"=", false))
                                sprintf(tmp, "%s %s and", tmp, value);
                        }
                    }
                    sprintf(tmp, "%s 1=1 ) ", tmp);
                    if (j-1 != 0)
                        sprintf(tmp, "%s or ", tmp);
                }
                sprintf(tmp, "%s group by %s",tmp, field->name);
                mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_RUNNING,
                                     tmp, thread_id, field_list->field_list.count, current_no);
                res = get_mysql_res(mysql, tmp);
                if (res == NULL)
                {
                    mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_FAILED,
                                         tmp, thread_id, field_list->field_list.count, current_no);
                    return TRUE;
                }
                row = mysql_fetch_row(res);
                
                while (row)
                {
                    if (row[0] == NULL)
                        row[0] = (char*)"NULL";
                    int in_kinds=0;
                    for (int k=0; k < field->cardinality && k < 256; ++k)
                    {
                        if (strcasecmp(field->kinds[k], row[0]) == 0)
                        {
                            in_kinds=1;
                            break;
                        }
                        
                    }
                    if (in_kinds == 0)
                    {
                        if (field->cardinality + 1 < 256)
                            strcpy(field->kinds[field->cardinality], row[0]);
                        field->cardinality++;
                    }
                    row = mysql_fetch_row(res);
                }
                mysql_free_result(res);
            }
            exchange_field_fore_and_tmp(field_list);
        }
        if (!insert_cardinality(mysql_dc, table_info, field->name, field->cardinality))
            mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_RUNNING,
                                 tmp, thread_id, field_list->field_list.count, current_no);
        else
            mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_FAILED,
                                 tmp, thread_id, field_list->field_list.count, current_no);
        
        field = LIST_GET_NEXT(link, field);
        clean_field_value(field_list);
        goto next_field;
    }
    
    if (!inception_collector_on)
        mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_STOPED,
                             tmp, thread_id, field_list->field_list.count, current_no);
    return FALSE;
}

int collect_cardinality(MYSQL* mysql, MYSQL* mysql_dc, MYSQL* mysql_collector,
                        collector_table_t* table_info, ulong thread_id)
{
    MYSQL_RES* res = NULL;
    MYSQL_ROW row;
    char keys[256][256];
    int key_count = 0;
    char tmp[512];
    collector_field_list_t field_list;
    
    memset(keys, 0, 256*256);
    //获取表中列的信息
    sprintf (tmp, "select COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, COLUMN_KEY \
             from information_schema.COLUMNS where TABLE_SCHEMA='%s' and TABLE_NAME='%s'",
             table_info->db, table_info->tname);
    mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_RUNNING, tmp, thread_id, 0, 0);
    res = get_mysql_res(mysql, tmp);
    if (res == NULL)
        return TRUE;
    row = mysql_fetch_row(res);
    if (row == NULL)
    {
        mysql_free_result(res);
        res = NULL;
        return TRUE;
    }
    LIST_INIT(field_list.field_list);
    while (row)
    {
        collector_field_t* field;
        field = (collector_field_t*)my_malloc(sizeof(collector_field_t), MY_ZEROFILL);
        strcpy(field->name, row[0]);
        strcpy(field->type, row[1]);
        if (row[2])
            field->length = atoi(row[2]);
        strcpy(field->key, row[3]);
        field->cardinality=0;
        field->seq_in_index=0;
        memset(field->kinds, 0, 256*256);
        strcpy(field->value_fore, "NULL");
        strcpy(field->value_hind, "NULL");
        strcpy(field->value_tmp, "NULL");
        field->done = false;
        LIST_ADD_LAST(link, field_list.field_list, field);
        row = mysql_fetch_row(res);
    }
    mysql_free_result(res);
    
    //获取主键信息
    sprintf (tmp, "show index from %s.%s", table_info->db, table_info->tname);
    mark_progress_detail(mysql_collector, table_info, PROGRESS_DETAIL_RUNNING, tmp, thread_id, 0, 0);
    res = get_mysql_res(mysql, tmp);
    if (res == NULL)
        return TRUE;
    row = mysql_fetch_row(res);
    if (row == NULL)
    {
        mysql_free_result(res);
        res = NULL;
        return TRUE;
    }
    
    int has_pri = 0;
    collector_field_t* field;
    while (row)
    {
        if (strcasecmp("PRIMARY", row[2]) == 0)
        {
            field = LIST_GET_FIRST(field_list.field_list);
            while (field)
            {
                if (strcasecmp(row[4], field->name) == 0)
                {
                    field->seq_in_index = atoi(row[3]);
                    strcpy(keys[field->seq_in_index-1], field->name);
                    key_count++;
                }
                field = LIST_GET_NEXT(link, field);
            }
            has_pri = 1;
        }
        row = mysql_fetch_row(res);
    }
    mysql_free_result(res);

    if (has_pri && count_every_field(mysql, mysql_dc, mysql_collector,
                          table_info, &field_list, keys, key_count, thread_id))
    {
        while (field_list.field_list.count > 0)
        {
            collector_field_t* field;
            field = LIST_GET_FIRST(field_list.field_list);
            LIST_REMOVE(link, field_list.field_list, field);
            my_free(field);
        }
        
        return TRUE;
    }
    
    while (field_list.field_list.count > 0)
    {
        collector_field_t* field;
        field = LIST_GET_FIRST(field_list.field_list);
        LIST_REMOVE(link, field_list.field_list, field);
        my_free(field);
    }

    return FALSE;
}

//该线程主要是消费作用，从cache队列中不断获取table信息，然后进行处理。
pthread_handler_t collector_work_thread(void* arg)
{
    THD *thd = NULL;
    MYSQL mysql_collector;
    MYSQL mysql_dc;
    MYSQL mysql;
    ulong thread_id=0;
    int loop_flag=0;
        
    my_thread_init();
    thd= new THD;
    thd->thread_stack= (char*) &thd;
    
    setup_connection_thread_globals(thd);
    
    thread_id = atol((char*)arg);
    
    if (get_mysql_connection(&mysql_collector, inception_collector_host, inception_collector_port,
                             inception_collector_user, inception_collector_password, NULL))
    {
        delete thd;
        my_thread_end();
        pthread_exit(0);
        return NULL;
    }
    if (get_mysql_connection(&mysql_dc, inception_datacenter_host, inception_datacenter_port,
                             inception_datacenter_user, inception_datacenter_password, NULL))
    {
        mysql_close(&mysql_collector);
        delete thd;
        my_thread_end();
        pthread_exit(0);
        return NULL;
    }
    
    while (inception_collector_on)
    {
begin:
        if (global_collector_cache.table_list.count == 0)
        {
            if (loop_flag == 0)
            {
                mysql_mutex_lock(&collector_idle_mutex);
                inception_collector_idle++;
                mysql_mutex_unlock(&collector_idle_mutex);
                mark_progress_detail(&mysql_collector, NULL, PROGRESS_DETAIL_FINISHED, NULL, thread_id, 0, 0);
                loop_flag=1;
            }

            sleep(THREAD_SLEEP_NSEC);
            continue;
        }

        if (loop_flag > 0)
        {
            mysql_mutex_lock(&collector_idle_mutex);
            inception_collector_idle--;
            mysql_mutex_unlock(&collector_idle_mutex);
            loop_flag = 0;
        }
        
        mysql_mutex_lock(&collector_cache_mutex);
        
        collector_table_t* table_info =
            LIST_GET_FIRST(global_collector_cache.table_list);
        if (table_info != NULL)
            LIST_REMOVE(link, global_collector_cache.table_list, table_info);

        mysql_mutex_unlock(&collector_cache_mutex);
        
        if (table_info == NULL)
            goto begin;
        
        if (get_mysql_connection(&mysql, table_info->host, table_info->port,
                                 remote_system_user, remote_system_password, table_info->db))
        {
            my_free(table_info);
            goto error;
        }
        if (create_db_table(&mysql_dc, table_info))
        {
            my_free(table_info);
            mysql_close(&mysql);
            goto error;
        }
        if (inception_collector_rule == COLLECTOR_RULE_ALL
            || inception_collector_rule & COLLECTOR_RULE_CARDINALITY)
        {
            if (collect_cardinality(&mysql, &mysql_dc, &mysql_collector, table_info, thread_id))
            {
                my_free(table_info);
                mysql_close(&mysql);
                goto error;
            }
        }
        my_free(table_info);
        mysql_close(&mysql);
        mark_progress_detail(&mysql_collector, NULL, PROGRESS_DETAIL_FINISHED, NULL, thread_id, 0, 0);
    }
    
error:
    mysql_mutex_lock(&collector_idle_mutex);
    inception_collector_idle--;
    mysql_mutex_unlock(&collector_idle_mutex);
    inception_collector_on = false;
    sql_print_information("cardinality_work_thread stop.");
    mysql_close(&mysql_collector);
    mysql_close(&mysql_dc);
    delete thd;
    my_thread_end();
    pthread_exit(0);
    return NULL;
}

//该线程主要是生产作用，创建work线程后，开始向cache队列中插入table信息。
//获取和释放全局collector需要加锁
pthread_handler_t inception_collector_thread(void* arg)
{
    pthread_t threadid;
    THD *thd= NULL;
    MYSQL* mysql;
    MYSQL_RES* source_res=NULL;
    MYSQL_ROW source_row;
    int total_tables = 0;
    int last_id = 1;
    double progress = 0.0;
    char tmp[512];
    char no[256][5];
    
    my_thread_init();
    thd= new THD();
    thd->thread_stack= (char*) &thd;
    
    pthread_detach_this_thread();
    
    setup_connection_thread_globals(thd);
    
    mysql_mutex_lock(&collector_idle_mutex);
    mysql = thd->get_collector_connection();
    mysql_mutex_unlock(&collector_idle_mutex);
    if (mysql == NULL)
        goto error;
    
    inception_collector_running_worker = inception_collector_parallel_workers;
    
    mark_progress_all(mysql, 0.00, PROGRESS_ALL_STARTED);
    
    strcpy(tmp, "select max(id) from `collector_data`.`table_dict`");
    
    source_res = get_mysql_res(mysql, tmp);
    if (source_res == NULL)
        goto error;
    
    source_row= mysql_fetch_row(source_res);
    if (source_row[0])
        total_tables = atoi(source_row[0]) + 1;
    mysql_free_result(source_res);
    
    strcpy(tmp, "select min(table_id) from `collector_data`.`progress_detail` \
           where state <> 'finished'");
    
    source_res = get_mysql_res(mysql, tmp);
    if (source_res == NULL)
        goto error;
    
    source_row= mysql_fetch_row(source_res);
    if (*source_row)
        last_id = atol(source_row[0]);
    mysql_free_result(source_res);
    
    strcpy(tmp, "truncate table collector_data.progress_detail");
    if (get_mysql_res(mysql, tmp))
        goto error;
    strcpy(tmp, "truncate table collector_data.progress_all");
    if (get_mysql_res(mysql, tmp))
        goto error;
    
    memset(no, 0, 256 * 5);
    for (int i=0; i < inception_collector_parallel_workers; ++i)
    {
        sprintf(no[i], "%d", i+1);
        mysql_thread_create(0, &threadid, &connection_attrib,
                            collector_work_thread, (void*)no[i]);
    }
    
    for (int i= last_id; i < total_tables && inception_collector_on; i= i+TABLE_ID_STEPS)
    {
        sprintf(tmp, "select host,port,db,tname,id,steps,sample_percent \
                from `collector_data`.`table_dict` where id>=%d and id <%d and refuse=0",
                i,i+TABLE_ID_STEPS);
        source_res = get_mysql_res(mysql, tmp);
        if (source_res == NULL)
            goto error;
        int j=0;
        source_row= mysql_fetch_row(source_res);
        while (source_row && inception_collector_on)
        {
            ++j;
            while (global_collector_cache.table_list.count >= CACHE_QUEUE_LENGTH);
            collector_table_t* table_info;
            table_info = (collector_table_t*)my_malloc(sizeof(collector_table_t), MY_ZEROFILL);
            
            strcpy(table_info->host, source_row[0]);
            strcpy(table_info->db, source_row[2]);
            strcpy(table_info->tname, source_row[3]);
            table_info->port = atoi(source_row[1]);
            table_info->table_id = atol(source_row[4]);
            table_info->steps = atoi(source_row[5]);
            table_info->sample_percent = atof(source_row[6]);
            LIST_ADD_LAST(link, global_collector_cache.table_list, table_info);
            source_row = mysql_fetch_row(source_res);
        }
        mysql_free_result(source_res);
        
        mysql_mutex_lock(&collector_cache_mutex);
        if (j > 0)
            progress = (double)(j - global_collector_cache.table_list.count) * 100 / (double)total_tables;
        mysql_mutex_unlock(&collector_cache_mutex);
        
        if (progress - 100.00 >= 0.00)
            progress = 99.99;

        mark_progress_all(mysql, progress, PROGRESS_ALL_RUNNING);
    }
    
    while (inception_collector_on == true
           && ((global_collector_cache.table_list.count > 0
           || inception_collector_idle < inception_collector_parallel_workers)))
        sleep(THREAD_SLEEP_NSEC);
    
    if (!inception_collector_on)
        mark_progress_all(mysql, progress, PROGRESS_ALL_STOPED);
    else
        mark_progress_all(mysql, 100.00, PROGRESS_ALL_FINISHED);
    
error:
    sql_print_information("inception_collector_thread stop.");
    inception_collector_on = false;
    source_res=NULL;
    
    mysql_mutex_lock(&collector_idle_mutex);
    inception_collector_idle--;
    thd->close_collector_connection();
    mysql_mutex_unlock(&collector_idle_mutex);

    delete thd;
    my_thread_end();
    pthread_exit(0);
    return NULL;
}

int assemble_rule(THD* thd)
{
    if (thd->lex->name.length == 0)
        return FALSE;
    
    if (strcasecmp("cardinality", thd->lex->name.str) == 0)
        inception_collector_rule |= COLLECTOR_RULE_CARDINALITY;
    else
        return TRUE;
    return FALSE;
}

int disassemble_rule(THD* thd)
{
    if (thd->lex->name.length == 0)
    {
        inception_collector_rule = COLLECTOR_RULE_ALL;
        return FALSE;
    }
    if (strcasecmp("cardinality", thd->lex->name.str) == 0)
        inception_collector_rule ^= COLLECTOR_RULE_CARDINALITY;
    else
        return TRUE;
    return FALSE;
}

int inception_collector_start(THD* thd)
{
    pthread_t threadid;
    if (assemble_rule(thd))
    {
        my_error(ER_UNKNOWN_COLLECTOR_RULE,MYF(0),thd->lex->name.str);
        return TRUE;
    }
    
    if (!inception_collector_on)
    {
        inception_collector_idle = 0;
        inception_collector_on = true;
        clear_collector_cache();
        mysql_thread_create(0, &threadid, &connection_attrib,
                            inception_collector_thread, NULL);
        while (inception_collector_running_worker != inception_collector_parallel_workers);
    }
    return FALSE;
}

int inception_collector_stop(THD* thd)
{
    if (disassemble_rule(thd))
    {
        my_error(ER_UNKNOWN_COLLECTOR_RULE,MYF(0),thd->lex->name.str);
        return TRUE;
    }
    
    if (inception_collector_on)
    {
        if (inception_collector_rule == COLLECTOR_RULE_ALL)
        {
            inception_collector_on = false;
            while (inception_collector_idle >= 0);
        }
        else
            return TRUE;
    }
    return FALSE;
}

int inception_collector_status(THD* thd)
{
    List<Item>      field_list;
    char            tmp[512];
    Protocol*       protocol= thd->protocol;
    MYSQL*          mysql;
    MYSQL_RES*      source_res;
    MYSQL_ROW       source_row;
    
    DBUG_ENTER("inception_collector_status");
    
    if (assemble_rule(thd))
    {
        my_error(ER_UNKNOWN_COLLECTOR_RULE,MYF(0),thd->lex->name.str);
        return TRUE;
    }
    
    field_list.push_back(new Item_empty_string("thread_id", FN_REFLEN));
    field_list.push_back(new Item_empty_string("table_id", FN_REFLEN));
    field_list.push_back(new Item_empty_string("dest_host", FN_REFLEN));
    field_list.push_back(new Item_empty_string("dest_port", FN_REFLEN));
    field_list.push_back(new Item_empty_string("dest_db", FN_REFLEN));
    field_list.push_back(new Item_empty_string("dest_tname", FN_REFLEN));
    field_list.push_back(new Item_empty_string("rule", FN_REFLEN));
    field_list.push_back(new Item_empty_string("state", FN_REFLEN));
    field_list.push_back(new Item_empty_string("sum_no", FN_REFLEN));
    field_list.push_back(new Item_empty_string("current_no", FN_REFLEN));
    field_list.push_back(new Item_empty_string("state_change_time", FN_REFLEN));
    field_list.push_back(new Item_empty_string("info", FN_REFLEN));
    
    if (protocol->send_result_set_metadata(&field_list,
        Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    {
        DBUG_RETURN(true);
    }

    if (inception_collector_rule == COLLECTOR_RULE_ALL)
        strcpy(tmp, "select thread_id, table_id, dest_host, dest_port, dest_db, \
                dest_tname, rule, state, sum_no, current_no, start_time, info \
                from collector_data.progress_detail order by rule, thread_id");
    else if (inception_collector_rule & COLLECTOR_RULE_CARDINALITY)
        strcpy(tmp, "select thread_id, table_id, dest_host, dest_port, dest_db, \
                dest_tname, rule, state, sum_no, current_no, start_time, info \
                from collector_data.progress_detail \
                where rule='cardinality' order by thread_id");
    
    mysql = thd->get_collector_connection();
    if (mysql == NULL)
        DBUG_RETURN(true);
    
    if (mysql_real_query(mysql, tmp, strlen(tmp)) ||
        (source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        thd->close_collector_connection();
        DBUG_RETURN(true);
    }
    
    source_row = mysql_fetch_row(source_res);
    while (source_row)
    {
        protocol->prepare_for_resend();
        protocol->store(source_row[0], system_charset_info);
        protocol->store(source_row[1], system_charset_info);
        protocol->store(source_row[2], system_charset_info);
        protocol->store(source_row[3], system_charset_info);
        protocol->store(source_row[4], system_charset_info);
        protocol->store(source_row[5], system_charset_info);
        protocol->store(source_row[6], system_charset_info);
        protocol->store(source_row[7], system_charset_info);
        protocol->store(source_row[8], system_charset_info);
        protocol->store(source_row[9], system_charset_info);
        protocol->store(source_row[10], system_charset_info);
        protocol->store(source_row[11], system_charset_info);
        protocol->write();
        source_row = mysql_fetch_row(source_res);
    }
    
    mysql_free_result(source_res);
    my_eof(thd);
    thd->close_collector_connection();
    
    DBUG_RETURN(FALSE);
    return FALSE;
}

int inception_collector_rule_list(THD* thd)
{
    List<Item>      field_list;
    char            tmp[100];
    Protocol*       protocol= thd->protocol;
    MYSQL*          mysql;
    MYSQL_RES*      source_res;
    MYSQL_ROW       source_row;
    
    DBUG_ENTER("inception_collector_rule_list");
    field_list.push_back(new Item_empty_string("Rule", FN_REFLEN));
    field_list.push_back(new Item_empty_string("state", FN_REFLEN));
    field_list.push_back(new Item_empty_string("start_time", FN_REFLEN));
    field_list.push_back(new Item_empty_string("stop_time", FN_REFLEN));
    field_list.push_back(new Item_empty_string("progress", FN_REFLEN));
    
    if (protocol->send_result_set_metadata(&field_list,
        Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    {
        DBUG_RETURN(true);
    }

    strcpy(tmp, "select rule, state, start_time, stop_time, progress \
            from collector_data.progress_all");
    mysql = thd->get_collector_connection();
    if (mysql == NULL)
        DBUG_RETURN(true);
    
    if (mysql_real_query(mysql, tmp, strlen(tmp)) ||
        (source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        thd->close_collector_connection();
        DBUG_RETURN(true);
    }
    
    source_row = mysql_fetch_row(source_res);
    while (source_row)
    {
        protocol->prepare_for_resend();
        protocol->store(source_row[0], system_charset_info);
        protocol->store(source_row[1], system_charset_info);
        protocol->store(source_row[2], system_charset_info);
        protocol->store(source_row[3], system_charset_info);
        protocol->store(source_row[4], system_charset_info);
        protocol->write();
        source_row = mysql_fetch_row(source_res);
    }
    
    mysql_free_result(source_res);
    my_eof(thd);
    thd->close_collector_connection();
    
    DBUG_RETURN(FALSE);
}

int inception_collector_init(THD* thd)
{
    MYSQL mysql;
    char tmp[1024];

    if (get_mysql_connection(&mysql, inception_collector_host, inception_collector_port,
                             inception_collector_user, inception_collector_password, NULL))
        return TRUE;
    
    strcpy(tmp, "create database collector_data");
    if (get_mysql_res(&mysql, tmp))
    {
        mysql_close(&mysql);
        return TRUE;
    }
    
    strcpy(tmp, "create table collector_data.table_dict(\
             `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\
             `host` varchar(20) NOT NULL DEFAULT '', \
             `port` int(11) NOT NULL DEFAULT '0', \
             `db` varchar(30) NOT NULL DEFAULT '', \
             `tname` varchar(30) NOT NULL DEFAULT '', \
             `refuse` tinyint NOT NULL DEFAULT '0', \
             `steps` int(11) NOT NULL DEFAULT '10000', \
             `sample_percent` decimal(5,4) NOT NULL DEFAULT '1.0000', \
             PRIMARY KEY (`id`) \
             ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;");
    if (get_mysql_res(&mysql, tmp))
    {
        mysql_close(&mysql);
        return TRUE;
    }
    
    strcpy(tmp, "create table collector_data.progress_all(\
             `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\
             `rule` varchar(20) NOT NULL DEFAULT '',\
             `state` varchar(15) NOT NULL DEFAULT '', \
             `start_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, \
             `stop_time`  timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, \
             `progress` decimal(5,2) NOT NULL DEFAULT '0', \
             PRIMARY KEY (`id`), \
             UNIQUE KEY `uniq_rule` (`rule`) \
             ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;");
    if (get_mysql_res(&mysql, tmp))
    {
        mysql_close(&mysql);
        return TRUE;
    }

    
    strcpy(tmp, "create table collector_data.progress_detail(\
             `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\
             `thread_id` bigint(20) unsigned NOT NULL DEFAULT '0', \
             `table_id` bigint(20) unsigned NOT NULL DEFAULT '0', \
             `dest_host` varchar(20) NOT NULL DEFAULT '', \
             `dest_port` int(11) NOT NULL DEFAULT '0', \
             `dest_db` varchar(30) NOT NULL DEFAULT '', \
             `dest_tname` varchar(30) NOT NULL DEFAULT '', \
             `rule` varchar(20) NOT NULL DEFAULT '',\
             `state` varchar(20) NOT NULL DEFAULT '', \
             `sum_no` int(11) NOT NULL DEFAULT '0', \
             `current_no` int(11) NOT NULL DEFAULT '0', \
             `start_time`  timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, \
             `info` varchar(255) NOT NULL DEFAULT '', \
             PRIMARY KEY (`id`), \
             UNIQUE KEY `uniq_thread_id_rule` (`thread_id`,`rule`) \
             ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;");
    if (get_mysql_res(&mysql, tmp))
    {
        mysql_close(&mysql);
        return TRUE;
    }

    if (!inception_collector_on)
    {
        strcpy(tmp, "update collector_data.progress_detail set state='stoped' \
                 where state = 'running';");
        if (get_mysql_res(&mysql, tmp))
        {
            mysql_close(&mysql);
            return TRUE;
        }
        strcpy(tmp, "update collector_data.progress_all set state='stoped' \
                 where state = 'running' or state = 'started';");
        if (get_mysql_res(&mysql, tmp))
        {
            mysql_close(&mysql);
            return TRUE;
        }
    }
    
    mysql_close(&mysql);
    return FALSE;
}

int inception_collector_execute(THD* thd)
{
    inception_collector_init(thd);
    
    switch (thd->lex->inception_cmd_sub_type)
    {
        case INCEPTION_START_COLLECTOR:
            return inception_collector_start(thd);
        case INCEPTION_STOP_COLLECTOR:
            return inception_collector_stop(thd);
        case INCEPTION_SHOW_COLLECTOR_STATUS:
            return inception_collector_status(thd);
        case INCEPTION_GET_COLLECTOR_LIST:
            return inception_collector_rule_list(thd);
        default:
            return FALSE;
    }
    
    return FALSE;
}
