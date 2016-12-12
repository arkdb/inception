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

#define CACHE_QUEUE_LENGTH            1000
#define LOOP_TIMES                    15

#define COLLECTOR_RULE_ALL            0
#define COLLECTOR_RULE_COUNT          1
#define COLLECTOR_RULE_DIST_COUNT     2

#define FIELD_VALUE_FORE                  0
#define FIELD_VALUE_TMP                   1
#define FIELD_VALUE_HIND                  2

#define THREAD_SLEEP_NSEC                 1

extern collector_instance_list_t global_collector_instance_cache;

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
        return TRUE;
    }

    return FALSE;
}

int get_mysql_connection(MYSQL* conn, char* host, uint port, char* user, char* password, char* db)
{
    if (port== 0 ||
        user== NULL || user[0] == '\0' ||
        host== NULL || host[0] == '\0' ||
        password== NULL || password[0] == '\0')
    {
        my_error(ER_INVALID_TRANSFER_INFO, MYF(0));
        return TRUE;
    }
    if (init_mysql_connection(conn, host, port, user, password, db))
        return TRUE;
    else
        return FALSE;
}

int get_mysql_res(MYSQL* conn, MYSQL_RES* (&mysql_res), char* sql)
{
    if (mysql_real_query(conn, sql, strlen(sql)))
    {
        if (mysql_errno(conn) != 1050 && mysql_errno(conn) != 1007/*ER_TABLE_EXISTS_ERROR*/)
        {
            if (mysql_errno(conn) == 1062)
                my_error(ER_DUP_KEY, MYF(0), mysql_error(conn));
            sql_print_information(mysql_error(conn));
            return TRUE;
        }
    }
    mysql_res = mysql_store_result(conn);
    return FALSE;
}

int inception_collector_init(THD* thd)
{
    MYSQL mysql;
    MYSQL_RES* mysql_res;
    char tmp[1024];
    
    if (get_mysql_connection(&mysql, inception_collector_host, inception_collector_port,
                             inception_collector_user, inception_collector_password, NULL))
        return TRUE;
    
    strcpy(tmp, "create database collector_data");
    if (get_mysql_res(&mysql, mysql_res, tmp))
    {
        mysql_close(&mysql);
        return TRUE;
    }
    
    strcpy(tmp, "create table collector_data.instance_dict(\
           `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\
           `name` varchar(32) NOT NULL DEFAULT '', \
           `host` varchar(20) NOT NULL DEFAULT '', \
           `port` int(11) NOT NULL DEFAULT '0', \
           `start_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, \
           `stop_time`  timestamp NOT NULL DEFAULT '2000-01-01 00:00:00', \
           `threads_limit` int(11) NOT NULL DEFAULT '5', \
           `tmp_host` varchar(20) NOT NULL DEFAULT '', \
           `tmp_port` int(11) NOT NULL DEFAULT '0', \
           PRIMARY KEY (`id`), \
           UNIQUE KEY `uniq_name` (`name`), \
           UNIQUE KEY `uniq_host_port` (`host`, `port`) \
           ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;");
    if (get_mysql_res(&mysql, mysql_res, tmp))
    {
        mysql_close(&mysql);
        return TRUE;
    }
    
    strcpy(tmp, "create table collector_data.table_dict(\
           `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\
           `host` varchar(20) NOT NULL DEFAULT '', \
           `port` int(11) NOT NULL DEFAULT '0', \
           `db` varchar(32) NOT NULL DEFAULT '', \
           `tname` varchar(32) NOT NULL DEFAULT '', \
           `rule` int(11) NOT NULL DEFAULT '0', \
           `refuse` tinyint NOT NULL DEFAULT '0', \
           `priority` int(11) NOT NULL DEFAULT '0', \
           `steps` int(11) NOT NULL DEFAULT '10000', \
           `sample_percent` decimal(5,4) NOT NULL DEFAULT '1.0000', \
           `period` int(11) NOT NULL DEFAULT '0', \
           `count_end_time` timestamp NOT NULL DEFAULT '2000-01-01 00:00:00', \
           `dist_count_end_time` timestamp NOT NULL DEFAULT '2000-01-01 00:00:00', \
           PRIMARY KEY (`id`), \
           KEY idx_host_port(`host`,`port`) \
           ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;");
    if (get_mysql_res(&mysql, mysql_res, tmp))
    {
        mysql_close(&mysql);
        return TRUE;
    }
    mysql_close(&mysql);
    return FALSE;
}

int create_db_table(MYSQL* conn_dc, collector_queue_item_t* item)
{
    MYSQL_RES* res_dc = NULL;
    char tmp[1024];
    char host_[30];
    
    strcpy(host_, item->host);
    str_replace(host_, (char*)".", (char*)"_");
    
    //创建采样信息存放实例的库
    sprintf (tmp, "create database collector_data_%s_%d", host_, item->port);
    if (get_mysql_res(conn_dc, res_dc, tmp))
        return TRUE;

    //创建采样count信息存放的表
    sprintf (tmp, "create table collector_data_%s_%d.count_%s_%s(\
             id bigint unsigned  not null primary key auto_increment,\
             variable varchar(32) not null default '', \
             value int unsigned not null default 0, \
             version bigint unsigned not null default 0, \
             start_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, \
             end_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, \
             UNIQUE KEY `uniq_variable_version` (`variable`,`version`) \
             )engine=innodb default charset=utf8 comment='count';", host_, item->port,
             item->db, item->tname);
    if (get_mysql_res(conn_dc, res_dc, tmp))
        return TRUE;
    
    //创建采样distinct count信息存放的表
    sprintf (tmp, "create table collector_data_%s_%d.dist_count_%s_%s(\
             id bigint unsigned  not null primary key auto_increment,\
             variable varchar(32) not null default '', \
             value int unsigned not null default 0, \
             version bigint unsigned not null default 0, \
             start_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, \
             end_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, \
             UNIQUE KEY `uniq_variable_version` (`variable`,`version`) \
             )engine=innodb default charset=utf8 comment='distinct_count';", host_, item->port,
             item->db, item->tname);
    if (get_mysql_res(conn_dc, res_dc, tmp))
        return TRUE;
    
    return FALSE;
}

int insert_count(MYSQL* mysql_dc, collector_queue_item_t* item, char* var, int value)
{
    MYSQL_RES* res_dc = NULL;
    char tmp[1024];
    char host_[30];
    
    strcpy(host_, item->host);
    str_replace(host_, (char*)".", (char*)"_");
    
    sprintf (tmp, "insert into collector_data_%s_%d.count_%s_%s(variable,value,version) \
             values('%s',%d,%ld) ON DUPLICATE KEY UPDATE value= value + %d;",
             host_, item->port, item->db, item->tname,var, value, item->version, value);
    if (get_mysql_res(mysql_dc, res_dc, tmp))
        return TRUE;
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

int instance_state(char* instance_name, char* state)
{
    collector_instance_t* instance = LIST_GET_FIRST(global_collector_instance_cache.instance_list);

    while (instance != NULL)
    {
        if (strcasecmp(instance_name, instance->name) == 0)
        {
            if (instance->on)
            {
                if (instance->pause)
                    strcpy(state, "pause");
                else
                    strcpy(state, "on");
                return TRUE;
            }
        }
        instance = LIST_GET_NEXT(link, instance);
    }
    strcpy(state, "off");
    return FALSE;
}

int get_field_value(collector_field_list_t* field_list, char* name, char* value, char* sign, int is_fore)
{
    collector_field_t* field = LIST_GET_FIRST(field_list->field_list);
    char field_value[256];
    while (field)
    {
        strcpy(field_value, is_fore?field->value_fore:field->value_hind);

        if (strcasecmp(name, field->name) == 0
            && strcasecmp("NULL", field_value) != 0)
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
            return FALSE;
        }
        field = LIST_GET_NEXT(link, field);
    }
    return TRUE;
}

int exchange_field_fore_and_tmp(collector_field_list_t* field_list)
{
    collector_field_t* field = LIST_GET_FIRST(field_list->field_list);
    while (field)
    {
        if (strcasecmp("PRI", field->key) == 0)
        {
            strcpy(field->value_fore, field->value_tmp);
            strcpy(field->value_tmp, "NULL");
            strcpy(field->value_hind, "NULL");
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

int clean_table_and_field_flag(collector_instance_t* (&instance))
{
    collector_table_t* tmp_table_info = LIST_GET_FIRST(instance->collector_table_list->table_list);
    while (tmp_table_info != NULL)
    {
        tmp_table_info->done = FALSE;
        tmp_table_info->field_done_count = 0;
        collector_field_t* tmp_field = LIST_GET_FIRST(tmp_table_info->collector_field_list->field_list);
        while (tmp_field != NULL)
        {
            tmp_field->is_beginning = TRUE;
            tmp_field->is_ending = FALSE;
            tmp_field->done = FALSE;
            tmp_field = LIST_GET_NEXT(link, tmp_field);
        }
        tmp_table_info = LIST_GET_NEXT(link, tmp_table_info);
    }
    return FALSE;
}

int free_queue(THD* (&thd))
{
    collector_queue_item_t* item = LIST_GET_FIRST(thd->collector_queue_item_list->item_list);
    while (item != NULL)
    {
        collector_queue_item_t* next_item = LIST_GET_NEXT(link, item);
        LIST_REMOVE(link, thd->collector_queue_item_list->item_list, item);
        my_free(item);
        item = next_item;
    }
    my_free(thd->collector_queue_item_list);
    thd->collector_queue_item_list = NULL;
    return FALSE;
}

int free_instance(collector_instance_t* (&instance))
{
    MYSQL           mysql;
    MYSQL_RES       *source_res;
    char            tmp[1024];
    if (!get_mysql_connection(&mysql, inception_collector_host, inception_collector_port,
                              inception_collector_user, inception_collector_password, NULL))
    {
        sprintf(tmp, "update collector_data.instance_dict set stop_time=now() \
                where name = \'%s\'", instance->name);
        get_mysql_res(&mysql, source_res ,tmp);
        mysql_close(&mysql);
    }

    collector_table_list_t *collector_table_list;
    collector_table_list = instance->collector_table_list;
    collector_table_t *table = LIST_GET_FIRST(collector_table_list->table_list);
    while (table != NULL)
    {
        collector_table_t *next_table = LIST_GET_NEXT(link, table);
        
        collector_field_t *field = LIST_GET_FIRST(table->collector_field_list->field_list);
        while (field != NULL) {
            collector_field_t *next_field = LIST_GET_NEXT(link, field);
            mysql_mutex_destroy(&field->dist_count_done_mutex);
            mysql_mutex_destroy(&field->count_done_mutex);
            LIST_REMOVE(link, table->collector_field_list->field_list, field);
            my_free(field);
            field = next_field;
        }
        my_free(table->collector_field_list);
        table->collector_field_list = NULL;
        LIST_REMOVE(link, collector_table_list->table_list, table);
        my_free(table);
        table = next_table;
    }
    my_free(collector_table_list);
    instance->collector_table_list = NULL;
    collector_worker_t* worker = LIST_GET_FIRST(instance->collector_worker_list->worker_list);
    while (worker != NULL)
    {
        collector_worker_t* next_worker = LIST_GET_NEXT(link, worker);
        LIST_REMOVE(link, instance->collector_worker_list->worker_list, worker);
        my_free(worker);
        worker = next_worker;
    }
    my_free(instance->collector_worker_list);
    instance->collector_worker_list = NULL;
    LIST_REMOVE(link, global_collector_instance_cache.instance_list, instance);
    mysql_mutex_destroy(&instance->collector_worker_mutex);
    my_free(instance);
    instance = NULL;
    return FALSE;
}

int validate_instance(THD* thd)
{
    MYSQL           *mysql;
    MYSQL_RES       *source_res;
    MYSQL_ROW       source_row;
    char            tmp[1024];
    int             rest = FALSE;
    
    mysql = thd->get_collector_connection();
    if (mysql == NULL)
    {
        rest = TRUE;
        goto done;
    }
    sprintf(tmp, "select count(*) from collector_data.instance_dict \
            where name = \'%s\'", thd->lex->name.str);
    if (get_mysql_res(mysql, source_res ,tmp))
    {
        rest = TRUE;
        goto done;
    }
    source_row= mysql_fetch_row(source_res);
    if (atoi(source_row[0]) != 1)
        rest = TRUE;
    mysql_free_result(source_res);
    
done:
    thd->close_all_connections();
    return rest;
}

int load_field(collector_table_t* (&table_info))
{
    MYSQL mysql;
    MYSQL_RES* res = NULL;
    MYSQL_ROW row;
    char tmp[1024];
    
    if (get_mysql_connection(&mysql, table_info->host, table_info->port,
                             remote_system_user, remote_system_password, table_info->db))
        return TRUE;
    
    //获取表中列的信息
    sprintf (tmp, "select COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, COLUMN_KEY \
             from information_schema.COLUMNS where TABLE_SCHEMA='%s' and TABLE_NAME='%s'",
             table_info->db, table_info->tname);
    
    if (get_mysql_res(&mysql, res, tmp))
        return TRUE;
    row = mysql_fetch_row(res);
    if (row == NULL)
    {
        mysql_free_result(res);
        res = NULL;
        return TRUE;
    }
    
    while (row)
    {
        collector_field_t* field;
        field = (collector_field_t*)my_malloc(sizeof(collector_field_t), MY_ZEROFILL);
        strcpy(field->name, row[0]);
        strcpy(field->type, row[1]);
        if (row[2])
            field->length = atoi(row[2]);
        strcpy(field->key, row[3]);
        field->seq_in_index = 0;
        field->is_beginning = TRUE;
        field->is_ending = FALSE;
        field->done = FALSE;
        field->count_sended_count = 0;
        field->count_done_count = 0;
        field->dist_count_sended_count = 0;
        field->dist_count_done_count = 0;
        mysql_mutex_init(NULL, &field->dist_count_done_mutex, MY_MUTEX_INIT_FAST);
        mysql_mutex_init(NULL, &field->count_done_mutex, MY_MUTEX_INIT_FAST);
        strcpy(field->value_fore, "NULL");
        strcpy(field->value_hind, "NULL");
        strcpy(field->value_tmp, "NULL");
        LIST_ADD_LAST(link, table_info->collector_field_list->field_list, field);
        row = mysql_fetch_row(res);
    }
    mysql_free_result(res);
    
    //获取列估计行数
    sprintf (tmp, "show table status like '%s'", table_info->tname);

    if (get_mysql_res(&mysql, res, tmp))
        return TRUE;
    row = mysql_fetch_row(res);
    if (row == NULL)
    {
        mysql_free_result(res);
        res = NULL;
        return TRUE;
    }
    
    if (row[4] != NULL)
        table_info->rows = atoi(row[4]) / table_info->steps;
    
    //获取主键信息
    sprintf (tmp, "show index from %s.%s", table_info->db, table_info->tname);
    
    if (get_mysql_res(&mysql, res, tmp))
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
            field = LIST_GET_FIRST(table_info->collector_field_list->field_list);
            while (field)
            {
                if (strcasecmp(row[4], field->name) == 0)
                {
                    field->seq_in_index = atoi(row[3]);
                    strcpy(table_info->keys[field->seq_in_index-1], field->name);
                    table_info->key_count++;
                }
                field = LIST_GET_NEXT(link, field);
            }
            has_pri = 1;
        }
        row = mysql_fetch_row(res);
    }
    mysql_free_result(res);
    if (has_pri)
        return FALSE;
    else
        return TRUE;
}

int calculate_rule(int rule, int count_done, int dist_count_done)
{
    int origin_rule = rule;
    if (count_done == 0 &&
        ((origin_rule & COLLECTOR_RULE_COUNT) > 0 || origin_rule == COLLECTOR_RULE_ALL))
        rule = rule | COLLECTOR_RULE_COUNT;
    if (dist_count_done == 0 &&
        ((origin_rule & COLLECTOR_RULE_DIST_COUNT) > 0 || origin_rule == COLLECTOR_RULE_ALL))
        rule = rule | COLLECTOR_RULE_DIST_COUNT;
    return rule;
}

int load_table(THD *thd, collector_instance_t* (&instance))
{
    MYSQL* mysql;
    MYSQL_RES* source_res=NULL;
    MYSQL_ROW source_row;
    char tmp[2048];
    int rest = FALSE;
    
    mysql = thd->get_collector_connection();
    if (mysql == NULL)
    {
        rest = TRUE;
        goto done;
    }
    
    LIST_INIT(instance->collector_table_list->table_list);

    sprintf(tmp, "(select host, port, db, tname, rule, steps, sample_percent, '0', '1' \
            from `collector_data`.`table_dict` where host='%s' and port=%d and refuse=0\
            and count_end_time <= DATE_SUB(NOW(), INTERVAL period MINUTE) \
            and dist_count_end_time > DATE_SUB(NOW(), INTERVAL period MINUTE)) \
            UNION ALL \
            (select host, port, db, tname, rule, steps, sample_percent, '1', '0' \
             from `collector_data`.`table_dict` where host='%s' and port=%d and refuse=0\
             and count_end_time > DATE_SUB(NOW(), INTERVAL period MINUTE) \
             and dist_count_end_time <= DATE_SUB(NOW(), INTERVAL period MINUTE))\
            UNION ALL \
            (select host, port, db, tname, rule, steps, sample_percent, '0', '0' \
             from `collector_data`.`table_dict` where host='%s' and port=%d and refuse=0\
             and count_end_time <= DATE_SUB(NOW(), INTERVAL period MINUTE) \
             and dist_count_end_time <= DATE_SUB(NOW(), INTERVAL period MINUTE))\
            ",
            instance->host, instance->port,
            instance->host, instance->port,
            instance->host, instance->port);

    if (get_mysql_res(mysql, source_res, tmp))
    {
        rest = TRUE;
        goto done;
    }
    source_row= mysql_fetch_row(source_res);
    
    while (source_row != NULL)
    {
        collector_table_t* table_info;
        table_info = (collector_table_t*)my_malloc(sizeof(collector_table_t), MY_ZEROFILL);
        
        strcpy(table_info->host, source_row[0]);
        strcpy(table_info->db, source_row[2]);
        strcpy(table_info->tname, source_row[3]);
        table_info->port = atoi(source_row[1]);
        table_info->rule = calculate_rule(atoi(source_row[4]), atoi(source_row[7]), atoi(source_row[8]));
        table_info->steps = atoi(source_row[5]);
        table_info->sample_percent = atof(source_row[6]);
        table_info->done = FALSE;
        table_info->key_count = 0;
        table_info->rows = 0;
        table_info->field_done_count = 0;
        memset(table_info->keys, 0, 256*256);
        table_info->collector_field_list =
        (collector_field_list_t*)my_malloc(sizeof(collector_field_list_t), MY_ZEROFILL);
        LIST_INIT(table_info->collector_field_list->field_list);
        if (!load_field(table_info))
            LIST_ADD_LAST(link, instance->collector_table_list->table_list, table_info);
        source_row = mysql_fetch_row(source_res);
    }
    mysql_free_result(source_res);

done:
    source_res=NULL;
    thd->close_all_connections();
    return rest;
}

int load_instance(THD* thd, collector_instance_t* (&instance))
{
    MYSQL           *mysql;
    MYSQL_RES       *source_res;
    MYSQL_ROW       source_row;
    char            tmp[1024];
    int             rest = FALSE;
    time_t          rawtime;
    
    collector_instance_t* tmp_instance = LIST_GET_FIRST(global_collector_instance_cache.instance_list);
    
    while (tmp_instance != NULL)
    {
        if (strcasecmp(thd->lex->name.str, tmp_instance->name) == 0)
        {
            instance = tmp_instance;
            goto done;
        }
        tmp_instance = LIST_GET_NEXT(link, tmp_instance);
    }
    
    mysql = thd->get_collector_connection();
    if (mysql == NULL)
    {
        rest = TRUE;
        goto done;
    }
    sprintf(tmp, "select host, port, threads_limit, tmp_host, tmp_port \
            from collector_data.instance_dict where name = \'%s\'", thd->lex->name.str);
    if (get_mysql_res(mysql, source_res, tmp))
    {
        rest = TRUE;
        goto done;
    }
    source_row = mysql_fetch_row(source_res);
    
    instance = (collector_instance_t*)my_malloc(sizeof(collector_instance_t), MY_ZEROFILL);
    strcpy(instance->name, thd->lex->name.str);
    strcpy(instance->host, source_row[0]);
    instance->port = atoi(source_row[1]);
    instance->threads_limit = atoi(source_row[2]);
    strcpy(instance->tmp_host, source_row[3]);
    instance->tmp_port = atoi(source_row[4]);
    instance->on = FALSE;
    instance->pause = FALSE;
    instance->thread_id = 1;
    instance->idle_num = 0;
    time(&rawtime);
    instance->version = rawtime;
    mysql_free_result(source_res);
    
    instance->collector_table_list =
    (collector_table_list_t*)my_malloc(sizeof(collector_table_list_t), MY_ZEROFILL);
    LIST_INIT(instance->collector_table_list->table_list);
    instance->collector_worker_list =
    (collector_worker_list_t*)my_malloc(sizeof(collector_worker_list_t), MY_ZEROFILL);
    LIST_INIT(instance->collector_worker_list->worker_list);
    for (int i=0; i < instance->threads_limit; ++i)
    {
        collector_worker_t* worker =
        (collector_worker_t*)my_malloc(sizeof(collector_worker_t), MY_ZEROFILL);
        worker->thread_id = i+1;
        worker->thd = NULL;
        LIST_ADD_LAST(link, instance->collector_worker_list->worker_list, worker);
    }
    
    mysql_mutex_init(NULL, &instance->collector_worker_mutex, MY_MUTEX_INIT_FAST);
    LIST_ADD_LAST(link, global_collector_instance_cache.instance_list, instance);
done:
    thd->close_all_connections();
    return rest;
}

int get_count_process(char* instance_name, char* count_process)
{
    ulong rows = 0;
    ulong sended_count = 0;
    collector_instance_t* instance = NULL;
    collector_instance_t* tmp_instance = LIST_GET_FIRST(global_collector_instance_cache.instance_list);

    while (tmp_instance != NULL)
    {
        if (strcasecmp(instance_name, tmp_instance->name) == 0)
        {
            instance = tmp_instance;
            break;
        }
        tmp_instance = LIST_GET_NEXT(link, tmp_instance);
    }

    strcpy(count_process, "NULL");
    if (instance == NULL)
        return TRUE;

    collector_table_t* table = LIST_GET_FIRST(instance->collector_table_list->table_list);

    while (table != NULL)
    {
        rows += table->rows;
        collector_field_t* first_field = LIST_GET_FIRST(table->collector_field_list->field_list);

        if (first_field->is_ending
            && first_field->count_sended_count == first_field->count_done_count)
            sended_count += table->rows;
        else
            sended_count += first_field->count_sended_count;

        table = LIST_GET_NEXT(link, table);
    }
    if (rows == 0 || instance->on == FALSE)
        sprintf(count_process, "NULL");
    else if (sended_count > rows) //rows是估计出来的，是可能比实际的表行数要小的，不过应该小不了太多
        sprintf(count_process, "99");
    else
        sprintf(count_process, "%ld", sended_count * 100 / rows);

    return FALSE;
}

int get_dist_count_process(char* instance_name, char* dist_count_process)
{
    ulong rows = 0;
    ulong sended_count = 0;
    collector_instance_t* instance = NULL;
    collector_instance_t* tmp_instance = LIST_GET_FIRST(global_collector_instance_cache.instance_list);

    while (tmp_instance != NULL)
    {
        if (strcasecmp(instance_name, tmp_instance->name) == 0)
        {
            instance = tmp_instance;
            break;
        }
        tmp_instance = LIST_GET_NEXT(link, tmp_instance);
    }

    strcpy(dist_count_process, "NULL");
    if (instance == NULL)
        return TRUE;

    collector_table_t* table = LIST_GET_FIRST(instance->collector_table_list->table_list);

    while (table != NULL)
    {
        collector_field_t* field = LIST_GET_FIRST(table->collector_field_list->field_list);

        while (field != NULL)
        {
            rows += table->rows;

            if (field->is_ending
                && field->dist_count_sended_count == field->dist_count_done_count)
                sended_count += table->rows;
            else
                sended_count += field->dist_count_sended_count;
            field = LIST_GET_NEXT(link, field);
        }
        table = LIST_GET_NEXT(link, table);
    }
    if (rows == 0 || instance->on == FALSE)
        sprintf(dist_count_process, "NULL");
    else if (sended_count > rows) //rows是估计出来的，是可能比实际的表行数要小的，不过应该小不了太多
        sprintf(dist_count_process, "99");
    else
        sprintf(dist_count_process, "%ld", sended_count * 100 / rows);

    return FALSE;
}

int collect_count(MYSQL* mysql, MYSQL* mysql_dc,
                  MYSQL* mysql_collector, collector_queue_item_t* item)
{
    MYSQL_RES* source_res=NULL;
    MYSQL_ROW  source_row;
    char       tmp[1024];
    
    if (get_mysql_res(mysql, source_res, item->sql))
        return TRUE;
    if (source_res == NULL)
        return TRUE;
    source_row= mysql_fetch_row(source_res);
    
    if (source_row == NULL)
    {
        mysql_free_result(source_res);
        return TRUE;
    }
    
    int count = atoi(source_row[0]);
    mysql_free_result(source_res);
    
    if (insert_count(mysql_dc, item, (char*)"count", count))
        return TRUE;
    
    mysql_mutex_lock(&item->field->count_done_mutex);
    item->field->count_done_count++;
    if (item->field->is_ending
        && item->field->count_done_count == item->field->count_sended_count)
    {
        item->table->field_done_count = item->table->collector_field_list->field_list.count;
        sprintf(tmp, "update collector_data.table_dict set count_end_time=now() \
                where host='%s' and port=%d and db='%s' and tname='%s'",
                item->host, item->port, item->db, item->tname);
        get_mysql_res(mysql_collector, source_res, tmp);
    }
    mysql_mutex_unlock(&item->field->count_done_mutex);
    return FALSE;
}

int collect_dist_count(MYSQL* mysql, MYSQL* mysql_dc,
                       MYSQL* mysql_collector, MYSQL* mysql_tmp, collector_queue_item_t* item)
{
    MYSQL_RES* source_res=NULL;
    MYSQL_ROW  source_row;
    str_t*     insert_sql;
    str_t*     tmp_chars;
    int        rest = FALSE;
    char       tmp[1024];
    char       host_[30];
    int        ignore = TRUE;
    
    strcpy(host_, item->host);
    str_replace(host_, (char*)".", (char*)"_");
    
    insert_sql = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(insert_sql);
    tmp_chars = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(tmp_chars);
    
    sprintf (tmp, "create database collector_tmp_data_%s_%d", host_, item->port);
    if (get_mysql_res(mysql_tmp, source_res, tmp))
    {
        rest = TRUE;
        goto done;
    }

    sprintf (tmp, "create table collector_tmp_data_%s_%d.%s_%s_%s(\
             value varchar(191) not null default '' primary key\
             )engine=innodb default charset=utf8mb4;", host_, item->port,
             item->db, item->tname, item->field->name);
    if (get_mysql_res(mysql_tmp, source_res, tmp))
    {
        rest = TRUE;
        goto done;
    }
    if (get_mysql_res(mysql, source_res, item->sql))
    {
        rest = TRUE;
        goto done;
    }
    if (source_res == NULL)
    {
        rest = TRUE;
        goto done;
    }
    
    source_row= mysql_fetch_row(source_res);
    
    if (source_row != NULL)
    {
        sprintf(tmp, "insert ignore into collector_tmp_data_%s_%d.%s_%s_%s(value) values",
                host_, item->port, item->db, item->tname, item->field->name);
        str_append(insert_sql, tmp);

        while (source_row != NULL)
        {
            if (source_row[0] != NULL)
            {
                str_append(insert_sql, "('");
                str_append_with_length(tmp_chars, source_row[0], 190);
                char* dupcharsql;
                dupcharsql = (char*)my_malloc(tmp_chars->str_len * 2 + 1, MYF(0));
                memset(dupcharsql, 0, tmp_chars->str_len * 2 + 1);
                mysql_dup_char(tmp_chars->str, dupcharsql, '\\');
                mysql_dup_char(tmp_chars->str, dupcharsql, '\'');
                str_append_with_length(insert_sql, dupcharsql, strlen(dupcharsql));
                str_append(insert_sql, "'),");
                str_truncate_0(tmp_chars);
                my_free(dupcharsql);
            }
            else
            {
                str_append(insert_sql, "(''),");
            }
            source_row= mysql_fetch_row(source_res);
        }
        str_truncate(insert_sql, 1);
        ignore = FALSE;
    }
    
    mysql_free_result(source_res);
    
    if (ignore == FALSE)
    {
        if (get_mysql_res(mysql_tmp, source_res, insert_sql->str))
        {
            rest = TRUE;
            goto done;
        }
        
        mysql_mutex_lock(&item->field->dist_count_done_mutex);
        item->field->dist_count_done_count++;

        if (item->field->is_ending
            && item->field->dist_count_done_count == item->field->dist_count_sended_count)
        {
            item->table->field_done_count++;
            
            ulong count = 0;
            sprintf(tmp, "select count(*) from collector_tmp_data_%s_%d.%s_%s_%s",
                    host_, item->port, item->db, item->tname, item->field->name);
            
            if (get_mysql_res(mysql_tmp, source_res, tmp))
            {
                rest = TRUE;
                mysql_mutex_unlock(&item->field->dist_count_done_mutex);
                goto done;
            }
            if (source_res == NULL)
            {
                rest = TRUE;
                mysql_mutex_unlock(&item->field->dist_count_done_mutex);
                goto done;
            }
            source_row= mysql_fetch_row(source_res);
            
            if (source_row == NULL && source_row[0] == NULL)
            {
                mysql_free_result(source_res);
                rest = TRUE;
                mysql_mutex_unlock(&item->field->dist_count_done_mutex);
                goto done;
            }
            
            count = atol(source_row[0]);
            mysql_free_result(source_res);

            sprintf(tmp, "insert into collector_data_%s_%d.dist_count_%s_%s(variable,value,version) \
                    values('%s',%ld,%ld)",
                    host_, item->port, item->db, item->tname, item->field->name, count, item->version);
            
            if (get_mysql_res(mysql_dc, source_res, tmp))
            {
                rest = TRUE;
                mysql_mutex_unlock(&item->field->dist_count_done_mutex);
                goto done;
            }
            
            sprintf(tmp, "drop table collector_tmp_data_%s_%d.%s_%s_%s",
                    host_, item->port, item->db, item->tname, item->field->name);
            get_mysql_res(mysql_tmp, source_res, tmp);

            if (item->table->field_done_count ==
                item->table->collector_field_list->field_list.count)
            {
                sprintf(tmp, "update collector_data.table_dict set dist_count_end_time=now() \
                        where host='%s' and port=%d and db='%s' and tname='%s'",
                        item->host, item->port, item->db, item->tname);
                get_mysql_res(mysql_collector, source_res, tmp);
            }
        }
        mysql_mutex_unlock(&item->field->dist_count_done_mutex);
    }
    
done:
    str_deinit(insert_sql);
    my_free(insert_sql);
    str_deinit(tmp_chars);
    my_free(tmp_chars);
    return rest;
}

pthread_handler_t collector_work_thread(void* arg)
{
    THD *thd = NULL;
    MYSQL mysql_collector;
    MYSQL mysql_dc;
    MYSQL mysql_tmp;
    MYSQL mysql;
    collector_instance_t* instance;
    int loop_times = 0;
    
    my_thread_init();
    thd= new THD;
    thd->thread_stack= (char*) &thd;
    
    setup_connection_thread_globals(thd);
    
    instance = (collector_instance_t*)arg;
    
    thd->collector_queue_item_list =
    (collector_queue_item_list_t*)my_malloc(sizeof(collector_queue_item_list_t), MY_ZEROFILL);
    LIST_INIT(thd->collector_queue_item_list->item_list);
    
    mysql_mutex_lock(&instance->collector_worker_mutex);
    collector_worker_t *worker = LIST_GET_FIRST(instance->collector_worker_list->worker_list);
    while (worker != NULL)
    {
        if (worker->thd == NULL)
        {
            worker->thd = thd;
            break;
        }
        worker = LIST_GET_NEXT(link, worker);
    }
    mysql_mutex_unlock(&instance->collector_worker_mutex);
    
    collector_queue_item_t* item = NULL;

    if (!instance->on)
        goto done_0;
    
    if (get_mysql_connection(&mysql_collector, inception_collector_host, inception_collector_port,
                             inception_collector_user, inception_collector_password, NULL))
        goto done_0;
    if (get_mysql_connection(&mysql_dc, inception_datacenter_host, inception_datacenter_port,
                             inception_datacenter_user, inception_datacenter_password, NULL))
        goto done_1;
    
    if (get_mysql_connection(&mysql, instance->host, instance->port,
                             remote_system_user, remote_system_password, NULL))
        goto done_2;
    
    if (get_mysql_connection(&mysql_tmp, instance->tmp_host, instance->tmp_port,
                             remote_system_user, remote_system_password, NULL))
        goto done_3;
    
begin:
    if (instance->on)
    {
        if (instance->pause)
        {
            sleep(THREAD_SLEEP_NSEC);
            goto begin;
        }

        item = LIST_GET_FIRST(thd->collector_queue_item_list->item_list);
        while (item != NULL)
        {
            if (loop_times > LOOP_TIMES)
            {
                mysql_mutex_lock(&instance->collector_worker_mutex);
                instance->idle_num--;
                mysql_mutex_unlock(&instance->collector_worker_mutex);
            }
            loop_times = 0;
            if (create_db_table(&mysql_dc, item))
                goto done;
            
            if (item->type == COLLECTOR_RULE_COUNT)
            {
                if (collect_count(&mysql, &mysql_dc, &mysql_collector, item))
                    goto done;
            }
            
            if (item->type == COLLECTOR_RULE_DIST_COUNT)
            {
                if (collect_dist_count(&mysql, &mysql_dc, &mysql_collector, &mysql_tmp, item))
                    goto done;
            }
            
            collector_queue_item_t* next_item = LIST_GET_NEXT(link, item);
            LIST_REMOVE(link, thd->collector_queue_item_list->item_list, item);
            my_free(item);
            item = next_item;
        }
        if (loop_times == LOOP_TIMES)
        {
            mysql_mutex_lock(&instance->collector_worker_mutex);
            instance->idle_num++;
            mysql_mutex_unlock(&instance->collector_worker_mutex);
        }

        if (item == NULL)
        {
            loop_times++;
            sleep(THREAD_SLEEP_NSEC);
            goto begin;
        }
    }
    
done:
    mysql_close(&mysql_tmp);
done_3:
    mysql_close(&mysql);
done_2:
    mysql_close(&mysql_dc);
done_1:
    mysql_close(&mysql_collector);
done_0:
    sql_print_information("collector_work_thread stop.");
    instance->on = FALSE;
    if (worker != NULL && instance->collector_worker_list != NULL)
    {
        LIST_REMOVE(link, instance->collector_worker_list->worker_list, worker);
        worker->thd = NULL;
        my_free(worker);
    }
    free_queue(thd);
    delete thd;
    my_thread_end();
    pthread_exit(0);
    return NULL;
}

int assemble_item(collector_instance_t* (&instance), collector_table_t* (&table_info),
                  collector_field_t* (&field), int type, char* tmp)
{
    collector_queue_item_t* item =
        (collector_queue_item_t*)my_malloc(sizeof(collector_queue_item_t), MY_ZEROFILL);
    strcpy(item->sql, tmp);
    item->type = type;
    strcpy(item->host, table_info->host);
    item->port = table_info->port;
    strcpy(item->db, table_info->db);
    strcpy(item->tname, table_info->tname);
    item->version = instance->version;
    item->field = field;
    item->table = table_info;

    collector_worker_t* worker = LIST_GET_FIRST(instance->collector_worker_list->worker_list);
    while (worker != NULL)
    {
        if (!instance->on)
            return FALSE;
        if (worker->thread_id == instance->thread_id
            && worker->thd->collector_queue_item_list != NULL)
        {
            while (worker->thd->collector_queue_item_list->item_list.count >= CACHE_QUEUE_LENGTH)
                sleep(THREAD_SLEEP_NSEC);

            LIST_ADD_LAST(link, worker->thd->collector_queue_item_list->item_list, item);
            if (++instance->thread_id > instance->threads_limit)
                instance->thread_id = 1;
            if (type == COLLECTOR_RULE_COUNT)
                field->count_sended_count++;
            else if (type == COLLECTOR_RULE_DIST_COUNT)
                field->dist_count_sended_count++;
            break;
        }
        worker = LIST_GET_NEXT(link, worker);
    }

    if (instance->collector_worker_list->worker_list.count == 0)
        return TRUE;
    return FALSE;
}

int assemble_fields_value(MYSQL* mysql, collector_table_t* table_info,
                          collector_field_list_t* field_list, collector_field_t* field_t, int is_first)
{
    MYSQL_RES* res = NULL;
    MYSQL_ROW row;
    char tmp[1024];
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
                        field_t->done = TRUE;
                        return TRUE;
                    }
                    sprintf(tmp, "%s %s and", tmp, value);
                }
                else
                {
                    if (get_field_value(field_list, keys[i], value, (char*)"=", true))
                    {
                        field_t->done = TRUE;
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
    
    if (get_mysql_res(mysql, res, tmp))
    {
        field_t->done = TRUE;
        return TRUE;
    }
    row = mysql_fetch_row(res);
    if (row == NULL)
    {
        if (is_first)
        {
            field_t->done = TRUE;
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
    {
        for (int i = 0; i < count; ++i)
            set_field_value(field_list, keys[i], row[i], FIELD_VALUE_TMP);
    }
    else
    {
        if (!is_first)
            field_t->is_ending = TRUE;
    }
    mysql_free_result(res);
    return FALSE;
}

int hand_out_count_sql(MYSQL* mysql,
                       collector_instance_t* (&instance))
{
    char tmp[1024];
    uint table_done_count = 0;
    collector_table_t* table_info;
    
    while (table_done_count != instance->collector_table_list->table_list.count)
    {
        table_info = LIST_GET_FIRST(instance->collector_table_list->table_list);
        while(table_info != NULL && instance->on)
        {
            if (!(table_info->rule == COLLECTOR_RULE_ALL
                 || table_info->rule & COLLECTOR_RULE_COUNT))
            {
                table_done_count++;
                table_info->done = TRUE;
                table_info->field_done_count = table_info->collector_field_list->field_list.count;
                table_info = LIST_GET_NEXT(link, table_info);
                continue;
            }

            //判断表是否已做完
            if (table_info->done)
            {
                table_info = LIST_GET_NEXT(link, table_info);
                continue;
            }
            collector_field_t* field = LIST_GET_FIRST(table_info->collector_field_list->field_list);
            
            if (field == NULL)
            {
                table_info->field_done_count = table_info->collector_field_list->field_list.count;
                table_info->done = TRUE;
                table_done_count++;
                continue;
            }
            
            if (field != NULL && field->is_beginning)
            {
                if (assemble_fields_value(mysql, table_info,
                                          table_info->collector_field_list,
                                          field, TRUE))
                {
                    clean_field_value(table_info->collector_field_list);
                    table_info->field_done_count = table_info->collector_field_list->field_list.count;
                    table_info->done = TRUE;
                    table_done_count++;
                    table_info = LIST_GET_NEXT(link, table_info);
                    continue;
                }
                field->is_beginning = FALSE;
            }
            assemble_fields_value(mysql, table_info,
                                  table_info->collector_field_list,
                                  field, FALSE);
            if (field->done)
            {
                table_info->done = TRUE;
                table_done_count++;
                continue;
            }
            
            int limits = table_info->steps * table_info->sample_percent;
            sprintf(tmp, "select count(*) from %s.%s force index(primary) \
                    where 1=1 and ", table_info->db, table_info->tname);
            for (int j = table_info->key_count; j > 0; --j)
            {
                sprintf(tmp, "%s ( ", tmp);
                for (int i = 0; i< j; ++i)
                {
                    char value[256];
                    if (i+1 == j)
                    {
                        if (!get_field_value(table_info->collector_field_list,
                                             table_info->keys[i], value, (char*)">=", TRUE))
                            sprintf(tmp, "%s %s and", tmp, value);
                        if (!get_field_value(table_info->collector_field_list,
                                             table_info->keys[i], value, (char*)"<=", false))
                            sprintf(tmp, "%s %s and", tmp, value);
                    }
                    else
                    {
                        if (!get_field_value(table_info->collector_field_list,
                                             table_info->keys[i], value, (char*)"=", TRUE))
                            sprintf(tmp, "%s %s and", tmp, value);
                        if (!get_field_value(table_info->collector_field_list,
                                             table_info->keys[i], value, (char*)"=", FALSE))
                            sprintf(tmp, "%s %s and", tmp, value);
                    }
                }
                sprintf(tmp, "%s 1=1 ) ", tmp);
                if (j-1 != 0)
                    sprintf(tmp, "%s or ", tmp);
            }
            sprintf(tmp, "%s limit %d", tmp, limits);
            
            if (assemble_item(instance, table_info, field, COLLECTOR_RULE_COUNT, tmp))
                return TRUE;

            exchange_field_fore_and_tmp(table_info->collector_field_list);
            table_info = LIST_GET_NEXT(link, table_info);
        }
    }
    return FALSE;
}

int hand_out_dist_count_sql(MYSQL *mysql, collector_instance_t* (&instance))
{
    char tmp[1024];
    uint table_done_count = 0;
    collector_table_t* table_info;
    
    while (table_done_count != instance->collector_table_list->table_list.count)
    {
        table_info = LIST_GET_FIRST(instance->collector_table_list->table_list);
        while(table_info != NULL && instance->on)
        {
            if (!(table_info->rule == COLLECTOR_RULE_ALL
                  || table_info->rule & COLLECTOR_RULE_DIST_COUNT))
            {
                table_done_count++;
                table_info->done = TRUE;
                table_info->field_done_count = table_info->collector_field_list->field_list.count;
                table_info = LIST_GET_NEXT(link, table_info);
                continue;
            }

            //判断表是否已做完
            if (table_info->done)
            {
                table_info = LIST_GET_NEXT(link, table_info);
                continue;
            }
            collector_field_t* field = LIST_GET_FIRST(table_info->collector_field_list->field_list);
            //找到第一个未做完的列
            while (field != NULL)
            {
                if (!field->done)
                    break;
                field = LIST_GET_NEXT(link, field);
            }
            //如果没有没做完的列，则表标记做完
            if (field == NULL)
            {
                table_info->done = TRUE;
                table_done_count++;
                continue;
            }

            if (field != NULL && field->is_beginning)
            {
                if (assemble_fields_value(mysql, table_info,
                                          table_info->collector_field_list,
                                          field, TRUE))
                {
                    clean_field_value(table_info->collector_field_list);
                    table_info->field_done_count++;
                    table_info = LIST_GET_NEXT(link, table_info);
                    continue;
                }
                field->is_beginning = FALSE;
            }
            assemble_fields_value(mysql, table_info,
                                  table_info->collector_field_list,
                                  field, FALSE);

            if (field->done)
                continue;

            int limits = table_info->steps * table_info->sample_percent;
            sprintf(tmp, "select %s, count(*) from %s.%s force index(primary) \
                    where 1=1 and ", field->name, table_info->db, table_info->tname);
            for (int j = table_info->key_count; j > 0; --j)
            {
                sprintf(tmp, "%s ( ", tmp);
                for (int i = 0; i< j; ++i)
                {
                    char value[256];
                    if (i+1 == j)
                    {
                        if (!get_field_value(table_info->collector_field_list,
                                             table_info->keys[i], value, (char*)">=", true))
                            sprintf(tmp, "%s %s and", tmp, value);
                        if (!get_field_value(table_info->collector_field_list,
                                             table_info->keys[i], value, (char*)"<=", false))
                            sprintf(tmp, "%s %s and", tmp, value);
                    }
                    else
                    {
                        if (!get_field_value(table_info->collector_field_list,
                                             table_info->keys[i], value, (char*)"=", true))
                            sprintf(tmp, "%s %s and", tmp, value);
                        if (!get_field_value(table_info->collector_field_list,
                                             table_info->keys[i], value, (char*)"=", false))
                            sprintf(tmp, "%s %s and", tmp, value);
                    }
                }
                sprintf(tmp, "%s 1=1 ) ", tmp);
                if (j-1 != 0)
                    sprintf(tmp, "%s or ", tmp);
            }
            sprintf(tmp, "%s group by %s limit %d", tmp, field->name, limits);
            
            if (assemble_item(instance, table_info, field, COLLECTOR_RULE_DIST_COUNT, tmp))
                return TRUE;

            exchange_field_fore_and_tmp(table_info->collector_field_list);
            table_info = LIST_GET_NEXT(link, table_info);
        }
    }
    return FALSE;
}

int wait_last_time_hand_out(collector_instance_t* (&instance))
{
    collector_table_t* table_info = LIST_GET_FIRST(instance->collector_table_list->table_list);
    while (table_info != NULL)
    {
        if (table_info->done &&
            table_info->field_done_count == table_info->collector_field_list->field_list.count)
        {
            table_info = LIST_GET_NEXT(link, table_info);
            continue;
        }
        else
        {
            sleep(THREAD_SLEEP_NSEC);
            continue;
        }
    }
    return FALSE;
}

int hand_out_item(collector_instance_t* (&instance))
{
    MYSQL mysql;

    collector_table_t *table_info = LIST_GET_FIRST(instance->collector_table_list->table_list);
    if (table_info == NULL)
        return TRUE;

    if (get_mysql_connection(&mysql, table_info->host, table_info->port,
                             remote_system_user, remote_system_password, NULL))
        return TRUE;

    if (hand_out_count_sql(&mysql, instance))
        goto done;
    wait_last_time_hand_out(instance);

    clean_table_and_field_flag(instance);

    if (hand_out_dist_count_sql(&mysql, instance))
        goto done;
    wait_last_time_hand_out(instance);

done:
    clean_table_and_field_flag(instance);
    return FALSE;
}

pthread_handler_t inception_collector_thread(void* arg)
{
    pthread_t threadid;
    THD *thd= NULL;
    
    my_thread_init();
    thd= new THD();
    thd->thread_stack= (char*) &thd;
    
    pthread_detach_this_thread();
    
    setup_connection_thread_globals(thd);
    
    thd->lex->name.str = (char*)arg;
    thd->lex->name.length = strlen((char*)arg);

    collector_worker_t *last_worker = NULL;
    collector_instance_t* instance = NULL;

    if (load_instance(thd, instance) || load_table(thd, instance))
        goto done;
    
    for (int i=0; i < instance->threads_limit; ++i)
        mysql_thread_create(0, &threadid, &connection_attrib,
                            collector_work_thread, (void*)instance);
    //确保线程都创建起来才能往线程队列中插入数据。
    last_worker = LIST_GET_LAST(instance->collector_worker_list->worker_list);
    while (last_worker->thd == NULL)
        sleep(THREAD_SLEEP_NSEC);
    
    if (hand_out_item(instance))
        goto done;
    
    while (instance->idle_num != instance->threads_limit && instance->on)
        sleep(THREAD_SLEEP_NSEC);
    
done:
    sql_print_information("inception_collector_thread stop.");
    instance->on = FALSE;
    while (instance->collector_worker_list->worker_list.count != 0)
        sleep(THREAD_SLEEP_NSEC);
    free_instance(instance);
    thd->close_all_connections();
    delete thd;
    my_thread_end();
    pthread_exit(0);
    return NULL;
}

int inception_collector_start(THD* thd)
{
    pthread_t       threadid;
    MYSQL           mysql;
    MYSQL_RES       *source_res;
    char            tmp[1024];

    if (validate_instance(thd))
    {
        my_error(ER_UNKNOWN_COLLECTOR_INSTANCE,MYF(0),thd->lex->name.str);
        return TRUE;
    }

    collector_instance_t* instance = NULL;
    if (load_instance(thd, instance))
        return TRUE;

    if (!get_mysql_connection(&mysql, inception_collector_host, inception_collector_port,
                              inception_collector_user, inception_collector_password, NULL))
    {
        sprintf(tmp, "update collector_data.instance_dict set start_time=now() \
                where name = \'%s\'", instance->name);
        get_mysql_res(&mysql, source_res ,tmp);
        mysql_close(&mysql);
    }

    if (!instance->on)
    {
        instance->on = TRUE;
        mysql_thread_create(0, &threadid, &connection_attrib,
                            inception_collector_thread, (void*)thd->lex->name.str);
        collector_worker_t *last_worker = NULL;
        last_worker = LIST_GET_LAST(instance->collector_worker_list->worker_list);
        while (last_worker->thd == NULL)
            sleep(THREAD_SLEEP_NSEC);
    }

    return FALSE;
}

int inception_collector_stop(THD* thd)
{
    if (validate_instance(thd))
    {
        my_error(ER_UNKNOWN_COLLECTOR_INSTANCE,MYF(0),thd->lex->name.str);
        return TRUE;
    }
    
    collector_instance_t* instance = NULL;
    if (load_instance(thd, instance))
        return TRUE;
    
    if (instance->on)
    {
        instance->on = FALSE;
        while (instance->collector_worker_list != NULL)
            sleep(THREAD_SLEEP_NSEC);
    }
    return FALSE;
}

int inception_collector_pause(THD* thd)
{
    if (validate_instance(thd))
    {
        my_error(ER_UNKNOWN_COLLECTOR_INSTANCE,MYF(0),thd->lex->name.str);
        return TRUE;
    }

    collector_instance_t* instance = NULL;
    if (load_instance(thd, instance))
        return TRUE;

    instance->pause = TRUE;
    return FALSE;
}

int inception_collector_continue(THD* thd)
{
    if (validate_instance(thd))
    {
        my_error(ER_UNKNOWN_COLLECTOR_INSTANCE,MYF(0),thd->lex->name.str);
        return TRUE;
    }

    collector_instance_t* instance = NULL;
    if (load_instance(thd, instance))
        return TRUE;

    instance->pause = FALSE;
    return FALSE;
}

int inception_create_collector_instance(THD *thd)
{
    MYSQL *mysql;
    MYSQL_RES *mysql_res = NULL;
    char tmp[1024];
    int rest = FALSE;
    
    if (thd->lex->ident.length > 32)
    {
        my_error(ER_WRONG_STRING_LENGTH,MYF(0),thd->lex->ident.str, "instance_name", 32);
        rest = TRUE;
        goto done;
    }
    if (thd->lex->comment.length > 15)
    {
        my_error(ER_WRONG_STRING_LENGTH,MYF(0),thd->lex->comment.str, "host", 15);
        rest = TRUE;
        goto done;
    }
    
    if (thd->lex->name.length > 15)
    {
        my_error(ER_WRONG_STRING_LENGTH,MYF(0),thd->lex->comment.str, "tmp_host", 15);
        rest = TRUE;
        goto done;
    }

    mysql = thd->get_collector_connection();
    if (mysql == NULL)
    {
        rest = TRUE;
        goto done;
    }
    sprintf(tmp, "insert into collector_data.instance_dict(`name`,`host`,`port`,\
            `threads_limit`,`tmp_host`,`tmp_port`) \
            values(\'%s\',\'%s\',%ld, %d,\'%s\',%d)", thd->lex->ident.str, thd->lex->comment.str,
            thd->lex->type, thd->lex->nest_level, thd->lex->name.str, thd->lex->profile_options);
    if (get_mysql_res(mysql, mysql_res, tmp))
    {
        rest = TRUE;
        goto done;
    }
    
done:
    thd->close_all_connections();
    return rest;
}

int inception_get_collector_instance_list(THD *thd)
{
    List<Item>      field_list;
    char            tmp[1024];
    Protocol*       protocol= thd->protocol;
    MYSQL*          mysql;
    MYSQL_RES*      source_res;
    MYSQL_ROW       source_row;
    int             rest = FALSE;
    
    mysql = thd->get_collector_connection();
    if (mysql == NULL)
    {
        rest = TRUE;
        goto done;
    }
    
    DBUG_ENTER("inception_get_collector_instance_list");
    
    field_list.push_back(new Item_empty_string("instance_name", FN_REFLEN));
    field_list.push_back(new Item_empty_string("host", FN_REFLEN));
    field_list.push_back(new Item_empty_string("port", FN_REFLEN));
    field_list.push_back(new Item_empty_string("threads_limit", FN_REFLEN));
    field_list.push_back(new Item_empty_string("state", FN_REFLEN));
    field_list.push_back(new Item_empty_string("count_procecss", FN_REFLEN));
    field_list.push_back(new Item_empty_string("dist_count_procecss", FN_REFLEN));
    field_list.push_back(new Item_empty_string("start_time", FN_REFLEN));
    field_list.push_back(new Item_empty_string("stop_time", FN_REFLEN));
    field_list.push_back(new Item_empty_string("tmp_host", FN_REFLEN));
    field_list.push_back(new Item_empty_string("tmp_port", FN_REFLEN));
    
    if (protocol->send_result_set_metadata(&field_list,
                                           Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    {
        rest = TRUE;
        goto done;
    }
    strcpy(tmp, "select name, host, port, threads_limit, start_time, stop_time, \
           tmp_host, tmp_port from collector_data.instance_dict");
    
    if (mysql_real_query(mysql, tmp, strlen(tmp)) ||
        (source_res = mysql_store_result(mysql)) == NULL)
    {
        my_message(mysql_errno(mysql), mysql_error(mysql), MYF(0));
        rest = TRUE;
        goto done;
    }
    
    source_row = mysql_fetch_row(source_res);
    while (source_row)
    {
        char state[10];
        char count_process[10];
        char dist_count_process[10];
        get_dist_count_process(source_row[0], dist_count_process);
        if (strcasecmp("NULL", dist_count_process) != 0
            && strcasecmp("0", dist_count_process) != 0)
            strcpy(count_process, "100");
        else
            get_count_process(source_row[0], count_process);

        protocol->prepare_for_resend();
        protocol->store(source_row[0], system_charset_info);
        protocol->store(source_row[1], system_charset_info);
        protocol->store(source_row[2], system_charset_info);
        protocol->store(source_row[3], system_charset_info);
        instance_state(source_row[0], state);
        protocol->store(state, system_charset_info);
        protocol->store(count_process, system_charset_info);
        protocol->store(dist_count_process, system_charset_info);
        protocol->store(source_row[4], system_charset_info);
        protocol->store(source_row[5], system_charset_info);
        protocol->store(source_row[6], system_charset_info);
        protocol->store(source_row[7], system_charset_info);
        protocol->write();
        source_row = mysql_fetch_row(source_res);
    }
    
    mysql_free_result(source_res);
    my_eof(thd);

done:
    thd->close_all_connections();
    return rest;
}

int inception_set_collector_instance_threads_limit(THD *thd)
{
    MYSQL *mysql;
    MYSQL_RES *mysql_res = NULL;
    collector_instance_t* instance = NULL;
    char tmp[1024];
    int rest = FALSE;
    ulong threads_limit = thd->lex->type;
    char instance_name[32];
    strcpy(instance_name, thd->lex->name.str);
    
    if (validate_instance(thd) || load_instance(thd, instance))
    {
        my_error(ER_UNKNOWN_COLLECTOR_INSTANCE,MYF(0),thd->lex->name.str);
        rest = TRUE;
        goto done;
    }

    if (instance->on)
    {
        my_error(ER_COLLECTOR_INSTANCE_ON,MYF(0),thd->lex->name.str);
        rest = TRUE;
        goto done;
    }
    
    instance->threads_limit = threads_limit;
    
    mysql = thd->get_collector_connection();
    if (mysql == NULL)
    {
        rest = TRUE;
        goto done;
    }
    sprintf(tmp, "update collector_data.instance_dict set threads_limit=%ld where name='%s'",
            threads_limit, instance_name);
    if (get_mysql_res(mysql, mysql_res, tmp))
    {
        rest = TRUE;
        goto done;
    }

done:
    thd->close_all_connections();
    return rest;
}

int inception_set_collector_instance_status(THD *thd)
{
    List<Item>      field_list;
    Protocol*       protocol= thd->protocol;
    int             rest = FALSE;
    collector_instance_t* instance = NULL;
    collector_worker_t*     worker = NULL;
    
    if (validate_instance(thd) || load_instance(thd, instance))
    {
        my_error(ER_UNKNOWN_COLLECTOR_INSTANCE,MYF(0),thd->lex->name.str);
        rest = TRUE;
        goto done;
    }
    
    field_list.push_back(new Item_return_int("thread_id", 10, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("host", FN_REFLEN));
    field_list.push_back(new Item_return_int("port", 10, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("db", FN_REFLEN));
    field_list.push_back(new Item_empty_string("tname", FN_REFLEN));
    field_list.push_back(new Item_return_int("queue_length", 10, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_return_int("queue_remain", 10, MYSQL_TYPE_LONG));
    field_list.push_back(new Item_empty_string("sql", FN_REFLEN));
    
    if (protocol->send_result_set_metadata(&field_list,
                                           Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    {
        rest = TRUE;
        goto done;
    }
    
    worker = LIST_GET_FIRST(instance->collector_worker_list->worker_list);
    while (worker != NULL && worker->thd != NULL
           && worker->thd->collector_queue_item_list != NULL)
    {
        collector_queue_item_t *item = LIST_GET_FIRST(worker->thd->collector_queue_item_list->item_list);
        if (item != NULL)
        {
            protocol->prepare_for_resend();
            protocol->store(worker->thread_id);
            if (item != NULL)
                protocol->store(item->host, system_charset_info);
            if (item != NULL)
                protocol->store(item->port);
            if (item != NULL)
                protocol->store(item->db, system_charset_info);
            if (item != NULL)
                protocol->store(item->tname, system_charset_info);
            if (item != NULL)
                protocol->store(CACHE_QUEUE_LENGTH);
            if (item != NULL)
                protocol->store(worker->thd->collector_queue_item_list->item_list.count);
            if (item != NULL)
                protocol->store(item->sql, system_charset_info);
            protocol->write();
        }
        worker = LIST_GET_NEXT(link, worker);
    }
    my_eof(thd);
done:
    return rest;
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
        case INCEPTION_CREATE_COLLECTOR_INSTANCE:
            return inception_create_collector_instance(thd);
        case INCEPTION_SET_COLLECTOR_INSTANCE_THREADS_LIMIT:
            return inception_set_collector_instance_threads_limit(thd);
        case INCEPTION_GET_COLLECTOR_INSTANCE_LIST:
            return inception_get_collector_instance_list(thd);
        case INCEPTION_GET_COLLECTOR_INSTANCE_STATUS:
            return inception_set_collector_instance_status(thd);
        case INCEPTION_PAUSE_COLLECTOR:
            return inception_collector_pause(thd);
        case INCEPTION_CONTINUE_COLLECTOR:
            return inception_collector_continue(thd);
        default:
            return FALSE;
    }
    return FALSE;
}
