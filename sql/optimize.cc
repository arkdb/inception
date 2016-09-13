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

#include "sql_parse.h"
#include "mysqld.h"
#include <string.h>
#include "sql_db.h"
#include "sql_common.h"
#include "derror.h"
#include "mysys_err.h"
#include "item_subselect.h"

int optimize_item(THD* thd, optimize_cache_node_t* query_node, Item* item, st_select_lex *select_lex);

int 
mysql_optimize_where(
    THD* thd, 
    optimize_cache_node_t* optimize_node,
    st_select_lex *select_lex
)
{
    if (select_lex->where)
    {
        optimize_item(thd, optimize_node, select_lex->where, select_lex);
    }

    return false;
}

int mysql_optimize_tables(
    THD* thd, 
    st_select_lex *select_lex,
    TABLE_LIST* tables
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
        optimize_item(thd, optimize_node, item, select_lex);
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

    mysql_optimize_where(thd, optimize_node, select_lex);
    return 0;
}

int optimize_sum_item(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* item,
    st_select_lex *select_lex
)
{
    return 0;
}

int optimize_func_item_field_compare(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* left_item,
    Item* right_item
)
{
    Item_field* left_item_field = dynamic_cast<Item_field*>(left_item);
    Item_field* right_item_field = dynamic_cast<Item_field*>(right_item);
    field_info_t* field_info_r = (field_info_t*)right_item_field->field_info;
    field_info_t* field_info_l = (field_info_t*)left_item_field->field_info;
    table_rt_t* table_info_r= (table_rt_t*)right_item_field->table_rt;
    table_rt_t* table_info_l= (table_rt_t*)left_item_field->table_rt;
    if (field_info_r && field_info_l)
    {
        if (field_info_r->real_type != field_info_l->real_type)
        {
            my_error(ER_DIFF_TYPE_COMPARE_FIELD, MYF(0), 
                table_info_l->table_info->table_name, field_info_l->field_name, 
                field_info_l->data_type, table_info_r->table_info->table_name,
                field_info_r->field_name, field_info_r->data_type);
            mysql_errmsg_append(thd);
        }
        if (field_info_r->charsetnr != field_info_l->charsetnr)
        {
            my_error(ER_DIFF_CHARSET_COMPARE_FIELD, MYF(0), 
                table_info_l->table_info->table_name, field_info_l->field_name, 
                get_charset_name(field_info_l->charsetnr), table_info_r->table_info->table_name,
                field_info_r->field_name, get_charset_name(field_info_r->charsetnr));
            mysql_errmsg_append(thd);
        }
    }

    return false;
}

int optimize_function_item_field_existed(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* item
)
{
    for (uint i=0; i < ((Item_func*) item)->argument_count();i++)
    {
        Item *right_item= ((Item_func*) item)->arguments()[i];
        if (right_item->type() == Item::FIELD_ITEM)
        {
            Item_field* left_item_field = dynamic_cast<Item_field*>(right_item);
            field_info_t* field_info_l = (field_info_t*)left_item_field->field_info;
            table_rt_t* table_info_l= (table_rt_t*)left_item_field->table_rt;
            my_error(ER_FUNC_EXISTED_ON_FIELD, MYF(0), 
                table_info_l->table_info->table_name, field_info_l->field_name, 
                ((Item_func*) item)->func_name());
            mysql_errmsg_append(thd);
        }
    }

    return false;
}

int optimize_like_item_field_compare(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* left_item,
    Item* right_item
)
{
    String tmp;
    String* stringval;

    Item_field* left_item_field = dynamic_cast<Item_field*>(left_item);
    field_info_t* field_info_l = (field_info_t*)left_item_field->field_info;
    table_rt_t* table_info_l= (table_rt_t*)left_item_field->table_rt;

    stringval = ((Item_string*) right_item)->val_str(&tmp);
    if (right_item->type() == Item::STRING_ITEM && 
        left_item->type() == Item::FIELD_ITEM)
    {
        if (!strncasecmp(stringval->ptr(), "%", 1)) 
        {
            my_error(ER_LIKE_COMP_PREFIX_PERCENT, MYF(0), 
                table_info_l->table_info->table_name, field_info_l->field_name, stringval->ptr());
            mysql_errmsg_append(thd);
        }
    }

    return false;
}

longlong optimize_get_field_cardinality(
    THD* thd, 
    table_info_t* table_info,
    char* fieldname,
    st_select_lex *select_lex
)
{
    /* 获取表中某个列的cardinality值：
     * 从两方面获取，首先从数据采集库中查，这是准确的，但如果还没有采集
     * 则从索引的show index from t结果中找到这个列来获取，不过不太准确
     * */
    index_info_t*   index_info;
    index_field_t*   index_field;
    /* TODO: 这里应该是第一部分，但目前还没有采集，只能依赖第二种方式了 */

    /* The second part of get field cardinality value*/
    index_info = LIST_GET_FIRST(table_info->index_lst);
    while (index_info)
    {
        index_field = LIST_GET_FIRST(index_info->field_lst);
        while (index_field)
        {
            if (!strcasecmp(fieldname, index_field->field_name))
                break;
            index_field = LIST_GET_NEXT(link, index_field);
        }

        if (index_field)
            return index_field->cardinality;
        index_info = LIST_GET_NEXT(link, index_info);
    }

    if (index_field)
        return index_field->cardinality;
    
    return -1;
}

int optimize_make_index_name_from_cond(
    cond_info_t* cond_info
)
{
    str_t index_name;
    str_init(&index_name);
    char timestamp[32];
    cond_field_t* cond_field;
    int first_field = true;

    time_t now= my_time(0);

    cond_field = LIST_GET_FIRST(cond_info->field_lst);
    while (cond_field)
    {
        if (!first_field)
            str_append(&index_name, ",");

        str_append(&index_name, cond_field->field_name);
        first_field = false;
        cond_field = LIST_GET_NEXT(link, cond_field);
    }

    strcpy(cond_info->index_fields, str_get(&index_name));


    sprintf(timestamp, "%d", (int)now);
    str_append(&index_name, timestamp);

    my_make_scrambled_password_sha1(timestamp, str_get(&index_name), str_get_len(&index_name));
    sprintf(cond_info->index_name, "IAI_%s", timestamp + 33);

    str_deinit(&index_name);

    return false;
}

int optimize_data_type_match(
    enum enum_field_types real_type,
    int item_type
)
{
    if (item_type == Item::INT_ITEM ||
        item_type == Item::REAL_ITEM ||
        item_type == Item::NULL_ITEM ||
        item_type == Item::STRING_ITEM ||
        item_type == Item::DECIMAL_ITEM)
    {
        if (item_type == Item::INT_ITEM)
        {
            if (real_type == MYSQL_TYPE_INT24 || real_type == MYSQL_TYPE_LONG)
                return true;
        }

        if (item_type == Item::STRING_ITEM)
        {
            if (real_type == MYSQL_TYPE_VARCHAR || real_type == MYSQL_TYPE_VARCHAR ||
                real_type == MYSQL_TYPE_VAR_STRING || real_type == MYSQL_TYPE_STRING)
                return true;
        }

        return false;
    }

    return -1;
}

int
optimize_convert_item_to_type(
    THD* thd,
    char* type_buf,
    Item* item
)
{
    if (!item)
        return 0;
    switch (item->type())
    {
    case Item::STRING_ITEM:
        strcpy(type_buf, "VARCHAR");
        break;
    case Item::INT_ITEM:
        strcpy(type_buf, "INT");
        break;
    case Item::REAL_ITEM:
        strcpy(type_buf, "DOUBLE");
        break;
    case Item::NULL_ITEM:
        strcpy(type_buf, "NULL");
        break;
    case Item::DECIMAL_ITEM:
        strcpy(type_buf, "DECIMAL");
        break;
    default:
        strcpy(type_buf, "UNKNOWN");
        break;
    }
    return 0;
}


int
optimize_convert_item_to_string(
    THD* thd,
    str_t* print_str,
    Item* item
)
{
    if (!item)
        return 0;
    switch (item->type())
    {
    case Item::STRING_ITEM:
        {
            String* stringval;
            String tmp;
            char* fieldname;
            stringval = ((Item_string*) item)->val_str(&tmp);
            fieldname= (char*)my_malloc(stringval->length() + 10, MY_ZEROFILL);
            sprintf(fieldname, "\"%s\"", stringval->ptr());
            str_append(print_str, fieldname);
            my_free(fieldname);
        }
        break;
    case Item::INT_ITEM:
        {
            char fieldname[FN_LEN];
            sprintf(fieldname, "%lld", ((Item_int*) item)->val_int());
            str_append(print_str, fieldname);
        }
        break;
    case Item::REAL_ITEM:
        {
            char fieldname[FN_LEN];
            sprintf(fieldname, "%f", ((Item_int*) item)->val_real());
            str_append(print_str, fieldname);
        }
        break;
    case Item::NULL_ITEM:
        {
            str_append(print_str, "NULL");
        }
        break;
    case Item::DECIMAL_ITEM:
        {
            String* stringval;
            String tmp;
            char* fieldname;
            stringval = ((Item_string*) item)->val_str(&tmp);
            fieldname= (char*)my_malloc(stringval->length(), MY_ZEROFILL);
            sprintf(fieldname, "%s", stringval->ptr());
            str_append(print_str, fieldname);
            my_free(fieldname);
        }
        break;
    default:
        break;
    }
    return 0;
}

int optimize_decide_index_working(
    THD* thd, 
    optimize_cache_node_t* query_node,
    cond_info_t*    cond_info,
    index_info_t*   index_info,
    int             match_count
)
{
    cond_field_t*     cond_field;
    Item*             right_item;
    int               count = 0;

    cond_info->match_count = match_count;

    //比较表达式右值与左值数据类型不同时，不能使用索引
    cond_field = LIST_GET_FIRST(cond_info->field_lst);
    while (cond_field && count < match_count)
    {
        right_item = cond_field->right_item;
        if (optimize_data_type_match(cond_field->field_info->real_type, right_item->type()) == 0)
        {
            str_t  item_string;
            str_init(&item_string);
            char    type_buf[32];

            optimize_convert_item_to_string(thd, &item_string, right_item);
            optimize_convert_item_to_type(thd, type_buf, right_item);
            my_error(ER_CONVERT_DATA_TYPE, MYF(0), cond_info->table_rt->table_info->table_name, 
                cond_field->field_name, str_get(&item_string), 
                type_buf, cond_field->field_info->data_type);
            mysql_errmsg_append(thd);
            cond_info->match_count = count;
            my_error(ER_INDEX_USED_TRUNCATE, MYF(0), count, 
                cond_info->table_rt->table_info->table_name, 
                index_info->index_name);
            mysql_errmsg_append(thd);
            break;
        }

        count ++;
        cond_field = LIST_GET_NEXT(link, cond_field);
    }

    return false;
}

int optimize_func_cond_select_index(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* item,
    st_select_lex *select_lex
)
{
    cond_field_t* cond_field;
    cond_info_t* cond_info;
    index_info_t*   index_info;
    index_field_t*  index_field;
    table_info_t*   table_info;
    int             max_match_count=0;
    int             match_count;
    index_info_t*   match_index;
    str_t index_name;

    str_init(&index_name);
    cond_info = LIST_GET_FIRST(select_lex->cond_lst);
    while (cond_info)
    {
        max_match_count = 0;
        table_info = cond_info->table_rt->table_info;
        index_info = LIST_GET_FIRST(table_info->index_lst);
        while (index_info)
        {
            match_count = 0;
            cond_field = LIST_GET_FIRST(cond_info->field_lst);
            index_field = LIST_GET_FIRST(index_info->field_lst);
            while (cond_field && index_field)
            {
                if (strcasecmp(index_field->field_name, cond_field->field_name))
                    break;

                match_count ++;

                cond_field = LIST_GET_NEXT(link, cond_field);
                index_field = LIST_GET_NEXT(link, index_field);
            }

            /* 判断索引等值比较类型是不是匹配，如果不匹配用不了索引 */
            // match_count = cond_info->match_count;
            if (match_count > 0 && (match_count > max_match_count || 
                  (match_count == max_match_count && 
                   LIST_GET_LEN(match_index->field_lst) < LIST_GET_LEN(index_info->field_lst))))
            {
                max_match_count = match_count; 
                match_index = index_info;
            }

            index_info = LIST_GET_NEXT(link, index_info);
        }

        if (max_match_count > 0)
        {
            /* 找到一个匹配度最大的索引，如果找到的这个比较好，则
             * 这个查询表达式已经是最优的了，而如果不够好，需要新建或者调整,
             * 除此之外，这里需要找到一些不能使用索引的情况，即使索引列是对
             * 应的，但实际上由于种种原因不能使用索引*/
            optimize_decide_index_working(thd, query_node, cond_info, match_index, max_match_count);
        }
        else
        {
            /* 加一个新的索引 */
            optimize_make_index_name_from_cond(cond_info);
            my_error(ER_ADD_INDEX, MYF(0), table_info->db_name, 
                table_info->table_name, cond_info->index_name, cond_info->index_fields);
            mysql_errmsg_append(thd);
        }

        cond_info = LIST_GET_NEXT(link, cond_info);
    }

    return false;
}

int optimize_func_cond_and_item_one(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* item_arg,
    st_select_lex *select_lex
)
{
    cond_field_t* cond_field;
    cond_field_t* cond_field_tmp;
    cond_info_t* cond_info;

    Item *left_item= ((Item_func*) item_arg)->arguments()[0];
    Item *right_item = ((Item_func*) item_arg)->arguments()[1];
    Item_field* left_item_field = dynamic_cast<Item_field*>(left_item);
    field_info_t* field_info_l = (field_info_t*)left_item_field->field_info;
    table_rt_t* table_info_l = (table_rt_t*)left_item_field->table_rt;

    /* 找到当前表在当前表达式中的对列的查询表达式，不在同一个AND
     * 条件表达式中的，需要分成不同组合 */
    cond_info = LIST_GET_FIRST(select_lex->cond_lst);
    while (cond_info)
    {
        if (cond_info->table_rt == table_info_l && cond_info->cond_item == item_arg)
            break;
        cond_info = LIST_GET_NEXT(link, cond_info);
    }

    if (!cond_info)
    {
        cond_info = (cond_info_t*)my_malloc(sizeof(cond_info_t), MY_ZEROFILL);
        cond_info->cond_item = item_arg;
        cond_info->table_rt = table_info_l;
        LIST_ADD_LAST(link, select_lex->cond_lst, cond_info);
    }

    if (!field_info_l->cardinality)
        field_info_l->cardinality = optimize_get_field_cardinality(thd, 
            table_info_l->table_info, field_info_l->field_name, select_lex);

    /* 如果cardinality为1，则说明这个列所有数据都是一样的，建索引没有意义
     * TODO: 可以参数化这个1，用来控制索引选择性的要求,
     * 对于没有索引的列，则不会被漏掉，有可能需要在这列上建索引 */
    if (field_info_l->cardinality <= 1 && field_info_l->cardinality > 0)
        return false;

    /* 对cardinality做排序，从前到后，找到第一个比新插入的列小的列 */
    cond_field_tmp = LIST_GET_FIRST(cond_info->field_lst);
    while (cond_field_tmp)
    {
        if (cond_field_tmp->cardinality < field_info_l->cardinality)
            break;
        cond_field_tmp = LIST_GET_NEXT(link, cond_field_tmp);
    }

    cond_field = (cond_field_t*)my_malloc(sizeof(cond_field_t), MY_ZEROFILL);
    cond_field->cardinality = field_info_l->cardinality;
    cond_field->right_item = right_item;
    strcpy(cond_field->field_name, field_info_l->field_name);
    cond_field->field_info = field_info_l;
    if (cond_field_tmp)
        LIST_INSERT_BEFORE(link, cond_info->field_lst, cond_field_tmp, cond_field);
    else
        LIST_ADD_LAST(link, cond_info->field_lst, cond_field);

    return false;
}

int optimize_func_cond_and_item(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* item,
    st_select_lex *select_lex
)
{
    List<Item> *args= ((Item_cond*) item)->argument_list();
    List_iterator<Item> li(*args);
    Item *item_arg;
    cond_field_t* cond_field;
    cond_field_t* cond_field_tmp;
    cond_info_t* cond_info;

    /* 这里加入的时候，需要先对每个列的cardinality做排序 */
    while ((item_arg= li++))
    {
        if (item_arg->type() != Item::FUNC_ITEM || 
            ((Item_func *)item_arg)->functype() != Item_func::EQ_FUNC)
            continue;
            
        optimize_func_cond_and_item_one(thd, query_node, item_arg, select_lex);
    }

    return false;
}

int optimize_func_cond_item(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* item,
    st_select_lex *select_lex
)
{
    if (!item)
        return 0;
    switch(((Item_func *)item)->functype())
    {
    case Item_func::COND_OR_FUNC:
        break;
    case Item_func::COND_AND_FUNC:
        {
            List<Item> *args= ((Item_cond*) item)->argument_list();
            List_iterator<Item> li(*args);
            Item *item_arg;
            while ((item_arg= li++))
            {
                optimize_item(thd, query_node, item_arg, select_lex);
            }

            optimize_func_cond_and_item(thd, query_node, item, select_lex);
            optimize_func_cond_select_index(thd, query_node, item, select_lex);
        }
        break;
    default:
        break;
    }

    return false;
}

int optimize_item_func_compare(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* item,
    st_select_lex *select_lex
)
{
    Item *left_item= ((Item_func*) item)->arguments()[0];
    optimize_item(thd, query_node, left_item, select_lex);
    Item *right_item= ((Item_func*) item)->arguments()[1];
    optimize_item(thd, query_node, right_item, select_lex);

    /* 为了方便后面处理，对于这种比较表达式，都将FIELD放在左边 */
    if (left_item->type() != Item::FIELD_ITEM && 
        right_item->type() == Item::FIELD_ITEM)
    {
        ((Item_func*) item)->arguments()[1] = left_item;
        ((Item_func*) item)->arguments()[0] = right_item;
        left_item = ((Item_func*) item)->arguments()[0];
        right_item = ((Item_func*) item)->arguments()[1];
    }

    if (left_item->type() == Item::FIELD_ITEM)
    {
        Item_field* left_item_field = dynamic_cast<Item_field*>(left_item);
        field_info_t* field_info_l = (field_info_t*)left_item_field->field_info;
        table_rt_t* table_rt = (table_rt_t*)left_item_field->table_rt;

        if (left_item->type() == Item::FIELD_ITEM && 
            right_item->type() != Item::FIELD_ITEM)
        {
            if (optimize_data_type_match(field_info_l->real_type, right_item->type()) == 0)
            {
                char buf[64];
                optimize_convert_item_to_type(thd, buf, right_item);
                my_error(ER_DIFF_TYPE_COMPARE_FIELD, MYF(0), 
                    table_rt->table_info->table_name, field_info_l->field_name, 
                    field_info_l->data_type, "CONST", "CONST", buf);
                mysql_errmsg_append(thd);
            }
        }

        if (left_item->type() == Item::FIELD_ITEM && 
            right_item->type() == Item::FIELD_ITEM)
            optimize_func_item_field_compare(thd, query_node, left_item, right_item);
    }

    /* 处理where条件只有一个表达式条件的情况 */
    if (select_lex->where && select_lex->where->type() == Item::FUNC_ITEM &&
        (((Item_func *)select_lex->where)->functype() == Item_func::EQ_FUNC))
    {
        optimize_func_cond_and_item_one(thd, query_node, select_lex->where, select_lex);
        optimize_func_cond_select_index(thd, query_node, select_lex->where, select_lex);
    }

    return false;
}

int optimize_func_item(
    THD* thd, 
    optimize_cache_node_t* query_node,
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
            optimize_item_func_compare(thd, query_node, item, select_lex);
        }
        break;

    case Item_func::ISNULL_FUNC:
    case Item_func::ISNOTNULL_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            optimize_item(thd, query_node, left_item, select_lex);
        }
        break;
    case Item_func::LIKE_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            Item *right_item= ((Item_func*) item)->arguments()[1];
            optimize_item(thd, query_node, left_item, select_lex);
            optimize_item(thd, query_node, right_item, select_lex);
            optimize_like_item_field_compare(thd, query_node, left_item, right_item);
        }
        break;
    case Item_func::BETWEEN:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            Item *right_item1= ((Item_func*) item)->arguments()[1];
            Item *right_item2= ((Item_func*) item)->arguments()[2];
            optimize_item(thd, query_node, left_item, select_lex);
            optimize_item(thd, query_node, right_item1, select_lex);
            optimize_item(thd, query_node, right_item2, select_lex);
        }
        break;
    case Item_func::IN_FUNC:
    case Item_func::MULT_EQUAL_FUNC:
        {
            for (uint i=0; i < ((Item_func*) item)->argument_count();i++)
            {
                Item *right_item= ((Item_func*) item)->arguments()[i];
                optimize_item(thd, query_node, right_item, select_lex);
            }
        }
        break;
    case Item_func::NEG_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            optimize_item(thd, query_node, left_item, select_lex);
        }
        break;
    case Item_func::NOT_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            optimize_item(thd, query_node, left_item, select_lex);
        }
        break;
    case Item_func::NOW_FUNC:
        {
        }
        break;
    case Item_func::EXTRACT_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            optimize_item(thd, query_node, left_item, select_lex);
        }
        break;
    case Item_func::FUNC_SP:
    case Item_func::UNKNOWN_FUNC:
        {
            for (uint i=0; i < ((Item_func*) item)->argument_count();i++)
            {
                Item *right_item= ((Item_func*) item)->arguments()[i];
                optimize_item(thd, query_node, right_item, select_lex);
            }
            optimize_function_item_field_existed(thd, query_node, item);
        }
        break;

    default:
        optimize_function_item_field_existed(thd, query_node, item);
        break;
    }

    return false;
}


int optimize_item(
    THD* thd, 
    optimize_cache_node_t* query_node,
    Item* item,
    st_select_lex *select_lex
)
{
    if (!item)
        return 0;
    switch (item->type()) {
    case Item::INT_ITEM:
    case Item::REAL_ITEM:
    case Item::NULL_ITEM:
    case Item::STRING_ITEM:
    case Item::DECIMAL_ITEM:
        break;
    case Item::REF_ITEM:
    case Item::FIELD_ITEM:
        {
            table_rt_t* tablert;
            if (!strcasecmp(((Item_field*)item)->field_name, "*"))
                break;

            dynamic_cast<Item_field*>(item)->table_rt = NULL;
            dynamic_cast<Item_field*>(item)->field_info = NULL;
            tablert = mysql_find_field_from_all_tables(
                thd, &query_node->rt_lst, select_lex, ((Item_field*)item)->db_name, 
                ((Item_field*)item)->table_name, ((Item_field*)item)->field_name); 
            if (tablert)
            {
                dynamic_cast<Item_field*>(item)->table_rt = tablert;
                if (strcasecmp(((Item_field*)item)->field_name, "*"))
                {
                    dynamic_cast<Item_field*>(item)->field_info = 
                      mysql_find_field_by_name(tablert->table_info, 
                          (char*)((Item_field*)item)->field_name);
                }
            }
            else if (select_lex->order_group_having)
            {
                Item* item_item;
                List_iterator<Item> it(select_lex->item_list);
                while ((item_item = it++))
                {
                    if (item_item->item_name.is_set())
                    {
                        if (!strcasecmp(item_item->item_name.ptr(), 
                              ((Item_field*)item)->field_name))
                        {
                            ((Item_field*)item)->field_info = mysql_find_field_by_name(
                                tablert->table_info, (char*)((Item_field*)item)->field_name);
                            break;
                        }
                    }
                }

                if (item_item == NULL)
                {
                    my_error(ER_COLUMN_NOT_EXISTED, MYF(0), ((Item_field*)item)->field_name);
                    mysql_errmsg_append(thd);
                }
            }
            else
            {
                my_error(ER_COLUMN_NOT_EXISTED, MYF(0), ((Item_field*)item)->field_name);
                mysql_errmsg_append(thd);
            }
        }
        break;
    case Item::COND_ITEM:
        {
            optimize_func_cond_item(thd, query_node, item, select_lex);
        }
        break;
    case Item::FUNC_ITEM:
        {
            optimize_func_item(thd, query_node, item, select_lex);
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
                if (mysql_optimize_subselect(thd, query_node, select_lex_new, false))
                    return true;
            }
        }
        break;
    case Item::SUM_FUNC_ITEM:
        {
            optimize_sum_item(thd, query_node, item, select_lex);
        }
        break;
    case Item::ROW_ITEM:
        {
            for (uint i=0; i < ((Item_row*)item)->cols();i++)
            {
                Item *right_item= ((Item_row*)item)->element_index(i);
                optimize_item(thd, query_node, right_item, select_lex);
            }
        }
        break;
    default:
        break;
    }

    return false;
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

