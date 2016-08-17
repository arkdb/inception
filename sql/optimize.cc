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
        }
        break;
    default:
        break;
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
            Item *left_item= ((Item_func*) item)->arguments()[0];
            optimize_item(thd, query_node, left_item, select_lex);
            Item *right_item= ((Item_func*) item)->arguments()[1];
            optimize_item(thd, query_node, right_item, select_lex);
            if (left_item->type() == Item::FIELD_ITEM && 
                right_item->type() == Item::FIELD_ITEM)
            {
                optimize_func_item_field_compare(thd, query_node, left_item, right_item);
            }
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

