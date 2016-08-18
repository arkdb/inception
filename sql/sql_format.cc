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

int mysql_format_subselect(THD* thd, format_cache_node_t*   format_node, str_t* print_str, st_select_lex *select_lex, bool top);
int format_item(THD* thd, format_cache_node_t*   format_node, str_t* print_str, Item* item, st_select_lex *select_lex);

int
format_sum_item(
    THD* thd,
    format_cache_node_t*   format_node,
    str_t* print_str,
    Item* item,
    st_select_lex *select_lex
)
{
    Item_sum *item_sum= (((Item_sum*) item));
    switch(item_sum->sum_func())
    {
    case Item_sum::COUNT_FUNC:
        str_append(print_str, "COUNT(");
        break;
    case Item_sum::COUNT_DISTINCT_FUNC:
        str_append(print_str, "COUNT(DISTINCT ");
        break;
    case Item_sum::SUM_FUNC:
        str_append(print_str, "SUM(");
        break;
    case Item_sum::SUM_DISTINCT_FUNC:
        str_append(print_str, "SUM(DISTINCT ");
        break;
    case Item_sum::AVG_FUNC:
        str_append(print_str, "AVG(");
        break;
    case Item_sum::AVG_DISTINCT_FUNC:
        str_append(print_str, "AVG(DISTINCT ");
        break;
    case Item_sum::MIN_FUNC:
        str_append(print_str, "MIN(");
        break;
    case Item_sum::MAX_FUNC:
        str_append(print_str, "MAX(");
        break;
    case Item_sum::STD_FUNC:
        str_append(print_str, "STD(");
        break;
    case Item_sum::VARIANCE_FUNC:
        str_append(print_str, "VARIANCE(");
        break;
    case Item_sum::SUM_BIT_FUNC:
        str_append(print_str, "SUMBIT(");
        break;
    case Item_sum::UDF_SUM_FUNC:
        str_append(print_str, "UDFSUM(");
        break;
    case Item_sum::GROUP_CONCAT_FUNC:
        str_append(print_str, "GROUP_CONCAT(");
        break;
    default:
        break;
    }
    
    Item* item_count = ((Item_sum_count*) item)->get_arg(0);
    format_item(thd, format_node, print_str, item_count, select_lex);
    str_append(print_str, ")");
    
    return 0;
}

int
format_func_item(
    THD* thd,
    format_cache_node_t*   format_node,
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
            Item *left_item= ((Item_func*) item)->arguments()[0];
            format_item(thd, format_node, print_str, left_item, select_lex);
            
            if (((Item_func *)item)->functype() == Item_func::EQ_FUNC)
                str_append(print_str, "=");
            else if (((Item_func *)item)->functype() == Item_func::NE_FUNC)
                str_append(print_str, "!=");
            else if (((Item_func *)item)->functype() == Item_func::LT_FUNC)
                str_append(print_str, ">");
            else if (((Item_func *)item)->functype() == Item_func::LE_FUNC)
                str_append(print_str, "<=");
            else if (((Item_func *)item)->functype() == Item_func::GE_FUNC)
                str_append(print_str, ">=");
            else if (((Item_func *)item)->functype() == Item_func::GT_FUNC)
                str_append(print_str, ">");
            
            Item *right_item= ((Item_func*) item)->arguments()[1];
            format_item(thd, format_node, print_str, right_item, select_lex);
        }
        break;
    case Item_func::COND_OR_FUNC:
    case Item_func::COND_AND_FUNC:
        {
            List<Item> *args= ((Item_cond*) item)->argument_list();
            List_iterator<Item> li(*args);
            Item *item_arg;
            int first=0;
            while ((item_arg= li++))
            {
                if (first!=0)
                {
                    if (((Item_func *)item)->functype() == Item_func::COND_AND_FUNC)
                        str_append(print_str, " AND ");
                    else if (((Item_func *)item)->functype() == Item_func::COND_OR_FUNC)
                        str_append(print_str, " OR ");
                }
                format_item(thd, format_node, print_str, item_arg, select_lex);
                first=1;
            }
        }
        break;
    case Item_func::ISNULL_FUNC:
    case Item_func::ISNOTNULL_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            
            format_item(thd, format_node, print_str, left_item, select_lex);
            
            if (((Item_func *)item)->functype() == Item_func::ISNULL_FUNC)
                str_append(print_str, " IS NULL ");
            else
                str_append(print_str, " IS NOT NULL ");
        }
        break;
    case Item_func::LIKE_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            Item *right_item= ((Item_func*) item)->arguments()[1];
            
            format_item(thd, format_node, print_str, left_item, select_lex);
            
            Item_func_like* like_item= dynamic_cast<Item_func_like*>(item);
            if (like_item && like_item->not_like)
                str_append(print_str, " NOT");
            
            str_append(print_str, " LIKE ");
            format_item(thd, format_node, print_str, right_item, select_lex);
        }
        break;
    case Item_func::BETWEEN:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            Item *right_item1= ((Item_func*) item)->arguments()[1];
            Item *right_item2= ((Item_func*) item)->arguments()[2];
            format_item(thd, format_node, print_str, left_item, select_lex);
            
            Item_func_between* between_item= dynamic_cast<Item_func_between*>(item);
            if (between_item && between_item->negated)
                str_append(print_str, " NOT");
            
            str_append(print_str, " BETWEEN ");
            format_item(thd, format_node, print_str, right_item1, select_lex);
            str_append(print_str, " AND ");
            format_item(thd, format_node, print_str, right_item2, select_lex);
        }
        break;
    case Item_func::IN_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            format_item(thd, format_node, print_str, left_item, select_lex);
            
            Item_func_opt_neg* in_item;
            in_item = dynamic_cast<Item_func_opt_neg*>(item);
            if (in_item && in_item->negated)
                str_append(print_str, " NOT IN (");
            else
                str_append(print_str, " IN (");
            
            for (uint i=1; i < ((Item_func*) item)->argument_count();i++)
            {
                Item *right_item= ((Item_func*) item)->arguments()[i];
                format_item(thd, format_node, print_str, right_item, select_lex);
                str_append(print_str, ",");
            }
            
            str_truncate(print_str, 1);
            str_append(print_str, ")");
        }
        break;
    case Item_func::MULT_EQUAL_FUNC:
        {
            for (uint i=0; i < ((Item_func*) item)->argument_count();i++)
            {
                Item *right_item= ((Item_func*) item)->arguments()[i];
                format_item(thd, format_node, print_str, right_item, select_lex);
                str_append(print_str, "=");
            }
            
            str_truncate(print_str, 1);
        }
        break;
    case Item_func::NEG_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            str_append(print_str, "-");
            format_item(thd, format_node, print_str, left_item, select_lex);
        }
        break;
    case Item_func::NOT_FUNC:
        {
            Item *left_item= ((Item_func*) item)->arguments()[0];
            if ((left_item->type() != Item::SUBSELECT_ITEM && 
                dynamic_cast<Item_in_subselect*>(left_item)) &&
               (((Item_func*) item))->functype() != Item_func::LIKE_FUNC)
                str_append(print_str, " NOT ");
            format_item(thd, format_node, print_str, left_item, select_lex);
        }
        break;
    case Item_func::NOW_FUNC:
        {
            str_append(print_str, "NOW()");
        }
        break;
    case Item_func::EXTRACT_FUNC:
        {
            str_append(print_str, " EXTRACT(");
            Item *left_item= ((Item_func*) item)->arguments()[0];
            format_item(thd, format_node, print_str, left_item, select_lex);
            str_append(print_str, ")");
        }
        break;
    case Item_func::FUNC_SP:
    case Item_func::UNKNOWN_FUNC:
        break;
    default:
        break;
    }
    
    return 0;
}

int mysql_format_select_condition(
    THD* thd,
    format_cache_node_t*   format_node,
    str_t* print_str,
    st_select_lex *select_lex
)
{
    ORDER*   order;
    if (select_lex->where)
    {
        str_append(print_str, " WHERE ");
        format_item(thd, format_node, print_str, select_lex->where, select_lex);
    }
    
    if (select_lex->group_list.elements != 0)
    {
        str_append(print_str, " GROUP BY ");
        select_lex->order_group_having = true;
        for (order= select_lex->group_list.first; order; order= order->next)
        {
            format_item(thd, format_node, print_str, *order->item, select_lex);
            str_append(print_str, ",");
        }
        select_lex->order_group_having = false;
        str_truncate(print_str, 1);
    }
    
    if (select_lex->having)
    {
        str_append(print_str, " HAVING ");
        select_lex->order_group_having = true;
        format_item(thd, format_node, print_str, select_lex->having, select_lex);
        select_lex->order_group_having = false;
    }
    
    if (select_lex->order_list.elements != 0)
    {
        str_append(print_str, " ORDER BY ");
        select_lex->order_group_having = true;
        for (order= select_lex->order_list.first ; order; order= order->next)
        {
            format_item(thd, format_node, print_str, *order->item, select_lex);
            str_append(print_str, ",");
        }
        select_lex->order_group_having = false;
        str_truncate(print_str, 1);
    }
    
    if (select_lex->select_limit)
    {
        str_append(print_str, " LIMIT ");
        
        if (select_lex->offset_limit)
        {
            format_item(thd, format_node, print_str, select_lex->offset_limit, select_lex);
            str_append(print_str, ",");
        }
        format_item(thd, format_node, print_str, select_lex->select_limit, select_lex);
    }
    
    return 0;
}

int mysql_format_tables(
    THD* thd,
    format_cache_node_t* format_node,
    st_select_lex *select_lex,
    str_t* print_str,
    TABLE_LIST* tables
)
{
    char tablename[FN_LEN];
    char using_cond[FN_LEN];
    TABLE_LIST* table;
    Item    *join_cond;
    
    if (tables)
    {
        if (format_node->is_update == 0)
            str_append(print_str, " FROM ");
        int first=0;
        for (table= tables; table; table= table->next_local)
        {
            if (table->outer_join == JOIN_TYPE_RIGHT)
                str_append(print_str, " RIGHT JOIN ");
            else if (table->outer_join == JOIN_TYPE_LEFT)
                str_append(print_str, " LEFT JOIN ");
            else if (table->straight == true)
                str_append(print_str, " STRAIGHT_JOIN ");
            else if (table->natural_join_type == 1)
                str_append(print_str, " JOIN ");
            else if (first==1)
                str_append(print_str, ",");
            
            first=1;
            
            if (table->is_view_or_derived())
            {
                mysql_format_subselect(thd, format_node, print_str,
                                       table->derived->first_select(), false);
                sprintf(tablename, " %s", table->alias);
                str_append(print_str, tablename);
            }
            else
            {
                sprintf(tablename, "%s.", table->db);
                str_append(print_str, tablename);
                
                sprintf(tablename, "%s", table->table_name);
                str_append(print_str, tablename);
                
            }
            
            if (table->join_using_fields && table->join_using_fields->elements > 0)
            {
                str_append(print_str, " USING(");
                while (table->join_using_fields->elements > 0)
                {
                    String* field= table->join_using_fields->pop();
                    sprintf(using_cond, "%s", field->ptr());
                    str_append(print_str, using_cond);
                    str_append(print_str, ",");
                }
                str_truncate(print_str, 1);
                str_append(print_str, ")");
            }
            
            if (table->join_cond())
            {
                str_append(print_str, " ON ");
                
                join_cond = table->join_cond();
                if (join_cond)
                {
                    format_item(thd, format_node, print_str, join_cond, select_lex);
                }
            }
        }
    }
    
    return 0;
}

int mysql_format_select(THD* thd)
{
    format_cache_node_t*   format_node;
    format_cache_t*        format_cache;
    SELECT_LEX* select_lex = &thd->lex->select_lex;
    
    format_cache = thd->format_cache;
    
    format_node = (format_cache_node_t*)my_malloc(sizeof(format_cache_node_t), MY_ZEROFILL);
    format_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    format_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(format_node->query_tree);
    str_init(format_node->sql_statements);
    format_node->is_update= 0;
    str_append_with_length(format_node->sql_statements, thd->query(), thd->query_length());
    
    if (mysql_format_subselect(thd, format_node, format_node->query_tree, select_lex, true))
        return true;
    
    if (thd->errmsg != NULL && str_get_len(thd->errmsg) > 0)
    {
        format_node->errlevel= INCEPTION_PARSE;
        format_node->errmsg= thd->errmsg;
        thd->errmsg= NULL;
    }
    
    LIST_ADD_LAST(link, format_cache->field_lst, format_node);
    return false;
}


int mysql_format_subselect(
    THD* thd,
    format_cache_node_t*   format_node,
    str_t* print_str,
    st_select_lex *select_lex,
    bool top
)
{
    Item* item;
    TABLE_LIST* tables;
    
    if (mysql_load_tables(thd, &format_node->rt_lst, select_lex))
        return true;
    if (!top)
    {
        str_append(print_str, "(");
    }
    str_append(print_str, "SELECT ");
    List_iterator<Item> it(select_lex->item_list);
    while ((item= it++))
    {
        format_item(thd, format_node, print_str, item, select_lex);
        str_append(print_str, ",");
    }
    str_truncate(print_str, 1);
    
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
        mysql_format_tables(thd, format_node, select_lex, print_str, tables);
    }
    
    mysql_format_select_condition(thd, format_node, print_str, select_lex);
    if (!top)
        str_append(print_str, ")");
    
    return 0;
}

int
format_item(
    THD* thd,
    format_cache_node_t*   format_node,
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
            if (thd->thd_sinfo->parameterize == 1)
                str_append(print_str, "?");
            else
            {
                String* stringval;
                String tmp;
                char* fieldname;
                stringval = ((Item_string*) item)->val_str(&tmp);
                fieldname= (char*)my_malloc(stringval->length() + 10, MY_ZEROFILL);
                sprintf(fieldname, "%s", stringval->ptr());
                str_append(print_str, fieldname);
            }
        }
        break;
    case Item::REF_ITEM:
    case Item::FIELD_ITEM:
        {
            table_info_t* tableinfo;
            table_rt_t* tablert;
            char fieldname[FN_LEN];
            char dbname[FN_LEN];
            char tablename[FN_LEN];
            dbname[0]=fieldname[0]=tablename[0] = '\0';
            
            if (!strcasecmp(((Item_field*)item)->field_name, "*"))
            {
                if (((Item_field*)item)->table_name)
                    sprintf(fieldname, "%s.", ((Item_field*)item)->field_name);
                
                sprintf(fieldname, "%s", ((Item_field*)item)->field_name);
                str_append(print_str, fieldname);
                break;
            }
            
            if (((Item_field*)item)->db_name)
                sprintf(dbname, "%s.", ((Item_field*)item)->db_name);
            if (((Item_field*)item)->table_name)
                sprintf(tablename, "%s.", ((Item_field*)item)->table_name);
            
            tablert = mysql_find_field_from_all_tables(thd, &format_node->rt_lst, 
                          select_lex, ((Item_field*)item)->db_name,
                          ((Item_field*)item)->table_name, ((Item_field*)item)->field_name);
            if (tablert)
            {
                if (strcasecmp(((Item_field*)item)->field_name, "*"))
                {
                    if (tablert && thd->variables.inception_format_sql_full_path)
                    {
                        tableinfo = tablert->table_info;
                        sprintf(tablename, "%s.", tableinfo->table_name);
                        
                        if (dbname[0] == '\0' && tableinfo->db_name[0] != '\0')
                            sprintf(dbname, "%s.", tableinfo->db_name);
                        if (tablename[0] == '\0')
                            sprintf(tablename, "%s.", tableinfo->table_name);
                    }
                    
                    str_append(print_str, dbname);
                    str_append(print_str, tablename);
                }
                
                sprintf(fieldname, "%s", ((Item_field*)item)->field_name);
                str_append(print_str, fieldname);
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
                            sprintf(fieldname, "%s", ((Item_field*)item)->field_name);
                            str_append(print_str, fieldname);
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
    case Item::FUNC_ITEM:
        {
            format_func_item(thd, format_node, print_str, item, select_lex);
        }
        break;
    case Item::INT_ITEM:
        {
            if (thd->thd_sinfo->parameterize == 1)
                str_append(print_str, "?");
            else
            {
                char fieldname[FN_LEN];
                sprintf(fieldname, "%lld", ((Item_int*) item)->val_int());
                str_append(print_str, fieldname);
            }
        }
        break;
    case Item::REAL_ITEM:
        {
            if (thd->thd_sinfo->parameterize == 1)
                str_append(print_str, "?");
            else
            {
                char fieldname[FN_LEN];
                sprintf(fieldname, "%f", ((Item_int*) item)->val_real());
                str_append(print_str, fieldname);
            }
        }
        break;
    case Item::NULL_ITEM:
        {
            str_append(print_str, "NULL");
        }
        break;
    case Item::COND_ITEM:
        {
            format_func_item(thd, format_node, print_str, item, select_lex);
        }
        break;
    case Item::SUBSELECT_ITEM:
        {
            st_select_lex *select_lex_new;
            subselect_single_select_engine* real_engine;
            Item_in_subselect* insubselect;
            
            insubselect = dynamic_cast<Item_in_subselect*>(item);
            if (insubselect && insubselect->left_expr)
            {
                format_item(thd, format_node, print_str, insubselect->left_expr, select_lex);
                if (insubselect->not_in_subselect)
                    str_append(print_str, " NOT IN ");
                else
                    str_append(print_str, " IN ");
            }
            
            const subselect_engine *engine = ((Item_subselect*)item)->get_engine_for_explain();
            subselect_single_select_engine::enum_engine_type engine_type = engine->engine_type();
            
            if (engine_type == subselect_engine::SINGLE_SELECT_ENGINE)
            {
                real_engine = (subselect_single_select_engine*)engine;
                select_lex_new = real_engine->get_st_select_lex();
                if (mysql_format_subselect(thd, format_node, print_str, select_lex_new, false))
                    return true;
            }
        }
        break;
    case Item::SUM_FUNC_ITEM:
        {
            format_sum_item(thd, format_node, print_str, item, select_lex);
        }
        break;
    case Item::ROW_ITEM:
        {
            for (uint i=0; i < ((Item_row*)item)->cols();i++)
            {
                Item *right_item= ((Item_row*)item)->element_index(i);
                format_item(thd, format_node, print_str, right_item, select_lex);
                str_append(print_str, ",");
            }
            str_truncate(print_str, 1);
        }
        break;
    case Item::DECIMAL_ITEM:
        {
            if (thd->thd_sinfo->parameterize == 1)
                str_append(print_str, "?");
            else
            {
                String* stringval;
                String tmp;
                char* fieldname;
                stringval = ((Item_string*) item)->val_str(&tmp);
                fieldname= (char*)my_malloc(stringval->length(), MY_ZEROFILL);
                sprintf(fieldname, "%s", stringval->ptr());
                str_append(print_str, fieldname);
            }
        }
        break;
    default:
        break;
    }
    
    return 0;
}

int mysql_format_not_support(THD* thd)
{
    format_cache_node_t*   format_node;
    format_cache_t*        format_cache;
    
    format_cache = thd->format_cache;
    
    format_node = (format_cache_node_t*)my_malloc(sizeof(format_cache_node_t), MY_ZEROFILL);
    format_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    format_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(format_node->query_tree);
    str_init(format_node->sql_statements);
    format_node->is_update= 0;
    str_append_with_length(format_node->sql_statements, thd->query(), thd->query_length());
    
    my_error(ER_NOT_SUPPORTED_YET, MYF(0));
    mysql_errmsg_append(thd);
    if (thd->errmsg != NULL && str_get_len(thd->errmsg) > 0)
    {
        format_node->errlevel= INCEPTION_PARSE;
        format_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }
    
    LIST_ADD_LAST(link, format_cache->field_lst, format_node);
    return false;
}

int mysql_format_insert(THD* thd)
{
    format_cache_node_t*   format_node;
    format_cache_t*        format_cache;
    SELECT_LEX* select_lex = &thd->lex->select_lex;
    Item* item;
    List_item *values;
    char tablename[FN_LEN];
    
    format_cache = thd->format_cache;
    
    format_node = (format_cache_node_t*)my_malloc(sizeof(format_cache_node_t), MY_ZEROFILL);
    format_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    format_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(format_node->query_tree);
    str_init(format_node->sql_statements);
    format_node->is_update= 0;
    str_append_with_length(format_node->sql_statements, thd->query(), thd->query_length());
    mysql_load_tables(thd, &format_node->rt_lst, select_lex);
    
    str_append(format_node->query_tree, "INSERT INTO ");
    
    sprintf(tablename, "%s.", thd->lex->query_tables->db);
    str_append(format_node->query_tree, tablename);
    
    sprintf(tablename, "%s", thd->lex->query_tables->table_name);
    str_append(format_node->query_tree, tablename);
    
    if (thd->lex->field_list.elements > 0)
    {
        str_append(format_node->query_tree, "(");
        List_iterator<Item> it(thd->lex->field_list);
        while ((item= it++))
        {
            format_item(thd, format_node, format_node->query_tree, item, &thd->lex->select_lex);
            str_append(format_node->query_tree, ",");
        }
        
        str_truncate(format_node->query_tree, 1);
        str_append(format_node->query_tree, ")");
    }
    
    if (thd->lex->sql_command != SQLCOM_INSERT_SELECT)
    {
        List<List_item> &values_list = thd->lex->many_values;
        List_iterator_fast<List_item> its(values_list);
        str_append(format_node->query_tree, " VALUES");
        while ((values = its++))
        {
            str_append(format_node->query_tree, "(");
            List_iterator<Item> it(*values);
            while ((item= it++))
            {
                format_item(thd, format_node, format_node->query_tree, item, &thd->lex->select_lex);
                str_append(format_node->query_tree, ",");
            }
            str_truncate(format_node->query_tree, 1);
            str_append(format_node->query_tree, "),");
        }
        str_truncate(format_node->query_tree, 1);
    }
    else
    {
        str_append(format_node->query_tree, " ");
        if (mysql_format_subselect(thd, format_node, format_node->query_tree, select_lex, true))
            return true;
    }
    
    if (thd->errmsg != NULL && str_get_len(thd->errmsg) > 0)
    {
        format_node->errlevel= INCEPTION_PARSE;
        format_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }
    
    LIST_ADD_LAST(link, format_cache->field_lst, format_node);
    return false;
}

int mysql_format_delete(THD* thd)
{
    format_cache_node_t*   format_node;
    format_cache_t*        format_cache;
    SELECT_LEX* select_lex = &thd->lex->select_lex;
    
    format_cache = thd->format_cache;
    
    format_node = (format_cache_node_t*)my_malloc(sizeof(format_cache_node_t), MY_ZEROFILL);
    format_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    format_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(format_node->query_tree);
    str_init(format_node->sql_statements);
    format_node->is_update= 0;
    str_append_with_length(format_node->sql_statements, thd->query(), thd->query_length());
    mysql_load_tables(thd, &format_node->rt_lst, select_lex);
    
    str_append(format_node->query_tree, "DELETE");
    if (thd->lex->auxiliary_table_list.first)
    {
        mysql_format_tables(thd, format_node, select_lex, format_node->query_tree,
                            thd->lex->auxiliary_table_list.first);
        str_append(format_node->query_tree, ",");
        mysql_format_tables(thd, format_node, select_lex, format_node->query_tree,
                            thd->lex->query_tables);
    }
    else
        mysql_format_tables(thd, format_node, select_lex, format_node->query_tree,
                            thd->lex->query_tables);
    
    mysql_format_select_condition(thd, format_node, format_node->query_tree, select_lex);
    
    if (thd->errmsg != NULL && str_get_len(thd->errmsg) > 0)
    {
        format_node->errlevel= INCEPTION_PARSE;
        format_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }
    
    LIST_ADD_LAST(link, format_cache->field_lst, format_node);
    return false;
}

int mysql_format_update(THD* thd)
{
    format_cache_node_t*        format_node;
    format_cache_t*             format_cache;
    SELECT_LEX* select_lex = &thd->lex->select_lex;
    Item* item_it;
    Item* item_vit;
    
    format_cache = thd->format_cache;
    
    format_node = (format_cache_node_t*)my_malloc(sizeof(format_cache_node_t), MY_ZEROFILL);
    format_node->sql_statements = (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    format_node->query_tree= (str_t*)my_malloc(sizeof(str_t), MY_ZEROFILL);
    str_init(format_node->query_tree);
    str_init(format_node->sql_statements);
    format_node->is_update= 1;
    str_append_with_length(format_node->sql_statements, thd->query(), thd->query_length());
    mysql_load_tables(thd, &format_node->rt_lst, select_lex);
    
    str_append(format_node->query_tree, "UPDATE ");
    
    mysql_format_tables(thd, format_node, select_lex, format_node->query_tree,
                        thd->lex->query_tables);
    
    str_append(format_node->query_tree, " SET ");
    
    List_iterator<Item> it(thd->lex->select_lex.item_list);
    List_iterator<Item> vit(thd->lex->value_list);
    
    while ((item_it= it++) && (item_vit= vit++))
    {
        format_item(thd, format_node, format_node->query_tree, item_it, &thd->lex->select_lex);
        str_append(format_node->query_tree, "=");
        format_item(thd, format_node, format_node->query_tree, item_vit, &thd->lex->select_lex);
        str_append(format_node->query_tree, ",");
    }
    
    str_truncate(format_node->query_tree, 1);
    
    mysql_format_select_condition(thd, format_node, format_node->query_tree, select_lex);
    
    if (thd->errmsg != NULL && str_get_len(thd->errmsg) > 0)
    {
        format_node->errlevel= INCEPTION_PARSE;
        format_node->errmsg = thd->errmsg;
        thd->errmsg = NULL;
    }
    
    LIST_ADD_LAST(link, format_cache->field_lst, format_node);
    return false;
}

int mysql_format_change_db(THD* thd)
{
    LEX_STRING db_str= { (char *) thd->lex->select_lex.db, strlen(thd->lex->select_lex.db) };
    mysql_change_db(thd, &db_str, FALSE);
    
    return false;
}

