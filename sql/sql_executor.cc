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

/**
  @file

  @brief
  Query execution


  @defgroup Query_Executor  Query Executor
  @{
*/

#include "sql_select.h"
#include "sql_executor.h"
#include "sql_optimizer.h"
#include "sql_join_buffer.h"
#include "opt_trace.h"
#include "sql_test.h"
#include "sql_base.h"
#include "key.h"
#include "sql_derived.h"
#include "sql_show.h"
#include "filesort.h"
#include "sql_tmp_table.h"
#include "records.h"          // rr_sequential
#include "opt_explain_format.h" // Explain_format_flags

#include <algorithm>
using std::max;
using std::min;

static void save_const_null_info(JOIN *join, table_map *save_nullinfo);
static void restore_const_null_info(JOIN *join, table_map save_nullinfo);
static int do_select(JOIN *join);

// static enum_nested_loop_state
// evaluate_join_record(JOIN *join, JOIN_TAB *join_tab);
static enum_nested_loop_state
end_write(JOIN *join, JOIN_TAB *join_tab, bool end_of_records);
static enum_nested_loop_state
end_update(JOIN *join, JOIN_TAB *join_tab, bool end_of_records);
static enum_nested_loop_state
end_unique_update(JOIN *join, JOIN_TAB *join_tab, bool end_of_records);
static void copy_sum_funcs(Item_sum **func_ptr, Item_sum **end_ptr);

static int join_read_system(JOIN_TAB *tab);
static int join_read_const(JOIN_TAB *tab);
static int join_read_key(JOIN_TAB *tab);
static int join_read_always_key(JOIN_TAB *tab);
static int join_no_more_records(READ_RECORD *info);
static int join_read_next(READ_RECORD *info);
static int test_if_quick_select(JOIN_TAB *tab);
static int join_read_next_same(READ_RECORD *info);
static int join_read_prev(READ_RECORD *info);
static int join_ft_read_first(JOIN_TAB *tab);
static int join_ft_read_next(READ_RECORD *info);
static int join_read_always_key_or_null(JOIN_TAB *tab);
static int join_read_next_same_or_null(READ_RECORD *info);
static bool remove_dup_with_compare(THD *thd, TABLE *entry, Field **field,
                                    ulong offset,Item *having);
static bool remove_dup_with_hash_index(THD *thd,TABLE *table,
                                       uint field_count, Field **first_field,
                                       ulong key_length,Item *having);
static int join_read_linked_first(JOIN_TAB *tab);
static int join_read_linked_next(READ_RECORD *info);
static bool cmp_buffer_with_ref(THD *thd, TABLE *table, TABLE_REF *tab_ref);

/**
  Execute select, executor entry point.

  @todo
    When can we have here thd->net.report_error not zero?
*/

void
JOIN::exec()
{
//   Opt_trace_context * const trace= &thd->opt_trace;
//   Opt_trace_object trace_wrapper(trace);
//   Opt_trace_object trace_exec(trace, "join_execution");
//   trace_exec.add_select_number(select_lex->select_number);
//   Opt_trace_array trace_steps(trace, "steps");
  List<Item> *columns_list= &fields_list;
  DBUG_ENTER("JOIN::exec");

  DBUG_ASSERT(!tables || thd->lex->is_query_tables_locked());
  DBUG_ASSERT(!(select_options & SELECT_DESCRIBE));


  // Ignore errors of execution if option IGNORE present
  if (thd->lex->ignore)
    thd->lex->current_select->no_error= true;

  if (prepare_result(&columns_list))
    DBUG_VOID_RETURN;

  if (!tables_list && (tables || !select_lex->with_sum_func))
  {                                           // Only test of functions
    /*
      We have to test for 'conds' here as the WHERE may not be constant
      even if we don't have any tables for prepared statements or if
      conds uses something like 'rand()'.

      Don't evaluate the having clause here. return_zero_rows() should
      be called only for cases where there are no matching rows after
      evaluating all conditions except the HAVING clause.
    */
    if (select_lex->cond_value != Item::COND_FALSE &&
        (!conds || conds->val_int()))
    {
      if (result->send_result_set_metadata(*columns_list,
                                           Protocol::SEND_NUM_ROWS |
                                           Protocol::SEND_EOF))
      {
        DBUG_VOID_RETURN;
      }

      /*
        If the HAVING clause is either impossible or always true, then
        JOIN::having is set to NULL by optimize_cond.
        In this case JOIN::exec must check for JOIN::having_value, in the
        same way it checks for JOIN::cond_value.
      */
//       if (((select_lex->having_value != Item::COND_FALSE) &&
//            (!having || having->val_int())) 
//           && do_send_rows && result->send_data(fields_list))
//         error= 1;
//       else
      {
        //error= (int) result->send_eof();
        send_records= ((select_options & OPTION_FOUND_ROWS) ? 1 :
                       thd->get_sent_row_count());
      }
      /* Query block (without union) always returns 0 or 1 row */
      thd->limit_found_rows= send_records;
      thd->set_examined_row_count(0);
    }
//     else
//     {
//       return_zero_rows(this, *columns_list);
//     }
    DBUG_VOID_RETURN;
  }

//   if (zero_result_cause)
//   {
//     return_zero_rows(this, *columns_list);
//     DBUG_VOID_RETURN;
//   }
  
  /*
    Initialize examined rows here because the values from all join parts
    must be accumulated in examined_row_count. Hence every join
    iteration must count from zero.
  */
  examined_rows= 0;

  /* XXX: When can we have here thd->is_error() not zero? */
  if (thd->is_error())
  {
    error= thd->is_error();
    DBUG_VOID_RETURN;
  }

  DBUG_PRINT("info", ("%s", thd->proc_info));
  result->send_result_set_metadata(*fields,
                                   Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF);
  error= do_select(this);
  /* Accumulate the counts from all join iterations of all join parts. */
  thd->inc_examined_row_count(examined_rows);
  DBUG_PRINT("counts", ("thd->examined_row_count: %lu",
                        (ulong) thd->get_examined_row_count()));

  DBUG_VOID_RETURN;
}



static void
copy_sum_funcs(Item_sum **func_ptr, Item_sum **end_ptr)
{
  for (; func_ptr != end_ptr ; func_ptr++)
    (void) (*func_ptr)->save_in_result_field(1);
  return;
}


static bool
init_sum_functions(Item_sum **func_ptr, Item_sum **end_ptr)
{
  for (; func_ptr != end_ptr ;func_ptr++)
  {
    if ((*func_ptr)->reset_and_add())
      return 1;
  }
  /* If rollup, calculate the upper sum levels */
  for ( ; *func_ptr ; func_ptr++)
  {
    if ((*func_ptr)->aggregator_add())
      return 1;
  }
  return 0;
}


static bool
update_sum_func(Item_sum **func_ptr)
{
  Item_sum *func;
  for (; (func= (Item_sum*) *func_ptr) ; func_ptr++)
    if (func->aggregator_add())
      return 1;
  return 0;
}

/** 
  Copy result of functions to record in tmp_table. 

  Uses the thread pointer to check for errors in 
  some of the val_xxx() methods called by the 
  save_in_result_field() function.
  TODO: make the Item::val_xxx() return error code

  @param func_ptr  array of the function Items to copy to the tmp table
  @param thd       pointer to the current thread for error checking
  @retval
    FALSE if OK
  @retval
    TRUE on error  
*/

bool
copy_funcs(Item **func_ptr, const THD *thd)
{
  Item *func;
  for (; (func = *func_ptr) ; func_ptr++)
  {
    func->save_in_result_field(1);
    /*
      Need to check the THD error state because Item::val_xxx() don't
      return error code, but can generate errors
      TODO: change it for a real status check when Item::val_xxx()
      are extended to return status code.
    */  
    if (thd->is_error())
      return TRUE;
  }
  return FALSE;
}

static int
do_select(JOIN *join)
{
  int rc= 0;
  enum_nested_loop_state error= NESTED_LOOP_OK;
  DBUG_ENTER("do_select");

  join->send_records=0;
  if (join->plan_is_const() && !join->need_tmp)
  {
//     Next_select_func end_select= setup_end_select_func(join, NULL);
    /*
      HAVING will be checked after processing aggregate functions,
      But WHERE should checkd here (we alredy have read tables)

      @todo: consider calling end_select instead of duplicating code
    */
    /*if (!join->conds || join->conds->val_int())
    {
      // HAVING will be checked by end_select
      error= (*end_select)(join, 0, 0);
      if (error >= NESTED_LOOP_OK)
	error= (*end_select)(join, 0, 1);

      / *
        If we don't go through evaluate_join_record(), do the counting
        here.  join->send_records is increased on success in end_send(),
        so we don't touch it here.
      * /
      join->examined_rows++;
      DBUG_ASSERT(join->examined_rows <= 1);
    }
    else */if (join->send_row_on_empty_set())
    {
      table_map save_nullinfo= 0;
      /*
        If this is a subquery, we need to save and later restore
        the const table NULL info before clearing the tables
        because the following executions of the subquery do not
        reevaluate constant fields. @see save_const_null_info
        and restore_const_null_info
      */
      if (join->select_lex->master_unit()->item && join->const_tables)
        save_const_null_info(join, &save_nullinfo);

      // Calculate aggregate functions for no rows
      List_iterator_fast<Item> it(*join->fields);
      Item *item;
      while ((item= it++))
        item->no_rows_in_result();

      // Mark tables as containing only NULL values
      join->clear();

//       if (!join->having || join->having->val_int())
//         rc= join->result->send_data(*join->fields);

      if (save_nullinfo)
        restore_const_null_info(join, save_nullinfo);
    }
    /*
      An error can happen when evaluating the conds 
      (the join condition and piece of where clause 
      relevant to this join table).
    */
    if (join->thd->is_error())
      error= NESTED_LOOP_ERROR;
  }
  else
  {
    JOIN_TAB *join_tab= join->join_tab + join->const_tables;
    DBUG_ASSERT(join->primary_tables);
    error= join->first_select(join,join_tab,0);
    if (error >= NESTED_LOOP_OK)
      error= join->first_select(join,join_tab,1);
  }

  join->thd->limit_found_rows= join->send_records;
  /* Use info provided by filesort. */
  if (join->order)
  {
    // Save # of found records prior to cleanup
    JOIN_TAB *sort_tab;
    JOIN_TAB *join_tab= join->join_tab;
    uint const_tables= join->const_tables;

    // Take record count from first non constant table or from last tmp table
    if (join->tmp_tables > 0)
      sort_tab= join_tab + join->primary_tables + join->tmp_tables - 1;
    else
    {
      DBUG_ASSERT(!join->plan_is_const());
      sort_tab= join_tab + const_tables;
    }
    if (sort_tab->filesort &&
        sort_tab->filesort->sortorder)
    {
      join->thd->limit_found_rows= sort_tab->records;
    }
  }

  {
    /*
      The following will unlock all cursors if the command wasn't an
      update command
    */
    join->join_free();			// Unlock all cursors
  }
  if (error == NESTED_LOOP_OK)
  {
    /*
      Sic: this branch works even if rc != 0, e.g. when
      send_data above returns an error.
    */
//     if (join->result->send_eof())
//       rc= 1;                                  // Don't send error
    DBUG_PRINT("info",("%ld records output", (long) join->send_records));
  }
  else
    rc= -1;
#ifndef DBUG_OFF
  if (rc)
  {
    DBUG_PRINT("error",("Error: do_select() failed"));
  }
#endif
  rc= join->thd->is_error() ? -1 : rc;
  DBUG_RETURN(rc);
}

enum_nested_loop_state
sub_select(JOIN *join,JOIN_TAB *join_tab,bool end_of_records)
{
  DBUG_ENTER("sub_select");

  join_tab->table->null_row=0;
  if (end_of_records)
  {
    enum_nested_loop_state nls=
      (*join_tab->next_select)(join,join_tab+1,end_of_records);
    DBUG_RETURN(nls);
  }
  READ_RECORD *info= &join_tab->read_record;

//   if (join_tab->prepare_scan())
//     DBUG_RETURN(NESTED_LOOP_ERROR);

  join->return_tab= join_tab;
  join_tab->not_null_compl= true;
  join_tab->found_match= false;

  if (join_tab->last_inner)
  {
    /* join_tab is the first inner table for an outer join operation. */

    /* Set initial state of guard variables for this table.*/
    join_tab->found=0;

    /* Set first_unmatched for the last inner table of this group */
    join_tab->last_inner->first_unmatched= join_tab;
  }
  if (join_tab->do_firstmatch() || join_tab->do_loosescan())
  {
    /*
      join_tab is the first table of a LooseScan range, or has a "jump"
      address in a FirstMatch range.
      Reset the matching for this round of execution.
    */
    join_tab->match_tab->found_match= false;
  }

  join->thd->get_stmt_da()->reset_current_row_for_warning();

  enum_nested_loop_state rc= NESTED_LOOP_OK;
  bool in_first_read= true;
  while (rc == NESTED_LOOP_OK && join->return_tab >= join_tab)
  {
    int error;
    if (in_first_read)
    {
      in_first_read= false;
      error= (*join_tab->read_first_record)(join_tab);
    }
    else
      error= info->read_record(info);

    DBUG_EXECUTE_IF("bug13822652_1", join->thd->killed= THD::KILL_QUERY;);

    if (error > 0 || (join->thd->is_error()))   // Fatal error
      rc= NESTED_LOOP_ERROR;
    else if (error < 0)
      break;
    else if (join->thd->killed)			// Aborted by user
    {
      join->thd->send_kill_message();
      rc= NESTED_LOOP_KILLED;
    }
//     else
//     {
//       if (join_tab->keep_current_rowid)
//         join_tab->table->file->position(join_tab->table->record[0]);
//       rc= evaluate_join_record(join, join_tab);
//     }
  }

//   if (rc == NESTED_LOOP_OK && join_tab->last_inner && !join_tab->found)
//     rc= evaluate_null_complemented_join_record(join, join_tab);

  DBUG_RETURN(rc);
}

/*****************************************************************************
  The different ways to read a record
  Returns -1 if row was not found, 0 if row was found and 1 on errors
*****************************************************************************/

/** Help function when we get some an error from the table handler. */

int report_handler_error(TABLE *table, int error)
{
  if (error == HA_ERR_END_OF_FILE || error == HA_ERR_KEY_NOT_FOUND)
  {
    table->status= STATUS_GARBAGE;
    return -1;					// key not found; ok
  }
  /*
    Do not spam the error log with these temporary errors:
       LOCK_DEADLOCK LOCK_WAIT_TIMEOUT TABLE_DEF_CHANGED
    Also skip printing to error log if the current thread has been killed.
  */
  if (error != HA_ERR_LOCK_DEADLOCK &&
      error != HA_ERR_LOCK_WAIT_TIMEOUT &&
      error != HA_ERR_TABLE_DEF_CHANGED &&
      !table->in_use->killed)
    sql_print_error("Got error %d when reading table '%s'",
		    error, table->s->path.str);
  table->file->print_error(error,MYF(0));
  return 1;
}


int safe_index_read(JOIN_TAB *tab)
{
  int error;
  TABLE *table= tab->table;
  if ((error=table->file->ha_index_read_map(table->record[0],
                                            tab->ref.key_buff,
                                            make_prev_keypart_map(tab->ref.key_parts),
                                            HA_READ_KEY_EXACT)))
    return report_handler_error(table, error);
  return 0;
}

int read_first_record_seq(JOIN_TAB *tab)
{
  if (tab->read_record.table->file->ha_rnd_init(1))
    return 1;
  return (*tab->read_record.read_record)(&tab->read_record);
}
static bool compare_record(TABLE *table, Field **ptr)
{
  for (; *ptr ; ptr++)
  {
    if ((*ptr)->cmp_offset(table->s->rec_buff_length))
      return 1;
  }
  return 0;
}

static bool copy_blobs(Field **ptr)
{
  for (; *ptr ; ptr++)
  {
    if ((*ptr)->flags & BLOB_FLAG)
      if (((Field_blob *) (*ptr))->copy())
	return 1;				// Error
  }
  return 0;
}

static void free_blobs(Field **ptr)
{
  for (; *ptr ; ptr++)
  {
    if ((*ptr)->flags & BLOB_FLAG)
      ((Field_blob *) (*ptr))->free();
  }
}


bool
JOIN_TAB::remove_duplicates()
{
  bool error;
  ulong reclength,offset;
  uint field_count;
  List<Item> *fields= (this-1)->fields;
  DBUG_ENTER("remove_duplicates");

  DBUG_ASSERT(join->tmp_tables > 0 && table->s->tmp_table != NO_TMP_TABLE);

  table->reginfo.lock_type=TL_WRITE;

  /* Calculate how many saved fields there is in list */
  field_count=0;
  List_iterator<Item> it(*fields);
  Item *item;
  while ((item=it++))
  {
    if (item->get_tmp_table_field() && ! item->const_item())
      field_count++;
  }

  if (!field_count && !(join->select_options & OPTION_FOUND_ROWS) && !having) 
  {                    // only const items with no OPTION_FOUND_ROWS
    join->unit->select_limit_cnt= 1;		// Only send first row
    DBUG_RETURN(false);
  }
  Field **first_field= table->field+ table->s->fields - field_count;
  offset= (field_count ? 
           table->field[table->s->fields - field_count]->
           offset(table->record[0]) : 0);
  reclength= table->s->reclength-offset;

  free_io_cache(table);				// Safety
  table->file->info(HA_STATUS_VARIABLE);
  if (table->s->db_type() == heap_hton ||
      (!table->s->blob_fields &&
       ((ALIGN_SIZE(reclength) + HASH_OVERHEAD) * table->file->stats.records <
	join->thd->variables.sortbuff_size)))
    error=remove_dup_with_hash_index(join->thd, table,
				     field_count, first_field,
				     reclength, having);
  else
    error=remove_dup_with_compare(join->thd, table, first_field, offset,
				  having);

  free_blobs(first_field);
  DBUG_RETURN(error);
}


static bool remove_dup_with_compare(THD *thd, TABLE *table, Field **first_field,
                                    ulong offset, Item *having)
{
  handler *file=table->file;
  char *org_record,*new_record;
  uchar *record;
  int error;
  ulong reclength= table->s->reclength-offset;
  DBUG_ENTER("remove_dup_with_compare");

  org_record=(char*) (record=table->record[0])+offset;
  new_record=(char*) table->record[1]+offset;

  if ((error= file->ha_rnd_init(1)))
    goto err;
  error=file->ha_rnd_next(record);
  for (;;)
  {
    if (thd->killed)
    {
      thd->send_kill_message();
      error=0;
      goto err;
    }
    if (error)
    {
      if (error == HA_ERR_RECORD_DELETED)
      {
        error= file->ha_rnd_next(record);
        continue;
      }
      if (error == HA_ERR_END_OF_FILE)
	break;
      goto err;
    }
    if (having && !having->val_int())
    {
      if ((error=file->ha_delete_row(record)))
	goto err;
      error=file->ha_rnd_next(record);
      continue;
    }
    if (copy_blobs(first_field))
    {
      my_message(ER_OUTOFMEMORY, ER(ER_OUTOFMEMORY), MYF(0));
      error=0;
      goto err;
    }
    memcpy(new_record,org_record,reclength);

    /* Read through rest of file and mark duplicated rows deleted */
    bool found=0;
    for (;;)
    {
      if ((error=file->ha_rnd_next(record)))
      {
	if (error == HA_ERR_RECORD_DELETED)
	  continue;
	if (error == HA_ERR_END_OF_FILE)
	  break;
	goto err;
      }
      if (compare_record(table, first_field) == 0)
      {
	if ((error=file->ha_delete_row(record)))
	  goto err;
      }
      else if (!found)
      {
	found=1;
	file->position(record);	// Remember position
      }
    }
    if (!found)
      break;					// End of file
    /* Restart search on next row */
    error=file->restart_rnd_next(record,file->ref);
  }

  file->extra(HA_EXTRA_NO_CACHE);
  DBUG_RETURN(false);
err:
  file->extra(HA_EXTRA_NO_CACHE);
  if (file->inited)
    (void) file->ha_rnd_end();
  if (error)
    file->print_error(error,MYF(0));
  DBUG_RETURN(true);
}


/**
  Generate a hash index for each row to quickly find duplicate rows.

  @note
    Note that this will not work on tables with blobs!
*/

static bool remove_dup_with_hash_index(THD *thd, TABLE *table,
                                       uint field_count,
                                       Field **first_field,
                                       ulong key_length,
                                       Item *having)
{
  uchar *key_buffer, *key_pos, *record=table->record[0];
  int error;
  handler *file= table->file;
  ulong extra_length= ALIGN_SIZE(key_length)-key_length;
  uint *field_lengths,*field_length;
  HASH hash;
  DBUG_ENTER("remove_dup_with_hash_index");

  if (!my_multi_malloc(MYF(MY_WME),
		       &key_buffer,
		       (uint) ((key_length + extra_length) *
			       (long) file->stats.records),
		       &field_lengths,
		       (uint) (field_count*sizeof(*field_lengths)),
		       NullS))
    DBUG_RETURN(true);

  {
    Field **ptr;
    ulong total_length= 0;
    for (ptr= first_field, field_length=field_lengths ; *ptr ; ptr++)
    {
      uint length= (*ptr)->sort_length();
      (*field_length++)= length;
      total_length+= length;
    }
    DBUG_PRINT("info",("field_count: %u  key_length: %lu  total_length: %lu",
                       field_count, key_length, total_length));
    DBUG_ASSERT(total_length <= key_length);
    key_length= total_length;
    extra_length= ALIGN_SIZE(key_length)-key_length;
  }

  if (my_hash_init(&hash, &my_charset_bin, (uint) file->stats.records, 0, 
                   key_length, (my_hash_get_key) 0, 0, 0))
  {
    my_free(key_buffer);
    DBUG_RETURN(true);
  }

  if ((error= file->ha_rnd_init(1)))
    goto err;
  key_pos=key_buffer;
  for (;;)
  {
    uchar *org_key_pos;
    if (thd->killed)
    {
      thd->send_kill_message();
      error=0;
      goto err;
    }
    if ((error=file->ha_rnd_next(record)))
    {
      if (error == HA_ERR_RECORD_DELETED)
	continue;
      if (error == HA_ERR_END_OF_FILE)
	break;
      goto err;
    }
    if (having && !having->val_int())
    {
      if ((error=file->ha_delete_row(record)))
	goto err;
      continue;
    }

    /* copy fields to key buffer */
    org_key_pos= key_pos;
    field_length=field_lengths;
    for (Field **ptr= first_field ; *ptr ; ptr++)
    {
      (*ptr)->make_sort_key(key_pos,*field_length);
      key_pos+= *field_length++;
    }
    /* Check if it exists before */
    if (my_hash_search(&hash, org_key_pos, key_length))
    {
      /* Duplicated found ; Remove the row */
      if ((error=file->ha_delete_row(record)))
	goto err;
    }
    else
    {
      if (my_hash_insert(&hash, org_key_pos))
        goto err;
    }
    key_pos+=extra_length;
  }
  my_free(key_buffer);
  my_hash_free(&hash);
  file->extra(HA_EXTRA_NO_CACHE);
  (void) file->ha_rnd_end();
  DBUG_RETURN(false);

err:
  my_free(key_buffer);
  my_hash_free(&hash);
  file->extra(HA_EXTRA_NO_CACHE);
  if (file->inited)
    (void) file->ha_rnd_end();
  if (error)
    file->print_error(error,MYF(0));
  DBUG_RETURN(true);
}


/*
  eq_ref: Create the lookup key and check if it is the same as saved key

  SYNOPSIS
    cmp_buffer_with_ref()
      tab      Join tab of the accessed table
      table    The table to read.  This is usually tab->table, except for 
               semi-join when we might need to make a lookup in a temptable
               instead.
      tab_ref  The structure with methods to collect index lookup tuple. 
               This is usually table->ref, except for the case of when we're 
               doing lookup into semi-join materialization table.

  DESCRIPTION 
    Used by eq_ref access method: create the index lookup key and check if 
    we've used this key at previous lookup (If yes, we don't need to repeat
    the lookup - the record has been already fetched)

  RETURN 
    TRUE   No cached record for the key, or failed to create the key (due to
           out-of-domain error)
    FALSE  The created key is the same as the previous one (and the record 
           is already in table->record)
*/

static bool
cmp_buffer_with_ref(THD *thd, TABLE *table, TABLE_REF *tab_ref)
{
  bool no_prev_key;
  if (!tab_ref->disable_cache)
  {
    if (!(no_prev_key= tab_ref->key_err))
    {
      /* Previous access found a row. Copy its key */
      memcpy(tab_ref->key_buff2, tab_ref->key_buff, tab_ref->key_length);
    }
  }
  else 
    no_prev_key= TRUE;
  if ((tab_ref->key_err= cp_buffer_from_ref(thd, table, tab_ref)) ||
      no_prev_key)
    return 1;
  return memcmp(tab_ref->key_buff2, tab_ref->key_buff, tab_ref->key_length)
    != 0;
}


bool
cp_buffer_from_ref(THD *thd, TABLE *table, TABLE_REF *ref)
{
  enum enum_check_fields save_count_cuted_fields= thd->count_cuted_fields;
  thd->count_cuted_fields= CHECK_FIELD_IGNORE;
  my_bitmap_map *old_map= dbug_tmp_use_all_columns(table, table->write_set);
  bool result= 0;

  for (uint part_no= 0; part_no < ref->key_parts; part_no++)
  {
    store_key *s_key= ref->key_copy[part_no];
    if (!s_key)
      continue;

    if (s_key->copy() & 1)
    {
      result= 1;
      break;
    }
  }
  thd->count_cuted_fields= save_count_cuted_fields;
  dbug_tmp_restore_column_map(table->write_set, old_map);
  return result;
}


/**
  allocate group fields or take prepared (cached).

  @param main_join   join of current select
  @param curr_join   current join (join of current select or temporary copy
                     of it)

  @retval
    0   ok
  @retval
    1   failed
*/

bool
make_group_fields(JOIN *main_join, JOIN *curr_join)
{
  if (main_join->group_fields_cache.elements)
  {
    curr_join->group_fields= main_join->group_fields_cache;
    curr_join->sort_and_group= 1;
  }
  else
  {
    if (alloc_group_fields(curr_join, curr_join->group_list))
      return (1);
    main_join->group_fields_cache= curr_join->group_fields;
  }
  return (0);
}


/**
  Get a list of buffers for saveing last group.

  Groups are saved in reverse order for easyer check loop.
*/

bool
alloc_group_fields(JOIN *join, ORDER *group)
{
  if (group)
  {
    for (; group ; group=group->next)
    {
      Cached_item *tmp=new_Cached_item(join->thd, *group->item, FALSE);
      if (!tmp || join->group_fields.push_front(tmp))
	return TRUE;
    }
  }
  join->sort_and_group=1;			/* Mark for do_select */
  return FALSE;
}


/*
  Test if a single-row cache of items changed, and update the cache.

  @details Test if a list of items that typically represents a result
  row has changed. If the value of some item changed, update the cached
  value for this item.
  
  @param list list of <item, cached_value> pairs stored as Cached_item.

  @return -1 if no item changed
  @return index of the first item that changed
*/

int test_if_item_cache_changed(List<Cached_item> &list)
{
  DBUG_ENTER("test_if_item_cache_changed");
  List_iterator<Cached_item> li(list);
  int idx= -1,i;
  Cached_item *buff;

  for (i=(int) list.elements-1 ; (buff=li++) ; i--)
  {
    if (buff->cmp())
      idx=i;
  }
  DBUG_PRINT("info", ("idx: %d", idx));
  DBUG_RETURN(idx);
}


/**
  Setup copy_fields to save fields at start of new group.

  Setup copy_fields to save fields at start of new group

  Only FIELD_ITEM:s and FUNC_ITEM:s needs to be saved between groups.
  Change old item_field to use a new field with points at saved fieldvalue
  This function is only called before use of send_result_set_metadata.

  @param thd                   THD pointer
  @param param                 temporary table parameters
  @param ref_pointer_array     array of pointers to top elements of filed list
  @param res_selected_fields   new list of items of select item list
  @param res_all_fields        new list of all items
  @param elements              number of elements in select item list
  @param all_fields            all fields list

  @todo
    In most cases this result will be sent to the user.
    This should be changed to use copy_int or copy_real depending
    on how the value is to be used: In some cases this may be an
    argument in a group function, like: IF(ISNULL(col),0,COUNT(*))

  @retval
    0     ok
  @retval
    !=0   error
*/

bool
setup_copy_fields(THD *thd, TMP_TABLE_PARAM *param,
		  Ref_ptr_array ref_pointer_array,
		  List<Item> &res_selected_fields, List<Item> &res_all_fields,
		  uint elements, List<Item> &all_fields)
{
  Item *pos;
  List_iterator_fast<Item> li(all_fields);
  Copy_field *copy= NULL;
  Copy_field *copy_start __attribute__((unused));
  res_selected_fields.empty();
  res_all_fields.empty();
  List_iterator_fast<Item> itr(res_all_fields);
  List<Item> extra_funcs;
  uint i, border= all_fields.elements - elements;
  DBUG_ENTER("setup_copy_fields");

  if (param->field_count && 
      !(copy=param->copy_field= new Copy_field[param->field_count]))
    goto err2;

  param->copy_funcs.empty();
  copy_start= copy;
  for (i= 0; (pos= li++); i++)
  {
    Field *field;
    uchar *tmp;
    Item *real_pos= pos->real_item();
    /*
      Aggregate functions can be substituted for fields (by e.g. temp tables).
      We need to filter those substituted fields out.
    */
    if (real_pos->type() == Item::FIELD_ITEM &&
        !(real_pos != pos &&
          ((Item_ref *)pos)->ref_type() == Item_ref::AGGREGATE_REF))
    {
      Item_field *item;
      if (!(item= new Item_field(thd, ((Item_field*) real_pos))))
	goto err;
      if (pos->type() == Item::REF_ITEM)
      {
        /* preserve the names of the ref when dereferncing */
        Item_ref *ref= (Item_ref *) pos;
        item->db_name= ref->db_name;
        item->table_name= ref->table_name;
        item->item_name= ref->item_name;
      }
      pos= item;
      if (item->field->flags & BLOB_FLAG)
      {
	if (!(pos= Item_copy::create(pos)))
	  goto err;
       /*
         Item_copy_string::copy for function can call 
         Item_copy_string::val_int for blob via Item_ref.
         But if Item_copy_string::copy for blob isn't called before,
         it's value will be wrong
         so let's insert Item_copy_string for blobs in the beginning of 
         copy_funcs
         (to see full test case look at having.test, BUG #4358) 
       */
	if (param->copy_funcs.push_front(pos))
	  goto err;
      }
      else
      {
	/* 
	   set up save buffer and change result_field to point at 
	   saved value
	*/
	field= item->field;
	item->result_field=field->new_field(thd->mem_root,field->table, 1);
        /*
          We need to allocate one extra byte for null handling and
          another extra byte to not get warnings from purify in
          Field_string::val_int
        */
	if (!(tmp= (uchar*) sql_alloc(field->pack_length()+2)))
	  goto err;
        if (copy)
        {
          DBUG_ASSERT (param->field_count > (uint) (copy - copy_start));
          copy->set(tmp, item->result_field);
          item->result_field->move_field(copy->to_ptr,copy->to_null_ptr,1);
#ifdef HAVE_purify
          copy->to_ptr[copy->from_length]= 0;
#endif
          copy++;
        }
      }
    }
    else if ((real_pos->type() == Item::FUNC_ITEM ||
	      real_pos->type() == Item::SUBSELECT_ITEM ||
	      real_pos->type() == Item::CACHE_ITEM ||
	      real_pos->type() == Item::COND_ITEM) &&
	     !real_pos->with_sum_func)
    {						// Save for send fields
      pos= real_pos;
      /* TODO:
	 In most cases this result will be sent to the user.
	 This should be changed to use copy_int or copy_real depending
	 on how the value is to be used: In some cases this may be an
	 argument in a group function, like: IF(ISNULL(col),0,COUNT(*))
      */
      if (!(pos= Item_copy::create(pos)))
	goto err;
      if (i < border)                           // HAVING, ORDER and GROUP BY
      {
        if (extra_funcs.push_back(pos))
          goto err;
      }
      else if (param->copy_funcs.push_back(pos))
	goto err;
    }
    res_all_fields.push_back(pos);
    ref_pointer_array[((i < border)? all_fields.elements-i-1 : i-border)]=
      pos;
  }
  param->copy_field_end= copy;

  for (i= 0; i < border; i++)
    itr++;
  itr.sublist(res_selected_fields, elements);
  /*
    Put elements from HAVING, ORDER BY and GROUP BY last to ensure that any
    reference used in these will resolve to a item that is already calculated
  */
  param->copy_funcs.concat(&extra_funcs);

  DBUG_RETURN(0);

 err:
  if (copy)
    delete [] param->copy_field;			// This is never 0
  param->copy_field=0;
err2:
  DBUG_RETURN(TRUE);
}


/**
  Make a copy of all simple SELECT'ed items.

  This is done at the start of a new group so that we can retrieve
  these later when the group changes.
*/

void
copy_fields(TMP_TABLE_PARAM *param)
{
  Copy_field *ptr=param->copy_field;
  Copy_field *end=param->copy_field_end;

  DBUG_ASSERT((ptr != NULL && end >= ptr) || (ptr == NULL && end == NULL));

  for (; ptr < end; ptr++)
    (*ptr->do_copy)(ptr);

  List_iterator_fast<Item> it(param->copy_funcs);
  Item_copy *item;
  while ((item = (Item_copy*) it++))
    item->copy();
}


/**
  Change all funcs and sum_funcs to fields in tmp table, and create
  new list of all items.

  @param thd                   THD pointer
  @param ref_pointer_array     array of pointers to top elements of filed list
  @param res_selected_fields   new list of items of select item list
  @param res_all_fields        new list of all items
  @param elements              number of elements in select item list
  @param all_fields            all fields list

  @retval
    0     ok
  @retval
    !=0   error
*/

bool
change_to_use_tmp_fields(THD *thd, Ref_ptr_array ref_pointer_array,
			 List<Item> &res_selected_fields,
			 List<Item> &res_all_fields,
			 uint elements, List<Item> &all_fields)
{
  List_iterator_fast<Item> it(all_fields);
  Item *item_field,*item;
  DBUG_ENTER("change_to_use_tmp_fields");

  res_selected_fields.empty();
  res_all_fields.empty();

  uint border= all_fields.elements - elements;
  for (uint i= 0; (item= it++); i++)
  {
    Field *field;
    if (item->with_sum_func && item->type() != Item::SUM_FUNC_ITEM)
      item_field= item;
    else if (item->type() == Item::FIELD_ITEM)
      item_field= item->get_tmp_table_item(thd);
    else if (item->type() == Item::FUNC_ITEM &&
             ((Item_func*)item)->functype() == Item_func::SUSERVAR_FUNC)
    {
      field= item->get_tmp_table_field();
      if (field != NULL)
      {
        /*
          Replace "@:=<expression>" with "@:=<tmp table column>". Otherwise, we
          would re-evaluate <expression>, and if expression were a subquery, this
          would access already-unlocked tables.
        */
        Item_func_set_user_var* suv=
          new Item_func_set_user_var(thd, (Item_func_set_user_var*) item);
        Item_field *new_field= new Item_field(field);
        if (!suv || !new_field)
          DBUG_RETURN(true);                  // Fatal error
        List<Item> list;
        list.push_back(new_field);
        suv->set_arguments(list);
        item_field= suv;
      }
      else
        item_field= item;
    }
    else if ((field= item->get_tmp_table_field()))
    {
      if (item->type() == Item::SUM_FUNC_ITEM && field->table->group)
        item_field= ((Item_sum*) item)->result_item(field);
      else
        item_field= (Item*) new Item_field(field);
      if (!item_field)
        DBUG_RETURN(true);                    // Fatal error

      if (item->real_item()->type() != Item::FIELD_ITEM)
        field->orig_table= 0;
      item_field->item_name= item->item_name;
      if (item->type() == Item::REF_ITEM)
      {
        Item_field *ifield= (Item_field *) item_field;
        Item_ref *iref= (Item_ref *) item;
        ifield->table_name= iref->table_name;
        ifield->db_name= iref->db_name;
      }
#ifndef DBUG_OFF
      if (!item_field->item_name.is_set())
      {
        char buff[256];
        String str(buff,sizeof(buff),&my_charset_bin);
        str.length(0);
        item->print(&str, QT_ORDINARY);
        item_field->item_name.copy(str.ptr(), str.length());
      }
#endif
    }
    else
      item_field= item;

    res_all_fields.push_back(item_field);
    ref_pointer_array[((i < border)? all_fields.elements-i-1 : i-border)]=
      item_field;
  }

  List_iterator_fast<Item> itr(res_all_fields);
  for (uint i= 0; i < border; i++)
    itr++;
  itr.sublist(res_selected_fields, elements);
  DBUG_RETURN(false);
}


/**
  Change all sum_func refs to fields to point at fields in tmp table.
  Change all funcs to be fields in tmp table.

  @param thd                   THD pointer
  @param ref_pointer_array     array of pointers to top elements of filed list
  @param res_selected_fields   new list of items of select item list
  @param res_all_fields        new list of all items
  @param elements              number of elements in select item list
  @param all_fields            all fields list

  @retval
    0	ok
  @retval
    1	error
*/

bool
change_refs_to_tmp_fields(THD *thd, Ref_ptr_array ref_pointer_array,
			  List<Item> &res_selected_fields,
			  List<Item> &res_all_fields, uint elements,
			  List<Item> &all_fields)
{
  List_iterator_fast<Item> it(all_fields);
  Item *item, *new_item;
  res_selected_fields.empty();
  res_all_fields.empty();

  uint i, border= all_fields.elements - elements;
  for (i= 0; (item= it++); i++)
  {
    res_all_fields.push_back(new_item= item->get_tmp_table_item(thd));
    ref_pointer_array[((i < border)? all_fields.elements-i-1 : i-border)]=
      new_item;
  }

  List_iterator_fast<Item> itr(res_all_fields);
  for (i= 0; i < border; i++)
    itr++;
  itr.sublist(res_selected_fields, elements);

  return thd->is_fatal_error;
}


/**
  Save NULL-row info for constant tables. Used in conjunction with
  restore_const_null_info() to restore constant table null_row and
  status values after temporarily marking rows as NULL. This is only
  done for const tables in subqueries because these values are not
  recalculated on next execution of the subquery.

  @param join               The join for which const tables are about to be
                            marked as containing only NULL values
  @param[out] save_nullinfo Const tables that have null_row=false and
                            STATUS_NULL_ROW set are tagged in this
                            table_map so that the value can be
                            restored by restore_const_null_info()

  @see mark_as_null_row
  @see restore_const_null_info
*/
static void save_const_null_info(JOIN *join, table_map *save_nullinfo)
{
  DBUG_ASSERT(join->const_tables);

  for (uint tableno= 0; tableno < join->const_tables; tableno++)
  {
    TABLE *tbl= (join->join_tab+tableno)->table;
    /*
      tbl->status and tbl->null_row must be in sync: either both set
      or none set. Otherwise, an additional table_map parameter is
      needed to save/restore_const_null_info() these separately
    */
    DBUG_ASSERT(tbl->null_row ? (tbl->status & STATUS_NULL_ROW) :
                               !(tbl->status & STATUS_NULL_ROW));

    if (!tbl->null_row)
      *save_nullinfo|= tbl->map;
  }
}

/**
  Restore NULL-row info for constant tables. Used in conjunction with
  save_const_null_info() to restore constant table null_row and status
  values after temporarily marking rows as NULL. This is only done for
  const tables in subqueries because these values are not recalculated
  on next execution of the subquery.

  @param join            The join for which const tables have been
                         marked as containing only NULL values
  @param save_nullinfo   Const tables that had null_row=false and
                         STATUS_NULL_ROW set when
                         save_const_null_info() was called

  @see mark_as_null_row
  @see save_const_null_info
*/
static void restore_const_null_info(JOIN *join, table_map save_nullinfo)
{
  DBUG_ASSERT(join->const_tables && save_nullinfo);

  for (uint tableno= 0; tableno < join->const_tables; tableno++)
  {
    TABLE *tbl= (join->join_tab+tableno)->table;
    if ((save_nullinfo & tbl->map))
    {
      /*
        The table had null_row=false and STATUS_NULL_ROW set when
        save_const_null_info was called
      */
      tbl->null_row= false;
      tbl->status&= ~STATUS_NULL_ROW;
    }
  }
}


/****************************************************************************
  QEP_tmp_table implementation
****************************************************************************/

/**
  @brief Instantiate tmp table and start index scan if necessary
  @todo Tmp table always would be created, even for empty result. Extend
        executor to avoid tmp table creation when no rows were written
        into tmp table.
  @return
    true  error
    false ok
*/

bool
QEP_tmp_table::prepare_tmp_table()
{
  TABLE *table= join_tab->table;
  JOIN *join= join_tab->join;
  int rc= 0;

  if (!join_tab->table->is_created())
  {
    if (instantiate_tmp_table(table, join_tab->tmp_table_param->keyinfo,
                              join_tab->tmp_table_param->start_recinfo,
                              &join_tab->tmp_table_param->recinfo,
                              join->select_options,
                              join->thd->variables.big_tables,
                              &join->thd->opt_trace))
      return true;
    (void) table->file->extra(HA_EXTRA_WRITE_CACHE);
    empty_record(table);
  }
  /* If it wasn't already, start index scan for grouping using table index. */
  if (!table->file->inited && table->group &&
      join_tab->tmp_table_param->sum_func_count && table->s->keys)
    rc= table->file->ha_index_init(0, 0);
  else
    rc= table->file->ha_rnd_init(0);
  if (rc)
  {
    table->file->print_error(rc, MYF(0));
    return true;
  }
  return false;
}


/**
  @brief Prepare table if necessary and call write_func to save record

  @param end_of_record  the end_of_record signal to pass to the writer

  @return return one of enum_nested_loop_state.
*/

enum_nested_loop_state
QEP_tmp_table::put_record(bool end_of_records)
{
  // Lasy tmp table creation/initialization
  if (!join_tab->table->file->inited)
    prepare_tmp_table();
  enum_nested_loop_state rc= (*write_func)(join_tab->join, join_tab,
                                           end_of_records);
  return rc;
}


/**
  @brief Finish rnd/index scan after accumulating records, switch ref_array,
         and send accumulated records further.
  @return return one of enum_nested_loop_state.
*/



/**
  @} (end of group Query_Executor)
*/

