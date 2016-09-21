/* Copyright (c) 2006, 2012, Oracle and/or its affiliates. All rights reserved.

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

#ifndef SQL_PARSE_INCLUDED
#define SQL_PARSE_INCLUDED

#include "my_global.h"                          /* NO_EMBEDDED_ACCESS_CHECKS */
#include "sql_acl.h"                            /* GLOBAL_ACLS */
#include "rpl_mi.h"

class Comp_creator;
class Item;
class Object_creation_ctx;
class Parser_state;
struct TABLE_LIST;
class THD;
class Table_ident;
struct LEX;

enum enum_mysql_completiontype {
  ROLLBACK_RELEASE=-2, ROLLBACK=1,  ROLLBACK_AND_CHAIN=7,
  COMMIT_RELEASE=-1,   COMMIT=0,    COMMIT_AND_CHAIN=6
};

#define INCEPTION_COM_DATABASES         1
#define INCEPTION_COM_TABLES            2
#define INCEPTION_COM_DESC_TABLE        3
#define INCEPTION_COM_TABLE_DEF         4

#define INCEPTION_NOERR                 0x00
#define INCEPTION_RULES                 0x01
#define INCEPTION_PARSE                 0x02

#define INCEPTION_STATE_INIT            1
#define INCEPTION_STATE_CHECKING        2
#define INCEPTION_STATE_EXECUTING       3
#define INCEPTION_STATE_BACKUP          4
#define INCEPTION_STATE_DEINIT          5
#define INCEPTION_STATE_SEND            6

extern "C" int test_if_data_home_dir(const char *dir);

bool stmt_causes_implicit_commit(const THD *thd, uint mask);

bool select_precheck(THD *thd, LEX *lex, TABLE_LIST *tables,
                     TABLE_LIST *first_table);
bool multi_update_precheck(THD *thd, TABLE_LIST *tables);
bool multi_delete_precheck(THD *thd, TABLE_LIST *tables);
int mysql_multi_update_prepare(THD *thd);
int mysql_multi_delete_prepare(THD *thd, uint *table_count);
bool mysql_insert_select_prepare(THD *thd);
bool update_precheck(THD *thd, TABLE_LIST *tables);
bool delete_precheck(THD *thd, TABLE_LIST *tables);
bool insert_precheck(THD *thd, TABLE_LIST *tables);
bool create_table_precheck(THD *thd, TABLE_LIST *tables,
                           TABLE_LIST *create_table);

bool parse_sql(THD *thd,
               Parser_state *parser_state,
               Object_creation_ctx *creation_ctx);

uint kill_one_thread(THD *thd, ulong id, bool only_kill_query);

void free_items(Item *item);
void cleanup_items(Item *item);

Comp_creator *comp_eq_creator(bool invert);
Comp_creator *comp_ge_creator(bool invert);
Comp_creator *comp_gt_creator(bool invert);
Comp_creator *comp_le_creator(bool invert);
Comp_creator *comp_lt_creator(bool invert);
Comp_creator *comp_ne_creator(bool invert);

void get_default_definer(THD *thd, LEX_USER *definer);
LEX_USER *create_default_definer(THD *thd);
LEX_USER *create_definer(THD *thd, LEX_STRING *user_name, LEX_STRING *host_name);
LEX_USER *get_current_user(THD *thd, LEX_USER *user);
bool check_string_byte_length(LEX_STRING *str, const char *err_msg,
                              uint max_byte_length);
bool check_string_char_length(LEX_STRING *str, const char *err_mg,
                              uint max_char_length, const CHARSET_INFO *cs,
                              bool no_error);
bool check_string_char_with_length(char* str, size_t length, const char *err_msg,
	uint max_char_length, const CHARSET_INFO *cs,
	bool no_error);
const CHARSET_INFO* merge_charset_and_collation(const CHARSET_INFO *cs,
                                                const CHARSET_INFO *cl);
bool check_host_name(LEX_STRING *str);
bool check_identifier_name(LEX_STRING *str, uint max_char_length,
                           uint err_code, const char *param_for_err_msg);
bool mysql_test_parse_for_slave(THD *thd,char *inBuf,uint length);
bool is_explainable_query(enum enum_sql_command command);
bool is_log_table_write_query(enum enum_sql_command command);
bool alloc_query(THD *thd, const char *packet, uint packet_length);
void mysql_init_select(LEX *lex);
void mysql_parse(THD *thd, uint length, Parser_state *parser_state);
void mysql_reset_thd_for_next_command(THD *thd);
bool mysql_new_select(LEX *lex, bool move_down);
void create_select_for_variable(const char *var_name);
void create_table_set_open_action_and_adjust_tables(LEX *lex);
void mysql_init_multi_delete(LEX *lex);
bool multi_delete_set_locks_and_link_aux_tables(LEX *lex);
void create_table_set_open_action_and_adjust_tables(LEX *lex);
pthread_handler_t handle_bootstrap(void *arg);
int mysql_execute_command(THD *thd);
bool do_command(THD *thd);
void do_handle_bootstrap(THD *thd);
bool dispatch_command(enum enum_server_command command, THD *thd,
		      char* packet, uint packet_length);
void log_slow_statement(THD *thd);
bool log_slow_applicable(THD *thd);
void log_slow_do(THD *thd);
bool append_file_to_dir(THD *thd, const char **filename_ptr,
                        const char *table_name);
bool append_file_to_dir(THD *thd, const char **filename_ptr,
                        const char *table_name);
void execute_init_command(THD *thd, LEX_STRING *init_command,
                          mysql_rwlock_t *var_lock);
bool add_field_to_list(THD *thd, LEX_STRING *field_name, enum enum_field_types type,
		       char *length, char *decimal,
		       uint type_modifier,
		       Item *default_value, Item *on_update_value,
		       LEX_STRING *comment,
		       char *change, List<String> *interval_list,
		       const CHARSET_INFO *cs,
		       uint uint_geom_type);
bool add_to_list(THD *thd, SQL_I_List<ORDER> &list, Item *group, bool asc);
void add_join_on(TABLE_LIST *b,Item *expr);
void add_join_natural(TABLE_LIST *a,TABLE_LIST *b,List<String> *using_fields,
                      SELECT_LEX *lex);
bool push_new_name_resolution_context(THD *thd,
                                      TABLE_LIST *left_op,
                                      TABLE_LIST *right_op);
void store_position_for_column(const char *name);
void init_update_queries(void);
bool check_simple_select();
Item *negate_expression(THD *thd, Item *expr);
bool check_stack_overrun(THD *thd, long margin, uchar *dummy);

/* Variables */

extern const char* any_db;
extern uint sql_command_flags[];
extern uint server_command_flags[];
extern const LEX_STRING command_name[];
extern uint server_command_flags[];

/* Inline functions */
inline bool check_identifier_name(LEX_STRING *str, uint err_code)
{
  return check_identifier_name(str, NAME_CHAR_LEN, err_code, "");
}

inline bool check_identifier_name(LEX_STRING *str)
{
  return check_identifier_name(str, NAME_CHAR_LEN, 0, "");
}

/* These were under the INNODB_COMPATIBILITY_HOOKS */

bool check_global_access(THD *thd, ulong want_access);

inline bool is_supported_parser_charset(const CHARSET_INFO *cs)
{
  return (cs->mbminlen == 1);
}

int mysql_check_column_default(
    THD* thd,
    Item *default_value,
    uint flags,
    field_info_t* field_info,
    const char*   field_name,
    enum enum_field_types real_type
);
int mysql_field_check(THD* thd, Create_field* field, char* table_name);
void mysql_check_index_attribute(THD * thd, Key* key, char* table_name);
int mysql_get_command_type(int sql_command, char* command_type);
int mysql_check_subselect_item( THD* thd, st_select_lex *select_lex, bool top);
int mysql_check_item( THD* thd, Item* item, st_select_lex *select_lex);
int print_item(THD* thd, query_print_cache_node_t*   query_node, str_t* print_str, Item* item, st_select_lex *select_lex);
int mysql_execute_commit(THD *thd);
void mysql_free_all_table_definition(THD*  thd);
int mysql_alloc_record(table_info_t* table_info, MYSQL *mysql);
int mysql_check_binlog_format(THD* thd, char* binlogformat);
int mysql_get_master_version(MYSQL* mysql, Master_info* mi);
int mysql_request_binlog_dump( MYSQL*  mysql, char*  file_name, int   binlog_pos, int server_id_in);
ulong mysql_read_event(MYSQL* mysql);
int mysql_process_event(Master_info* mi,const char* buf, ulong event_len, Log_event** evlog);
int mysql_parse_table_map_log_event_low(Master_info *mi, Log_event* ev, table_info_t* table_info);
table_info_t* mysql_get_table_object(THD* thd, char* dbname, char* tablename, int not_exist_report);
int mysql_get_field_string(Field* field, String* backupsql, char* null_arr, int field_index, int qurot_flag,  int doublequtor_escape);
int inception_transfer_execute_store_with_transaction( Master_info* mi, Log_event* ev, char*  sql);
int inception_transfer_execute_store_simple( Master_info* mi, Log_event* ev, char*  sql);
int mysql_unpack_row(
    Master_info* mi,
    ulong          m_table_id,
    uchar const *const row_data,
    MY_BITMAP const *cols,
    uchar const **const row_end,
    uchar const *const row_end_ptr, 
    int update_after);
str_t* str_init(str_t* str);
str_t* str_truncate_0(str_t* str);
void str_deinit(str_t* str);
str_t* str_append_1( str_t*  str, const char* new_string);
str_t* str_append( str_t*  str, const char* new_string);
char* str_get(str_t* str);
int str_get_len(str_t* str);
str_t* str_append_with_length( str_t*  str, const char* new_string, int len);
int register_slave_on_master(MYSQL* mysql, bool *suppress_warnings, int server_id_in);
char* mysql_get_alter_table_post_part( THD*  thd, char* statement, int ignore);
bool setup_connection_thread_globals(THD *thd);
int inception_init_slave_thread(THD* thd);
bool parse_sql(THD *thd, Parser_state *parser_state, Object_creation_ctx *creation_ctx);
ulong mysql_read_event_for_transfer(Master_info* mi, MYSQL* mysql);
void free_tables_to_lock(Master_info*	mi);
int mysql_get_field_string_for_tranfer(Master_info* mi,  Field* field, str_t* backup_sql, char* null_arr, int field_index, int qutor_flag);
void mysql_set_cache_new_column_type(field_info_t* field_info, Create_field*   field);
int inception_mts_get_commit_positions( Master_info* mi, Log_event* ev);
int inception_stop_transfer( transfer_cache_t* datacenter);
bool inception_transfer_killed(THD* thd, transfer_cache_t* datacenter);
void inception_transfer_fetch_binlogsha1( Master_info* mi, Log_event* ev);
int inception_mts_insert_commit_positions( transfer_cache_t* datacenter, mts_thread_t* mts_thread);
int inception_wait_mts_threads_finish( transfer_cache_t* datacenter);
int inception_wait_and_free_mts( transfer_cache_t* datacenter, int need_lock);
int inception_table_create(THD *thd, String *create_sql);
int mysql_cache_deinit_task(THD* thd);
char* inception_get_task_sequence(THD* thd);
int mysql_print_subselect( THD* thd, query_print_cache_node_t*   query_node, str_t* print_str, st_select_lex *select_lex, bool top);
int mysql_dup_char( char* src, char* dest, char chr);
table_info_t* mysql_get_table_info_by_id( Master_info* mi, ulong m_table_id);
int inception_transfer_options_init(THD* thd,char* datacenter,MYSQL* mysql,str_t* insert_sql);
int inception_transfer_additional_tables_init(THD* thd,char* datacenter,MYSQL* mysql);
int mysql_execute_inception_set_command_for_dc(THD* thd);
table_info_t* mysql_get_table_object_from_cache( THD*  thd, char*  dbname, char*  tablename);
int mysql_extract_update_tables( THD* thd, sql_cache_node_t* sql_cache_node);
int mysql_check_dml_query_tables(THD* thd);
uint mysql_get_explain_info(THD* thd, MYSQL*  mysql, char*  select_sql, explain_info_t** explain_ret, int report_err, char* dbname);
int mysql_anlyze_explain(THD* thd, explain_info_t* explain);
void mysql_data_seek2(MYSQL_RES *result, my_ulonglong row);

#endif /* SQL_PARSE_INCLUDED */
