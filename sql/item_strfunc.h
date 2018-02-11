#ifndef ITEM_STRFUNC_INCLUDED
#define ITEM_STRFUNC_INCLUDED

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


/* This file defines all string functions */
#include "crypt_genhash_impl.h"
#include "json_dom.h"           // Json_dom, Json_wrapper
#include "json_path.h"          // Json_path
#include "mem_root_array.h"     // Mem_root_array
#include "prealloced_array.h"   // Prealloced_array

class MY_LOCALE;

class Item_str_func :public Item_func
{
protected:
  /**
     Sets the result value of the function an empty string, using the current
     character set. No memory is allocated.
     @retval A pointer to the str_value member.
   */
  String *make_empty_result() {
    str_value.set("", 0, collation.collation);
    return &str_value; 
  }
public:
  Item_str_func() :Item_func() { decimals=NOT_FIXED_DEC; }
  Item_str_func(Item *a) :Item_func(a) {decimals=NOT_FIXED_DEC; }
  Item_str_func(Item *a,Item *b) :Item_func(a,b) { decimals=NOT_FIXED_DEC; }
  Item_str_func(Item *a,Item *b,Item *c) :Item_func(a,b,c) { decimals=NOT_FIXED_DEC; }
  Item_str_func(Item *a,Item *b,Item *c,Item *d) :Item_func(a,b,c,d) {decimals=NOT_FIXED_DEC; }
  Item_str_func(Item *a,Item *b,Item *c,Item *d, Item* e) :Item_func(a,b,c,d,e) {decimals=NOT_FIXED_DEC; }
  Item_str_func(List<Item> &list) :Item_func(list) {decimals=NOT_FIXED_DEC; }
  longlong val_int();
  double val_real();
  my_decimal *val_decimal(my_decimal *);
  bool get_date(MYSQL_TIME *ltime, uint fuzzydate)
  {
    return get_date_from_string(ltime, fuzzydate);
  }
  bool get_time(MYSQL_TIME *ltime)
  {
    return get_time_from_string(ltime);
  }
  enum Item_result result_type () const { return STRING_RESULT; }
  void left_right_max_length();
  bool fix_fields(THD *thd, Item **ref);
  String *val_str_from_val_str_ascii(String *str, String *str2);
};



/*
  Functions that return values with ASCII repertoire
*/
class Item_str_ascii_func :public Item_str_func
{
  String ascii_buf;
public:
  Item_str_ascii_func() :Item_str_func()
  { collation.set_repertoire(MY_REPERTOIRE_ASCII); }
  Item_str_ascii_func(Item *a) :Item_str_func(a)
  { collation.set_repertoire(MY_REPERTOIRE_ASCII); }
  Item_str_ascii_func(Item *a,Item *b) :Item_str_func(a,b)
  { collation.set_repertoire(MY_REPERTOIRE_ASCII); }
  Item_str_ascii_func(Item *a,Item *b,Item *c) :Item_str_func(a,b,c)
  { collation.set_repertoire(MY_REPERTOIRE_ASCII); }
  String *val_str(String *str)
  {
    return val_str_from_val_str_ascii(str, &ascii_buf);
  }
  virtual String *val_str_ascii(String *)= 0;
};


class Item_func_md5 :public Item_str_ascii_func
{
  String tmp_value;
public:
  Item_func_md5(Item *a) :Item_str_ascii_func(a) {}
  String *val_str_ascii(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "md5"; }
};


class Item_func_sha :public Item_str_ascii_func
{
public:
  Item_func_sha(Item *a) :Item_str_ascii_func(a) {}
  String *val_str_ascii(String *);    
  void fix_length_and_dec();      
  const char *func_name() const { return "sha"; }	
};

class Item_func_sha2 :public Item_str_ascii_func
{
public:
  Item_func_sha2(Item *a, Item *b) :Item_str_ascii_func(a, b) {}
  String *val_str_ascii(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "sha2"; }
};

class Item_func_to_base64 :public Item_str_ascii_func
{
  String tmp_value;
public:
  Item_func_to_base64(Item *a) :Item_str_ascii_func(a) {}
  String *val_str_ascii(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "to_base64"; }
};

class Item_func_from_base64 :public Item_str_func
{
  String tmp_value;
public:
  Item_func_from_base64(Item *a) :Item_str_func(a) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "from_base64"; }
};


class Item_func_aes_encrypt :public Item_str_func
{
public:
  Item_func_aes_encrypt(Item *a, Item *b) :Item_str_func(a,b) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "aes_encrypt"; }
};

class Item_func_aes_decrypt :public Item_str_func	
{
public:
  Item_func_aes_decrypt(Item *a, Item *b) :Item_str_func(a,b) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "aes_decrypt"; }
};


class Item_func_concat :public Item_str_func
{
  String tmp_value;
public:
  Item_func_concat(List<Item> &list) :Item_str_func(list) {}
  Item_func_concat(Item *a,Item *b) :Item_str_func(a,b) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "concat"; }
};

class Item_func_concat_ws :public Item_str_func
{
  String tmp_value;
public:
  Item_func_concat_ws(List<Item> &list) :Item_str_func(list) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "concat_ws"; }
  table_map not_null_tables() const { return 0; }
};

class Item_func_reverse :public Item_str_func
{
  String tmp_value;
public:
  Item_func_reverse(Item *a) :Item_str_func(a) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "reverse"; }
};


class Item_func_replace :public Item_str_func
{
  String tmp_value,tmp_value2;
public:
  Item_func_replace(Item *org,Item *find,Item *replace)
    :Item_str_func(org,find,replace) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "replace"; }
};


class Item_func_insert :public Item_str_func
{
  String tmp_value;
public:
  Item_func_insert(Item *org,Item *start,Item *length,Item *new_str)
    :Item_str_func(org,start,length,new_str) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "insert"; }
};


class Item_str_conv :public Item_str_func
{
protected:
  uint multiply;
  my_charset_conv_case converter;
  String tmp_value;
public:
  Item_str_conv(Item *item) :Item_str_func(item) {}
  String *val_str(String *);
};


class Item_func_lcase :public Item_str_conv
{
public:
  Item_func_lcase(Item *item) :Item_str_conv(item) {}
  const char *func_name() const { return "lcase"; }
  void fix_length_and_dec();
};

class Item_func_ucase :public Item_str_conv
{
public:
  Item_func_ucase(Item *item) :Item_str_conv(item) {}
  const char *func_name() const { return "ucase"; }
  void fix_length_and_dec();
};


class Item_func_left :public Item_str_func
{
  String tmp_value;
public:
  Item_func_left(Item *a,Item *b) :Item_str_func(a,b) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "left"; }
};


class Item_func_right :public Item_str_func
{
  String tmp_value;
public:
  Item_func_right(Item *a,Item *b) :Item_str_func(a,b) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "right"; }
};


class Item_func_substr :public Item_str_func
{
  String tmp_value;
public:
  Item_func_substr(Item *a,Item *b) :Item_str_func(a,b) {}
  Item_func_substr(Item *a,Item *b,Item *c) :Item_str_func(a,b,c) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "substr"; }
};


class Item_func_substr_index :public Item_str_func
{
  String tmp_value;
public:
  Item_func_substr_index(Item *a,Item *b,Item *c) :Item_str_func(a,b,c) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "substring_index"; }
};


class Item_func_trim :public Item_str_func
{
protected:
  String tmp_value;
  String remove;
public:
  Item_func_trim(Item *a,Item *b) :Item_str_func(a,b) {}
  Item_func_trim(Item *a) :Item_str_func(a) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "trim"; }
  virtual void print(String *str, enum_query_type query_type);
  virtual const char *mode_name() const { return "both"; }
};


class Item_func_ltrim :public Item_func_trim
{
public:
  Item_func_ltrim(Item *a,Item *b) :Item_func_trim(a,b) {}
  Item_func_ltrim(Item *a) :Item_func_trim(a) {}
  String *val_str(String *);
  const char *func_name() const { return "ltrim"; }
  const char *mode_name() const { return "leading"; }
};


class Item_func_rtrim :public Item_func_trim
{
public:
  Item_func_rtrim(Item *a,Item *b) :Item_func_trim(a,b) {}
  Item_func_rtrim(Item *a) :Item_func_trim(a) {}
  String *val_str(String *);
  const char *func_name() const { return "rtrim"; }
  const char *mode_name() const { return "trailing"; }
};


/*
  Item_func_password -- new (4.1.1) PASSWORD() function implementation.
  Returns strcat('*', octet2hex(sha1(sha1(password)))). '*' stands for new
  password format, sha1(sha1(password) is so-called hash_stage2 value.
  Length of returned string is always 41 byte. To find out how entire
  authentication procedure works, see comments in password.c.
*/

class Item_func_password :public Item_str_ascii_func
{
  char m_hashed_password_buffer[CRYPT_MAX_PASSWORD_SIZE + 1];
  unsigned int m_hashed_password_buffer_len;
  bool m_recalculate_password;
public:
  Item_func_password(Item *a) : Item_str_ascii_func(a)
  {
    m_hashed_password_buffer_len= 0;
    m_recalculate_password= false;
  }
  String *val_str_ascii(String *str);
  void fix_length_and_dec();
  const char *func_name() const { return "password"; }
  static char *create_password_hash_buffer(THD *thd, const char *password,
                                           size_t pass_len);
};


/*
  Item_func_old_password -- PASSWORD() implementation used in MySQL 3.21 - 4.0
  compatibility mode. This item is created in sql_yacc.yy when
  'old_passwords' session variable is set, and to handle OLD_PASSWORD()
  function.
*/

class Item_func_old_password :public Item_str_ascii_func
{
  char tmp_value[SCRAMBLED_PASSWORD_CHAR_LENGTH_323+1];
public:
  Item_func_old_password(Item *a) :Item_str_ascii_func(a) {}
  String *val_str_ascii(String *str);
  void fix_length_and_dec()
  {
    fix_length_and_charset(SCRAMBLED_PASSWORD_CHAR_LENGTH_323, default_charset());
  } 
  const char *func_name() const { return "old_password"; }
  static char *alloc(THD *thd, const char *password, size_t pass_len);
};


class Item_func_des_encrypt :public Item_str_func
{
  String tmp_value,tmp_arg;
public:
  Item_func_des_encrypt(Item *a) :Item_str_func(a) {}
  Item_func_des_encrypt(Item *a, Item *b): Item_str_func(a,b) {}
  String *val_str(String *);
  void fix_length_and_dec()
  {
    maybe_null=1;
    /* 9 = MAX ((8- (arg_len % 8)) + 1) */
    max_length = args[0]->max_length + 9;
  }
  const char *func_name() const { return "des_encrypt"; }
};

class Item_func_des_decrypt :public Item_str_func
{
  String tmp_value;
public:
  Item_func_des_decrypt(Item *a) :Item_str_func(a) {}
  Item_func_des_decrypt(Item *a, Item *b): Item_str_func(a,b) {}
  String *val_str(String *);
  void fix_length_and_dec()
  {
    maybe_null=1;
    /* 9 = MAX ((8- (arg_len % 8)) + 1) */
    max_length= args[0]->max_length;
    if (max_length >= 9U)
      max_length-= 9U;
  }
  const char *func_name() const { return "des_decrypt"; }
};

class Item_func_encrypt :public Item_str_func
{
  String tmp_value;

  /* Encapsulate common constructor actions */
  void constructor_helper()
  {
    collation.set(&my_charset_bin);
  }
public:
  Item_func_encrypt(Item *a) :Item_str_func(a)
  {
    constructor_helper();
  }
  Item_func_encrypt(Item *a, Item *b): Item_str_func(a,b)
  {
    constructor_helper();
  }
  String *val_str(String *);
  void fix_length_and_dec() { maybe_null=1; max_length = 13; }
  const char *func_name() const { return "encrypt"; }
};

#include "sql_crypt.h"


class Item_func_encode :public Item_str_func
{
private:
  /** Whether the PRNG has already been seeded. */
  bool seeded;
protected:
  SQL_CRYPT sql_crypt;
public:
  Item_func_encode(Item *a, Item *seed):
    Item_str_func(a, seed) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "encode"; }
protected:
  virtual void crypto_transform(String *);
private:
  /** Provide a seed for the PRNG sequence. */
  bool seed();
};


class Item_func_decode :public Item_func_encode
{
public:
  Item_func_decode(Item *a, Item *seed): Item_func_encode(a, seed) {}
  const char *func_name() const { return "decode"; }
protected:
  void crypto_transform(String *);
};


class Item_func_sysconst :public Item_str_func
{
public:
  Item_func_sysconst()
  { collation.set(system_charset_info,DERIVATION_SYSCONST); }
  Item *safe_charset_converter(const CHARSET_INFO *tocs);
  /*
    Used to create correct Item name in new converted item in
    safe_charset_converter, return string representation of this function
    call
  */
  virtual const Name_string fully_qualified_func_name() const = 0;
};


class Item_func_database :public Item_func_sysconst
{
public:
  Item_func_database() :Item_func_sysconst() {}
  String *val_str(String *);
  void fix_length_and_dec()
  {
    max_length= MAX_FIELD_NAME * system_charset_info->mbmaxlen;
    maybe_null=1;
  }
  const char *func_name() const { return "database"; }
  const Name_string fully_qualified_func_name() const
  { return NAME_STRING("database()"); }
};


class Item_func_user :public Item_func_sysconst
{
protected:
  bool init (const char *user, const char *host);

public:
  Item_func_user()
  {
    str_value.set("", 0, system_charset_info);
  }
  String *val_str(String *)
  {
    DBUG_ASSERT(fixed == 1);
    return (null_value ? 0 : &str_value);
  }
  bool fix_fields(THD *thd, Item **ref);
  void fix_length_and_dec()
  {
    max_length= (USERNAME_LENGTH +
                 (HOSTNAME_LENGTH + 1) * SYSTEM_CHARSET_MBMAXLEN);
  }
  const char *func_name() const { return "user"; }
  const Name_string fully_qualified_func_name() const
  { return NAME_STRING("user()"); }
  type_conversion_status save_in_field(Field *field, bool no_conversions)
  {
    return save_str_value_in_field(field, &str_value);
  }
};


class Item_func_current_user :public Item_func_user
{
  Name_resolution_context *context;

public:
  Item_func_current_user(Name_resolution_context *context_arg)
    : context(context_arg) {}
  bool fix_fields(THD *thd, Item **ref);
  const char *func_name() const { return "current_user"; }
  const Name_string fully_qualified_func_name() const
  { return NAME_STRING("current_user()"); }
};


class Item_func_soundex :public Item_str_func
{
  String tmp_value;
public:
  Item_func_soundex(Item *a) :Item_str_func(a) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "soundex"; }
};


class Item_func_elt :public Item_str_func
{
public:
  Item_func_elt(List<Item> &list) :Item_str_func(list) {}
  double val_real();
  longlong val_int();
  String *val_str(String *str);
  void fix_length_and_dec();
  const char *func_name() const { return "elt"; }
};


class Item_func_make_set :public Item_str_func
{
  Item *item;
  String tmp_str;

public:
  Item_func_make_set(Item *a,List<Item> &list) :Item_str_func(list),item(a) {}
  String *val_str(String *str);
  bool fix_fields(THD *thd, Item **ref)
  {
    DBUG_ASSERT(fixed == 0);
    bool res= ((!item->fixed && item->fix_fields(thd, &item)) ||
               item->check_cols(1) ||
               Item_func::fix_fields(thd, ref));
    maybe_null|= item->maybe_null;
    return res;
  }
  void split_sum_func(THD *thd, Ref_ptr_array ref_pointer_array,
                      List<Item> &fields);
  void fix_length_and_dec();
  void update_used_tables();
  const char *func_name() const { return "make_set"; }

  bool walk(Item_processor processor, bool walk_subquery, uchar *arg)
  {
    return item->walk(processor, walk_subquery, arg) ||
      Item_str_func::walk(processor, walk_subquery, arg);
  }
  Item *transform(Item_transformer transformer, uchar *arg);
  virtual void print(String *str, enum_query_type query_type);
};


class Item_func_format :public Item_str_ascii_func
{
  String tmp_str;
  MY_LOCALE *locale;
public:
  Item_func_format(Item *org, Item *dec): Item_str_ascii_func(org, dec) {}
  Item_func_format(Item *org, Item *dec, Item *lang):
  Item_str_ascii_func(org, dec, lang) {}
  
  MY_LOCALE *get_locale(Item *item);
  String *val_str_ascii(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "format"; }
  virtual void print(String *str, enum_query_type query_type);
};


class Item_func_char :public Item_str_func
{
public:
  Item_func_char(List<Item> &list) :Item_str_func(list)
  { collation.set(&my_charset_bin); }
  Item_func_char(List<Item> &list, const CHARSET_INFO *cs) :
  Item_str_func(list)
  { collation.set(cs); }  
  String *val_str(String *);
  void fix_length_and_dec() 
  {
    max_length= arg_count * 4;
  }
  const char *func_name() const { return "char"; }
};


class Item_func_repeat :public Item_str_func
{
  String tmp_value;
public:
  Item_func_repeat(Item *arg1,Item *arg2) :Item_str_func(arg1,arg2) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "repeat"; }
};


class Item_func_space :public Item_str_func
{
public:
  Item_func_space(Item *arg1):Item_str_func(arg1) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "space"; }
};


class Item_func_rpad :public Item_str_func
{
  String tmp_value, rpad_str;
public:
  Item_func_rpad(Item *arg1,Item *arg2,Item *arg3)
    :Item_str_func(arg1,arg2,arg3) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "rpad"; }
};


class Item_func_lpad :public Item_str_func
{
  String tmp_value, lpad_str;
public:
  Item_func_lpad(Item *arg1,Item *arg2,Item *arg3)
    :Item_str_func(arg1,arg2,arg3) {}
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "lpad"; }
};


class Item_func_conv :public Item_str_func
{
public:
  Item_func_conv(Item *a,Item *b,Item *c) :Item_str_func(a,b,c) {}
  const char *func_name() const { return "conv"; }
  String *val_str(String *);
  void fix_length_and_dec()
  {
    collation.set(default_charset());
    max_length=64;
    maybe_null= 1;
  }
};


class Item_func_hex :public Item_str_ascii_func
{
  String tmp_value;
public:
  Item_func_hex(Item *a) :Item_str_ascii_func(a) {}
  const char *func_name() const { return "hex"; }
  String *val_str_ascii(String *);
  void fix_length_and_dec()
  {
    collation.set(default_charset());
    decimals=0;
    fix_char_length(args[0]->max_length * 2);
  }
};

class Item_func_unhex :public Item_str_func
{
  String tmp_value;
public:
  Item_func_unhex(Item *a) :Item_str_func(a) 
  { 
    /* there can be bad hex strings */
    maybe_null= 1; 
  }
  const char *func_name() const { return "unhex"; }
  String *val_str(String *);
  void fix_length_and_dec()
  {
    collation.set(&my_charset_bin);
    decimals=0;
    max_length=(1+args[0]->max_length)/2;
  }
};


#ifndef DBUG_OFF
class Item_func_like_range :public Item_str_func
{
protected:
  String min_str;
  String max_str;
  const bool is_min;
public:
  Item_func_like_range(Item *a, Item *b, bool is_min_arg)
    :Item_str_func(a, b), is_min(is_min_arg)
  { maybe_null= 1; }
  String *val_str(String *);
  void fix_length_and_dec()
  {
    collation.set(args[0]->collation);
    decimals=0;
    max_length= MAX_BLOB_WIDTH;
  }
};


class Item_func_like_range_min :public Item_func_like_range
{
public:
  Item_func_like_range_min(Item *a, Item *b) 
    :Item_func_like_range(a, b, true) { }
  const char *func_name() const { return "like_range_min"; }
};


class Item_func_like_range_max :public Item_func_like_range
{
public:
  Item_func_like_range_max(Item *a, Item *b)
    :Item_func_like_range(a, b, false) { }
  const char *func_name() const { return "like_range_max"; }
};
#endif


class Item_char_typecast :public Item_str_func
{
  int cast_length;
  const CHARSET_INFO *cast_cs, *from_cs;
  bool charset_conversion;
  String tmp_value;
public:
  Item_char_typecast(Item *a, int length_arg, const CHARSET_INFO *cs_arg)
    :Item_str_func(a), cast_length(length_arg), cast_cs(cs_arg) {}
  enum Functype functype() const { return CHAR_TYPECAST_FUNC; }
  bool eq(const Item *item, bool binary_cmp) const;
  const char *func_name() const { return "cast_as_char"; }
  String *val_str(String *a);
  void fix_length_and_dec();
  virtual void print(String *str, enum_query_type query_type);
};


class Item_func_binary :public Item_str_func
{
public:
  Item_func_binary(Item *a) :Item_str_func(a) {}
  String *val_str(String *a)
  {
    DBUG_ASSERT(fixed == 1);
    String *tmp=args[0]->val_str(a);
    null_value=args[0]->null_value;
    if (tmp)
      tmp->set_charset(&my_charset_bin);
    return tmp;
  }
  void fix_length_and_dec()
  {
    collation.set(&my_charset_bin);
    max_length=args[0]->max_length;
  }
  virtual void print(String *str, enum_query_type query_type);
  const char *func_name() const { return "cast_as_binary"; }
};


class Item_load_file :public Item_str_func
{
  String tmp_value;
public:
  Item_load_file(Item *a) :Item_str_func(a) {}
  String *val_str(String *);
  const char *func_name() const { return "load_file"; }
  void fix_length_and_dec()
  {
    collation.set(&my_charset_bin, DERIVATION_COERCIBLE);
    maybe_null=1;
    max_length=MAX_BLOB_WIDTH;
  }
};


class Item_func_export_set: public Item_str_func
{
 public:
  Item_func_export_set(Item *a,Item *b,Item* c) :Item_str_func(a,b,c) {}
  Item_func_export_set(Item *a,Item *b,Item* c,Item* d) :Item_str_func(a,b,c,d) {}
  Item_func_export_set(Item *a,Item *b,Item* c,Item* d,Item* e) :Item_str_func(a,b,c,d,e) {}
  String  *val_str(String *str);
  void fix_length_and_dec();
  const char *func_name() const { return "export_set"; }
};

class Item_func_quote :public Item_str_func
{
  String tmp_value;
public:
  Item_func_quote(Item *a) :Item_str_func(a) {}
  const char *func_name() const { return "quote"; }
  String *val_str(String *);
  void fix_length_and_dec()
  {
    collation.set(args[0]->collation);
    ulong max_result_length= (ulong) args[0]->max_length * 2 +
                                  2 * collation.collation->mbmaxlen;
    max_length= std::min<ulong>(max_result_length, MAX_BLOB_WIDTH);
  }
};

class Item_func_conv_charset :public Item_str_func
{
  bool use_cached_value;
  String tmp_value;
public:
  bool safe;
  const CHARSET_INFO *conv_charset; // keep it public
  Item_func_conv_charset(Item *a, const CHARSET_INFO *cs) :Item_str_func(a) 
  { conv_charset= cs; use_cached_value= 0; safe= 0; }
  Item_func_conv_charset(Item *a, const CHARSET_INFO *cs,
                         bool cache_if_const) :Item_str_func(a)
  {
    DBUG_ASSERT(args[0]->fixed);
    conv_charset= cs;
    if (cache_if_const && args[0]->const_item())
    {
      uint errors= 0;
      String tmp, *str= args[0]->val_str(&tmp);
      if (!str || str_value.copy(str->ptr(), str->length(),
                                 str->charset(), conv_charset, &errors))
        null_value= 1;
      use_cached_value= 1;
      str_value.mark_as_const();
      safe= (errors == 0);
    }
    else
    {
      use_cached_value= 0;
      /*
        Conversion from and to "binary" is safe.
        Conversion to Unicode is safe.
        Other kind of conversions are potentially lossy.
      */
      safe= (args[0]->collation.collation == &my_charset_bin ||
             cs == &my_charset_bin ||
             (cs->state & MY_CS_UNICODE));
    }
  }
  String *val_str(String *);
  void fix_length_and_dec();
  const char *func_name() const { return "convert"; }
  virtual void print(String *str, enum_query_type query_type);
};

class Item_func_set_collation :public Item_str_func
{
public:
  Item_func_set_collation(Item *a, Item *b) :Item_str_func(a,b) {};
  String *val_str(String *);
  void fix_length_and_dec();
  bool eq(const Item *item, bool binary_cmp) const;
  const char *func_name() const { return "collate"; }
  enum Functype functype() const { return COLLATE_FUNC; }
  virtual void print(String *str, enum_query_type query_type);
  Item_field *field_for_view_update()
  {
    /* this function is transparent for view updating */
    return args[0]->field_for_view_update();
  }
};

class Item_func_charset :public Item_str_func
{
public:
  Item_func_charset(Item *a) :Item_str_func(a) {}
  String *val_str(String *);
  const char *func_name() const { return "charset"; }
  void fix_length_and_dec()
  {
     collation.set(system_charset_info);
     max_length= 64 * collation.collation->mbmaxlen; // should be enough
     maybe_null= 0;
  };
  table_map not_null_tables() const { return 0; }
};

class Item_func_collation :public Item_str_func
{
public:
  Item_func_collation(Item *a) :Item_str_func(a) {}
  String *val_str(String *);
  const char *func_name() const { return "collation"; }
  void fix_length_and_dec()
  {
     collation.set(system_charset_info);
     max_length= 64 * collation.collation->mbmaxlen; // should be enough
     maybe_null= 0;
  };
  table_map not_null_tables() const { return 0; }
};

class Item_func_weight_string :public Item_str_func
{
  String tmp_value;
  uint flags;
  uint nweights;
  uint result_length;
  Field *field;
public:
  Item_func_weight_string(Item *a, uint result_length_arg,
                          uint nweights_arg, uint flags_arg)
  :Item_str_func(a), field(NULL)
  {
    nweights= nweights_arg;
    flags= flags_arg;
    result_length= result_length_arg;
  }
  const char *func_name() const { return "weight_string"; }
  String *val_str(String *);
  void fix_length_and_dec();
};

class Item_func_crc32 :public Item_int_func
{
  String value;
public:
  Item_func_crc32(Item *a) :Item_int_func(a) { unsigned_flag= 1; }
  const char *func_name() const { return "crc32"; }
  void fix_length_and_dec() { max_length=10; }
  longlong val_int();
};

class Item_func_uncompressed_length : public Item_int_func
{
  String value;
public:
  Item_func_uncompressed_length(Item *a):Item_int_func(a){}
  const char *func_name() const{return "uncompressed_length";}
  void fix_length_and_dec() { max_length=10; }
  longlong val_int();
};

#ifdef HAVE_COMPRESS
#define ZLIB_DEPENDED_FUNCTION ;
#else
#define ZLIB_DEPENDED_FUNCTION { null_value=1; return 0; }
#endif

class Item_func_compress: public Item_str_func
{
  String buffer;
public:
  Item_func_compress(Item *a):Item_str_func(a){}
  void fix_length_and_dec(){max_length= (args[0]->max_length*120)/100+12;}
  const char *func_name() const{return "compress";}
  String *val_str(String *) ZLIB_DEPENDED_FUNCTION
};

class Item_func_uncompress: public Item_str_func
{
  String buffer;
public:
  Item_func_uncompress(Item *a): Item_str_func(a){}
  void fix_length_and_dec(){ maybe_null= 1; max_length= MAX_BLOB_WIDTH; }
  const char *func_name() const{return "uncompress";}
  String *val_str(String *) ZLIB_DEPENDED_FUNCTION
};

class Item_func_uuid: public Item_str_func
{
public:
  Item_func_uuid(): Item_str_func() {}
  void fix_length_and_dec()
  {
    collation.set(system_charset_info,
                  DERIVATION_COERCIBLE, MY_REPERTOIRE_ASCII);
    fix_char_length(UUID_LENGTH);
  }
  const char *func_name() const{ return "uuid"; }
  String *val_str(String *);
};

#ifdef HAVE_REPLICATION
class Item_func_gtid_subtract: public Item_str_ascii_func
{
  String buf1, buf2;
public:
  Item_func_gtid_subtract(Item *a, Item *b) :Item_str_ascii_func(a, b) {}
  void fix_length_and_dec();
  const char *func_name() const{ return "gtid_subtract"; }
  String *val_str_ascii(String *);
};
#endif // if HAVE_REPLICATION

int calculate_password(String *str, char *buffer);

class Item_func_like;
struct Json_scalar_holder;

/** For use by JSON_CONTAINS_PATH() and JSON_SEARCH() */
enum enum_one_or_all_type
{
    ooa_one,
    ooa_all,
    ooa_null,
    ooa_error,
    ooa_uninitialized
};

/**
 Path cache for JSON functions. Caches parsed path
 objects for arguments which are string literals.
 Maintains a vector of path objects and an array of
 ints which map path argument numbers to slots in
 the array.
 */
//class Json_path_cache
//{
//private:
//    // holder for path strings
//    String m_path_value;
//    
//    // list of paths
//    Prealloced_array<Json_path, 8, false> m_paths;
//    
//    // map argument indexes to indexes into m_paths
//    Mem_root_array<int, true> m_arg_idx_to_vector_idx;
//    
//    // remembers whether a constant path was null or invalid
//    Mem_root_array<bool, true> m_arg_idx_to_problem_indicator;
//    
//    // number of cells in m_arg_idx_to_vector
//    uint m_size;
//    
//public:
//    Json_path_cache(THD *thd, uint size);
//    ~Json_path_cache();
//    
//    /**
//     Parse a path expression if necessary. Does nothing if the path
//     expression is constant and it has already been parsed. Assumes that
//     we've already verified that the path expression is not null. Raises an
//     error if the path expression is syntactically incorrect. Raises an
//     error if the path expression contains wildcard tokens but is not
//     supposed to. Otherwise puts the parsed path onto the
//     path vector.
//     
//     @param[in]  args             Array of args to a JSON function
//     @param[in]  arg_idx          Index of the path_expression in args
//     @param[in]  forbid_wildcards True if the path shouldn't contain * or **
//     
//     @returns false on success, true on error or if the path is NULL
//     */
//    bool parse_and_cache_path(Item ** args, uint arg_idx,
//                              bool forbid_wildcards);
//    
//    
//    /**
//     Return an already parsed path expression.
//     
//     @param[in]  arg_idx   Index of the path_expression in the JSON function args
//     
//     @returns the already parsed path
//     */
//    Json_path *get_path(uint arg_idx);
//    
//    /**
//     Reset the cache for re-use when a statement is re-executed.
//     */
//    void reset_cache();
//};

/* JSON function support  */

/**
 Base class for all item functions that a return JSON value
 */
class Item_json_func : public Item_func
{
protected:
    /// String used when reading JSON binary values or JSON text values.
    String m_value;
    /// String used for converting JSON text values to utf8mb4 charset.
    String m_conversion_buffer;
    /// String used for converting a JSON value to text in val_str().
    String m_string_buffer;
    
    // Cache for constant path expressions
//    Json_path_cache m_path_cache;
    
    type_conversion_status save_in_field_inner(Field *field, bool no_conversions);
    
public:
    Item_json_func(THD *thd, Item *a) : Item_func(a)
//    ,m_path_cache(thd, 1)
    {}
    Item_json_func(THD *thd, Item *a, Item *b) : Item_func(a, b)
//    ,m_path_cache(thd, 2)
    {}
    Item_json_func(THD *thd, Item *a, Item *b, Item *c)
    : Item_func(a, b, c)
//    , m_path_cache(thd, 3)
    {}
    Item_json_func(THD *thd, List<Item> a) : Item_func(a)
//    ,m_path_cache(thd, arg_count)
    {}
    
    enum_field_types field_type() const { return MYSQL_TYPE_JSON; }
    
    void fix_length_and_dec()
    {
        max_length= MAX_BLOB_WIDTH;
        maybe_null= true;
        collation.set(&my_charset_utf8mb4_bin, DERIVATION_IMPLICIT);
    }
    enum Item_result result_type () const { return STRING_RESULT; }
    String *val_str(String *arg);
    bool get_date(MYSQL_TIME *ltime, my_time_flags_t fuzzydate);
    bool get_time(MYSQL_TIME *ltime);
    longlong val_int();
    double val_real();
    my_decimal *val_decimal(my_decimal *decimal_value);
    
    /** Cleanup between executions of the statement */
    void cleanup();
    
    Item_result cast_to_int_type () const { return INT_RESULT; }
    
    void update_null_value ()
    {
        Json_wrapper wr;
        val_json(&wr);
    }
};

/**
 Return the JSON value of the argument in a wrapper. Abstracts whether
 the value comes from a field or a function. Does not handle literals.
 See also get_json_wrapper.
 
 @param[in]     args     the arguments
 @param[in]     arg_idx  the argument index
 @param[in,out] result   the JSON value wrapper
 
 @returns false iff the argument is a JSON field or function result
 */
bool json_value(Item **args, uint arg_idx, Json_wrapper *result);

/**
 Return the JSON value of the argument in a wrapper. Abstracts whether
 the value comes from a field or a function or a valid JSON text.
 
 @param[in]  args          the arguments
 @param[in]  arg_idx       the argument index
 @param[out] str           the string buffer
 @param[in]  func_name     the name of the function we are executing
 @param[out] result        the JSON value wrapper
 @param[in]  preserve_neg_zero_int
 Whether integer negative zero should be preserved.
 If set to TRUE, -0 is handled as a DOUBLE. Double
 negative zero (-0.0) is preserved regardless of what
 this parameter is set to.
 @result false if we found a value or NULL, true if not.
 */
bool get_json_wrapper(Item **args, uint arg_idx, String *str,
                      const char *func_name, Json_wrapper *wrapper,
                      bool preserve_neg_zero_int= false);

/**
 Convert Json values or MySQL values to JSON.
 
 @param[in]     args       arguments to function
 @param[in]     arg_idx    the index of the argument to process
 @param[in]     calling_function    name of the calling function
 @param[in,out] value      working area (if the returned Json_wrapper points
 to a binary value rather than a DOM, this string
 will end up holding the binary representation, and
 it must stay alive until the wrapper is destroyed
 or converted from binary to DOM)
 @param[in,out] tmp        temporary scratch space for converting strings to
 the correct charset; only used if accept_string is
 true and conversion is needed
 @param[in,out] wr         the result wrapper
 @param[in,out] scalar     pointer to pre-allocated memory that can be
 borrowed by the result wrapper if the result is a
 scalar. If the pointer is NULL, memory for a
 scalar result will be allocated on the heap.
 @param[in]                accept_string
 if true, accept MySQL strings as JSON strings
 by converting them to UTF8, else emit an error
 @returns false if we found a value or NULL, true otherwise
 */
bool get_json_atom_wrapper(Item **args, uint arg_idx,
                           const char *calling_function, String *value,
                           String *tmp, Json_wrapper *wr,
                           Json_scalar_holder *scalar, bool accept_string);

/**
 Check a non-empty val for character set. If it has character set
 my_charset_binary, signal error and return false. Else, try to convert to
 my_charset_utf8mb4_binary. If this fails, signal error and return true, else
 return false.
 
 @param[in]     val       the string to be checked
 @param[in,out] buf       buffer to hold the converted string
 @param[out]    resptr    the resulting, possibly converted string,
 only set if no error
 @param[out]    reslength the length of resptr
 @param[in]     require_string
 If true, give error messages if binary string. If we
 see a conversion error (space), we give error
 notwithstanding this parameter value
 
 @returns True if the string could not be converted. False on success.
 */
bool ensure_utf8mb4(String *val,
                    String *buf,
                    const char **resptr,
                    size_t *reslength,
                    bool require_string);

/**
 Create a new Json_scalar_holder instance.
 */
Json_scalar_holder *create_json_scalar_holder();

/**
 Destroy a Json_scalar_holder instance.
 */
void delete_json_scalar_holder(Json_scalar_holder *holder);

/**
 Get a pointer to the Json_scalar object contained in a Json_scalar_holder.
 @param[in] holder  the holder object
 @return a pointer to a Json_scalar, or NULL if the holder is empty
 */
Json_scalar *get_json_scalar_from_holder(Json_scalar_holder *holder);

/**
 Represents the JSON function JSON_VALID( <value> )
 */
class Item_func_json_valid :public Item_int_func
{
    String m_value;
public:
    Item_func_json_valid(Item *a) : Item_int_func(a)
    {}
    
    const char *func_name() const
    {
        return "json_valid";
    }
    
    bool is_bool_func()
    {
        return 1;
    }
    
    longlong val_int();
    
    void fix_length_and_dec()
    {
        maybe_null= true;
    }
};

/**
 Represents the JSON function JSON_CONTAINS()
 */
class Item_func_json_contains :public Item_int_func
{
    String m_doc_value;
//    Json_path_cache m_path_cache;
    
public:
    Item_func_json_contains(THD *thd, List<Item> a)
    : Item_int_func(a)
//    , m_path_cache(thd, arg_count)
    {}
    
    const char *func_name() const
    {
        return "json_contains";
    }
    
    bool is_bool_func()
    {
        return 1;
    }
    
    longlong val_int();
    
    void fix_length_and_dec()
    {
        maybe_null= true;
    }
    
    /** Cleanup between executions of the statement */
    void cleanup();
};

/**
 Represents the JSON function JSON_CONTAINS_PATH()
 */
class Item_func_json_contains_path :public Item_int_func
{
    String m_doc_value;
    String m_one_or_all_value;
    enum_one_or_all_type m_cached_ooa;
    
    // Cache for constant path expressions
//    Json_path_cache m_path_cache;
    
public:
    Item_func_json_contains_path(THD *thd, List<Item> a)
    : Item_int_func(a),
    m_cached_ooa(ooa_uninitialized)
//    , m_path_cache(thd, arg_count)
    {}
    
    const char *func_name() const
    {
        return "json_contains_path";
    }
    
    bool is_bool_func()
    {
        return 1;
    }
    
    longlong val_int();
    
    void fix_length_and_dec()
    {
        maybe_null= true;
    }
    
    /** Cleanup between executions of the statement */
    void cleanup();
};

/**
 Represents the JSON function JSON_TYPE
 */
class Item_func_json_type :public Item_str_func
{
    String m_value;
public:
    Item_func_json_type(Item *a) : Item_str_func(a)
    {}
    
    const char *func_name() const
    {
        return "json_type";
    }
    
    void fix_length_and_dec()
    {
        maybe_null= true;
        m_value.set_charset(&my_charset_utf8mb4_bin);
        fix_length_and_charset(Json_dom::typelit_max_length, &my_charset_utf8mb4_bin);
    };
    
    String *val_str(String *);
};

/**
 Represents a "CAST( <value> AS JSON )" coercion.
 */
class Item_json_typecast :public Item_json_func
{
public:
    Item_json_typecast(THD *thd, Item *a) : Item_json_func(thd, a)
    {}
    
    void print(String *str, enum_query_type query_type);
    const char *func_name() const { return "cast_as_json"; }
    const char *cast_type() const { return "json"; }
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_LENGTH()
 */
class Item_func_json_length :public Item_int_func
{
    String m_doc_value;
    
    // Cache for constant path expressions
//    Json_path_cache m_path_cache;
    
public:
    Item_func_json_length(THD *thd, Item *a)
    : Item_int_func(a)
//    , m_path_cache(thd, 1)
    {}
    
    Item_func_json_length(THD *thd, Item *a, Item *b)
    : Item_int_func(a, b)
//    , m_path_cache(thd, 2)
    {}
    
    void fix_length_and_dec()
    {
        maybe_null= true;
    }
    
    const char *func_name() const
    {
        return "json_length";
    }
    
    longlong val_int();
    
    /** Cleanup between executions of the statement */
    void cleanup();
};

/**
 Represents the JSON function JSON_DEPTH()
 */
class Item_func_json_depth :public Item_int_func
{
    String m_doc_value;
    
public:
    Item_func_json_depth(Item *a)
    : Item_int_func(a)
    {}
    
    const char *func_name() const
    {
        return "json_depth";
    }
    
    longlong val_int();
};

/**
 Represents the JSON function JSON_KEYS()
 */
class Item_func_json_keys :public Item_json_func
{
    String m_doc_value;
    
public:
    Item_func_json_keys(THD *thd, Item *a)
    : Item_json_func(thd, a)
    {}
    
    Item_func_json_keys(THD *thd, Item *a, Item *b)
    : Item_json_func(thd, a, b)
    {}
    
    const char *func_name() const
    {
        return "json_keys";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_EXTRACT()
 */
class Item_func_json_extract :public Item_json_func
{
    String m_doc_value;
    
public:
    Item_func_json_extract(THD *thd, List<Item> a)
    : Item_json_func(thd, a)
    {}
    
    Item_func_json_extract(THD *thd, Item *a, Item *b)
    : Item_json_func(thd, a, b)
    {}
    
    const char *func_name() const
    {
        return "json_extract";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_ARRAY_APPEND()
 */
class Item_func_json_array_append :public Item_json_func
{
    String m_doc_value;
    
public:
    Item_func_json_array_append(THD *thd, List<Item> a)
    : Item_json_func(thd,  a)
    {}
    
    const char *func_name() const
    {
        return "json_array_append";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_INSERT()
 */
class Item_func_json_insert :public Item_json_func
{
    String m_doc_value;
    Json_path_clone m_path;
    
public:
    Item_func_json_insert(THD *thd, List<Item> a)
    : Item_json_func(thd, a)
    {}
    
    const char *func_name() const
    {
        return "json_insert";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_ARRAY_INSERT()
 */
class Item_func_json_array_insert :public Item_json_func
{
    String m_doc_value;
    Json_path_clone m_path;
    
public:
    Item_func_json_array_insert(THD *thd, List<Item> a)
    : Item_json_func(thd, a)
    {}
    
    const char *func_name() const
    {
        return "json_array_insert";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Common base class for JSON_SET() and JSON_REPLACE().
 */
class Item_func_json_set_replace :public Item_json_func
{
    /// True if this is JSON_SET, false if it is JSON_REPLACE.
    const bool m_json_set;
    String m_doc_value;
    Json_path_clone m_path;
    
protected:
    Item_func_json_set_replace(THD *thd, List<Item> a, bool json_set)
    : Item_json_func(thd, a), m_json_set(json_set)
    {}
    
public:
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_SET()
 */
class Item_func_json_set :public Item_func_json_set_replace
{
public:
    Item_func_json_set(THD *thd, List<Item> a)
    : Item_func_json_set_replace(thd, a, true)
    {}
    
    const char *func_name() const
    {
        return "json_set";
    }
};

/**
 Represents the JSON function JSON_REPLACE()
 */
class Item_func_json_replace :public Item_func_json_set_replace
{
public:
    Item_func_json_replace(THD *thd, List<Item> a)
    : Item_func_json_set_replace(thd, a, false)
    {}
    
    const char *func_name() const
    {
        return "json_replace";
    }
};

/**
 Represents the JSON function JSON_ARRAY()
 */
class Item_func_json_array :public Item_json_func
{
public:
    Item_func_json_array(THD *thd, List<Item> a)
    : Item_json_func(thd, a)
    {}
    
    const char *func_name() const
    {
        return "json_array";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_OBJECT()
 */
class Item_func_json_row_object :public Item_json_func
{
    String tmp_key_value;
public:
    Item_func_json_row_object(THD *thd, List<Item> a)
    : Item_json_func(thd, a)
    {}
    
    const char *func_name() const
    {
        return "json_object";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_SEARCH()
 */
class Item_func_json_search :public Item_json_func
{
    String m_doc_value;
    String m_one_or_all_value;
    String m_search_string_value;
    enum_one_or_all_type m_cached_ooa;
    String m_escape;
    
    // LIKE machinery
    Item_string *m_source_string_item;
    Item_func_like *m_like_node;
public:
    /**
     Construct a JSON_SEARCH() node.
     
     @param[in] pos Parser position
     @param[in] a Nodes which must be fixed (i.e. bound/resolved)
     
     @returns a JSON_SEARCH() node.
     */
    Item_func_json_search(THD *thd, List<Item> a)
    : Item_json_func(thd, a),
    m_cached_ooa(ooa_uninitialized)
    {}
    
    
    const char *func_name() const
    {
        return "json_search";
    }
    
    bool val_json(Json_wrapper *wr);
    
    /**
     Bind logic for the JSON_SEARCH() node.
     */
    bool fix_fields(THD *, Item **);
    
    /** Cleanup between executions of the statement */
    void cleanup();
};

/**
 Represents the JSON function JSON_REMOVE()
 */
class Item_func_json_remove :public Item_json_func
{
    String m_doc_value;
    
public:
    Item_func_json_remove(THD *thd, List<Item> a);
    
    const char *func_name() const
    {
        return "json_remove";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_MERGE()
 */
class Item_func_json_merge :public Item_json_func
{
public:
    Item_func_json_merge(THD *thd, List<Item> a)
    : Item_json_func(thd, a)
    {}
    
    const char *func_name() const
    {
        return "json_merge";
    }
    
    bool val_json(Json_wrapper *wr);
};

/**
 Represents the JSON function JSON_QUOTE()
 */
class Item_func_json_quote :public Item_str_func
{
    String m_value;
public:
    Item_func_json_quote(List<Item> a)
    : Item_str_func(a)
    {}
    
    const char *func_name() const
    {
        return "json_quote";
    }
    
    void fix_length_and_dec()
    {
        maybe_null= true;
        
        /*
         Any interior character could be replaced by a 6 character
         escape sequence. Plus we will add 2 framing quote characters.
         */
        uint32 max_char_length= (6 * args[0]->max_length) + 2;
        fix_length_and_charset(max_char_length, &my_charset_utf8mb4_bin);
    };
    
    String *val_str(String *tmpspace);
};

/**
 Represents the JSON function JSON_UNQUOTE()
 */
class Item_func_json_unquote :public Item_str_func
{
    String m_value;
public:
    Item_func_json_unquote(List<Item> a)
    : Item_str_func(a)
    {}
    
    Item_func_json_unquote(Item *a)
    : Item_str_func(a)
    {}
    
    const char *func_name() const
    {
        return "json_unquote";
    }
    
    void fix_length_and_dec()
    {
        maybe_null= true;
        fix_length_and_charset(args[0]->max_length, &my_charset_utf8mb4_bin);
    };
    
    String *val_str(String *str);
};

/**
 Turn a GEOMETRY value into a JSON value per the GeoJSON specification revison 1.0.
 This method is implemented in item_geofunc.cc.
 
 @param[in/out] wr The wrapper to be stuffed with the JSON value.
 @param[in/]    geometry_arg The source GEOMETRY value.
 @param[in]     calling_function Name of user-invoked function (for errors)
 @param[in]     max_decimal_digits See the user documentation for ST_AsGeoJSON.
 @param[in]     add_bounding_box See the user documentation for ST_AsGeoJSON.
 @param[in]     add_short_crs_urn See the user documentation for ST_AsGeoJSON.
 @param[in]     add_long_crs_urn See the user documentation for ST_AsGeoJSON.
 @param[in/out] geometry_srid Spatial Reference System Identifier to be filled in.
 
 @return false if the conversion succeeds, true otherwise
 */
bool geometry_to_json(Json_wrapper *wr, Item *geometry_arg,
                      const char *calling_function,
                      int max_decimal_digits,
                      bool add_bounding_box,
                      bool add_short_crs_urn,
                      bool add_long_crs_urn,
                      uint32 *geometry_srid);

#endif /* ITEM_STRFUNC_INCLUDED */
