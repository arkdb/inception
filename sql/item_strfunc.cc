/*
   Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/


/**
  @file

  @brief
  This file defines all string functions

  @warning
    Some string functions don't always put and end-null on a String.
    (This shouldn't be needed)
*/

/* May include caustic 3rd-party defs. Use early, so it can override nothing. */
#include "sha2.h"
#include "my_global.h"                          // HAVE_*

#include "sql_priv.h"
/*
  It is necessary to include set_var.h instead of item.h because there
  are dependencies on include order for set_var.h and item.h. This
  will be resolved later.
*/
#include "sql_class.h"                          // set_var.h: THD
#include "set_var.h"
#include "mysqld.h"                             // LOCK_uuid_generator
#include "sql_acl.h"                            // SUPER_ACL
#include "des_key_file.h"       // st_des_keyschedule, st_des_keyblock
#include "password.h"           // my_make_scrambled_password,
                                // my_make_scrambled_password_323

#include "sql_time.h"
#include "json_dom.h"
#include "template_utils.h"
#include "crypt_genhash_impl.h"
#include <m_ctype.h>
#include <base64.h>
#include "my_md5.h"
#include "sha1.h"
#include "my_aes.h"
#include <zlib.h>
C_MODE_START
#include "../mysys/my_static.h"			// For soundex_map
C_MODE_END

using std::min;
using std::max;

/*
  For the Items which have only val_str_ascii() method
  and don't have their own "native" val_str(),
  we provide a "wrapper" method to convert from ASCII
  to Item character set when it's necessary.
  Conversion happens only in case of "tricky" Item character set (e.g. UCS2).
  Normally conversion does not happen, and val_str_ascii() is immediately
  returned instead.
*/
String *Item_str_func::val_str_from_val_str_ascii(String *str, String *str2)
{
  DBUG_ASSERT(fixed == 1);

  if (!(collation.collation->state & MY_CS_NONASCII))
  {
    String *res= val_str_ascii(str);
    if (res)
      res->set_charset(collation.collation);
    return res;
  }
  
  DBUG_ASSERT(str != str2);
  
  uint errors;
  String *res= val_str_ascii(str);
  if (!res)
    return 0;
  
  if ((null_value= str2->copy(res->ptr(), res->length(),
                              &my_charset_latin1, collation.collation,
                              &errors)))
    return 0;
  
  return str2;
}

bool Item_str_func::fix_fields(THD *thd, Item **ref)
{
  bool res= Item_func::fix_fields(thd, ref);
  /*
    In Item_str_func::check_well_formed_result() we may set null_value
    flag on the same condition as in test() below.
  */
  maybe_null= (maybe_null || thd->is_strict_mode());
  return res;
}


my_decimal *Item_str_func::val_decimal(my_decimal *decimal_value)
{
  DBUG_ASSERT(fixed == 1);
  char buff[64];
  String *res, tmp(buff,sizeof(buff), &my_charset_bin);
  res= val_str(&tmp);
  if (!res)
    return 0;
  (void)str2my_decimal(E_DEC_FATAL_ERROR, (char*) res->ptr(),
                       res->length(), res->charset(), decimal_value);
  return decimal_value;
}


double Item_str_func::val_real()
{
  DBUG_ASSERT(fixed == 1);
  int err_not_used;
  char *end_not_used, buff[64];
  String *res, tmp(buff,sizeof(buff), &my_charset_bin);
  res= val_str(&tmp);
  return res ? my_strntod(res->charset(), (char*) res->ptr(), res->length(),
			  &end_not_used, &err_not_used) : 0.0;
}


longlong Item_str_func::val_int()
{
  DBUG_ASSERT(fixed == 1);
  int err;
  char buff[22];
  String *res, tmp(buff,sizeof(buff), &my_charset_bin);
  res= val_str(&tmp);
  return (res ?
	  my_strntoll(res->charset(), res->ptr(), res->length(), 10, NULL,
		      &err) :
	  (longlong) 0);
}


String *Item_func_md5::val_str_ascii(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String * sptr= args[0]->val_str(str);
  str->set_charset(&my_charset_bin);
  if (sptr)
  {
    uchar digest[MD5_HASH_SIZE];
	DBUG_ASSERT(0);
    null_value=0;
//     compute_md5_hash((char *) digest, (const char *) sptr->ptr(), sptr->length());
    if (str->alloc(32))				// Ensure that memory is free
    {
      null_value=1;
      return 0;
    }
    array_to_hex((char *) str->ptr(), digest, MD5_HASH_SIZE);
    str->length((uint) 32);
    return str;
  }
  null_value=1;
  return 0;
}


void Item_func_md5::fix_length_and_dec()
{
  /*
    The MD5() function treats its parameter as being a case sensitive. Thus
    we set binary collation on it so different instances of MD5() will be
    compared properly.
  */
  args[0]->collation.set(
      get_charset_by_csname(args[0]->collation.collation->csname,
                            MY_CS_BINSORT,MYF(0)), DERIVATION_COERCIBLE);
  fix_length_and_charset(32, default_charset());
}


String *Item_func_sha::val_str_ascii(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String * sptr= args[0]->val_str(str);
  str->set_charset(&my_charset_bin);
  if (sptr)  /* If we got value different from NULL */
  {
    /* Temporary buffer to store 160bit digest */
    uint8 digest[SHA1_HASH_SIZE];
    //compute_sha1_hash(digest, (const char *) sptr->ptr(), sptr->length());
    /* Ensure that memory is free */
    if (!(str->alloc(SHA1_HASH_SIZE * 2)))
    {
      array_to_hex((char *) str->ptr(), digest, SHA1_HASH_SIZE);
      str->length((uint)  SHA1_HASH_SIZE*2);
      null_value=0;
      return str;
    }
  }
  null_value=1;
  return 0;
}

void Item_func_sha::fix_length_and_dec()
{
  /*
    The SHA() function treats its parameter as being a case sensitive. Thus
    we set binary collation on it so different instances of MD5() will be
    compared properly.
  */
  args[0]->collation.set(
      get_charset_by_csname(args[0]->collation.collation->csname,
                            MY_CS_BINSORT,MYF(0)), DERIVATION_COERCIBLE);
  // size of hex representation of hash
  fix_length_and_charset(SHA1_HASH_SIZE * 2, default_charset());
}

String *Item_func_sha2::val_str_ascii(String *str)
{
  DBUG_ASSERT(fixed == 1);
#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
  unsigned char digest_buf[SHA512_DIGEST_LENGTH];
  String *input_string;
  unsigned char *input_ptr;
  size_t input_len;
  uint digest_length= 0;

  str->set_charset(&my_charset_bin);

  input_string= args[0]->val_str(str);
  if (input_string == NULL)
  {
    null_value= TRUE;
    return (String *) NULL;
  }

  null_value= args[0]->null_value;
  if (null_value)
    return (String *) NULL;

  input_ptr= (unsigned char *) input_string->ptr();
  input_len= input_string->length();

  switch ((uint) args[1]->val_int()) {
#ifndef OPENSSL_NO_SHA512
  case 512:
    digest_length= SHA512_DIGEST_LENGTH;
    (void) SHA512(input_ptr, input_len, digest_buf);
    break;
  case 384:
    digest_length= SHA384_DIGEST_LENGTH;
    (void) SHA384(input_ptr, input_len, digest_buf);
    break;
#endif
#ifndef OPENSSL_NO_SHA256
  case 224:
    digest_length= SHA224_DIGEST_LENGTH;
    (void) SHA224(input_ptr, input_len, digest_buf);
    break;
  case 256:
  case 0: // SHA-256 is the default
    digest_length= SHA256_DIGEST_LENGTH;
    (void) SHA256(input_ptr, input_len, digest_buf);
    break;
#endif
  default:
    if (!args[1]->const_item())
      push_warning_printf(current_thd,
        Sql_condition::WARN_LEVEL_WARN,
        ER_WRONG_PARAMETERS_TO_NATIVE_FCT,
        ER(ER_WRONG_PARAMETERS_TO_NATIVE_FCT), "sha2");
    null_value= TRUE;
    return NULL;
  }

  /* 
    Since we're subverting the usual String methods, we must make sure that
    the destination has space for the bytes we're about to write.
  */
  str->realloc((uint) digest_length*2 + 1); /* Each byte as two nybbles */

  /* Convert the large number to a string-hex representation. */
  array_to_hex((char *) str->ptr(), digest_buf, digest_length);

  /* We poked raw bytes in.  We must inform the the String of its length. */
  str->length((uint) digest_length*2); /* Each byte as two nybbles */

  null_value= FALSE;
  return str;

#else
  push_warning_printf(current_thd,
    Sql_condition::WARN_LEVEL_WARN,
    ER_FEATURE_DISABLED,
    ER(ER_FEATURE_DISABLED),
    "sha2", "--with-ssl");
  null_value= TRUE;
  return (String *) NULL;
#endif /* defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY) */
}


void Item_func_sha2::fix_length_and_dec()
{
  maybe_null = 1;
  max_length = 0;

#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
  int sha_variant= args[1]->const_item() ? args[1]->val_int() : 512;

  switch (sha_variant) {
#ifndef OPENSSL_NO_SHA512
  case 512:
    fix_length_and_charset(SHA512_DIGEST_LENGTH * 2, default_charset());
    break;
  case 384:
    fix_length_and_charset(SHA384_DIGEST_LENGTH * 2, default_charset());
    break;
#endif
#ifndef OPENSSL_NO_SHA256
  case 256:
  case 0: // SHA-256 is the default
    fix_length_and_charset(SHA256_DIGEST_LENGTH * 2, default_charset());
    break;
  case 224:
    fix_length_and_charset(SHA224_DIGEST_LENGTH * 2, default_charset());
    break;
#endif
  default:
    push_warning_printf(current_thd,
      Sql_condition::WARN_LEVEL_WARN,
      ER_WRONG_PARAMETERS_TO_NATIVE_FCT,
      ER(ER_WRONG_PARAMETERS_TO_NATIVE_FCT), "sha2");
  }

  /*
    The SHA2() function treats its parameter as being a case sensitive.
    Thus we set binary collation on it so different instances of SHA2()
    will be compared properly.
  */

  args[0]->collation.set(
      get_charset_by_csname(
        args[0]->collation.collation->csname,
        MY_CS_BINSORT,
        MYF(0)),
      DERIVATION_COERCIBLE);
#else
  push_warning_printf(current_thd,
    Sql_condition::WARN_LEVEL_WARN,
    ER_FEATURE_DISABLED,
    ER(ER_FEATURE_DISABLED),
    "sha2", "--with-ssl");
#endif /* defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY) */
}

/* Implementation of AES encryption routines */

String *Item_func_aes_encrypt::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  char key_buff[80];
  String tmp_key_value(key_buff, sizeof(key_buff), system_charset_info);
  String *sptr= args[0]->val_str(str);			// String to encrypt
  String *key=  args[1]->val_str(&tmp_key_value);	// key
  int aes_length;
  if (sptr && key) // we need both arguments to be not NULL
  {
    null_value=0;
//     aes_length=my_aes_get_size(sptr->length()); // Calculate result length

//     if (!str_value.alloc(aes_length))		// Ensure that memory is free
//     {
//       // finally encrypt directly to allocated buffer.
//       if (my_aes_encrypt(sptr->ptr(),sptr->length(), (char*) str_value.ptr(),
// 			 key->ptr(), key->length()) == aes_length)
//       {
// 	// We got the expected result length
// 	str_value.length((uint) aes_length);
// 	return &str_value;
//       }
//     }
  }
  null_value=1;
  return 0;
}


void Item_func_aes_encrypt::fix_length_and_dec()
{
  max_length=0;
}


String *Item_func_aes_decrypt::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  char key_buff[80];
  String tmp_key_value(key_buff, sizeof(key_buff), system_charset_info);
  String *sptr, *key;
  DBUG_ENTER("Item_func_aes_decrypt::val_str");

  sptr= args[0]->val_str(str);			// String to decrypt
  key=  args[1]->val_str(&tmp_key_value);	// Key
  if (sptr && key)  			// Need to have both arguments not NULL
  {
    null_value=0;
//     if (!str_value.alloc(sptr->length()))  // Ensure that memory is free
//     {
//       // finally decrypt directly to allocated buffer.
//       int length;
//       length=my_aes_decrypt(sptr->ptr(), sptr->length(),
// 			    (char*) str_value.ptr(),
//                             key->ptr(), key->length());
//       if (length >= 0)  // if we got correct data data
//       {
//         str_value.length((uint) length);
//         DBUG_RETURN(&str_value);
//       }
//     }
  }
  // Bad parameters. No memory or bad data will all go here
  null_value=1;
  DBUG_RETURN(0);
}


void Item_func_aes_decrypt::fix_length_and_dec()
{
   max_length=args[0]->max_length;
   maybe_null= 1;
}


void Item_func_to_base64::fix_length_and_dec()
{
  maybe_null= args[0]->maybe_null;
  collation.set(default_charset(), DERIVATION_COERCIBLE, MY_REPERTOIRE_ASCII);
  if (args[0]->max_length > (uint) base64_encode_max_arg_length())
  {
    maybe_null= 1;
    fix_char_length_ulonglong((ulonglong) base64_encode_max_arg_length());
  }
  else
  {
    int length= base64_needed_encoded_length((int) args[0]->max_length);
    DBUG_ASSERT(length > 0);
    fix_char_length_ulonglong((ulonglong) length - 1);
  }
}


String *Item_func_to_base64::val_str_ascii(String *str)
{
  String *res= args[0]->val_str(str);
  bool too_long= false;
  int length;
  if (!res ||
      res->length() > (uint) base64_encode_max_arg_length() ||
      (too_long=
       ((uint) (length= base64_needed_encoded_length((int) res->length())) >
        current_thd->variables.max_allowed_packet)) ||
      tmp_value.alloc((uint) length))
  {
    null_value= 1; // NULL input, too long input, or OOM.
    if (too_long)
    {
      push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                          ER_WARN_ALLOWED_PACKET_OVERFLOWED,
                          ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED), func_name(),
                          current_thd->variables.max_allowed_packet);
    }
    return 0;
  }
  base64_encode(res->ptr(), (int) res->length(), (char*) tmp_value.ptr());
  DBUG_ASSERT(length > 0);
  tmp_value.length((uint) length - 1); // Without trailing '\0'
  null_value= 0;
  return &tmp_value;
}


void Item_func_from_base64::fix_length_and_dec()
{
  if (args[0]->max_length > (uint) base64_decode_max_arg_length())
  {
    fix_char_length_ulonglong((ulonglong) base64_decode_max_arg_length());
  }
  else
  {
    int length= base64_needed_decoded_length((int) args[0]->max_length);
    fix_char_length_ulonglong((ulonglong) length);
  }
  maybe_null= 1; // Can be NULL, e.g. in case of badly formed input string
}


String *Item_func_from_base64::val_str(String *str)
{
  String *res= args[0]->val_str_ascii(str);
  bool too_long= false;
  int length;
  const char *end_ptr;

  if (!res ||
      res->length() > (uint) base64_decode_max_arg_length() ||
      (too_long=
       ((uint) (length= base64_needed_decoded_length((int) res->length())) >
        current_thd->variables.max_allowed_packet)) ||
      tmp_value.alloc((uint) length) ||
      (length= base64_decode(res->ptr(), (int) res->length(),
                             (char *) tmp_value.ptr(), &end_ptr, 0)) < 0 ||
      end_ptr < res->ptr() + res->length())
  {
    null_value= 1; // NULL input, too long input, OOM, or badly formed input
    if (too_long)
    {
      push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                          ER_WARN_ALLOWED_PACKET_OVERFLOWED,
                          ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED), func_name(),
                          current_thd->variables.max_allowed_packet);
    }
    return 0;
  }
  tmp_value.length((uint) length);
  null_value= 0;
  return &tmp_value;
}


/**
  Concatenate args with the following premises:
  If only one arg (which is ok), return value of arg;
  Don't reallocate val_str() if not absolute necessary.
*/

String *Item_func_concat::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res,*res2,*use_as_buff;
  uint i;
  bool is_const= 0;

  null_value=0;
  if (!(res=args[0]->val_str(str)))
    goto null;
  use_as_buff= &tmp_value;
  /* Item_subselect in --ps-protocol mode will state it as a non-const */
  is_const= args[0]->const_item() || !args[0]->used_tables();
  for (i=1 ; i < arg_count ; i++)
  {
    if (res->length() == 0)
    {
      if (!(res=args[i]->val_str(str)))
	goto null;
      /*
       CONCAT accumulates its result in the result of its the first
       non-empty argument. Because of this we need is_const to be 
       evaluated only for it.
      */
      is_const= args[i]->const_item() || !args[i]->used_tables();
    }
    else
    {
      if (!(res2=args[i]->val_str(use_as_buff)))
	goto null;
      if (res2->length() == 0)
	continue;
      if (res->length()+res2->length() >
	  current_thd->variables.max_allowed_packet)
      {
	push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			    ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			    ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED), func_name(),
			    current_thd->variables.max_allowed_packet);
	goto null;
      }
      if (!is_const && res->alloced_length() >= res->length()+res2->length())
      {						// Use old buffer
	res->append(*res2);
      }
      else if (str->alloced_length() >= res->length()+res2->length())
      {
	if (str->ptr() == res2->ptr())
	  str->replace(0,0,*res);
	else
	{
	  str->copy(*res);
	  str->append(*res2);
	}
        res= str;
        use_as_buff= &tmp_value;
      }
      else if (res == &tmp_value)
      {
	if (res->append(*res2))			// Must be a blob
	  goto null;
      }
      else if (res2 == &tmp_value)
      {						// This can happend only 1 time
	if (tmp_value.replace(0,0,*res))
	  goto null;
	res= &tmp_value;
	use_as_buff=str;			// Put next arg here
      }
      else if (tmp_value.is_alloced() && res2->ptr() >= tmp_value.ptr() &&
	       res2->ptr() <= tmp_value.ptr() + tmp_value.alloced_length())
      {
	/*
	  This happens really seldom:
	  In this case res2 is sub string of tmp_value.  We will
	  now work in place in tmp_value to set it to res | res2
	*/
	/* Chop the last characters in tmp_value that isn't in res2 */
	tmp_value.length((uint32) (res2->ptr() - tmp_value.ptr()) +
			 res2->length());
	/* Place res2 at start of tmp_value, remove chars before res2 */
	if (tmp_value.replace(0,(uint32) (res2->ptr() - tmp_value.ptr()),
			      *res))
	  goto null;
	res= &tmp_value;
	use_as_buff=str;			// Put next arg here
      }
      else
      {						// Two big const strings
        /*
          NOTE: We should be prudent in the initial allocation unit -- the
          size of the arguments is a function of data distribution, which
          can be any. Instead of overcommitting at the first row, we grow
          the allocated amount by the factor of 2. This ensures that no
          more than 25% of memory will be overcommitted on average.
        */

        uint concat_len= res->length() + res2->length();

        if (tmp_value.alloced_length() < concat_len)
        {
          if (tmp_value.alloced_length() == 0)
          {
            if (tmp_value.alloc(concat_len))
              goto null;
          }
          else
          {
            uint new_len = max(tmp_value.alloced_length() * 2, concat_len);

            if (tmp_value.realloc(new_len))
              goto null;
          }
        }

	if (tmp_value.copy(*res) || tmp_value.append(*res2))
	  goto null;

	res= &tmp_value;
	use_as_buff=str;
      }
      is_const= 0;
    }
  }
  res->set_charset(collation.collation);
  return res;

null:
  null_value=1;
  return 0;
}


void Item_func_concat::fix_length_and_dec()
{
  ulonglong char_length= 0;

  if (agg_arg_charsets_for_string_result(collation, args, arg_count))
    return;

  for (uint i=0 ; i < arg_count ; i++)
    char_length+= args[i]->max_char_length();

  fix_char_length_ulonglong(char_length);
}

/**
  @details
  Function des_encrypt() by tonu@spam.ee & monty
  Works only if compiled with OpenSSL library support.
  @return
    A binary string where first character is CHAR(128 | key-number).
    If one uses a string key key_number is 127.
    Encryption result is longer than original by formula:
  @code new_length= org_length + (8-(org_length % 8))+1 @endcode
*/

String *Item_func_des_encrypt::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
  uint code= ER_WRONG_PARAMETERS_TO_PROCEDURE;
  DES_cblock ivec;
  struct st_des_keyblock keyblock;
  struct st_des_keyschedule keyschedule;
  const char *append_str="********";
  uint key_number, res_length, tail;
  String *res= args[0]->val_str(str);

  if ((null_value= args[0]->null_value))
    return 0;                                   // ENCRYPT(NULL) == NULL
  if ((res_length=res->length()) == 0)
    return make_empty_result();
  if (arg_count == 1)
  {
    /* Protect against someone doing FLUSH DES_KEY_FILE */
    mysql_mutex_lock(&LOCK_des_key_file);
    keyschedule= des_keyschedule[key_number=des_default_key];
    mysql_mutex_unlock(&LOCK_des_key_file);
  }
  else if (args[1]->result_type() == INT_RESULT)
  {
    key_number= (uint) args[1]->val_int();
    if (key_number > 9)
      goto error;
    mysql_mutex_lock(&LOCK_des_key_file);
    keyschedule= des_keyschedule[key_number];
    mysql_mutex_unlock(&LOCK_des_key_file);
  }
  else
  {
    String *keystr=args[1]->val_str(&tmp_value);
    if (!keystr)
      goto error;
    key_number=127;				// User key string

    /* We make good 24-byte (168 bit) key from given plaintext key with MD5 */
    memset(&ivec, 0, sizeof(ivec));
    EVP_BytesToKey(EVP_des_ede3_cbc(),EVP_md5(),NULL,
		   (uchar*) keystr->ptr(), (int) keystr->length(),
		   1, (uchar*) &keyblock,ivec);
    DES_set_key_unchecked(&keyblock.key1,&keyschedule.ks1);
    DES_set_key_unchecked(&keyblock.key2,&keyschedule.ks2);
    DES_set_key_unchecked(&keyblock.key3,&keyschedule.ks3);
  }

  /*
     The problem: DES algorithm requires original data to be in 8-bytes
     chunks. Missing bytes get filled with '*'s and result of encryption
     can be up to 8 bytes longer than original string. When decrypted,
     we do not know the size of original string :(
     We add one byte with value 0x1..0x8 as the last byte of the padded
     string marking change of string length.
  */

  tail= 8 - (res_length % 8);                   // 1..8 marking extra length
  res_length+=tail;
  tmp_arg.realloc(res_length);
  tmp_arg.length(0);
  tmp_arg.append(res->ptr(), res->length());
  code= ER_OUT_OF_RESOURCES;
  if (tmp_arg.append(append_str, tail) || tmp_value.alloc(res_length+1))
    goto error;
  tmp_arg[res_length-1]=tail;                   // save extra length
  tmp_value.realloc(res_length+1);
  tmp_value.length(res_length+1);
  tmp_value.set_charset(&my_charset_bin);
  tmp_value[0]=(char) (128 | key_number);
  // Real encryption
  memset(&ivec, 0, sizeof(ivec));
  DES_ede3_cbc_encrypt((const uchar*) (tmp_arg.ptr()),
		       (uchar*) (tmp_value.ptr()+1),
		       res_length,
		       &keyschedule.ks1,
		       &keyschedule.ks2,
		       &keyschedule.ks3,
		       &ivec, TRUE);
  return &tmp_value;

error:
  push_warning_printf(current_thd,Sql_condition::WARN_LEVEL_WARN,
                          code, ER(code),
                          "des_encrypt");
#else
  push_warning_printf(current_thd,Sql_condition::WARN_LEVEL_WARN,
                      ER_FEATURE_DISABLED, ER(ER_FEATURE_DISABLED),
                      "des_encrypt", "--with-ssl");
#endif /* defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY) */
  null_value=1;
  return 0;
}


String *Item_func_des_decrypt::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
  uint code= ER_WRONG_PARAMETERS_TO_PROCEDURE;
  DES_cblock ivec;
  struct st_des_keyblock keyblock;
  struct st_des_keyschedule keyschedule;
  String *res= args[0]->val_str(str);
  uint length,tail;

  if ((null_value= args[0]->null_value))
    return 0;
  length= res->length();
  if (length < 9 || (length % 8) != 1 || !((*res)[0] & 128))
    return res;				// Skip decryption if not encrypted

  if (arg_count == 1)			// If automatic uncompression
  {
    uint key_number=(uint) (*res)[0] & 127;
    // Check if automatic key and that we have privilege to uncompress using it
    if (!(current_thd->security_ctx->master_access & SUPER_ACL) ||
        key_number > 9)
      goto error;

    mysql_mutex_lock(&LOCK_des_key_file);
    keyschedule= des_keyschedule[key_number];
    mysql_mutex_unlock(&LOCK_des_key_file);
  }
  else
  {
    // We make good 24-byte (168 bit) key from given plaintext key with MD5
    String *keystr=args[1]->val_str(&tmp_value);
    if (!keystr)
      goto error;

    memset(&ivec, 0, sizeof(ivec));
    EVP_BytesToKey(EVP_des_ede3_cbc(),EVP_md5(),NULL,
		   (uchar*) keystr->ptr(),(int) keystr->length(),
		   1,(uchar*) &keyblock,ivec);
    // Here we set all 64-bit keys (56 effective) one by one
    DES_set_key_unchecked(&keyblock.key1,&keyschedule.ks1);
    DES_set_key_unchecked(&keyblock.key2,&keyschedule.ks2);
    DES_set_key_unchecked(&keyblock.key3,&keyschedule.ks3);
  }
  code= ER_OUT_OF_RESOURCES;
  if (tmp_value.alloc(length-1))
    goto error;

  memset(&ivec, 0, sizeof(ivec));
  DES_ede3_cbc_encrypt((const uchar*) res->ptr()+1,
		       (uchar*) (tmp_value.ptr()),
		       length-1,
		       &keyschedule.ks1,
		       &keyschedule.ks2,
		       &keyschedule.ks3,
		       &ivec, FALSE);
  /* Restore old length of key */
  if ((tail=(uint) (uchar) tmp_value[length-2]) > 8)
    goto wrong_key;				     // Wrong key
  tmp_value.length(length-1-tail);
  tmp_value.set_charset(&my_charset_bin);
  return &tmp_value;

error:
  push_warning_printf(current_thd,Sql_condition::WARN_LEVEL_WARN,
                          code, ER(code),
                          "des_decrypt");
wrong_key:
#else
  push_warning_printf(current_thd,Sql_condition::WARN_LEVEL_WARN,
                      ER_FEATURE_DISABLED, ER(ER_FEATURE_DISABLED),
                      "des_decrypt", "--with-ssl");
#endif /* defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY) */
  null_value=1;
  return 0;
}


/**
  concat with separator. First arg is the separator
  concat_ws takes at least two arguments.
*/

String *Item_func_concat_ws::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  char tmp_str_buff[10];
  String tmp_sep_str(tmp_str_buff, sizeof(tmp_str_buff),default_charset_info),
         *sep_str, *res, *res2,*use_as_buff;
  uint i;
  bool is_const= 0;

  null_value=0;
  if (!(sep_str= args[0]->val_str(&tmp_sep_str)))
    goto null;

  use_as_buff= &tmp_value;
  str->length(0);				// QQ; Should be removed
  res=str;

  // Skip until non-null argument is found.
  // If not, return the empty string
  for (i=1; i < arg_count; i++)
    if ((res= args[i]->val_str(str)))
    {
      is_const= args[i]->const_item() || !args[i]->used_tables();
      break;
    }

  if (i ==  arg_count)
    return make_empty_result();

  for (i++; i < arg_count ; i++)
  {
    if (!(res2= args[i]->val_str(use_as_buff)))
      continue;					// Skip NULL

    if (res->length() + sep_str->length() + res2->length() >
	current_thd->variables.max_allowed_packet)
    {
      push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			  ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			  ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED), func_name(),
			  current_thd->variables.max_allowed_packet);
      goto null;
    }
    if (!is_const && res->alloced_length() >=
	res->length() + sep_str->length() + res2->length())
    {						// Use old buffer
      res->append(*sep_str);			// res->length() > 0 always
      res->append(*res2);
    }
    else if (str->alloced_length() >=
	     res->length() + sep_str->length() + res2->length())
    {
      /* We have room in str;  We can't get any errors here */
      if (str->ptr() == res2->ptr())
      {						// This is quite uncommon!
	str->replace(0,0,*sep_str);
	str->replace(0,0,*res);
      }
      else
      {
	str->copy(*res);
	str->append(*sep_str);
	str->append(*res2);
      }
      res=str;
      use_as_buff= &tmp_value;
    }
    else if (res == &tmp_value)
    {
      if (res->append(*sep_str) || res->append(*res2))
	goto null; // Must be a blob
    }
    else if (res2 == &tmp_value)
    {						// This can happend only 1 time
      if (tmp_value.replace(0,0,*sep_str) || tmp_value.replace(0,0,*res))
	goto null;
      res= &tmp_value;
      use_as_buff=str;				// Put next arg here
    }
    else if (tmp_value.is_alloced() && res2->ptr() >= tmp_value.ptr() &&
	     res2->ptr() < tmp_value.ptr() + tmp_value.alloced_length())
    {
      /*
	This happens really seldom:
	In this case res2 is sub string of tmp_value.  We will
	now work in place in tmp_value to set it to res | sep_str | res2
      */
      /* Chop the last characters in tmp_value that isn't in res2 */
      tmp_value.length((uint32) (res2->ptr() - tmp_value.ptr()) +
		       res2->length());
      /* Place res2 at start of tmp_value, remove chars before res2 */
      if (tmp_value.replace(0,(uint32) (res2->ptr() - tmp_value.ptr()),
			    *res) ||
	  tmp_value.replace(res->length(),0, *sep_str))
	goto null;
      res= &tmp_value;
      use_as_buff=str;			// Put next arg here
    }
    else
    {						// Two big const strings
      /*
        NOTE: We should be prudent in the initial allocation unit -- the
        size of the arguments is a function of data distribution, which can
        be any. Instead of overcommitting at the first row, we grow the
        allocated amount by the factor of 2. This ensures that no more than
        25% of memory will be overcommitted on average.
      */

      uint concat_len= res->length() + sep_str->length() + res2->length();

      if (tmp_value.alloced_length() < concat_len)
      {
        if (tmp_value.alloced_length() == 0)
        {
          if (tmp_value.alloc(concat_len))
            goto null;
        }
        else
        {
          uint new_len = max(tmp_value.alloced_length() * 2, concat_len);

          if (tmp_value.realloc(new_len))
            goto null;
        }
      }

      if (tmp_value.copy(*res) ||
	  tmp_value.append(*sep_str) ||
	  tmp_value.append(*res2))
	goto null;
      res= &tmp_value;
      use_as_buff=str;
    }
  }
  res->set_charset(collation.collation);
  return res;

null:
  null_value=1;
  return 0;
}


void Item_func_concat_ws::fix_length_and_dec()
{
  ulonglong char_length;

  if (agg_arg_charsets_for_string_result(collation, args, arg_count))
    return;

  /*
     arg_count cannot be less than 2,
     it is done on parser level in sql_yacc.yy
     so, (arg_count - 2) is safe here.
  */
  char_length= (ulonglong) args[0]->max_char_length() * (arg_count - 2);
  for (uint i=1 ; i < arg_count ; i++)
    char_length+= args[i]->max_char_length();

  fix_char_length_ulonglong(char_length);
}


String *Item_func_reverse::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res = args[0]->val_str(str);
  char *ptr, *end, *tmp;

  if ((null_value=args[0]->null_value))
    return 0;
  /* An empty string is a special case as the string pointer may be null */
  if (!res->length())
    return make_empty_result();
  if (tmp_value.alloced_length() < res->length() &&
      tmp_value.realloc(res->length()))
  {
    null_value= 1;
    return 0;
  }
  tmp_value.length(res->length());
  tmp_value.set_charset(res->charset());
  ptr= (char *) res->ptr();
  end= ptr + res->length();
  tmp= (char *) tmp_value.ptr() + tmp_value.length();
#ifdef USE_MB
  if (use_mb(res->charset()))
  {
    register uint32 l;
    while (ptr < end)
    {
      if ((l= my_ismbchar(res->charset(),ptr,end)))
      {
        tmp-= l;
        memcpy(tmp,ptr,l);
        ptr+= l;
      }
      else
        *--tmp= *ptr++;
    }
  }
  else
#endif /* USE_MB */
  {
    while (ptr < end)
      *--tmp= *ptr++;
  }
  return &tmp_value;
}


void Item_func_reverse::fix_length_and_dec()
{
  agg_arg_charsets_for_string_result(collation, args, 1);
  DBUG_ASSERT(collation.collation != NULL);
  fix_char_length(args[0]->max_char_length());
}

/**
  Replace all occurences of string2 in string1 with string3.

  Don't reallocate val_str() if not needed.

  @todo
    Fix that this works with binary strings when using USE_MB 
*/

String *Item_func_replace::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res,*res2,*res3;
  int offset;
  uint from_length,to_length;
  bool alloced=0;
#ifdef USE_MB
  const char *ptr,*end,*strend,*search,*search_end;
  register uint32 l;
  bool binary_cmp;
#endif

  null_value=0;
  res=args[0]->val_str(str);
  if (args[0]->null_value)
    goto null;
  res2=args[1]->val_str(&tmp_value);
  if (args[1]->null_value)
    goto null;

  res->set_charset(collation.collation);

#ifdef USE_MB
  binary_cmp = ((res->charset()->state & MY_CS_BINSORT) || !use_mb(res->charset()));
#endif

  if (res2->length() == 0)
    return res;
#ifndef USE_MB
  if ((offset=res->strstr(*res2)) < 0)
    return res;
#else
  offset=0;
  if (binary_cmp && (offset=res->strstr(*res2)) < 0)
    return res;
#endif
  if (!(res3=args[2]->val_str(&tmp_value2)))
    goto null;
  from_length= res2->length();
  to_length=   res3->length();

#ifdef USE_MB
  if (!binary_cmp)
  {
    search=res2->ptr();
    search_end=search+from_length;
redo:
    DBUG_ASSERT(res->ptr() || !offset);
    ptr=res->ptr()+offset;
    strend=res->ptr()+res->length();
    /*
      In some cases val_str() can return empty string
      with ptr() == NULL and length() == 0.
      Let's check strend to avoid overflow.
    */
    end= strend ? strend - from_length + 1 : NULL;
    while (ptr < end)
    {
        if (*ptr == *search)
        {
          register char *i,*j;
          i=(char*) ptr+1; j=(char*) search+1;
          while (j != search_end)
            if (*i++ != *j++) goto skip;
          offset= (int) (ptr-res->ptr());
          if (res->length()-from_length + to_length >
	      current_thd->variables.max_allowed_packet)
	  {
	    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
				ER_WARN_ALLOWED_PACKET_OVERFLOWED,
				ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
				func_name(),
				current_thd->variables.max_allowed_packet);

            goto null;
	  }
          if (!alloced)
          {
            alloced=1;
            res=copy_if_not_alloced(str,res,res->length()+to_length);
          }
          res->replace((uint) offset,from_length,*res3);
	  offset+=(int) to_length;
          goto redo;
        }
skip:
        if ((l=my_ismbchar(res->charset(), ptr,strend))) ptr+=l;
        else ++ptr;
    }
  }
  else
#endif /* USE_MB */
    do
    {
      if (res->length()-from_length + to_length >
	  current_thd->variables.max_allowed_packet)
      {
	push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			    ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			    ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED), func_name(),
			    current_thd->variables.max_allowed_packet);
        goto null;
      }
      if (!alloced)
      {
        alloced=1;
        res=copy_if_not_alloced(str,res,res->length()+to_length);
      }
      res->replace((uint) offset,from_length,*res3);
      offset+=(int) to_length;
    }
    while ((offset=res->strstr(*res2,(uint) offset)) >= 0);
  return res;

null:
  null_value=1;
  return 0;
}


void Item_func_replace::fix_length_and_dec()
{
  ulonglong char_length= (ulonglong) args[0]->max_char_length();
  int diff=(int) (args[2]->max_char_length() - args[1]->max_char_length());
  if (diff > 0 && args[1]->max_char_length())
  {						// Calculate of maxreplaces
    ulonglong max_substrs= char_length / args[1]->max_char_length();
    char_length+= max_substrs * (uint) diff;
  }

  if (agg_arg_charsets_for_string_result_with_comparison(collation, args, 3))
    return;
  fix_char_length_ulonglong(char_length);
}


String *Item_func_insert::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res,*res2;
  longlong start, length;  /* must be longlong to avoid truncation */

  null_value=0;
  res=args[0]->val_str(str);
  res2=args[3]->val_str(&tmp_value);
  start= args[1]->val_int() - 1;
  length= args[2]->val_int();

  if (args[0]->null_value || args[1]->null_value || args[2]->null_value ||
      args[3]->null_value)
    goto null; /* purecov: inspected */

  if ((start < 0) || (start > res->length()))
    return res;                                 // Wrong param; skip insert
  if ((length < 0) || (length > res->length()))
    length= res->length();

  /*
    There is one exception not handled (intentionaly) by the character set
    aggregation code. If one string is strong side and is binary, and
    another one is weak side and is a multi-byte character string,
    then we need to operate on the second string in terms on bytes when
    calling ::numchars() and ::charpos(), rather than in terms of characters.
    Lets substitute its character set to binary.
  */
  if (collation.collation == &my_charset_bin)
  {
    res->set_charset(&my_charset_bin);
    res2->set_charset(&my_charset_bin);
  }

  /* start and length are now sufficiently valid to pass to charpos function */
   start= res->charpos((int) start);
   length= res->charpos((int) length, (uint32) start);

  /* Re-testing with corrected params */
  if (start > res->length())
    return res; /* purecov: inspected */        // Wrong param; skip insert
  if (length > res->length() - start)
    length= res->length() - start;

  if ((ulonglong) (res->length() - length + res2->length()) >
      (ulonglong) current_thd->variables.max_allowed_packet)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
			func_name(), current_thd->variables.max_allowed_packet);
    goto null;
  }
  res=copy_if_not_alloced(str,res,res->length());
  res->replace((uint32) start,(uint32) length,*res2);
  return res;
null:
  null_value=1;
  return 0;
}


void Item_func_insert::fix_length_and_dec()
{
  ulonglong char_length;

  // Handle character set for args[0] and args[3].
  if (agg_arg_charsets_for_string_result(collation, args, 2, 3))
    return;
  char_length= ((ulonglong) args[0]->max_char_length() +
                (ulonglong) args[3]->max_char_length());
  fix_char_length_ulonglong(char_length);
}


String *Item_str_conv::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res;
  if (!(res=args[0]->val_str(str)))
  {
    null_value=1; /* purecov: inspected */
    return 0; /* purecov: inspected */
  }
  null_value=0;
  if (multiply == 1)
  {
    uint len;
    res= copy_if_not_alloced(str,res,res->length());
    len= converter(collation.collation, (char*) res->ptr(), res->length(),
                                        (char*) res->ptr(), res->length());
    DBUG_ASSERT(len <= res->length());
    res->length(len);
  }
  else
  {
    uint len= res->length() * multiply;
    tmp_value.alloc(len);
    tmp_value.set_charset(collation.collation);
    len= converter(collation.collation, (char*) res->ptr(), res->length(),
                                        (char*) tmp_value.ptr(), len);
    tmp_value.length(len);
    res= &tmp_value;
  }
  return res;
}


void Item_func_lcase::fix_length_and_dec()
{
  agg_arg_charsets_for_string_result(collation, args, 1);
  DBUG_ASSERT(collation.collation != NULL);
  multiply= collation.collation->casedn_multiply;
  converter= collation.collation->cset->casedn;
  fix_char_length_ulonglong((ulonglong) args[0]->max_char_length() * multiply);
}

void Item_func_ucase::fix_length_and_dec()
{
  agg_arg_charsets_for_string_result(collation, args, 1);
  DBUG_ASSERT(collation.collation != NULL);
  multiply= collation.collation->caseup_multiply;
  converter= collation.collation->cset->caseup;
  fix_char_length_ulonglong((ulonglong) args[0]->max_char_length() * multiply);
}


String *Item_func_left::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res= args[0]->val_str(str);

  /* must be longlong to avoid truncation */
  longlong length= args[1]->val_int();
  uint char_pos;

  if ((null_value=(args[0]->null_value || args[1]->null_value)))
    return 0;

  /* if "unsigned_flag" is set, we have a *huge* positive number. */
  if ((length <= 0) && (!args[1]->unsigned_flag))
    return make_empty_result();
  if ((res->length() <= (ulonglong) length) ||
      (res->length() <= (char_pos= res->charpos((int) length))))
    return res;

  tmp_value.set(*res, 0, char_pos);
  return &tmp_value;
}


void Item_str_func::left_right_max_length()
{
  uint32 char_length= args[0]->max_char_length();
  if (args[1]->const_item())
  {
    int length= (int) args[1]->val_int();
    if (args[1]->null_value)
      goto end;

    if (length <= 0)
      char_length=0;
    else
      set_if_smaller(char_length, (uint) length);
  }

end:
  fix_char_length(char_length);
}


void Item_func_left::fix_length_and_dec()
{
  agg_arg_charsets_for_string_result(collation, args, 1);
  DBUG_ASSERT(collation.collation != NULL);
  left_right_max_length();
}


String *Item_func_right::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res= args[0]->val_str(str);
  /* must be longlong to avoid truncation */
  longlong length= args[1]->val_int();

  if ((null_value=(args[0]->null_value || args[1]->null_value)))
    return 0; /* purecov: inspected */

  /* if "unsigned_flag" is set, we have a *huge* positive number. */
  if ((length <= 0) && (!args[1]->unsigned_flag))
    return make_empty_result(); /* purecov: inspected */

  if (res->length() <= (ulonglong) length)
    return res; /* purecov: inspected */

  uint start=res->numchars();
  if (start <= (uint) length)
    return res;
  start=res->charpos(start - (uint) length);
  tmp_value.set(*res,start,res->length()-start);
  return &tmp_value;
}


void Item_func_right::fix_length_and_dec()
{
  agg_arg_charsets_for_string_result(collation, args, 1);
  DBUG_ASSERT(collation.collation != NULL);
  left_right_max_length();
}


String *Item_func_substr::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res  = args[0]->val_str(str);
  /* must be longlong to avoid truncation */
  longlong start= args[1]->val_int();
  /* Assumes that the maximum length of a String is < INT_MAX32. */
  /* Limit so that code sees out-of-bound value properly. */
  longlong length= arg_count == 3 ? args[2]->val_int() : INT_MAX32;
  longlong tmp_length;

  if ((null_value=(args[0]->null_value || args[1]->null_value ||
		   (arg_count == 3 && args[2]->null_value))))
    return 0; /* purecov: inspected */

  /* Negative or zero length, will return empty string. */
  if ((arg_count == 3) && (length <= 0) && 
      (length == 0 || !args[2]->unsigned_flag))
    return make_empty_result();

  /* Assumes that the maximum length of a String is < INT_MAX32. */
  /* Set here so that rest of code sees out-of-bound value as such. */
  if ((length <= 0) || (length > INT_MAX32))
    length= INT_MAX32;

  /* if "unsigned_flag" is set, we have a *huge* positive number. */
  /* Assumes that the maximum length of a String is < INT_MAX32. */
  if ((!args[1]->unsigned_flag && (start < INT_MIN32 || start > INT_MAX32)) ||
      (args[1]->unsigned_flag && ((ulonglong) start > INT_MAX32)))
    return make_empty_result();

  start= ((start < 0) ? res->numchars() + start : start - 1);
  start= res->charpos((int) start);
  if ((start < 0) || ((uint) start + 1 > res->length()))
    return make_empty_result();

  length= res->charpos((int) length, (uint32) start);
  tmp_length= res->length() - start;
  length= min(length, tmp_length);

  if (!start && (longlong) res->length() == length)
    return res;
  tmp_value.set(*res, (uint32) start, (uint32) length);
  return &tmp_value;
}


void Item_func_substr::fix_length_and_dec()
{
  max_length=args[0]->max_length;

  agg_arg_charsets_for_string_result(collation, args, 1);
  DBUG_ASSERT(collation.collation != NULL);
  if (args[1]->const_item())
  {
    int32 start= (int32) args[1]->val_int();
    if (args[1]->null_value)
      goto end;
    if (start < 0)
      max_length= ((uint)(-start) > max_length) ? 0 : (uint)(-start);
    else
      max_length-= min((uint)(start - 1), max_length);
  }
  if (arg_count == 3 && args[2]->const_item())
  {
    int32 length= (int32) args[2]->val_int();
    if (args[2]->null_value)
      goto end;
    if (length <= 0)
      max_length=0; /* purecov: inspected */
    else
      set_if_smaller(max_length,(uint) length);
  }

end:
  max_length*= collation.collation->mbmaxlen;
}


void Item_func_substr_index::fix_length_and_dec()
{ 
  if (agg_arg_charsets_for_string_result_with_comparison(collation, args, 2))
    return;
  fix_char_length(args[0]->max_char_length());
}


String *Item_func_substr_index::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  char buff[MAX_FIELD_WIDTH];
  String tmp(buff,sizeof(buff),system_charset_info);
  String *res= args[0]->val_str(str);
  String *delimiter= args[1]->val_str(&tmp);
  int32 count= (int32) args[2]->val_int();
  int offset;

  if (args[0]->null_value || args[1]->null_value || args[2]->null_value)
  {					// string and/or delim are null
    null_value=1;
    return 0;
  }
  null_value=0;
  uint delimiter_length= delimiter->length();
  if (!res->length() || !delimiter_length || !count)
    return make_empty_result();		// Wrong parameters

  res->set_charset(collation.collation);

#ifdef USE_MB
  if (use_mb(res->charset()))
  {
    const char *ptr= res->ptr();
    const char *strend= ptr+res->length();
    const char *end= strend-delimiter_length+1;
    const char *search= delimiter->ptr();
    const char *search_end= search+delimiter_length;
    int32 n=0,c=count,pass;
    register uint32 l;
    for (pass=(count>0);pass<2;++pass)
    {
      while (ptr < end)
      {
        if (*ptr == *search)
        {
	  register char *i,*j;
	  i=(char*) ptr+1; j=(char*) search+1;
	  while (j != search_end)
	    if (*i++ != *j++) goto skip;
	  if (pass==0) ++n;
	  else if (!--c) break;
	  ptr+= delimiter_length;
	  continue;
	}
    skip:
        if ((l=my_ismbchar(res->charset(), ptr,strend))) ptr+=l;
        else ++ptr;
      } /* either not found or got total number when count<0 */
      if (pass == 0) /* count<0 */
      {
        c+=n+1;
        if (c<=0) return res; /* not found, return original string */
        ptr=res->ptr();
      }
      else
      {
        if (c) return res; /* Not found, return original string */
        if (count>0) /* return left part */
        {
	  tmp_value.set(*res,0,(ulong) (ptr-res->ptr()));
        }
        else /* return right part */
        {
	  ptr+= delimiter_length;
	  tmp_value.set(*res,(ulong) (ptr-res->ptr()), (ulong) (strend-ptr));
        }
      }
    }
  }
  else
#endif /* USE_MB */
  {
    if (count > 0)
    {					// start counting from the beginning
      for (offset=0; ; offset+= delimiter_length)
      {
	if ((offset= res->strstr(*delimiter, offset)) < 0)
	  return res;			// Didn't find, return org string
	if (!--count)
	{
	  tmp_value.set(*res,0,offset);
	  break;
	}
      }
    }
    else
    {
      /*
        Negative index, start counting at the end
      */
      for (offset=res->length(); offset; )
      {
        /* 
          this call will result in finding the position pointing to one 
          address space less than where the found substring is located
          in res
        */
	if ((offset= res->strrstr(*delimiter, offset)) < 0)
	  return res;			// Didn't find, return org string
        /*
          At this point, we've searched for the substring
          the number of times as supplied by the index value
        */
	if (!++count)
	{
	  offset+= delimiter_length;
	  tmp_value.set(*res,offset,res->length()- offset);
	  break;
	}
      }
      if (count)
        return res;			// Didn't find, return org string
    }
  }
  return (&tmp_value);
}

/*
** The trim functions are extension to ANSI SQL because they trim substrings
** They ltrim() and rtrim() functions are optimized for 1 byte strings
** They also return the original string if possible, else they return
** a substring that points at the original string.
*/


String *Item_func_ltrim::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  char buff[MAX_FIELD_WIDTH], *ptr, *end;
  String tmp(buff,sizeof(buff),system_charset_info);
  String *res, *remove_str;
  uint remove_length;
  LINT_INIT(remove_length);

  res= args[0]->val_str(str);
  if ((null_value=args[0]->null_value))
    return 0;
  remove_str= &remove;                          /* Default value. */
  if (arg_count == 2)
  {
    remove_str= args[1]->val_str(&tmp);
    if ((null_value= args[1]->null_value))
      return 0;
  }

  if ((remove_length= remove_str->length()) == 0 ||
      remove_length > res->length())
    return res;

  ptr= (char*) res->ptr();
  end= ptr+res->length();
  if (remove_length == 1)
  {
    char chr=(*remove_str)[0];
    while (ptr != end && *ptr == chr)
      ptr++;
  }
  else
  {
    const char *r_ptr=remove_str->ptr();
    end-=remove_length;
    while (ptr <= end && !memcmp(ptr, r_ptr, remove_length))
      ptr+=remove_length;
    end+=remove_length;
  }
  if (ptr == res->ptr())
    return res;
  tmp_value.set(*res,(uint) (ptr - res->ptr()),(uint) (end-ptr));
  return &tmp_value;
}


String *Item_func_rtrim::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  char buff[MAX_FIELD_WIDTH], *ptr, *end;
  String tmp(buff, sizeof(buff), system_charset_info);
  String *res, *remove_str;
  uint remove_length;
  LINT_INIT(remove_length);

  res= args[0]->val_str(str);
  if ((null_value=args[0]->null_value))
    return 0;
  remove_str= &remove;                          /* Default value. */
  if (arg_count == 2)
  {
    remove_str= args[1]->val_str(&tmp);
    if ((null_value= args[1]->null_value))
      return 0;
  }

  if ((remove_length= remove_str->length()) == 0 ||
      remove_length > res->length())
    return res;

  ptr= (char*) res->ptr();
  end= ptr+res->length();
#ifdef USE_MB
  char *p=ptr;
  register uint32 l;
#endif
  if (remove_length == 1)
  {
    char chr=(*remove_str)[0];
#ifdef USE_MB
    if (use_mb(res->charset()))
    {
      while (ptr < end)
      {
	if ((l=my_ismbchar(res->charset(), ptr,end))) ptr+=l,p=ptr;
	else ++ptr;
      }
      ptr=p;
    }
#endif
    while (ptr != end  && end[-1] == chr)
      end--;
  }
  else
  {
    const char *r_ptr=remove_str->ptr();
#ifdef USE_MB
    if (use_mb(res->charset()))
    {
  loop:
      while (ptr + remove_length < end)
      {
	if ((l=my_ismbchar(res->charset(), ptr,end))) ptr+=l;
	else ++ptr;
      }
      if (ptr + remove_length == end && !memcmp(ptr,r_ptr,remove_length))
      {
	end-=remove_length;
	ptr=p;
	goto loop;
      }
    }
    else
#endif /* USE_MB */
    {
      while (ptr + remove_length <= end &&
	     !memcmp(end-remove_length, r_ptr, remove_length))
	end-=remove_length;
    }
  }
  if (end == res->ptr()+res->length())
    return res;
  tmp_value.set(*res,0,(uint) (end-res->ptr()));
  return &tmp_value;
}


String *Item_func_trim::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  char buff[MAX_FIELD_WIDTH], *ptr, *end;
  const char *r_ptr;
  String tmp(buff, sizeof(buff), system_charset_info);
  String *res, *remove_str;
  uint remove_length;
  LINT_INIT(remove_length);

  res= args[0]->val_str(str);
  if ((null_value=args[0]->null_value))
    return 0;
  remove_str= &remove;                          /* Default value. */
  if (arg_count == 2)
  {
    remove_str= args[1]->val_str(&tmp);
    if ((null_value= args[1]->null_value))
      return 0;
  }

  if ((remove_length= remove_str->length()) == 0 ||
      remove_length > res->length())
    return res;

  ptr= (char*) res->ptr();
  end= ptr+res->length();
  r_ptr= remove_str->ptr();
  while (ptr+remove_length <= end && !memcmp(ptr,r_ptr,remove_length))
    ptr+=remove_length;
#ifdef USE_MB
  if (use_mb(res->charset()))
  {
    char *p=ptr;
    register uint32 l;
 loop:
    while (ptr + remove_length < end)
    {
      if ((l=my_ismbchar(res->charset(), ptr,end))) ptr+=l;
      else ++ptr;
    }
    if (ptr + remove_length == end && !memcmp(ptr,r_ptr,remove_length))
    {
      end-=remove_length;
      ptr=p;
      goto loop;
    }
    ptr=p;
  }
  else
#endif /* USE_MB */
  {
    while (ptr + remove_length <= end &&
	   !memcmp(end-remove_length,r_ptr,remove_length))
      end-=remove_length;
  }
  if (ptr == res->ptr() && end == ptr+res->length())
    return res;
  tmp_value.set(*res,(uint) (ptr - res->ptr()),(uint) (end-ptr));
  return &tmp_value;
}

void Item_func_trim::fix_length_and_dec()
{
  if (arg_count == 1)
  {
    agg_arg_charsets_for_string_result(collation, args, 1);
    DBUG_ASSERT(collation.collation != NULL);
    remove.set_charset(collation.collation);
    remove.set_ascii(" ",1);
  }
  else
  {
    // Handle character set for args[1] and args[0].
    // Note that we pass args[1] as the first item, and args[0] as the second.
    if (agg_arg_charsets_for_string_result_with_comparison(collation,
                                                           &args[1], 2, -1))
      return;
  }
  fix_char_length(args[0]->max_char_length());
}

void Item_func_trim::print(String *str, enum_query_type query_type)
{
  if (arg_count == 1)
  {
    Item_func::print(str, query_type);
    return;
  }
  str->append(Item_func_trim::func_name());
  str->append('(');
  str->append(mode_name());
  str->append(' ');
  args[1]->print(str, query_type);
  str->append(STRING_WITH_LEN(" from "));
  args[0]->print(str, query_type);
  str->append(')');
}


/**
  Helper function for calculating a new password. Used in 
  Item_func_password::fix_length_and_dec() for const parameters and in 
  Item_func_password::val_str_ascii() for non-const parameters.
  @param str The plain text password which should be digested
  @param buffer a pointer to the buffer where the digest will be stored.

  @note The buffer must be of at least CRYPT_MAX_PASSWORD_SIZE size.

  @return Size of the password.
*/

int calculate_password(String *str, char *buffer)
{
  DBUG_ASSERT(str);
  if (str->length() == 0) // PASSWORD('') returns ''
    return 0;
  
  int buffer_len= 0;
  THD *thd= current_thd;
  int old_passwords= 0;
  if (thd)
    old_passwords= thd->variables.old_passwords;
  
#if defined(HAVE_OPENSSL)
  if (old_passwords == 2)
  {
    my_make_scrambled_password(buffer, str->ptr(),
                               str->length());
    buffer_len= (int) strlen(buffer) + 1;
  }
  else
#endif
  if (old_passwords == 0)
  {
    my_make_scrambled_password_sha1(buffer, str->ptr(),
                                    str->length());
    buffer_len= SCRAMBLED_PASSWORD_CHAR_LENGTH;
  }
  else
  if (old_passwords == 1)
  {
    my_make_scrambled_password_323(buffer, str->ptr(),
                                   str->length());
    buffer_len= SCRAMBLED_PASSWORD_CHAR_LENGTH_323;
  }
  return buffer_len;
}

/* Item_func_password */
void Item_func_password::fix_length_and_dec()
{
  maybe_null= false; // PASSWORD() never returns NULL
  
  if (args[0]->const_item())
  {
    String str;
    String *res= args[0]->val_str(&str);
    if (!args[0]->null_value)
    {
      m_hashed_password_buffer_len=
        calculate_password(res, m_hashed_password_buffer);
      fix_length_and_charset(m_hashed_password_buffer_len, default_charset());
      m_recalculate_password= false;
      return;
    }
  }

  m_recalculate_password= true;
  fix_length_and_charset(CRYPT_MAX_PASSWORD_SIZE, default_charset());
}

String *Item_func_password::val_str_ascii(String *str)
{
  DBUG_ASSERT(fixed == 1);

  String *res= args[0]->val_str(str);

  if (args[0]->null_value)
    res= make_empty_result();

  /* we treat NULLs as equal to empty string when calling the plugin */
  //check_password_policy(res);

  null_value= 0;
  if (args[0]->null_value)  // PASSWORD(NULL) returns ''
    return res;
  
  if (m_recalculate_password)
    m_hashed_password_buffer_len= calculate_password(res,
                                                     m_hashed_password_buffer);

  if (m_hashed_password_buffer_len == 0)
    return make_empty_result();

  str->set(m_hashed_password_buffer, m_hashed_password_buffer_len,
           default_charset());

  return str;
}

char *Item_func_password::
  create_password_hash_buffer(THD *thd, const char *password,  size_t pass_len)
{
  String *password_str= new (thd->mem_root)String(password, thd->variables.
                                                    character_set_client);
  //check_password_policy(password_str);

  char *buff= NULL;
  if (thd->variables.old_passwords == 0)
  {
    /* Allocate memory for the password scramble and one extra byte for \0 */
    buff= (char *) thd->alloc(SCRAMBLED_PASSWORD_CHAR_LENGTH + 1);
    //my_make_scrambled_password_sha1(buff, password, pass_len);
  }
#if defined(HAVE_OPENSSL)
  else
  {
    /* Allocate memory for the password scramble and one extra byte for \0 */
    buff= (char *) thd->alloc(CRYPT_MAX_PASSWORD_SIZE + 1);
    my_make_scrambled_password(buff, password, pass_len);
  }
#endif
  return buff;
}

/* Item_func_old_password */

String *Item_func_old_password::val_str_ascii(String *str)
{
  String *res;

  DBUG_ASSERT(fixed == 1);

  res= args[0]->val_str(str);

  if ((null_value= args[0]->null_value))
    res= make_empty_result();
 
  /* we treat NULLs as equal to empty string when calling the plugin */
  //check_password_policy(res);

  if (null_value)
    return 0;

  if (res->length() == 0)
    return make_empty_result();

  //my_make_scrambled_password_323(tmp_value, res->ptr(), res->length());
  str->set(tmp_value, SCRAMBLED_PASSWORD_CHAR_LENGTH_323, &my_charset_latin1);
  return str;
}

char *Item_func_old_password::alloc(THD *thd, const char *password,
                                    size_t pass_len)
{
  char *buff= (char *) thd->alloc(SCRAMBLED_PASSWORD_CHAR_LENGTH_323+1);
  if (buff)
  {
    String *password_str= new (thd->mem_root)String(password, thd->variables.
                                                    character_set_client);
    //check_password_policy(password_str);
    //my_make_scrambled_password_323(buff, password, pass_len);
  }
  return buff;
}


#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

String *Item_func_encrypt::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res  =args[0]->val_str(str);

#ifdef HAVE_CRYPT
  char salt[3],*salt_ptr;
  if ((null_value=args[0]->null_value))
    return 0;
  if (res->length() == 0)
    return make_empty_result();
  if (arg_count == 1)
  {					// generate random salt
    time_t timestamp=current_thd->query_start();
    salt[0] = bin_to_ascii( (ulong) timestamp & 0x3f);
    salt[1] = bin_to_ascii(( (ulong) timestamp >> 5) & 0x3f);
    salt[2] = 0;
    salt_ptr=salt;
  }
  else
  {					// obtain salt from the first two bytes
    String *salt_str=args[1]->val_str(&tmp_value);
    if ((null_value= (args[1]->null_value || salt_str->length() < 2)))
      return 0;
    salt_ptr= salt_str->c_ptr_safe();
  }
  mysql_mutex_lock(&LOCK_crypt);
  char *tmp= crypt(res->c_ptr_safe(),salt_ptr);
  if (!tmp)
  {
    mysql_mutex_unlock(&LOCK_crypt);
    null_value= 1;
    return 0;
  }
  str->set(tmp, (uint) strlen(tmp), &my_charset_bin);
  str->copy();
  mysql_mutex_unlock(&LOCK_crypt);
  return str;
#else
  null_value=1;
  return 0;
#endif	/* HAVE_CRYPT */
}

bool Item_func_encode::seed()
{
  char buf[80];
  ulong rand_nr[2];
  String *key, tmp(buf, sizeof(buf), system_charset_info);

  if (!(key= args[1]->val_str(&tmp)))
    return TRUE;

  //hash_password(rand_nr, key->ptr(), key->length());
  //sql_crypt.init(rand_nr);

  return FALSE;
}

void Item_func_encode::fix_length_and_dec()
{
  max_length=args[0]->max_length;
  maybe_null=args[0]->maybe_null || args[1]->maybe_null;
  collation.set(&my_charset_bin);
  /* Precompute the seed state if the item is constant. */
  seeded= args[1]->const_item() &&
          (args[1]->result_type() == STRING_RESULT) && !seed();
}

String *Item_func_encode::val_str(String *str)
{
  String *res;
  DBUG_ASSERT(fixed == 1);

  if (!(res=args[0]->val_str(str)))
  {
    null_value= 1;
    return NULL;
  }

  if (!seeded && seed())
  {
    null_value= 1;
    return NULL;
  }

  null_value= 0;
  res= copy_if_not_alloced(str, res, res->length());
  crypto_transform(res);
  sql_crypt.reinit();

  return res;
}

void Item_func_encode::crypto_transform(String *res)
{
  //sql_crypt.encode((char*) res->ptr(),res->length());
  res->set_charset(&my_charset_bin);
}

void Item_func_decode::crypto_transform(String *res)
{
  //sql_crypt.decode((char*) res->ptr(),res->length());
}


Item *Item_func_sysconst::safe_charset_converter(const CHARSET_INFO *tocs)
{
  Item_string *conv;
  uint conv_errors;
  String tmp, cstr, *ostr= val_str(&tmp);
  if (null_value)
  {
    Item *null_item= new Item_null(fully_qualified_func_name());
    null_item->collation.set (tocs);
    return null_item;
  }
  cstr.copy(ostr->ptr(), ostr->length(), ostr->charset(), tocs, &conv_errors);
  if (conv_errors ||
      !(conv= new Item_static_string_func(fully_qualified_func_name(),
                                          cstr.ptr(), cstr.length(),
                                          cstr.charset(),
                                          collation.derivation)))
  {
    return NULL;
  }
  conv->str_value.copy();
  conv->str_value.mark_as_const();
  return conv;
}


String *Item_func_database::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  THD *thd= current_thd;
  if (thd->db == NULL)
  {
    null_value= 1;
    return 0;
  }
  else
    str->copy(thd->db, thd->db_length, system_charset_info);
  return str;
}


/**
  @note USER() is replicated correctly if binlog_format=ROW or (as of
  BUG#28086) binlog_format=MIXED, but is incorrectly replicated to ''
  if binlog_format=STATEMENT.
*/
bool Item_func_user::init(const char *user, const char *host)
{
  DBUG_ASSERT(fixed == 1);

  // For system threads (e.g. replication SQL thread) user may be empty
  if (user)
  {
    const CHARSET_INFO *cs= str_value.charset();
    size_t res_length= (strlen(user)+strlen(host)+2) * cs->mbmaxlen;

    if (str_value.alloc((uint) res_length))
    {
      null_value=1;
      return TRUE;
    }

    res_length=cs->cset->snprintf(cs, (char*)str_value.ptr(), (uint) res_length,
                                  "%s@%s", user, host);
    str_value.length((uint) res_length);
    str_value.mark_as_const();
  }
  return FALSE;
}


bool Item_func_user::fix_fields(THD *thd, Item **ref)
{
  return (Item_func_sysconst::fix_fields(thd, ref) ||
          init(thd->main_security_ctx.user,
               thd->main_security_ctx.host_or_ip));
}


bool Item_func_current_user::fix_fields(THD *thd, Item **ref)
{
  if (Item_func_sysconst::fix_fields(thd, ref))
    return TRUE;

  Security_context *ctx=
#ifndef NO_EMBEDDED_ACCESS_CHECKS
                         (context->security_ctx
                          ? context->security_ctx : thd->security_ctx);
#else
                         thd->security_ctx;
#endif /*NO_EMBEDDED_ACCESS_CHECKS*/
  return init(ctx->priv_user, ctx->priv_host);
}


void Item_func_soundex::fix_length_and_dec()
{
  uint32 char_length= args[0]->max_char_length();
  agg_arg_charsets_for_string_result(collation, args, 1);
  DBUG_ASSERT(collation.collation != NULL);
  set_if_bigger(char_length, 4);
  fix_char_length(char_length);
  tmp_value.set_charset(collation.collation);
}


/**
  If alpha, map input letter to soundex code.
  If not alpha and remove_garbage is set then skip to next char
  else return 0
*/

static int soundex_toupper(int ch)
{
  return (ch >= 'a' && ch <= 'z') ? ch - 'a' + 'A' : ch;
}


static char get_scode(int wc)
{
  int ch= soundex_toupper(wc);
  if (ch < 'A' || ch > 'Z')
  {
					// Thread extended alfa (country spec)
    return '0';				// as vokal
  }
  return(soundex_map[ch-'A']);
}


static bool my_uni_isalpha(int wc)
{
  /*
    Return true for all Basic Latin letters: a..z A..Z.
    Return true for all Unicode characters with code higher than U+00C0:
    - characters between 'z' and U+00C0 are controls and punctuations.
    - "U+00C0 LATIN CAPITAL LETTER A WITH GRAVE" is the first letter after 'z'.
  */
  return (wc >= 'a' && wc <= 'z') ||
         (wc >= 'A' && wc <= 'Z') ||
         (wc >= 0xC0);
}


String *Item_func_soundex::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res  =args[0]->val_str(str);
  char last_ch,ch;
  const CHARSET_INFO *cs= collation.collation;
  my_wc_t wc;
  uint nchars;
  int rc;

  if ((null_value= args[0]->null_value))
    return 0; /* purecov: inspected */

  if (tmp_value.alloc(max(res->length(), 4 * cs->mbminlen)))
    return str; /* purecov: inspected */
  char *to= (char *) tmp_value.ptr();
  char *to_end= to + tmp_value.alloced_length();
  char *from= (char *) res->ptr(), *end= from + res->length();
  
  for ( ; ; ) /* Skip pre-space */
  {
    if ((rc= cs->cset->mb_wc(cs, &wc, (uchar*) from, (uchar*) end)) <= 0)
      return make_empty_result(); /* EOL or invalid byte sequence */
    
    if (rc == 1 && cs->ctype)
    {
      /* Single byte letter found */
      if (my_isalpha(cs, *from))
      {
        last_ch= get_scode(*from);       // Code of the first letter
        *to++= soundex_toupper(*from++); // Copy first letter
        break;
      }
      from++;
    }
    else
    {
      from+= rc;
      if (my_uni_isalpha(wc))
      {
        /* Multibyte letter found */
        wc= soundex_toupper(wc);
        last_ch= get_scode(wc);     // Code of the first letter
        if ((rc= cs->cset->wc_mb(cs, wc, (uchar*) to, (uchar*) to_end)) <= 0)
        {
          /* Extra safety - should not really happen */
          DBUG_ASSERT(false);
          return make_empty_result();
        }
        to+= rc;
        break;
      }
    }
  }
  
  /*
     last_ch is now set to the first 'double-letter' check.
     loop on input letters until end of input
  */
  for (nchars= 1 ; ; )
  {
    if ((rc= cs->cset->mb_wc(cs, &wc, (uchar*) from, (uchar*) end)) <= 0)
      break; /* EOL or invalid byte sequence */

    if (rc == 1 && cs->ctype)
    {
      if (!my_isalpha(cs, *from++))
        continue;
    }
    else
    {
      from+= rc;
      if (!my_uni_isalpha(wc))
        continue;
    }
    
    ch= get_scode(wc);
    if ((ch != '0') && (ch != last_ch)) // if not skipped or double
    {
      // letter, copy to output
      if ((rc= cs->cset->wc_mb(cs, (my_wc_t) ch,
                               (uchar*) to, (uchar*) to_end)) <= 0)
      {
        // Extra safety - should not really happen
        DBUG_ASSERT(false);
        break;
      }
      to+= rc;
      nchars++;
      last_ch= ch;  // save code of last input letter
    }               // for next double-letter check
  }
  
  /* Pad up to 4 characters with DIGIT ZERO, if the string is shorter */
  if (nchars < 4) 
  {
    uint nbytes= (4 - nchars) * cs->mbminlen;
    cs->cset->fill(cs, to, nbytes, '0');
    to+= nbytes;
  }

  tmp_value.length((uint) (to-tmp_value.ptr()));
  return &tmp_value;
}


/**
  Change a number to format '3,333,333,333.000'.

  This should be 'internationalized' sometimes.
*/

const int FORMAT_MAX_DECIMALS= 30;


MY_LOCALE *Item_func_format::get_locale(Item *item)
{
  DBUG_ASSERT(arg_count == 3);
  String tmp, *locale_name= args[2]->val_str_ascii(&tmp);
  MY_LOCALE *lc;
  if (!locale_name ||
      !(lc= my_locale_by_name(locale_name->c_ptr_safe())))
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                        ER_UNKNOWN_LOCALE,
                        ER(ER_UNKNOWN_LOCALE),
                        locale_name ? locale_name->c_ptr_safe() : "NULL");
    lc= &my_locale_en_US;
  }
  return lc;
}

void Item_func_format::fix_length_and_dec()
{
  uint32 char_length= args[0]->max_char_length();
  uint32 max_sep_count= (char_length / 3) + (decimals ? 1 : 0) + /*sign*/1;
  collation.set(default_charset());
  fix_char_length(char_length + max_sep_count + decimals);
  if (arg_count == 3)
    locale= args[2]->basic_const_item() ? get_locale(args[2]) : NULL;
  else
    locale= &my_locale_en_US; /* Two arguments */
}


/**
  @todo
  This needs to be fixed for multi-byte character set where numbers
  are stored in more than one byte
*/

String *Item_func_format::val_str_ascii(String *str)
{
  uint32 str_length;
  /* Number of decimal digits */
  int dec;
  /* Number of characters used to represent the decimals, including '.' */
  uint32 dec_length;
  MY_LOCALE *lc;
  DBUG_ASSERT(fixed == 1);

  dec= (int) args[1]->val_int();
  if (args[1]->null_value)
  {
    null_value=1;
    return NULL;
  }

  lc= locale ? locale : get_locale(args[2]);

  dec= set_zone(dec, 0, FORMAT_MAX_DECIMALS);
  dec_length= dec ? dec+1 : 0;
  null_value=0;

  if (args[0]->result_type() == DECIMAL_RESULT ||
      args[0]->result_type() == INT_RESULT)
  {
    my_decimal dec_val, rnd_dec, *res;
    res= args[0]->val_decimal(&dec_val);
    if ((null_value=args[0]->null_value))
      return 0; /* purecov: inspected */
    my_decimal_round(E_DEC_FATAL_ERROR, res, dec, false, &rnd_dec);
    my_decimal2string(E_DEC_FATAL_ERROR, &rnd_dec, 0, 0, 0, str);
    str_length= str->length();
  }
  else
  {
    double nr= args[0]->val_real();
    if ((null_value=args[0]->null_value))
      return 0; /* purecov: inspected */
    nr= my_double_round(nr, (longlong) dec, FALSE, FALSE);
    str->set_real(nr, dec, &my_charset_numeric);
    if (isnan(nr) || my_isinf(nr))
      return str;
    str_length=str->length();
  }
  /* We need this test to handle 'nan' and short values */
  if (lc->grouping[0] > 0 &&
      str_length >= dec_length + 1 + lc->grouping[0])
  {
    /* We need space for ',' between each group of digits as well. */
    char buf[2 * FLOATING_POINT_BUFFER];
    int count;
    const char *grouping= lc->grouping;
    char sign_length= *str->ptr() == '-' ? 1 : 0;
    const char *src= str->ptr() + str_length - dec_length - 1;
    const char *src_begin= str->ptr() + sign_length;
    char *dst= buf + sizeof(buf);
    
    /* Put the fractional part */
    if (dec)
    {
      dst-= (dec + 1);
      *dst= lc->decimal_point;
      memcpy(dst + 1, src + 2, dec);
    }
    
    /* Put the integer part with grouping */
    for (count= *grouping; src >= src_begin; count--)
    {
      /*
        When *grouping==0x80 (which means "end of grouping")
        count will be initialized to -1 and
        we'll never get into this "if" anymore.
      */
      if (count == 0)
      {
        *--dst= lc->thousand_sep;
        if (grouping[1])
          grouping++;
        count= *grouping;
      }
      DBUG_ASSERT(dst > buf);
      *--dst= *src--;
    }
    
    if (sign_length) /* Put '-' */
      *--dst= *str->ptr();
    
    /* Put the rest of the integer part without grouping */
    str->copy(dst, buf + sizeof(buf) - dst, &my_charset_latin1);
  }
  else if (dec_length && lc->decimal_point != '.')
  {
    /*
      For short values without thousands (<1000)
      replace decimal point to localized value.
    */
    DBUG_ASSERT(dec_length <= str_length);
    ((char*) str->ptr())[str_length - dec_length]= lc->decimal_point;
  }
  return str;
}


void Item_func_format::print(String *str, enum_query_type query_type)
{
  str->append(STRING_WITH_LEN("format("));
  args[0]->print(str, query_type);
  str->append(',');
  args[1]->print(str, query_type);
  if(arg_count > 2)
  {
    str->append(',');
    args[2]->print(str,query_type);
  }
  str->append(')');
}

void Item_func_elt::fix_length_and_dec()
{
  uint32 char_length= 0;
  decimals=0;

  if (agg_arg_charsets_for_string_result(collation, args + 1, arg_count - 1))
    return;

  for (uint i= 1 ; i < arg_count ; i++)
  {
    set_if_bigger(char_length, args[i]->max_char_length());
    set_if_bigger(decimals,args[i]->decimals);
  }
  fix_char_length(char_length);
  maybe_null=1;					// NULL if wrong first arg
}


double Item_func_elt::val_real()
{
  DBUG_ASSERT(fixed == 1);
  uint tmp;
  null_value=1;
  if ((tmp=(uint) args[0]->val_int()) == 0 || tmp >= arg_count)
    return 0.0;
  double result= args[tmp]->val_real();
  null_value= args[tmp]->null_value;
  return result;
}


longlong Item_func_elt::val_int()
{
  DBUG_ASSERT(fixed == 1);
  uint tmp;
  null_value=1;
  if ((tmp=(uint) args[0]->val_int()) == 0 || tmp >= arg_count)
    return 0;

  longlong result= args[tmp]->val_int();
  null_value= args[tmp]->null_value;
  return result;
}


String *Item_func_elt::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  uint tmp;
  null_value=1;
  if ((tmp=(uint) args[0]->val_int()) == 0 || tmp >= arg_count)
    return NULL;

  String *result= args[tmp]->val_str(str);
  if (result)
    result->set_charset(collation.collation);
  null_value= args[tmp]->null_value;
  return result;
}


void Item_func_make_set::split_sum_func(THD *thd,
                                        Ref_ptr_array ref_pointer_array,
					List<Item> &fields)
{
  item->split_sum_func2(thd, ref_pointer_array, fields, &item, TRUE);
  Item_str_func::split_sum_func(thd, ref_pointer_array, fields);
}


void Item_func_make_set::fix_length_and_dec()
{
  uint32 char_length= arg_count - 1; /* Separators */

  if (agg_arg_charsets_for_string_result(collation, args, arg_count))
    return;
  
  for (uint i=0 ; i < arg_count ; i++)
    char_length+= args[i]->max_char_length();
  fix_char_length(char_length);
  used_tables_cache|=	  item->used_tables();
  not_null_tables_cache&= item->not_null_tables();
  const_item_cache&=	  item->const_item();
  with_sum_func= with_sum_func || item->with_sum_func;
}


void Item_func_make_set::update_used_tables()
{
  Item_func::update_used_tables();
  item->update_used_tables();
  used_tables_cache|=item->used_tables();
  const_item_cache&=item->const_item();
  with_subselect= item->has_subquery();
  with_stored_program= item->has_stored_program();
}


String *Item_func_make_set::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  ulonglong bits;
  bool first_found=0;
  Item **ptr=args;
  String *result= NULL;

  bits=item->val_int();
  if ((null_value=item->null_value))
    return NULL;

  if (arg_count < 64)
    bits &= ((ulonglong) 1 << arg_count)-1;

  for (; bits; bits >>= 1, ptr++)
  {
    if (bits & 1)
    {
      String *res= (*ptr)->val_str(str);
      if (res)					// Skip nulls
      {
	if (!first_found)
	{					// First argument
	  first_found=1;
	  if (res != str)
	    result=res;				// Use original string
	  else
	  {
	    if (tmp_str.copy(*res))		// Don't use 'str'
              return make_empty_result();
	    result= &tmp_str;
	  }
	}
	else
	{
	  if (result != &tmp_str)
	  {					// Copy data to tmp_str
            if (tmp_str.alloc((result != NULL ? result->length() : 0) +
                              res->length() + 1) ||
		tmp_str.copy(*result))
              return make_empty_result();
	    result= &tmp_str;
	  }
	  if (tmp_str.append(STRING_WITH_LEN(","), &my_charset_bin) ||
              tmp_str.append(*res))
            return make_empty_result();
	}
      }
    }
  }
  if (result == NULL)
    return make_empty_result();
  return result;
}


Item *Item_func_make_set::transform(Item_transformer transformer, uchar *arg)
{
  DBUG_ASSERT(!current_thd->stmt_arena->is_stmt_prepare());

  Item *new_item= item->transform(transformer, arg);
  if (!new_item)
    return 0;

  /*
    THD::change_item_tree() should be called only if the tree was
    really transformed, i.e. when a new item has been created.
    Otherwise we'll be allocating a lot of unnecessary memory for
    change records at each execution.
  */
  if (item != new_item)
    current_thd->change_item_tree(&item, new_item);
  return Item_str_func::transform(transformer, arg);
}


void Item_func_make_set::print(String *str, enum_query_type query_type)
{
  str->append(STRING_WITH_LEN("make_set("));
  item->print(str, query_type);
  if (arg_count)
  {
    str->append(',');
    print_args(str, 0, query_type);
  }
  str->append(')');
}


String *Item_func_char::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  str->length(0);
  str->set_charset(collation.collation);
  for (uint i=0 ; i < arg_count ; i++)
  {
    int32 num=(int32) args[i]->val_int();
    if (!args[i]->null_value)
    {
      char tmp[4];
      if (num & 0xFF000000L)
      {
        mi_int4store(tmp, num);
        str->append(tmp, 4, &my_charset_bin);
      }
      else if (num & 0xFF0000L)
      {
        mi_int3store(tmp, num);
        str->append(tmp, 3, &my_charset_bin);
      }
      else if (num & 0xFF00L)
      {
        mi_int2store(tmp, num);
        str->append(tmp, 2, &my_charset_bin);
      }
      else
      {
        tmp[0]= (char) num;
        str->append(tmp, 1, &my_charset_bin);
      }
    }
  }
  str->realloc(str->length());			// Add end 0 (for Purify)
  return check_well_formed_result(str);
}


inline String* alloc_buffer(String *res,String *str,String *tmp_value,
			    ulong length)
{
  if (res->alloced_length() < length)
  {
    if (str->alloced_length() >= length)
    {
      (void) str->copy(*res);
      str->length(length);
      return str;
    }
    if (tmp_value->alloc(length))
      return 0;
    (void) tmp_value->copy(*res);
    tmp_value->length(length);
    return tmp_value;
  }
  res->length(length);
  return res;
}


void Item_func_repeat::fix_length_and_dec()
{
  agg_arg_charsets_for_string_result(collation, args, 1);
  DBUG_ASSERT(collation.collation != NULL);
  if (args[1]->const_item())
  {
    /* must be longlong to avoid truncation */
    longlong count= args[1]->val_int();
    if (args[1]->null_value)
      goto end;

    /* Assumes that the maximum length of a String is < INT_MAX32. */
    /* Set here so that rest of code sees out-of-bound value as such. */
    if (count > INT_MAX32)
      count= INT_MAX32;

    ulonglong char_length= (ulonglong) args[0]->max_char_length() * count;
    fix_char_length_ulonglong(char_length);
    return;
  }

end:
  max_length= MAX_BLOB_WIDTH;
  maybe_null= 1;
}

/**
  Item_func_repeat::str is carefully written to avoid reallocs
  as much as possible at the cost of a local buffer
*/

String *Item_func_repeat::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  uint length,tot_length;
  char *to;
  /* must be longlong to avoid truncation */
  longlong count= args[1]->val_int();
  String *res= args[0]->val_str(str);

  if (args[0]->null_value || args[1]->null_value)
    goto err;				// string and/or delim are null
  null_value= 0;

  if (count <= 0 && (count == 0 || !args[1]->unsigned_flag))
    return make_empty_result();

  /* Assumes that the maximum length of a String is < INT_MAX32. */
  /* Bounds check on count:  If this is triggered, we will error. */
  if ((ulonglong) count > INT_MAX32)
    count= INT_MAX32;
  if (count == 1)			// To avoid reallocs
    return res;
  length=res->length();
  // Safe length check
  if (length > current_thd->variables.max_allowed_packet / (uint) count)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
			func_name(), current_thd->variables.max_allowed_packet);
    goto err;
  }
  tot_length= length*(uint) count;
  if (!(res= alloc_buffer(res,str,&tmp_value,tot_length)))
    goto err;

  to=(char*) res->ptr()+length;
  while (--count)
  {
    memcpy(to,res->ptr(),length);
    to+=length;
  }
  return (res);

err:
  null_value=1;
  return 0;
}



void Item_func_space::fix_length_and_dec()
{
  collation.set(default_charset(), DERIVATION_COERCIBLE, MY_REPERTOIRE_ASCII); 
  if (args[0]->const_item())
  {
    /* must be longlong to avoid truncation */
    longlong count= args[0]->val_int();
    if (args[0]->null_value)
      goto end;
    /*
     Assumes that the maximum length of a String is < INT_MAX32. 
     Set here so that rest of code sees out-of-bound value as such. 
    */
    if (count > INT_MAX32)
      count= INT_MAX32;
    fix_char_length_ulonglong(count); 
    return;
  }

end:
  max_length= MAX_BLOB_WIDTH;
  maybe_null= 1;
}


String *Item_func_space::val_str(String *str)
{
  uint tot_length;
  longlong count= args[0]->val_int();
  const CHARSET_INFO *cs= collation.collation;
   
  if (args[0]->null_value)
    goto err;				// string and/or delim are null
  null_value= 0;

  if (count <= 0 && (count == 0 || !args[0]->unsigned_flag))
    return make_empty_result();
  /*
   Assumes that the maximum length of a String is < INT_MAX32. 
   Bounds check on count:  If this is triggered, we will error. 
  */
  if ((ulonglong) count > INT_MAX32)
    count= INT_MAX32;

  // Safe length check
  tot_length= (uint) count * cs->mbminlen;
  if (tot_length > current_thd->variables.max_allowed_packet)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                        ER_WARN_ALLOWED_PACKET_OVERFLOWED,
                        ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
                        func_name(),
                        current_thd->variables.max_allowed_packet);
    goto err;
   }

  if (str->alloc(tot_length))
    goto err;
  str->length(tot_length);
  str->set_charset(cs);
  cs->cset->fill(cs, (char*) str->ptr(), tot_length, ' ');
  return str; 

err:
  null_value= 1;
  return 0;
}


void Item_func_rpad::fix_length_and_dec()
{
  // Handle character set for args[0] and args[2].
  if (agg_arg_charsets_for_string_result(collation, &args[0], 2, 2))
    return;
  if (args[1]->const_item())
  {
    ulonglong char_length= (ulonglong) args[1]->val_int();
    if (args[1]->null_value)
      goto end;
    DBUG_ASSERT(collation.collation->mbmaxlen > 0);
    /* Assumes that the maximum length of a String is < INT_MAX32. */
    /* Set here so that rest of code sees out-of-bound value as such. */
    if (char_length > INT_MAX32)
      char_length= INT_MAX32;
    fix_char_length_ulonglong(char_length);
    return;
  }

end:
  max_length= MAX_BLOB_WIDTH;
  maybe_null= 1;
}


String *Item_func_rpad::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  uint32 res_byte_length,res_char_length,pad_char_length,pad_byte_length;
  char *to;
  const char *ptr_pad;
  /* must be longlong to avoid truncation */
  longlong count= args[1]->val_int();
  longlong byte_count;
  String *res= args[0]->val_str(str);
  String *rpad= args[2]->val_str(&rpad_str);

  if (!res || args[1]->null_value || !rpad || 
      ((count < 0) && !args[1]->unsigned_flag))
    goto err;
  null_value=0;
  /* Assumes that the maximum length of a String is < INT_MAX32. */
  /* Set here so that rest of code sees out-of-bound value as such. */
  if ((ulonglong) count > INT_MAX32)
    count= INT_MAX32;
  /*
    There is one exception not handled (intentionaly) by the character set
    aggregation code. If one string is strong side and is binary, and
    another one is weak side and is a multi-byte character string,
    then we need to operate on the second string in terms on bytes when
    calling ::numchars() and ::charpos(), rather than in terms of characters.
    Lets substitute its character set to binary.
  */
  if (collation.collation == &my_charset_bin)
  {
    res->set_charset(&my_charset_bin);
    rpad->set_charset(&my_charset_bin);
  }

  if (count <= (res_char_length= res->numchars()))
  {						// String to pad is big enough
    res->length(res->charpos((int) count));	// Shorten result if longer
    return (res);
  }
  pad_char_length= rpad->numchars();

  byte_count= count * collation.collation->mbmaxlen;
  if ((ulonglong) byte_count > current_thd->variables.max_allowed_packet)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
			func_name(), current_thd->variables.max_allowed_packet);
    goto err;
  }
  if (args[2]->null_value || !pad_char_length)
    goto err;
  res_byte_length= res->length();	/* Must be done before alloc_buffer */
  if (!(res= alloc_buffer(res,str,&tmp_value, (ulong) byte_count)))
    goto err;

  to= (char*) res->ptr()+res_byte_length;
  ptr_pad=rpad->ptr();
  pad_byte_length= rpad->length();
  count-= res_char_length;
  for ( ; (uint32) count > pad_char_length; count-= pad_char_length)
  {
    memcpy(to,ptr_pad,pad_byte_length);
    to+= pad_byte_length;
  }
  if (count)
  {
    pad_byte_length= rpad->charpos((int) count);
    memcpy(to,ptr_pad,(size_t) pad_byte_length);
    to+= pad_byte_length;
  }
  res->length((uint) (to- (char*) res->ptr()));
  return (res);

 err:
  null_value=1;
  return 0;
}


void Item_func_lpad::fix_length_and_dec()
{
  // Handle character set for args[0] and args[2].
  if (agg_arg_charsets_for_string_result(collation, &args[0], 2, 2))
    return;
  
  if (args[1]->const_item())
  {
    ulonglong char_length= (ulonglong) args[1]->val_int();
    if (args[1]->null_value)
      goto end;
    DBUG_ASSERT(collation.collation->mbmaxlen > 0);
    /* Assumes that the maximum length of a String is < INT_MAX32. */
    /* Set here so that rest of code sees out-of-bound value as such. */
    if (char_length > INT_MAX32)
      char_length= INT_MAX32;
    fix_char_length_ulonglong(char_length);
    return;
  }

end:
  max_length= MAX_BLOB_WIDTH;
  maybe_null= 1;
}


String *Item_func_lpad::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  uint32 res_char_length,pad_char_length;
  /* must be longlong to avoid truncation */
  longlong count= args[1]->val_int();
  longlong byte_count;
  String *res= args[0]->val_str(&tmp_value);
  String *pad= args[2]->val_str(&lpad_str);

  if (!res || args[1]->null_value || !pad ||  
      ((count < 0) && !args[1]->unsigned_flag))
    goto err;  
  null_value=0;
  /* Assumes that the maximum length of a String is < INT_MAX32. */
  /* Set here so that rest of code sees out-of-bound value as such. */
  if ((ulonglong) count > INT_MAX32)
    count= INT_MAX32;

  /*
    There is one exception not handled (intentionaly) by the character set
    aggregation code. If one string is strong side and is binary, and
    another one is weak side and is a multi-byte character string,
    then we need to operate on the second string in terms on bytes when
    calling ::numchars() and ::charpos(), rather than in terms of characters.
    Lets substitute its character set to binary.
  */
  if (collation.collation == &my_charset_bin)
  {
    res->set_charset(&my_charset_bin);
    pad->set_charset(&my_charset_bin);
  }

  res_char_length= res->numchars();

  if (count <= res_char_length)
  {
    res->length(res->charpos((int) count));
    return res;
  }
  
  pad_char_length= pad->numchars();
  byte_count= count * collation.collation->mbmaxlen;
  
  if ((ulonglong) byte_count > current_thd->variables.max_allowed_packet)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
			func_name(), current_thd->variables.max_allowed_packet);
    goto err;
  }

  if (args[2]->null_value || !pad_char_length ||
      str->alloc((uint32) byte_count))
    goto err;
  
  str->length(0);
  str->set_charset(collation.collation);
  count-= res_char_length;
  while (count >= pad_char_length)
  {
    str->append(*pad);
    count-= pad_char_length;
  }
  if (count > 0)
    str->append(pad->ptr(), pad->charpos((int) count), collation.collation);

  str->append(*res);
  null_value= 0;
  return str;

err:
  null_value= 1;
  return 0;
}


String *Item_func_conv::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res= args[0]->val_str(str);
  char *endptr,ans[65],*ptr;
  longlong dec;
  int from_base= (int) args[1]->val_int();
  int to_base= (int) args[2]->val_int();
  int err;

  if (args[0]->null_value || args[1]->null_value || args[2]->null_value ||
      abs(to_base) > 36 || abs(to_base) < 2 ||
      abs(from_base) > 36 || abs(from_base) < 2 || !(res->length()))
  {
    null_value= 1;
    return NULL;
  }
  null_value= 0;
  unsigned_flag= !(from_base < 0);

  if (args[0]->field_type() == MYSQL_TYPE_BIT) 
  {
    /* 
     Special case: The string representation of BIT doesn't resemble the
     decimal representation, so we shouldn't change it to string and then to
     decimal. 
    */
    dec= args[0]->val_int();
  }
  else
  {
    if (from_base < 0)
      dec= my_strntoll(res->charset(), res->ptr(), res->length(),
                       -from_base, &endptr, &err);
    else
      dec= (longlong) my_strntoull(res->charset(), res->ptr(), res->length(),
                                   from_base, &endptr, &err);
  }

  if (!(ptr= longlong2str(dec, ans, to_base)) ||
      str->copy(ans, (uint32) (ptr - ans), default_charset()))
  {
    null_value= 1;
    return NULL;
  }
  return str;
}


String *Item_func_conv_charset::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  if (use_cached_value)
    return null_value ? 0 : &str_value;
  String *arg= args[0]->val_str(str);
  uint dummy_errors;
  if (!arg)
  {
    null_value=1;
    return 0;
  }
  null_value= tmp_value.copy(arg->ptr(), arg->length(), arg->charset(),
                             conv_charset, &dummy_errors);
  return null_value ? 0 : check_well_formed_result(&tmp_value);
}

void Item_func_conv_charset::fix_length_and_dec()
{
  collation.set(conv_charset, DERIVATION_IMPLICIT);
  fix_char_length(args[0]->max_char_length());
}

void Item_func_conv_charset::print(String *str, enum_query_type query_type)
{
  str->append(STRING_WITH_LEN("convert("));
  args[0]->print(str, query_type);
  str->append(STRING_WITH_LEN(" using "));
  str->append(conv_charset->csname);
  str->append(')');
}

String *Item_func_set_collation::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  str=args[0]->val_str(str);
  if ((null_value=args[0]->null_value))
    return 0;
  str->set_charset(collation.collation);
  return str;
}

void Item_func_set_collation::fix_length_and_dec()
{
  CHARSET_INFO *set_collation;
  const char *colname;
  String tmp, *str= args[1]->val_str(&tmp);
  colname= str->c_ptr();
  if (colname == binary_keyword)
    set_collation= get_charset_by_csname(args[0]->collation.collation->csname,
					 MY_CS_BINSORT,MYF(0));
  else
  {
    if (!(set_collation= mysqld_collation_get_by_name(colname)))
      return;
  }

  if (!set_collation || 
      !my_charset_same(args[0]->collation.collation,set_collation))
  {
    my_error(ER_COLLATION_CHARSET_MISMATCH, MYF(0),
             colname, args[0]->collation.collation->csname);
    return;
  }
  collation.set(set_collation, DERIVATION_EXPLICIT,
                args[0]->collation.repertoire);
  max_length= args[0]->max_length;
}


bool Item_func_set_collation::eq(const Item *item, bool binary_cmp) const
{
  /* Assume we don't have rtti */
  if (this == item)
    return 1;
  if (item->type() != FUNC_ITEM)
    return 0;
  Item_func *item_func=(Item_func*) item;
  if (arg_count != item_func->arg_count ||
      functype() != item_func->functype())
    return 0;
  Item_func_set_collation *item_func_sc=(Item_func_set_collation*) item;
  if (collation.collation != item_func_sc->collation.collation)
    return 0;
  for (uint i=0; i < arg_count ; i++)
    if (!args[i]->eq(item_func_sc->args[i], binary_cmp))
      return 0;
  return 1;
}


void Item_func_set_collation::print(String *str, enum_query_type query_type)
{
  str->append('(');
  args[0]->print(str, query_type);
  str->append(STRING_WITH_LEN(" collate "));
  DBUG_ASSERT(args[1]->basic_const_item() &&
              args[1]->type() == Item::STRING_ITEM);
  args[1]->str_value.print(str);
  str->append(')');
}

String *Item_func_charset::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  uint dummy_errors;

  const CHARSET_INFO *cs= args[0]->charset_for_protocol(); 
  null_value= 0;
  str->copy(cs->csname, (uint) strlen(cs->csname),
	    &my_charset_latin1, collation.collation, &dummy_errors);
  return str;
}

String *Item_func_collation::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  uint dummy_errors;
  const CHARSET_INFO *cs= args[0]->charset_for_protocol(); 

  null_value= 0;
  str->copy(cs->name, (uint) strlen(cs->name),
	    &my_charset_latin1, collation.collation, &dummy_errors);
  return str;
}


void Item_func_weight_string::fix_length_and_dec()
{
  const CHARSET_INFO *cs= args[0]->collation.collation;
  collation.set(&my_charset_bin, args[0]->collation.derivation);
  flags= my_strxfrm_flag_normalize(flags, cs->levels_for_order);
  field= args[0]->type() == FIELD_ITEM && args[0]->is_temporal() ?
         ((Item_field *) (args[0]))->field : (Field *) NULL;
  /* 
    Use result_length if it was given explicitly in constructor,
    otherwise calculate max_length using argument's max_length
    and "nweights".
  */  
  max_length= field ? field->pack_length() :
              result_length ? result_length :
              cs->mbmaxlen * max(args[0]->max_length, nweights);
  maybe_null= 1;
}


/* Return a weight_string according to collation */
String *Item_func_weight_string::val_str(String *str)
{
  String *res;
  const CHARSET_INFO *cs= args[0]->collation.collation;
  uint tmp_length, frm_length;
  DBUG_ASSERT(fixed == 1);

  if (args[0]->result_type() != STRING_RESULT ||
      !(res= args[0]->val_str(str)))
    goto nl;
  
  /*
    Use result_length if it was given in constructor
    explicitly, otherwise calculate result length
    from argument and "nweights".
  */
  tmp_length= field ? field->pack_length() :
              result_length ? result_length :
              cs->coll->strnxfrmlen(cs, cs->mbmaxlen *
                                    max(res->length(), nweights));

  if(tmp_length > current_thd->variables.max_allowed_packet)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                        ER_WARN_ALLOWED_PACKET_OVERFLOWED,
                        ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED), func_name(),
                        current_thd->variables.max_allowed_packet);
    goto nl;
  }

  if (tmp_value.alloc(tmp_length))
    goto nl;

  if (field)
  {
    frm_length= field->pack_length();
    field->make_sort_key((uchar *) tmp_value.ptr(), tmp_length);
  }
  else
    frm_length= cs->coll->strnxfrm(cs,
                                   (uchar *) tmp_value.ptr(), tmp_length,
                                   nweights ? nweights : tmp_length,
                                   (const uchar *) res->ptr(), res->length(),
                                   flags);
  tmp_value.length(frm_length);
  null_value= 0;
  return &tmp_value;

nl:
  null_value= 1;
  return 0;
}


String *Item_func_hex::val_str_ascii(String *str)
{
  String *res;
  DBUG_ASSERT(fixed == 1);
  if (args[0]->result_type() != STRING_RESULT)
  {
    ulonglong dec;
    char ans[65],*ptr;
    /* Return hex of unsigned longlong value */
    if (args[0]->result_type() == REAL_RESULT ||
        args[0]->result_type() == DECIMAL_RESULT)
    {
      double val= args[0]->val_real();
      if ((val <= (double) LONGLONG_MIN) || 
          (val >= (double) (ulonglong) ULONGLONG_MAX))
        dec=  ~(longlong) 0;
      else
        dec= (ulonglong) (val + (val > 0 ? 0.5 : -0.5));
    }
    else
      dec= (ulonglong) args[0]->val_int();

    if ((null_value= args[0]->null_value))
      return 0;
    
    if (!(ptr= longlong2str(dec, ans, 16)) ||
        str->copy(ans,(uint32) (ptr - ans),
        &my_charset_numeric))
      return make_empty_result();		// End of memory
    return str;
  }

  /* Convert given string to a hex string, character by character */
  res= args[0]->val_str(str);
  if (!res || tmp_value.alloc(res->length()*2+1))
  {
    null_value=1;
    return 0;
  }
  null_value=0;
  tmp_value.length(res->length()*2);
  tmp_value.set_charset(&my_charset_latin1);

  octet2hex((char*) tmp_value.ptr(), res->ptr(), res->length());
  return &tmp_value;
}

  /** Convert given hex string to a binary string. */

String *Item_func_unhex::val_str(String *str)
{
  const char *from, *end;
  char *to;
  String *res;
  uint length;
  DBUG_ASSERT(fixed == 1);

  res= args[0]->val_str(str);
  if (!res || tmp_value.alloc(length= (1+res->length())/2))
  {
    null_value=1;
    return 0;
  }

  from= res->ptr();
  null_value= 0;
  tmp_value.length(length);
  to= (char*) tmp_value.ptr();
  if (res->length() % 2)
  {
    int hex_char;
    *to++= hex_char= hexchar_to_int(*from++);
    if ((null_value= (hex_char == -1)))
      return 0;
  }
  for (end=res->ptr()+res->length(); from < end ; from+=2, to++)
  {
    int hex_char;
    *to= (hex_char= hexchar_to_int(from[0])) << 4;
    if ((null_value= (hex_char == -1)))
      return 0;
    *to|= hex_char= hexchar_to_int(from[1]);
    if ((null_value= (hex_char == -1)))
      return 0;
  }
  return &tmp_value;
}


#ifndef DBUG_OFF
String *Item_func_like_range::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  longlong nbytes= args[1]->val_int();
  String *res= args[0]->val_str(str);
  size_t min_len, max_len;
  const CHARSET_INFO *cs= collation.collation;

  if (!res || args[0]->null_value || args[1]->null_value ||
      nbytes < 0 || nbytes > MAX_BLOB_WIDTH ||
      min_str.alloc(nbytes) || max_str.alloc(nbytes))
    goto err;
  null_value=0;

  if (cs->coll->like_range(cs, res->ptr(), res->length(),
                           '\\', '_', '%', nbytes,
                           (char*) min_str.ptr(), (char*) max_str.ptr(),
                           &min_len, &max_len))
    goto err;

  min_str.set_charset(collation.collation);
  max_str.set_charset(collation.collation);
  min_str.length(min_len);
  max_str.length(max_len);

  return is_min ? &min_str : &max_str;

err:
  null_value= 1;
  return 0;
}
#endif


bool Item_char_typecast::eq(const Item *item, bool binary_cmp) const
{
  if (this == item)
    return 1;
  if (item->type() != FUNC_ITEM ||
      functype() != ((Item_func*)item)->functype())
    return 0;

  Item_char_typecast *cast= (Item_char_typecast*)item;
  if (cast_length != cast->cast_length ||
      cast_cs     != cast->cast_cs)
    return 0;

  if (!args[0]->eq(cast->args[0], binary_cmp))
      return 0;
  return 1;
}


void Item_char_typecast::print(String *str, enum_query_type query_type)
{
  str->append(STRING_WITH_LEN("cast("));
  args[0]->print(str, query_type);
  str->append(STRING_WITH_LEN(" as char"));
  if (cast_length >= 0)
    str->append_parenthesized(cast_length);
  if (cast_cs)
  {
    str->append(STRING_WITH_LEN(" charset "));
    str->append(cast_cs->csname);
  }
  str->append(')');
}


String *Item_char_typecast::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res;
  uint32 length;

  if (cast_length >= 0 &&
      ((unsigned) cast_length) > current_thd->variables.max_allowed_packet)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
			cast_cs == &my_charset_bin ?
                        "cast_as_binary" : func_name(),
                        current_thd->variables.max_allowed_packet);
    null_value= 1;
    return 0;
  }

  if (!charset_conversion)
  {
    if (!(res= args[0]->val_str(str)))
    {
      null_value= 1;
      return 0;
    }
  }
  else
  {
    // Convert character set if differ
    uint dummy_errors;
    if (!(res= args[0]->val_str(str)) ||
        tmp_value.copy(res->ptr(), res->length(), from_cs,
                       cast_cs, &dummy_errors))
    {
      null_value= 1;
      return 0;
    }
    res= &tmp_value;
  }

  res->set_charset(cast_cs);

  /*
    Cut the tail if cast with length
    and the result is longer than cast length, e.g.
    CAST('string' AS CHAR(1))
  */
  if (cast_length >= 0)
  {
    if (res->length() > (length= (uint32) res->charpos(cast_length)))
    {                                           // Safe even if const arg
      char char_type[40];
      my_snprintf(char_type, sizeof(char_type), "%s(%lu)",
                  cast_cs == &my_charset_bin ? "BINARY" : "CHAR",
                  (ulong) length);

      if (!res->alloced_length())
      {                                         // Don't change const str
        str_value= *res;                        // Not malloced string
        res= &str_value;
      }
      ErrConvString err(res);
      push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                          ER_TRUNCATED_WRONG_VALUE,
                          ER(ER_TRUNCATED_WRONG_VALUE), char_type,
                          err.ptr());
      res->length((uint) length);
    }
    else if (cast_cs == &my_charset_bin && res->length() < (uint) cast_length)
    {
      if (res->alloced_length() < (uint) cast_length)
      {
        str_value.alloc(cast_length);
        str_value.copy(*res);
        res= &str_value;
      }
      memset(const_cast<char*>(res->ptr() + res->length()), 0,
             cast_length - res->length());
      res->length(cast_length);
    }
  }
  null_value= 0;
  return res;
}


void Item_char_typecast::fix_length_and_dec()
{
  /*
    If we convert between two ASCII compatible character sets and the
    argument repertoire is MY_REPERTOIRE_ASCII then from_cs is set to cast_cs.
    This allows just to take over the args[0]->val_str() result
    and thus avoid unnecessary character set conversion.
  */
  from_cs= args[0]->collation.repertoire == MY_REPERTOIRE_ASCII &&
           my_charset_is_ascii_based(cast_cs) &&
           my_charset_is_ascii_based(args[0]->collation.collation) ?
           cast_cs : args[0]->collation.collation;


  collation.set(cast_cs, DERIVATION_IMPLICIT);
  fix_char_length(cast_length >= 0 ? cast_length :
                  cast_cs == &my_charset_bin ? args[0]->max_length :
                  args[0]->max_char_length());

  /* 
     We always force character set conversion if cast_cs
     is a multi-byte character set. It garantees that the
     result of CAST is a well-formed string.
     For single-byte character sets we allow just to copy from the argument.
     A single-byte character sets string is always well-formed. 
  */
  charset_conversion= (cast_cs->mbmaxlen > 1) ||
                      (!my_charset_same(from_cs, cast_cs) &&
                       from_cs != &my_charset_bin &&
                       cast_cs != &my_charset_bin);
}


void Item_func_binary::print(String *str, enum_query_type query_type)
{
  str->append(STRING_WITH_LEN("cast("));
  args[0]->print(str, query_type);
  str->append(STRING_WITH_LEN(" as binary)"));
}


#include <my_dir.h>				// For my_stat

String *Item_load_file::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *file_name;
  File file;
  MY_STAT stat_info;
  char path[FN_REFLEN];
  DBUG_ENTER("load_file");

  if (!(file_name= args[0]->val_str(str))
#ifndef NO_EMBEDDED_ACCESS_CHECKS
      || !(current_thd->security_ctx->master_access & FILE_ACL)
#endif
      )
    goto err;

  (void) fn_format(path, file_name->c_ptr_safe(), mysql_real_data_home, "",
		   MY_RELATIVE_PATH | MY_UNPACK_FILENAME);

  /* Read only allowed from within dir specified by secure_file_priv */
//   if (!is_secure_file_path(path))
//     goto err;

  if (!mysql_file_stat(key_file_loadfile, path, &stat_info, MYF(0)))
    goto err;

  if (!(stat_info.st_mode & S_IROTH))
  {
    /* my_error(ER_TEXTFILE_NOT_READABLE, MYF(0), file_name->c_ptr()); */
    goto err;
  }
  if (stat_info.st_size > (long) current_thd->variables.max_allowed_packet)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
			ER_WARN_ALLOWED_PACKET_OVERFLOWED,
			ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
			func_name(), current_thd->variables.max_allowed_packet);
    goto err;
  }
  if (tmp_value.alloc(stat_info.st_size))
    goto err;
  if ((file= mysql_file_open(key_file_loadfile,
                             file_name->ptr(), O_RDONLY, MYF(0))) < 0)
    goto err;
  if (mysql_file_read(file, (uchar*) tmp_value.ptr(), stat_info.st_size,
                      MYF(MY_NABP)))
  {
    mysql_file_close(file, MYF(0));
    goto err;
  }
  tmp_value.length(stat_info.st_size);
  mysql_file_close(file, MYF(0));
  null_value = 0;
  DBUG_RETURN(&tmp_value);

err:
  null_value = 1;
  DBUG_RETURN(0);
}


String* Item_func_export_set::val_str(String* str)
{
  DBUG_ASSERT(fixed == 1);
  String yes_buf, no_buf, sep_buf;
  const ulonglong the_set = (ulonglong) args[0]->val_int();
  const String *yes= args[1]->val_str(&yes_buf);
  const String *no= args[2]->val_str(&no_buf);
  const String *sep= NULL;

  uint num_set_values = 64;
  str->length(0);
  str->set_charset(collation.collation);

  /* Check if some argument is a NULL value */
  if (args[0]->null_value || args[1]->null_value || args[2]->null_value)
  {
    null_value= true;
    return NULL;
  }
  /*
    Arg count can only be 3, 4 or 5 here. This is guaranteed from the
    grammar for EXPORT_SET()
  */
  switch(arg_count) {
  case 5:
    num_set_values = (uint) args[4]->val_int();
    if (num_set_values > 64)
      num_set_values=64;
    if (args[4]->null_value)
    {
      null_value= true;
      return NULL;
    }
    /* Fall through */
  case 4:
    if (!(sep = args[3]->val_str(&sep_buf)))	// Only true if NULL
    {
      null_value= true;
      return NULL;
    }
    break;
  case 3:
    {
      /* errors is not checked - assume "," can always be converted */
      uint errors;
      sep_buf.copy(STRING_WITH_LEN(","), &my_charset_bin,
                   collation.collation, &errors);
      sep = &sep_buf;
    }
    break;
  default:
    DBUG_ASSERT(0); // cannot happen
  }
  null_value= false;

  const ulong max_allowed_packet= current_thd->variables.max_allowed_packet;
  const uint num_separators= num_set_values > 0 ? num_set_values - 1 : 0;
  const ulonglong max_total_length=
    num_set_values * max(yes->length(), no->length()) +
    num_separators * sep->length();

  if (unlikely(max_total_length > max_allowed_packet))
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                        ER_WARN_ALLOWED_PACKET_OVERFLOWED,
                        ER(ER_WARN_ALLOWED_PACKET_OVERFLOWED),
                        func_name(), max_allowed_packet);
    null_value= true;
    return NULL;
  }

  uint ix;
  ulonglong mask;
  for (ix= 0, mask=0x1; ix < num_set_values; ++ix, mask = (mask << 1))
  {
    if (the_set & mask)
      str->append(*yes);
    else
      str->append(*no);
    if (ix != num_separators)
      str->append(*sep);
  }
  return str;
}

void Item_func_export_set::fix_length_and_dec()
{
  uint32 length= max(args[1]->max_char_length(), args[2]->max_char_length());
  uint32 sep_length= (arg_count > 3 ? args[3]->max_char_length() : 1);

  if (agg_arg_charsets_for_string_result(collation,
                                         args + 1, min(4U, arg_count) - 1))
    return;
  fix_char_length(length * 64 + sep_length * 63);
}


#define get_esc_bit(mask, num) (1 & (*((mask) + ((num) >> 3))) >> ((num) & 7))

/**
  QUOTE() function returns argument string in single quotes suitable for
  using in a SQL statement.

  Adds a \\ before all characters that needs to be escaped in a SQL string.
  We also escape '^Z' (END-OF-FILE in windows) to avoid probelms when
  running commands from a file in windows.

  This function is very useful when you want to generate SQL statements.

  @note
    QUOTE(NULL) returns the string 'NULL' (4 letters, without quotes).

  @retval
    str	   Quoted string
  @retval
    NULL	   Out of memory.
*/

String *Item_func_quote::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  /*
    Bit mask that has 1 for set for the position of the following characters:
    0, \, ' and ^Z
  */

  static uchar escmask[32]=
  {
    0x01, 0x00, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  char *from, *to, *end, *start;
  String *arg= args[0]->val_str(str);
  uint arg_length, new_length;
  if (!arg)					// Null argument
  {
    /* Return the string 'NULL' */
    str->copy(STRING_WITH_LEN("NULL"), collation.collation);
    null_value= 0;
    return str;
  }

  arg_length= arg->length();

  if (collation.collation->mbmaxlen == 1)
  {
    new_length= arg_length + 2; /* for beginning and ending ' signs */
    for (from= (char*) arg->ptr(), end= from + arg_length; from < end; from++)
      new_length+= get_esc_bit(escmask, (uchar) *from);
  }
  else
  {
    new_length= (arg_length * 2) +  /* For string characters */
                (2 * collation.collation->mbmaxlen); /* For quotes */
  }

  if (tmp_value.alloc(new_length))
    goto null;

  if (collation.collation->mbmaxlen > 1)
  {
    const CHARSET_INFO *cs= collation.collation;
    int mblen;
    uchar *to_end;
    to= (char*) tmp_value.ptr();
    to_end= (uchar*) to + new_length;

    /* Put leading quote */
    if ((mblen= cs->cset->wc_mb(cs, '\'', (uchar *) to, to_end)) <= 0)
      goto null;
    to+= mblen;

    for (start= (char*) arg->ptr(), end= start + arg_length; start < end; )
    {
      my_wc_t wc;
      bool escape;
      if ((mblen= cs->cset->mb_wc(cs, &wc, (uchar*) start, (uchar*) end)) <= 0)
        goto null;
      start+= mblen;
      switch (wc) {
        case 0:      escape= 1; wc= '0'; break;
        case '\032': escape= 1; wc= 'Z'; break;
        case '\'':   escape= 1; break;
        case '\\':   escape= 1; break;
        default:     escape= 0; break;
      }
      if (escape)
      {
        if ((mblen= cs->cset->wc_mb(cs, '\\', (uchar*) to, to_end)) <= 0)
          goto null;
        to+= mblen;
      }
      if ((mblen= cs->cset->wc_mb(cs, wc, (uchar*) to, to_end)) <= 0)
        goto null;
      to+= mblen;
    }

    /* Put trailing quote */
    if ((mblen= cs->cset->wc_mb(cs, '\'', (uchar *) to, to_end)) <= 0)
      goto null;
    to+= mblen;
    new_length= to - tmp_value.ptr();
    goto ret;
  }

  /*
    We replace characters from the end to the beginning
  */
  to= (char*) tmp_value.ptr() + new_length - 1;
  *to--= '\'';
  for (start= (char*) arg->ptr(),end= start + arg_length; end-- != start; to--)
  {
    /*
      We can't use the bitmask here as we want to replace \O and ^Z with 0
      and Z
    */
    switch (*end)  {
    case 0:
      *to--= '0';
      *to=   '\\';
      break;
    case '\032':
      *to--= 'Z';
      *to=   '\\';
      break;
    case '\'':
    case '\\':
      *to--= *end;
      *to=   '\\';
      break;
    default:
      *to= *end;
      break;
    }
  }
  *to= '\'';

ret:
  tmp_value.length(new_length);
  tmp_value.set_charset(collation.collation);
  null_value= 0;
  return &tmp_value;

null:
  null_value= 1;
  return 0;
}

longlong Item_func_uncompressed_length::val_int()
{
  DBUG_ASSERT(fixed == 1);
  String *res= args[0]->val_str(&value);
  if (!res)
  {
    null_value=1;
    return 0; /* purecov: inspected */
  }
  null_value=0;
  if (res->is_empty()) return 0;

  /*
    If length is <= 4 bytes, data is corrupt. This is the best we can do
    to detect garbage input without decompressing it.
  */
  if (res->length() <= 4)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                        ER_ZLIB_Z_DATA_ERROR,
                        ER(ER_ZLIB_Z_DATA_ERROR));
    null_value= 1;
    return 0;
  }

 /*
    res->ptr() using is safe because we have tested that string is at least
    5 bytes long.
    res->c_ptr() is not used because:
      - we do not need \0 terminated string to get first 4 bytes
      - c_ptr() tests simbol after string end (uninitialiozed memory) which
        confuse valgrind
  */
  return uint4korr(res->ptr()) & 0x3FFFFFFF;
}

longlong Item_func_crc32::val_int()
{
  DBUG_ASSERT(fixed == 1);
  String *res=args[0]->val_str(&value);
  if (!res)
  {
    null_value=1;
    return 0; /* purecov: inspected */
  }
  null_value=0;
  return (longlong) 0;
}

#ifdef HAVE_COMPRESS
#include "zlib.h"

String *Item_func_compress::val_str(String *str)
{
  int err= Z_OK, code;
  ulong new_size;
  String *res;
  Byte *body;
  char *tmp, *last_char;
  DBUG_ASSERT(fixed == 1);

  if (!(res= args[0]->val_str(str)))
  {
    null_value= 1;
    return 0;
  }
  null_value= 0;
  if (res->is_empty()) return res;

  /*
    Citation from zlib.h (comment for compress function):

    Compresses the source buffer into the destination buffer.  sourceLen is
    the byte length of the source buffer. Upon entry, destLen is the total
    size of the destination buffer, which must be at least 0.1% larger than
    sourceLen plus 12 bytes.
    We assume here that the buffer can't grow more than .25 %.
  */
  new_size= res->length() + res->length() / 5 + 12;

  // Check new_size overflow: new_size <= res->length()
  if (((uint32) (new_size+5) <= res->length()) || 
      buffer.realloc((uint32) new_size + 4 + 1))
  {
    null_value= 1;
    return 0;
  }

  body= ((Byte*)buffer.ptr()) + 4;

  // As far as we have checked res->is_empty() we can use ptr()
  if ((err= compress(body, &new_size,
		     (const Bytef*)res->ptr(), res->length())) != Z_OK)
  {
    code= err==Z_MEM_ERROR ? ER_ZLIB_Z_MEM_ERROR : ER_ZLIB_Z_BUF_ERROR;
    push_warning(current_thd,Sql_condition::WARN_LEVEL_WARN,code,ER(code));
    null_value= 1;
    return 0;
  }

  tmp= (char*)buffer.ptr(); // int4store is a macro; avoid side effects
  int4store(tmp, res->length() & 0x3FFFFFFF);

  /* This is to ensure that things works for CHAR fields, which trim ' ': */
  last_char= ((char*)body)+new_size-1;
  if (*last_char == ' ')
  {
    *++last_char= '.';
    new_size++;
  }

  buffer.length((uint32)new_size + 4);
  return &buffer;
}


String *Item_func_uncompress::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  String *res= args[0]->val_str(str);
  ulong new_size;
  int err;
  uint code;

  if (!res)
    goto err;
  null_value= 0;
  if (res->is_empty())
    return res;

  /* If length is less than 4 bytes, data is corrupt */
  if (res->length() <= 4)
  {
    push_warning_printf(current_thd,Sql_condition::WARN_LEVEL_WARN,
			ER_ZLIB_Z_DATA_ERROR,
			ER(ER_ZLIB_Z_DATA_ERROR));
    goto err;
  }

  /* Size of uncompressed data is stored as first 4 bytes of field */
  new_size= uint4korr(res->ptr()) & 0x3FFFFFFF;
  if (new_size > current_thd->variables.max_allowed_packet)
  {
    push_warning_printf(current_thd,Sql_condition::WARN_LEVEL_WARN,
			ER_TOO_BIG_FOR_UNCOMPRESS,
			ER(ER_TOO_BIG_FOR_UNCOMPRESS),
                        static_cast<int>(current_thd->variables.
                                         max_allowed_packet));
    goto err;
  }
  if (buffer.realloc((uint32)new_size))
    goto err;

  if ((err= uncompress((Byte*)buffer.ptr(), &new_size,
		       ((const Bytef*)res->ptr())+4,res->length())) == Z_OK)
  {
    buffer.length((uint32) new_size);
    return &buffer;
  }

  code= ((err == Z_BUF_ERROR) ? ER_ZLIB_Z_BUF_ERROR :
	 ((err == Z_MEM_ERROR) ? ER_ZLIB_Z_MEM_ERROR : ER_ZLIB_Z_DATA_ERROR));
  push_warning(current_thd,Sql_condition::WARN_LEVEL_WARN,code,ER(code));

err:
  null_value= 1;
  return 0;
}
#endif

/*
  UUID, as in
    DCE 1.1: Remote Procedure Call,
    Open Group Technical Standard Document Number C706, October 1997,
    (supersedes C309 DCE: Remote Procedure Call 8/1994,
    which was basis for ISO/IEC 11578:1996 specification)
*/

static struct rand_struct uuid_rand;
static uint nanoseq;
static ulonglong uuid_time=0;
static char clock_seq_and_node_str[]="-0000-000000000000";

/**
  number of 100-nanosecond intervals between
  1582-10-15 00:00:00.00 and 1970-01-01 00:00:00.00.
*/
#define UUID_TIME_OFFSET ((ulonglong) 141427 * 24 * 60 * 60 * \
                          1000 * 1000 * 10)

#define UUID_VERSION      0x1000
#define UUID_VARIANT      0x8000

static void tohex(char *to, uint from, uint len)
{
  to+= len;
  while (len--)
  {
    *--to= _dig_vec_lower[from & 15];
    from >>= 4;
  }
}

static void set_clock_seq_str()
{
  uint16 clock_seq= ((uint)(my_rnd(&uuid_rand)*16383)) | UUID_VARIANT;
  tohex(clock_seq_and_node_str+1, clock_seq, 4);
  nanoseq= 0;
}

String *Item_func_uuid::val_str(String *str)
{
  DBUG_ASSERT(fixed == 1);
  char *s;
  THD *thd= current_thd;

  mysql_mutex_lock(&LOCK_uuid_generator);
  if (! uuid_time) /* first UUID() call. initializing data */
  {
    ulong tmp=sql_rnd_with_mutex();
    uchar mac[6];
    int i;
    if (my_gethwaddr(mac))
    {
      /* purecov: begin inspected */
      /*
        generating random "hardware addr"
        and because specs explicitly specify that it should NOT correlate
        with a clock_seq value (initialized random below), we use a separate
        randominit() here
      */
      randominit(&uuid_rand, tmp + (ulong) thd, tmp + (ulong)global_query_id);
      for (i=0; i < (int)sizeof(mac); i++)
        mac[i]=(uchar)(my_rnd(&uuid_rand)*255);
      /* purecov: end */    
    }
    s=clock_seq_and_node_str+sizeof(clock_seq_and_node_str)-1;
    for (i=sizeof(mac)-1 ; i>=0 ; i--)
    {
      *--s=_dig_vec_lower[mac[i] & 15];
      *--s=_dig_vec_lower[mac[i] >> 4];
    }
    randominit(&uuid_rand, tmp + (ulong) server_start_time,
	       tmp + (ulong) thd->status_var.bytes_sent);
    set_clock_seq_str();
  }

  ulonglong tv= my_getsystime() + UUID_TIME_OFFSET + nanoseq;

  if (likely(tv > uuid_time))
  {
    /*
      Current time is ahead of last timestamp, as it should be.
      If we "borrowed time", give it back, just as long as we
      stay ahead of the previous timestamp.
    */
    if (nanoseq)
    {
      DBUG_ASSERT((tv > uuid_time) && (nanoseq > 0));
      /*
        -1 so we won't make tv= uuid_time for nanoseq >= (tv - uuid_time)
      */
      ulong delta= min<ulong>(nanoseq, (ulong) (tv - uuid_time -1));
      tv-= delta;
      nanoseq-= delta;
    }
  }
  else
  {
    if (unlikely(tv == uuid_time))
    {
      /*
        For low-res system clocks. If several requests for UUIDs
        end up on the same tick, we add a nano-second to make them
        different.
        ( current_timestamp + nanoseq * calls_in_this_period )
        may end up > next_timestamp; this is OK. Nonetheless, we'll
        try to unwind nanoseq when we get a chance to.
        If nanoseq overflows, we'll start over with a new numberspace
        (so the if() below is needed so we can avoid the ++tv and thus
        match the follow-up if() if nanoseq overflows!).
      */
      if (likely(++nanoseq))
        ++tv;
    }

    if (unlikely(tv <= uuid_time))
    {
      /*
        If the admin changes the system clock (or due to Daylight
        Saving Time), the system clock may be turned *back* so we
        go through a period once more for which we already gave out
        UUIDs.  To avoid duplicate UUIDs despite potentially identical
        times, we make a new random component.
        We also come here if the nanoseq "borrowing" overflows.
        In either case, we throw away any nanoseq borrowing since it's
        irrelevant in the new numberspace.
      */
      set_clock_seq_str();
      tv= my_getsystime() + UUID_TIME_OFFSET;
      nanoseq= 0;
      DBUG_PRINT("uuid",("making new numberspace"));
    }
  }

  uuid_time=tv;
  mysql_mutex_unlock(&LOCK_uuid_generator);

  uint32 time_low=            (uint32) (tv & 0xFFFFFFFF);
  uint16 time_mid=            (uint16) ((tv >> 32) & 0xFFFF);
  uint16 time_hi_and_version= (uint16) ((tv >> 48) | UUID_VERSION);

  str->realloc(UUID_LENGTH+1);
  str->length(UUID_LENGTH);
  str->set_charset(system_charset_info);
  s=(char *) str->ptr();
  s[8]=s[13]='-';
  tohex(s, time_low, 8);
  tohex(s+9, time_mid, 4);
  tohex(s+14, time_hi_and_version, 4);
  strmov(s+18, clock_seq_and_node_str);
  return str;
}

// Used by the Json_path_cache
#define JPC_UNINITIALIZED -1

/** Helper routines */

// see the contract for this function in item_json_func.h
bool ensure_utf8mb4(String *val, String *buf,
                    const char **resptr, size_t *reslength, bool require_string)
{
    const CHARSET_INFO *cs= val->charset();
    
    if (cs == &my_charset_bin)
    {
        if (require_string)  
            my_error(ER_INVALID_JSON_CHARSET, MYF(0), my_charset_bin.csname);
        return true;
    }
    
    const char *s= val->ptr();
    size_t ss= val->length();
    
    if (my_charset_same(cs, &my_charset_utf8mb4_bin) ||
        my_charset_same(cs, &my_charset_utf8_bin) ||
        !strcmp(cs->csname, "ascii"))
    {
        /*
         Character data is directly converted to JSON if the character
         set is utf8mb4 or a subset.
         */
    }
    else
    { // If not, we convert, possibly with loss (best effort).
        uint dummy_errors;
        if (buf->copy(val->ptr(), val->length(), val->charset(),
                      &my_charset_utf8mb4_bin, &dummy_errors))
        {
            return true;                            /* purecov: inspected */
        }
        buf->set_charset(&my_charset_utf8mb4_bin);
        s= buf->ptr();
        ss= buf->length();
    }
    
    *resptr= s;
    *reslength= ss;
    return false;
}

/**
 Parse a JSON dom out of an argument to a JSON function.
 
 @param[in]  res          Pointer to string value of arg.
 @param[in]  arg_idx      0-based index of corresponding JSON function argument
 @param[in]  func_name    Name of the user-invoked JSON_ function
 @param[in,out] dom       If non-null, we want any text parsed DOM
 returned at the location pointed to
 @param[in]  require_str_or_json
 If true, generate an error if other types used
 as input
 @param[out] parse_error  set to true if the parser was run and found an error
 else false
 @param[in]  preserve_neg_zero_int
 Whether integer negative zero should be preserved.
 If set to TRUE, -0 is handled as a DOUBLE. Double
 negative zero (-0.0) is preserved regardless of what
 this parameter is set to.
 
 @returns false if the arg parsed as valid JSON, true otherwise
 */
static bool parse_json(String *res,
                       uint arg_idx,
                       const char *func_name,
                       Json_dom **dom,
                       bool require_str_or_json,
                       bool *parse_error,
                       bool preserve_neg_zero_int= false)
{
    char buff[MAX_FIELD_WIDTH];
    String utf8_res(buff, sizeof(buff), &my_charset_utf8mb4_bin);
    
    const char *safep;         // contents of res, possibly converted
    size_t safe_length;        // length of safep
    
    *parse_error= false;
    
    if (ensure_utf8mb4(res, &utf8_res, &safep, &safe_length,
                       require_str_or_json))
    {
        return true;
    }
    
    if (!dom)
    {
        DBUG_ASSERT(!require_str_or_json);
        return !is_valid_json_syntax(safep, safe_length);
    }
    
    const char *parse_err;
    size_t err_offset;
    *dom= Json_dom::parse(safep, safe_length, &parse_err, &err_offset,
                          preserve_neg_zero_int);
    
    if (*dom == NULL && parse_err != NULL)
    {
        /*
         Report syntax error. The last argument is no longer used, but kept to
         avoid changing error message format.
         */
        my_error(ER_INVALID_JSON_TEXT_IN_PARAM, MYF(0),
                 arg_idx + 1, func_name, parse_err, err_offset,
                 "");
        *parse_error= true;
    }
    return *dom == NULL;
}


/**
 Get the field type of an item. This function returns the same value
 as arg->field_type() in most cases, but in some cases it may return
 another field type in order to ensure that the item gets handled the
 same way as items of a different type.
 */
static enum_field_types get_normalized_field_type(Item *arg)
{
    enum_field_types ft= arg->field_type();
    switch (ft)
    {
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_LONG_BLOB:
            /*
             TINYTEXT, TEXT, MEDIUMTEXT, and LONGTEXT have type
             MYSQL_TYPE_BLOB. We want to treat them like strings. We check
             the collation to see if the blob is really a string.
             */
            if (arg->collation.collation != &my_charset_bin)
                return MYSQL_TYPE_STRING;
            break;
        case MYSQL_TYPE_VARCHAR:
            /*
             If arg represents a parameter to a prepared statement, its field
             type will be MYSQL_TYPE_VARCHAR instead of the actual type of
             the parameter. The item type will have the info, so adjust
             field_type to match.
             
             If arg is a bit-field literal (such as b'1010'), its field type
             will be MYSQL_TYPE_VARCHAR. Adjust it to MYSQL_TYPE_BIT to match
             the type of BIT fields.
             */
            switch (arg->type())
        {
            case Item::NULL_ITEM:
                return MYSQL_TYPE_NULL;
            case Item::INT_ITEM:
                return MYSQL_TYPE_LONGLONG;
            case Item::REAL_ITEM:
                return MYSQL_TYPE_DOUBLE;
            case Item::DECIMAL_ITEM:
                return MYSQL_TYPE_NEWDECIMAL;
            case Item::VARBIN_ITEM:
                return MYSQL_TYPE_BIT;
            default:
                break;
        }
        default:
            break;
    }
    return ft;
}


/**
 Helper method for Item_func_json_* methods. Check whether an argument
 can be converted to a utf8mb4 string.
 
 @param[in]  arg_item    An argument Item
 @param[out] value       Where to materialize the arg_item's string value
 @param[out] utf8_res    Buffer for use by ensure_utf8mb4.
 @param[in]  func_name   Name of the user-invoked JSON_ function
 @param[out] safep       String pointer after any relevant conversion
 @param[out] safe_length Corresponding string length
 
 @returns true if the Item is not a utf8mb4 string
 */
static bool get_json_string(Item *arg_item,
                            String *value,
                            String *utf8_res,
                            const char *func_name,
                            const char **safep,
                            size_t *safe_length)
{
    String *const res= arg_item->val_str(value);
    
    if (!res)
    {
        return true;
    }
    
    if (ensure_utf8mb4(res, utf8_res, safep, safe_length,
                       true))
    {
        return true;
    }
    
    return false;
}

#define CATCH_ALL(funcname, expr) \
    catch (...)\
    {\
        my_error(ER_STD_UNKNOWN_EXCEPTION, MYF(0), (funcname));\
        expr;\
    }

/**
 Helper method for Item_func_json_* methods. Check if a JSON item or
 JSON text is valid and, for the latter, optionally construct a DOM
 tree (i.e. only if valid).
 
 @param[in]     args       Item_func::args alias
 @param[in]     arg_idx    Index (0-based) of argument into the args array
 @param[out]    value      Item_func_json_*::m_value alias
 @param[in]     func_name  Name of the user-invoked JSON_ function
 @param[in,out] dom        If non-null, we want any text parsed DOM
 returned at the location pointed to
 @param[in]     require_str_or_json
 If true, generate an error if other types used
 as input
 @param[out]    valid      true if a valid JSON value was found (or NULL),
 else false
 @param[in]     preserve_neg_zero_int
 Whether integer negative zero should be preserved.
 If set to TRUE, -0 is handled as a DOUBLE. Double
 negative zero (-0.0) is preserved regardless of what
 this parameter is set to.
 
 @returns true iff syntax error *and* dom != null, else false
 */
static bool json_is_valid(Item **args,
                          uint arg_idx,
                          String *value,
                          const char *func_name,
                          Json_dom **dom,
                          bool require_str_or_json,
                          bool *valid,
                          bool preserve_neg_zero_int= false)
{
    Item *const arg_item= args[arg_idx];
    
    switch (get_normalized_field_type(arg_item))
    {
        case MYSQL_TYPE_NULL:
            arg_item->update_null_value();
            DBUG_ASSERT(arg_item->null_value);
            *valid= true;
            return false;
        case MYSQL_TYPE_JSON:
        {
            Json_wrapper w;
            // Also sets the null_value flag
            *valid= !arg_item->val_json(&w);
            return !*valid;
        }
        case MYSQL_TYPE_STRING:
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_VARCHAR:
        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_LONG_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_TINY_BLOB:
        {
            String *const res= arg_item->val_str(value);
            if (arg_item->type() == Item::FIELD_ITEM)
            {
                Item_field *fi= down_cast<Item_field *>(arg_item);
                Field *field= fi->field;
                if (field->flags & (ENUM_FLAG | SET_FLAG))
                {
                    *valid= false;
                    return false;
                }
            }
            
            if (arg_item->null_value)
            {
                *valid= true;
                return false;
            }
            
            bool parse_error= false;
            //这里解析json是否正确格式
            const bool failure= parse_json(res, arg_idx, func_name,
                                           dom, require_str_or_json,
                                           &parse_error, preserve_neg_zero_int);
            *valid= !failure;
            return parse_error;
        }
        default:
            if (require_str_or_json)
            {
                *valid= false;
                my_error(ER_INVALID_TYPE_FOR_JSON, MYF(0), arg_idx + 1, func_name);
                return true;
            }
            
            *valid= false;
            return false;
    }
}

/**
 Helper method for Item_func_json_* methods. Assumes that the caller
 has already verified that the path expression is not null. Raises an
 error if the path expression is syntactically incorrect. Raises an
 error if the path expression contains wildcard tokens but is not
 supposed to. Otherwise updates the supplied Json_path object with
 the parsed path.
 
 @param[in]  path_expression  A string Item to be interpreted as a path.
 @param[out] value            Holder for path string
 @param[in]  forbid_wildcards True if the path shouldn't contain * or **
 @param[out] json_path        The object that will hold the parsed path
 
 @returns false on success, true on error or if the path is NULL
 */
static bool parse_path(Item * path_expression, String *value,
                       bool forbid_wildcards, Json_path *json_path)
{
    String *path_value= path_expression->val_str(value);
    
    if (!path_value)
    {
        return true;
    }
    
    const char * path_chars= path_value->ptr();
    size_t path_length= path_value->length();
    char buff[STRING_BUFFER_USUAL_SIZE];
    String res(buff, sizeof(buff), &my_charset_utf8mb4_bin);
    
    if (ensure_utf8mb4(path_value, &res, &path_chars, &path_length, true))
    {
        return true;
    }
    
    // OK, we have a string encoded in utf-8. Does it parse?
    size_t bad_idx= 0;
    if (parse_path(false, path_length, path_chars, json_path, &bad_idx))
    {
        /*
         Issue an error message. The last argument is no longer used, but kept to
         avoid changing error message format.
         */
        my_error(ER_INVALID_JSON_PATH, MYF(0), bad_idx, "");
        return true;
    }
    
    if (forbid_wildcards && json_path->contains_wildcard_or_ellipsis())
    {
        my_error(ER_INVALID_JSON_PATH_WILDCARD, MYF(0));
        return true;
    }
    
    return false;
}


/**
 Parse a oneOrAll argument.
 
 @param[in]  candidate   The string to compare to "one" or "all"
 @param[in]  func_name   The name of the calling function
 
 @returns ooa_one, ooa_all, or ooa_error, based on the match
 */
enum_one_or_all_type parse_one_or_all(const char *candidate,
                                      const char *func_name)
{
    if (!my_strcasecmp(&my_charset_utf8mb4_general_ci, candidate, "all"))
        return ooa_all;
    
    if (!my_strcasecmp(&my_charset_utf8mb4_general_ci, candidate, "one"))
        return ooa_one;
    
    my_error(ER_JSON_BAD_ONE_OR_ALL_ARG, MYF(0), func_name);
    return ooa_error;
}

/**
 Parse and cache a (possibly constant) oneOrAll argument.
 
 @param[in]  arg           The oneOrAll arg passed to the JSON function.
 @param[in]  string_value  String variable to use for parsing.
 @param[in]  cached_ooa    Previous result of parsing this arg.
 @param[in]  func_name     The name of the calling JSON function.
 
 @returns ooa_one, ooa_all, ooa_null or ooa_error, based on the match
 */
enum_one_or_all_type parse_and_cache_ooa(Item *arg,
                                         String *string_value,
                                         enum_one_or_all_type *cached_ooa,
                                         const char *func_name)
{
    bool is_constant= arg->const_during_execution();
    
    if (is_constant)
    {
        if (*cached_ooa != ooa_uninitialized)
        {
            return *cached_ooa;
        }
    }
    
    String *const one_or_all= arg->val_str(string_value);
    if (!one_or_all || arg->null_value)
    {
        *cached_ooa= ooa_null;
    }
    else
    {
        *cached_ooa= parse_one_or_all(one_or_all->c_ptr_safe(), func_name);
    }
    
    return *cached_ooa;
}

/** Json_path_cache */

//Json_path_cache::Json_path_cache(THD *thd, uint size)
//: m_paths(key_memory_JSON),
//m_arg_idx_to_vector_idx(thd->mem_root),
//m_arg_idx_to_problem_indicator(thd->mem_root),
//m_size(size)
//{
//    reset_cache();
//}
//
//
//Json_path_cache::~Json_path_cache()
//{}


//bool Json_path_cache::parse_and_cache_path(Item ** args, uint arg_idx,
//                                           bool forbid_wildcards)
//{
//    Item *arg= args[arg_idx];
//    
//    bool is_constant= arg->const_during_execution();
//    int vector_idx= m_arg_idx_to_vector_idx[arg_idx];
//    
//    if (is_constant)
//    {
//        // nothing to do if it has already been parsed
//        if (vector_idx >= 0)
//        {
//            if (m_arg_idx_to_problem_indicator[vector_idx])
//            {
//                return true;
//            }
//            
//            return false;
//        }
//    }
//    
//    DBUG_ASSERT((vector_idx == JPC_UNINITIALIZED) || (vector_idx >= 0));
//    
//    if (vector_idx == JPC_UNINITIALIZED)
//    {
//        vector_idx= (int) m_paths.size();
//        if (m_paths.push_back(Json_path()))
//            return true;                            /* purecov: inspected */
//        m_arg_idx_to_vector_idx[arg_idx]= vector_idx;
//    }
//    else
//    {
//        // re-parsing a non-constant path for the next row
//        m_paths[vector_idx].clear();
//    }
//    
//    if (parse_path(arg, &m_path_value, forbid_wildcards, &m_paths[vector_idx]))
//    {
//        // oops, parsing failed
//        
//        if (is_constant)
//        {
//            // remember that we had a problem
//            m_arg_idx_to_problem_indicator[vector_idx]= true;
//        }
//        
//        return true;
//    }
//    
//    return false;
//}
//
//
//Json_path *Json_path_cache::get_path(uint arg_idx)
//{
//    int vector_idx= m_arg_idx_to_vector_idx[arg_idx];
//    
//    if ((vector_idx < 0) || m_arg_idx_to_problem_indicator[vector_idx])
//    {
//        return NULL;
//    }
//    
//    return &(m_paths.at(vector_idx));
//}
//
//
//void Json_path_cache::reset_cache()
//{
//    for (uint arg_idx= 0; arg_idx < m_size; arg_idx++)
//    {
//        m_arg_idx_to_vector_idx[arg_idx]= JPC_UNINITIALIZED;
//        m_arg_idx_to_problem_indicator[arg_idx] = false;
//    }
//    
//    m_paths.clear();
//}


/** JSON_*() support methods */

void Item_json_func::cleanup()
{
    Item_func::cleanup();
    
//    m_path_cache.reset_cache();
}


type_conversion_status
Item_json_func::save_in_field_inner(Field *field, bool no_conversions)
{
    if (field->type() == MYSQL_TYPE_JSON)
    {
        // Store the value in the JSON binary format.
        Field_json *f= down_cast<Field_json *>(field);
        Json_wrapper wr;
        val_json(&wr);
        
        if (null_value)
            return set_field_to_null(field);
        
        field->set_notnull();
        return f->store_json(&wr);
    }
    return TYPE_ERR_BAD_VALUE;
}


longlong Item_func_json_valid::val_int()
{
    DBUG_ASSERT(fixed == 1);
    bool result= 1;
    null_value= false;
    
    try
    {
        bool ok;
        if (json_is_valid(args, 0, &m_value, func_name(), NULL, false, &ok))
        {
            return error_int();
        }
        
        if (!ok)
        {
            null_value= false;
            return 0;
        }
        
        if (args[0]->null_value)
        {
            null_value= true;
            return 0;
        }
        
    } CATCH_ALL("json_valid", result= 0)        /* purecov: inspected */
    
    return result;
}


/// Base class for predicates that compare elements in a JSON array.
class Array_comparator
{
    const Json_wrapper &m_wrapper;
protected:
    Array_comparator(const Json_wrapper &wrapper) : m_wrapper(wrapper) {}
    int cmp(size_t idx1, size_t idx2) const
    {
        return m_wrapper[idx1].compare(m_wrapper[idx2]);
    }
};

/// Predicate that checks if one array element is less than another.
struct Array_less : public Array_comparator
{
    Array_less(const Json_wrapper &wrapper) : Array_comparator(wrapper) {}
    bool operator() (size_t idx1, size_t idx2) const
    {
        return cmp(idx1, idx2) < 0;
    }
};

/// Predicate that checks if two array elements are equal.
struct Array_equal : public Array_comparator
{
    Array_equal(const Json_wrapper &wrapper) : Array_comparator(wrapper) {}
    bool operator() (size_t idx1, size_t idx2) const
    {
        return cmp(idx1, idx2) == 0;
    }
};

typedef Prealloced_array<size_t, 16> Sorted_index_array;

/**
 Sort the elements of a JSON array and remove duplicates.
 
 @param[in]  orig  the original JSON array
 @param[out] v     vector that will be filled with the indexes of the array
 elements in increasing order
 @return false on success, true on error
 */
static bool sort_array(const Json_wrapper &orig, Sorted_index_array *v)
{
    if (v->reserve(orig.length()))
        return true;                              /* purecov: inspected */
    
    for (size_t i=0; i < orig.length(); i++)
        v->push_back(i);
    
    // Sort the array...
    std::sort(v->begin(), v->end(), Array_less(orig));
    // ... and remove duplicates.
    v->erase(std::unique(v->begin(), v->end(), Array_equal(orig)), v->end());
    
    return false;
}


/**
 Check if one Json_wrapper contains all the elements of another
 Json_wrapper.
 
 @param[in]  doc_wrapper   the containing document
 @param[in]  containee_wr  the possibly contained document
 @param[out] result        true if doc_wrapper contains containee_wr,
 false otherwise
 @retval false on success
 @retval true on failure
 */
static bool contains_wr(const Json_wrapper &doc_wrapper,
                        const Json_wrapper &containee_wr,
                        bool *result)
{
    if (doc_wrapper.type() == Json_dom::J_OBJECT)
    {
        if (containee_wr.type() != Json_dom::J_OBJECT)
        {
            *result= false;
            return false;
        }
        
        Json_wrapper_object_iterator d_oi= doc_wrapper.object_iterator();
        Json_wrapper_object_iterator c_oi= containee_wr.object_iterator();
        Json_key_comparator cmp;
        
        while (!c_oi.empty() && !d_oi.empty())
        {
            for(; !d_oi.empty() && cmp(d_oi.elt().first, c_oi.elt().first);
                d_oi.next()) {}
            
            if (d_oi.empty() || cmp(c_oi.elt().first, d_oi.elt().first))
            {
                *result= false;
                return false;
            }
            
            // key is the same, now compare values
            if (contains_wr(d_oi.elt().second, c_oi.elt().second, result))
                return true;                          /* purecov: inspected */
            if (!*result)
            {
                // Value didn't match, give up.
                return false;
            }
            c_oi.next();
        }
        *result= c_oi.empty(); // must be exhausted
        return false;
    }
    
    if (doc_wrapper.type() == Json_dom::J_ARRAY)
    {
        const Json_wrapper *wr= &containee_wr;
        Json_wrapper a_wr;
        
        if (containee_wr.type() != Json_dom::J_ARRAY)
        {
            // auto-wrap scalar or object in an array for uniform treatment later
            Json_wrapper scalar= containee_wr;
            Json_array *array_dom= new (std::nothrow) Json_array();
            if (!array_dom || array_dom->append_clone(scalar.to_dom()))
            {
                delete array_dom;                       /* purecov: inspected */
                return true;                            /* purecov: inspected */
            }
            Json_wrapper nw(array_dom);
            a_wr.steal(&nw);
            wr= &a_wr;
        }
        
        // Indirection vectors containing the original indices
        Sorted_index_array d(key_memory_JSON);
        Sorted_index_array c(key_memory_JSON);
        
        // Sort both vectors, so we can compare efficiently
        if (sort_array(doc_wrapper, &d) || sort_array(*wr, &c))
            return true;                              /* purecov: inspected */
        
        size_t doc_i= 0;
        
        for (size_t c_i= 0; c_i < c.size(); c_i++)
        {
            Json_dom::enum_json_type candt= (*wr)[c[c_i]].type();
            
            if (candt == Json_dom::J_ARRAY)
            {
                while (doc_i < d.size() &&
                       doc_wrapper[d[doc_i]].type() < candt)
                {
                    doc_i++;
                }
                
                bool found= false;
                /*
                 We do not increase doc_i here, use a tmp. We might need to check again
                 against doc_i: this allows duplicates in the candidate.
                 */
                for (size_t tmp= doc_i;
                     tmp < d.size() && doc_wrapper[d[tmp]].type() == Json_dom::J_ARRAY;
                     tmp++)
                {
                    if (contains_wr(doc_wrapper[d[tmp]], (*wr)[c[c_i]], result))
                        return true;                      /* purecov: inspected */
                    if (*result)
                    {
                        found= true;
                        break;
                    }
                }
                
                if (!found)
                {
                    *result= false;
                    return false;
                }
            }
            else
            {
                bool found= false;
                size_t tmp= doc_i;
                
                while (tmp < d.size())
                {
                    if (doc_wrapper[d[tmp]].type() == Json_dom::J_ARRAY ||
                        doc_wrapper[d[tmp]].type() == Json_dom::J_OBJECT)
                    {
                        if (contains_wr(doc_wrapper[d[tmp]], (*wr)[c[c_i]], result))
                            return true;                    /* purecov: inspected */
                        if (*result)
                        {
                            found= true;
                            break;
                        }
                    }
                    else if (doc_wrapper[d[tmp]].compare((*wr)[c[c_i]]) == 0)
                    {
                        found= true;
                        break;
                    }
                    tmp++;
                }
                
                if (doc_i == d.size() || !found)
                {
                    *result= false;
                    return false;
                }
            }
        }
        
        *result= true;
        return false;
    }
    
    *result= (doc_wrapper.compare(containee_wr) == 0);
    return false;
}


void Item_func_json_contains::cleanup()
{
    Item_int_func::cleanup();
    
//    m_path_cache.reset_cache();
}


longlong Item_func_json_contains::val_int()
{
    DBUG_ASSERT(fixed == 1);
    
    try
    {
        Json_wrapper doc_wrapper;
        
        // arg 0 is the document
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &doc_wrapper) ||
            args[0]->null_value)
        {
            null_value= true;
            return 0;
        }
        
        Json_wrapper containee_wr;
        
        // arg 1 is the possible containee
        if (get_json_wrapper(args, 1, &m_doc_value, func_name(), &containee_wr) ||
            args[1]->null_value)
        {
            null_value= true;
            return 0;
        }
        
        if (arg_count == 3)
        {
            // path is specified
//            if (m_path_cache.parse_and_cache_path(args, 2, true))
//            {
//                null_value= true;
//                return 0;
//            }
//            Json_path *path= m_path_cache.get_path(2);
//            
            Json_wrapper_vector v(key_memory_JSON);
//            if (doc_wrapper.seek(*path, &v, true, false))
//                return error_int();                 /* purecov: inspected */
            
            if (v.size() == 0)
            {
                null_value= true;
                return 0;
            }
            
            bool ret;
            if (contains_wr(v[0], containee_wr, &ret))
                return error_int();                /* purecov: inspected */
            null_value= false;
            return ret;
        }
        else
        {
            bool ret;
            if (contains_wr(doc_wrapper, containee_wr, &ret))
                return error_int();                /* purecov: inspected */
            null_value= false;
            return ret;
        }
    } CATCH_ALL("json_contains", return error_int()) /* purecov: inspected */
}


void Item_func_json_contains_path::cleanup()
{
    Item_int_func::cleanup();
    
//    m_path_cache.reset_cache();
    m_cached_ooa= ooa_uninitialized;
}

longlong Item_func_json_contains_path::val_int()
{
    DBUG_ASSERT(fixed == 1);
    longlong result= 0;
    null_value= false;
    
    Json_wrapper wrapper;
    Json_wrapper_vector hits(key_memory_JSON);
    
    try
    {
        // arg 0 is the document
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &wrapper) ||
            args[0]->null_value)
        {
            null_value= true;
            return 0;
        }
        
        // arg 1 is the oneOrAll flag
        bool require_all;
        switch (parse_and_cache_ooa(args[1], &m_one_or_all_value,
                                    &m_cached_ooa, func_name()))
        {
            case ooa_all:
            {
                require_all= true;
                break;
            }
            case ooa_one:
            {
                require_all= false;
                break;
            }
            case ooa_null:
            {
                null_value= true;
                return 0;
            }
            default:
            {
                return error_int();
            }
        }
        
        // the remaining args are paths
        for (uint32 i= 2; i < arg_count; ++i)
        {
//            if (m_path_cache.parse_and_cache_path(args, i, false))
//            {
//                null_value= true;
//                return 0;
//            }
//            Json_path *path= m_path_cache.get_path(i);
//            
//            hits.clear();
//            if (wrapper.seek(*path, &hits, true, true))
//                return error_int();               /* purecov: inspected */
            if (hits.size() > 0)
            {
                result= 1;
                if (!require_all)
                {
                    break;
                }
            }
            else
            {
                if (require_all)
                {
                    result= 0;
                    break;
                }
            }
        }
        
    } CATCH_ALL("json_contains_path", return error_int()) /* purecov: inspected */
    
    return result;
}


bool json_value(Item **args, uint arg_idx, Json_wrapper *result)
{
    Item *arg= args[arg_idx];
    
    if (arg->field_type() == MYSQL_TYPE_NULL)
    {
        arg->update_null_value();
        DBUG_ASSERT(arg->null_value);
        return false;
    }
    
    if (arg->field_type() != MYSQL_TYPE_JSON)
    {
        // This is not a JSON value. Give up.
        return true;
    }
    
    return arg->val_json(result);
}


bool get_json_wrapper(Item **args,
                      uint arg_idx,
                      String *str,
                      const char *func_name,
                      Json_wrapper *wrapper,
                      bool preserve_neg_zero_int)
{
    if (!json_value(args, arg_idx, wrapper))
    {
        // Found a JSON value, return successfully.
        return false;
    }
    
    if (args[arg_idx]->field_type() == MYSQL_TYPE_JSON)
    {
        /*
         If the type of the argument is JSON and json_value() returned
         false, it means the argument didn't contain valid JSON data.
         Give up.
         */
        return true;
    }
    
    /*
     Otherwise, it's a non-JSON type, so we need to see if we can
     convert it to JSON.
     */
    
    /* Is this a JSON text? */
    Json_dom *dom; //@< we'll receive a DOM here from a successful text parse
    
    bool valid;
    if (json_is_valid(args, arg_idx, str, func_name, &dom, true, &valid,
                      preserve_neg_zero_int))
        return true;
    
    if (!valid)
    {
        my_error(ER_INVALID_TYPE_FOR_JSON, MYF(0), arg_idx + 1, func_name);
        return true;
    }
    
    if (args[arg_idx]->null_value)
    {
        return false;
    }
    
    DBUG_ASSERT(dom);
    
    *wrapper= Json_wrapper(dom);
    return false;
    
}

/**
 Compute an index into json_type_string_map
 to be applied to certain sub-types of J_OPAQUE.
 
 @param field_type[in] The refined field type of the opaque value.
 
 @return an index into json_type_string_map
 */
static uint opaque_index(enum_field_types field_type)
{
    uint offset= 0;
    
    switch (field_type)
    {
        case MYSQL_TYPE_VARCHAR:
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_LONG_BLOB:
        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_STRING:
        {
            offset= static_cast<uint>(Json_dom::J_OPAQUE_BLOB);
            break;
        }
            
        case MYSQL_TYPE_BIT:
        {
            offset= static_cast<uint>(Json_dom::J_OPAQUE_BIT);
            break;
        }
            
        case MYSQL_TYPE_GEOMETRY:
        {
            /**
             Should not get here. This path should be orphaned by the
             work done on implicit CASTing of geometry values to geojson
             objects. However, that work was done late in the project
             cycle for WL#7909. Do something sensible in case we missed
             something.
             
             FIXME.
             */
            /* purecov: begin deadcode */
            DBUG_ABORT();
            offset= static_cast<uint>(Json_dom::J_OPAQUE_GEOMETRY);
            break;
            /* purecov: end */
        }
            
        default:
        {
            return static_cast<uint>(Json_dom::J_OPAQUE);
        }
    }
    
    return 1 + static_cast<uint>(Json_dom::J_ERROR) + offset;
}

String *Item_func_json_type::val_str(String *str)
{
    DBUG_ASSERT(fixed == 1);
    
    try
    {
        Json_wrapper wr;
        if (get_json_wrapper(args, 0, &m_value, func_name(), &wr) ||
            args[0]->null_value)
        {
            null_value= true;
            return NULL;
        }
        
        const Json_dom::enum_json_type type= wr.type();
        uint typename_idx= static_cast<uint>(type);
        if (type == Json_dom::J_OPAQUE)
        {
            typename_idx= opaque_index(wr.field_type());
        }
        
        m_value.length(0);
        if (m_value.append(Json_dom::json_type_string_map[typename_idx]))
            return error_str();                     /* purecov: inspected */
        
    } CATCH_ALL("json_type", return error_str()) /* purecov: inspected */
    
    null_value= false;
    return &m_value;
}


String *Item_json_func::val_str(String *str)
{
    DBUG_ASSERT(fixed == 1);
    Json_wrapper wr;
    if (val_json(&wr))
        return error_str();
    
    if (null_value)
        return NULL;
    
    m_string_buffer.length(0);
    
    if (wr.to_string(&m_string_buffer, true, func_name()))
        return error_str();
    
    null_value= false;
    return &m_string_buffer;
}


bool Item_json_func::get_date(MYSQL_TIME *ltime, my_time_flags_t fuzzydate)
{
    Json_wrapper wr;
    if (val_json(&wr))
        return true;
    
    if (null_value)
        return true;
    
    return wr.coerce_date(ltime, fuzzydate, func_name());
}


bool Item_json_func::get_time(MYSQL_TIME *ltime)
{
    Json_wrapper wr;
    if (val_json(&wr))
        return true;
    
    if (null_value)
        return true;
    
    return wr.coerce_time(ltime, func_name());
}


longlong Item_json_func::val_int()
{
    Json_wrapper wr;
    if (val_json(&wr))
        return 0;
    
    if (null_value)
        return 0;
    
    return wr.coerce_int(func_name());
}


double Item_json_func::val_real()
{
    char buff[MAX_FIELD_WIDTH];
    String str(buff, sizeof(buff), &my_charset_utf8mb4_bin);
    Json_wrapper wr;
    if (val_json(&wr))
        return 0.0;
    
    if (null_value)
        return 0.0;
    
    return wr.coerce_real(func_name());
}

my_decimal *Item_json_func::val_decimal(my_decimal *decimal_value)
{
    char buff[MAX_FIELD_WIDTH];
    String str(buff, sizeof(buff), &my_charset_utf8mb4_bin);
    Json_wrapper wr;
    
    if (val_json(&wr))
    {
        my_decimal_set_zero(decimal_value);
        return decimal_value;
    }
    if (null_value)
    {
        my_decimal_set_zero(decimal_value);
        return decimal_value;
    }
    return wr.coerce_decimal(decimal_value, func_name());
}


/**
 Type that is capable of holding objects of any sub-type of
 Json_scalar. Used for pre-allocating space in query-duration memory
 for JSON scalars that are to be returned by get_json_atom_wrapper().
 
 Note: boost::blank is included in the variant to ensure that it
 includes a type that is known to be nothrow default-constructible.
 The presence of such a type avoids heap allocation when assigning a
 new value to the variant. Look for the "never-empty" guarantee in
 the Boost documentation for details.
 */
struct Json_scalar_holder : public Sql_alloc
{
//    boost::variant<boost::blank, Json_string, Json_decimal, Json_int, Json_uint,
//    Json_double, Json_boolean, Json_null, Json_datetime,
//    Json_opaque> m_val;
};


/**
 Get a JSON value from a function, field or subselect scalar.
 
 @param[in]     arg         the function argument
 @param[in]     calling_function the name of the calling function
 @param[in,out] value       a scratch area
 @param[in,out] tmp         temporary scratch space for converting strings to
 the correct charset; only used if accept_string is
 true and conversion is needed
 @param[out]    wr          the retrieved JSON value
 @param[in,out] scalar      pointer to pre-allocated memory that can be
 borrowed by the result wrapper to hold the scalar
 result. If the pointer is NULL, memory will be
 allocated on the heap.
 @param[in]     accept_string
 if true, accept SQL strings as scalars
 (false implies we need a valid
 JSON parsable string)
 @return false if we could get a value or NULL, otherwise true
 */
bool val_json_func_field_subselect(Item* arg,
                                   const char *calling_function,
                                   String *value,
                                   String *tmp,
                                   Json_wrapper *wr,
                                   Json_scalar_holder *scalar,
                                   bool accept_string)
{
    enum_field_types field_type= get_normalized_field_type(arg);
    Json_dom *dom= NULL;
    
    switch (field_type)
    {
        case MYSQL_TYPE_INT24:
        case MYSQL_TYPE_LONG:
        case MYSQL_TYPE_SHORT:
        case MYSQL_TYPE_TINY:
        case MYSQL_TYPE_LONGLONG:
        {
            longlong i= arg->val_int();
            
            if (arg->null_value)
                return false;
            
            if (arg->unsigned_flag)
            {
                if (scalar)
                {
//                    scalar->m_val= Json_uint(i);
                }
                else
                {
                    dom= new (std::nothrow) Json_uint(i);
                    if (!dom)
                        return true;                       /* purecov: inspected */
                }
            }
            else if (scalar)
            {
//                scalar->m_val= Json_int(i);
            }
            else
            {
                dom= new (std::nothrow) Json_int(i);
                if (!dom)
                    return true;                         /* purecov: inspected */
            }
            
            break;
        }
        case MYSQL_TYPE_DATE:
        case MYSQL_TYPE_DATETIME:
        case MYSQL_TYPE_TIMESTAMP:
        case MYSQL_TYPE_TIME:
        {
            longlong dt= arg->val_temporal_by_field_type();
            
            if (arg->null_value)
                return false;
            
            MYSQL_TIME t;
            TIME_from_longlong_datetime_packed(&t, dt);
            t.time_type= field_type_to_timestamp_type(field_type);
            if (scalar)
            {
//                scalar->m_val= Json_datetime(t, field_type);
            }
            else
            {
                dom= new (std::nothrow) Json_datetime(t, field_type);
                if (!dom)
                    return true;                         /* purecov: inspected */
            }
            break;
        }
        case MYSQL_TYPE_NEWDECIMAL:
        {
            my_decimal m;
            my_decimal *r= arg->val_decimal(&m);
            
            if (arg->null_value)
                return false;
            
            if (!r)
            {
                my_error(ER_INVALID_CAST_TO_JSON, MYF(0));
                return true;
            }
            
            if (scalar)
            {
//                scalar->m_val= Json_decimal(*r);
            }
            else
            {
                dom= new (std::nothrow) Json_decimal(*r);
                if (!dom)
                    return true;                         /* purecov: inspected */
            }
            break;
        }
        case MYSQL_TYPE_DOUBLE:
        case MYSQL_TYPE_FLOAT:
        {
            double d= arg->val_real();
            
            if (arg->null_value)
                return false;
            
            if (scalar)
            {
//                scalar->m_val= Json_double(d);
            }
            else
            {
                dom= new (std::nothrow) Json_double(d);
                if (!dom)
                    return true;                         /* purecov: inspected */
            }
            break;
        }
//        case MYSQL_TYPE_GEOMETRY:
//        {
//            uint32 geometry_srid;
//            bool retval= geometry_to_json(wr, arg, calling_function, INT_MAX32,
//                                          false, false, false, &geometry_srid);
//            
//            /**
//             Scalar processing is irrelevant. Geometry types are converted
//             to JSON objects.
//             */
//            return retval;
//        }
        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_BIT:
        case MYSQL_TYPE_LONG_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_YEAR:
        {
            String *oo= arg->val_str(value);
            
            if (arg->null_value)
                return false;
            
            if (arg->type() == Item::FIELD_ITEM && field_type == MYSQL_TYPE_BLOB)
            {
                Item_field *it_f= down_cast<Item_field *>(arg);
                Field *f= it_f->field;
                Field_blob *fb= down_cast<Field_blob *>(f);
                switch (fb->pack_length() - portable_sizeof_char_ptr)
                {
                    case 1:
                        field_type= MYSQL_TYPE_TINY_BLOB;
                        break;
                    case 2:
                        field_type= MYSQL_TYPE_BLOB;
                        break;
                    case 3:
                        field_type= MYSQL_TYPE_MEDIUM_BLOB;
                        break;
                    case 4:
                        field_type= MYSQL_TYPE_LONG_BLOB;
                        break;
                    default:
                        DBUG_ABORT();
                }
            }
            
            if (scalar)
            {
//                scalar->m_val= Json_opaque(field_type, oo->ptr(), oo->length());
            }
            else
            {
                dom= new (std::nothrow) Json_opaque(field_type,
                                                    oo->ptr(), oo->length());
                if (!dom)
                    return true;                         /* purecov: inspected */
            }
            break;
        }
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_VARCHAR:
        case MYSQL_TYPE_ENUM:
        case MYSQL_TYPE_SET:
        case MYSQL_TYPE_STRING:
        {
            /*
             Wrong charset or Json syntax error (the latter: only if !accept_string,
             in which case a binary character set is our only hope for success).
             */
            String *res= arg->val_str(value);
            
            if (arg->null_value)
                return false;
            const CHARSET_INFO *cs= res->charset();
            
            if (cs == &my_charset_bin)
            {
                // BINARY or similar
                if (scalar)
                {
//                    scalar->m_val= Json_opaque(field_type, res->ptr(), res->length());
                }
                else
                {
                    dom= new (std::nothrow) Json_opaque(field_type,
                                                        res->ptr(), res->length());
                    if (!dom)
                        return true;                       /* purecov: inspected */
                }
                break;
            }
            else if (accept_string)
            {
                const char *s= res->ptr();
                size_t ss= res->length();
                
                if (ensure_utf8mb4(res, tmp, &s, &ss, true))
                {
                    return true;
                }
                
                if (scalar)
                {
//                    scalar->m_val= Json_string(std::string(s, ss));
                }
                else
                {
                    dom= new (std::nothrow) Json_string(std::string(s, ss));
                    if (!dom)
                        return true;                       /* purecov: inspected */
                }
            }
            else
            {
                my_error(ER_INVALID_CAST_TO_JSON, MYF(0));
                return true;
            }
            break;
        }
        case MYSQL_TYPE_DECIMAL:                      // pre 5.0
            my_error(ER_NOT_SUPPORTED_YET, MYF(0), "old decimal type");
            return true;
            
        case MYSQL_TYPE_NULL:
            /*
             This shouldn't happen, since the only caller of this function
             returns earlier if it sees that the type is MYSQL_TYPE_NULL.
             */
            /* purecov: begin inspected */
            arg->update_null_value();
            DBUG_ASSERT(arg->null_value);
            return false;
            /* purecov: end */
            
        case MYSQL_TYPE_JSON:
            DBUG_ABORT();                               /* purecov: inspected */
            // fall-through
        default:
            my_error(ER_INVALID_CAST_TO_JSON, MYF(0));
            return true;
    }
    
    // Exactly one of scalar and dom should be used.
    DBUG_ASSERT((scalar == NULL) != (dom == NULL));
    DBUG_ASSERT((scalar == NULL) ||
                (get_json_scalar_from_holder(scalar) != NULL));
    
    Json_wrapper w(scalar ? get_json_scalar_from_holder(scalar) : dom);
    if (scalar)
    {
        /*
         The DOM object lives in memory owned by the caller. Tell the
         wrapper that it's not the owner.
         */
        w.set_alias();
    }
    wr->steal(&w);
    
    return false;
}


/**
 Try to determine whether an argument has a boolean (as opposed
 to an int) type, and if so, return its boolean value.
 
 @param[in] arg The argument to inspect.
 @param[in/out] result Fill in the result if this is a boolean arg.
 
 @return True if the arg can be determined to have a boolean type.
 */
bool extract_boolean(Item *arg, bool *result)
{
    if (arg->is_bool_func())
    {
        *result= arg->val_int();
        return true;
    }
    
    if (arg->type() == Item::SUBSELECT_ITEM)
    {
        // EXISTS, IN, ALL, ANY subqueries have boolean type
        Item_subselect *subs= down_cast<Item_subselect *>(arg);
        switch (subs->substype())
        {
            case Item_subselect::EXISTS_SUBS:
            case Item_subselect::IN_SUBS:
            case Item_subselect::ALL_SUBS:
            case Item_subselect::ANY_SUBS:
                *result= arg->val_int();
                return true;
            default:
                break;
        }
    }
    
    if (arg->type() == Item::INT_ITEM)
    {
        const Name_string * const name= &arg->item_name;
        const bool is_literal_false= name->is_set() && name->eq("FALSE");
        const bool is_literal_true= name->is_set() && name->eq("TRUE");
        if (is_literal_false || is_literal_true)
        {
            *result= is_literal_true;
            return true;
        }
    }
    
    // doesn't fit any of the checks we perform
    return false;
}

// see the contract for this function in item_json_func.h
bool get_json_atom_wrapper(Item **args,
                           uint arg_idx,
                           const char *calling_function,
                           String *value,
                           String *tmp,
                           Json_wrapper *wr,
                           Json_scalar_holder *scalar,
                           bool accept_string)
{
    bool result= false;
    
    Item * const arg= args[arg_idx];
    
    try
    {
        if (!json_value(args, arg_idx, wr))
        {
            return false;
        }
        
        if (arg->field_type() == MYSQL_TYPE_JSON)
        {
            /*
             If the type of the argument is JSON and json_value() returned
             false, it means the argument didn't contain valid JSON data.
             Give up.
             */
            return true;
        }
        
        // boolean operators should produce boolean values
        bool  boolean_value;
        if (extract_boolean(arg, &boolean_value))
        {
            Json_dom *boolean_dom;
            if (scalar)
            {
//                scalar->m_val= Json_boolean(boolean_value);
                boolean_dom= get_json_scalar_from_holder(scalar);
            }
            else
            {
                boolean_dom= new (std::nothrow) Json_boolean(boolean_value);
                if (!boolean_dom)
                    return true;                         /* purecov: inspected */
            }
            Json_wrapper wrapper(boolean_dom);
            if (scalar)
            {
                /*
                 The DOM object lives in memory owned by the caller. Tell the
                 wrapper that it's not the owner.
                 */
                wrapper.set_alias();
            }
            wr->steal(&wrapper);
            return false;
        }
        
        /*
         Allow other types as first-class or opaque JSON values.
         But how to determine what the type is? We do a best effort...
         */
        result= val_json_func_field_subselect(arg, calling_function, value, tmp, wr,
                                              scalar, accept_string);
        
    } CATCH_ALL("CAST(... AS JSON)", result= true) /* purecov: inspected */
    
    return result;
}


/**
 Convert JSON values or MySQL values to JSON. Converts SQL NULL
 to the JSON null literal.
 
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
 @returns false if we found a value or NULL, true otherwise
 */
bool get_atom_null_as_null(Item **args, uint arg_idx,
                           const char *calling_function, String *value,
                           String *tmp, Json_wrapper *wr)
{
    if (get_json_atom_wrapper(args, arg_idx, calling_function, value,
                              tmp, wr, NULL, true))
        return true;
    
    if (args[arg_idx]->null_value)
    {
        Json_wrapper null_wrapper(new (std::nothrow) Json_null());
        wr->steal(&null_wrapper);
    }
    
    return false;
}


bool Item_json_typecast::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    Json_dom *dom= NULL;       //@< if non-null we want a DOM from parse
    
    if (args[0]->field_type() == MYSQL_TYPE_NULL)
    {
        null_value= true;
        return false;
    }
    
    if (args[0]->field_type() == MYSQL_TYPE_JSON)
    {
        if (json_value(args, 0, wr))
            return error_json();
        
        null_value= args[0]->null_value;
        return false;
    }
    
    bool valid;
    if (json_is_valid(args, 0, &m_value, func_name(),
                      &dom, false, &valid))
        return error_json();
    
    if (valid)
    {
        if (args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        // We were able to parse a JSON value from a string.
        DBUG_ASSERT(dom);
        // Pass on the DOM wrapped
        Json_wrapper w(dom);
        wr->steal(&w);
        null_value= false;
        return false;
    }
    
    // Not a non-binary string, nor a JSON value, wrap the rest
    
    if (get_json_atom_wrapper(args, 0, func_name(), &m_value,
                              &m_conversion_buffer,
                              wr, NULL, true))
        return error_json();
    
    null_value= args[0]->null_value;
    return false;
}


void Item_json_typecast::print(String *str, enum_query_type query_type)
{
    str->append(STRING_WITH_LEN("cast("));
    args[0]->print(str, query_type);
    str->append(STRING_WITH_LEN(" as "));
    str->append(cast_type());
    str->append(')');
}


void Item_func_json_length::cleanup()
{
    Item_int_func::cleanup();
    
//    m_path_cache.reset_cache();
}


longlong Item_func_json_length::val_int()
{
    DBUG_ASSERT(fixed == 1);
    longlong result= 0;
    
    Json_wrapper wrapper;
    
    try
    {
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &wrapper) ||
            args[0]->null_value)
        {
            null_value= true;
            return 0;
        }
    } CATCH_ALL("json_length", return 0)        /* purecov: inspected */
    
    if (arg_count > 1)
    {
//        if (m_path_cache.parse_and_cache_path(args, 1, true))
//        {
//            null_value= true;
//            return 0;
//        }
//        Json_path *json_path= m_path_cache.get_path(1);
//        
        Json_wrapper_vector hits(key_memory_JSON);
//        if (wrapper.seek(*json_path, &hits, true, true))
//            return error_int();                 /* purecov: inspected */
        
        if (hits.size() != 1)
        {
            // path does not exist. return null.
            null_value= true;
            return 0;
        }
        
        // there should only be one hit because wildcards were forbidden
        DBUG_ASSERT(hits.size() == 1);
        
        wrapper.steal(&hits[0]);
    }
    
    result= wrapper.length();
    
    null_value= false;
    return result;
}


longlong Item_func_json_depth::val_int()
{
    DBUG_ASSERT(fixed == 1);
    longlong result= 0;
    
    Json_wrapper wrapper;
    
    try
    {
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &wrapper) ||
            args[0]->null_value)
        {
            null_value= true;
            return 0;
        }
    } CATCH_ALL("json_depth", return error_int()) /* purecov: inspected */
    
    result= wrapper.depth();
    
    null_value= false;
    return result;
}


bool Item_func_json_keys::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    Json_wrapper wrapper;
    
    try
    {
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &wrapper))
            return error_json();
        if (args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        
        if (arg_count > 1)
        {
//            if (m_path_cache.parse_and_cache_path(args, 1, true))
//            {
//                null_value= true;
//                return false;
//            }
//            Json_path *path= m_path_cache.get_path(1);
            
            Json_wrapper_vector hits(key_memory_JSON);
//            if (wrapper.seek(*path, &hits, false, true))
//                return error_json();              /* purecov: inspected */
            
            if (hits.size() != 1)
            {
                null_value= true;
                return false;
            }
            
            wrapper.steal(&hits[0]);
        }
        
        if (wrapper.type() != Json_dom::J_OBJECT)
        {
            null_value= true;
            return false;
        }
        
        // We have located a JSON object value, now collect its keys
        // and return them as a JSON array.
        Json_array *res= new (std::nothrow) Json_array();
        if (!res)
            return error_json();                /* purecov: inspected */
        for (Json_wrapper_object_iterator i(wrapper.object_iterator());
             !i.empty(); i.next())
        {
            if (res->append_alias(new (std::nothrow) Json_string(i.elt().first)))
            {
                delete res;                             /* purecov: inspected */
                return error_json();              /* purecov: inspected */
            }
        }
        Json_wrapper resw(res);
        wr->steal(&resw);
        
    } CATCH_ALL("json_keys", return error_json()) /* purecov: inspected */
    
    null_value= false;
    return false;
}


bool Item_func_json_extract::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    try
    {
        Json_wrapper w;
        
        // multiple paths means multiple possible matches
        bool could_return_multiple_matches= (arg_count > 2);
        
        // collect results here
        Json_wrapper_vector v(key_memory_JSON);
        
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &w))
            return error_json();
        
        if (args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        
        for (uint32 i= 1; i < arg_count; ++i)
        {
//            if (m_path_cache.parse_and_cache_path(args, i, false))
//            {
//                null_value= true;
//                return false;
//            }
//            Json_path *path= m_path_cache.get_path(i);
//            
//            if (path->contains_wildcard_or_ellipsis())
//            {
//                could_return_multiple_matches= true;
//            }
//            
//            if (w.seek(*path, &v, true, false))
//                return error_json();              /* purecov: inspected */
        }
        
        if (v.size() == 0)
        {
            null_value= true;
            return false;
        }
        else if (could_return_multiple_matches)
        {
            Json_array *a= new (std::nothrow) Json_array();
            if (!a)
                return error_json();              /* purecov: inspected */
            for (Json_wrapper_vector::iterator it= v.begin(); it != v.end(); ++it)
            {
                if (a->append_clone(it->to_dom()))
                {
                    delete a;                             /* purecov: inspected */
                    return error_json();            /* purecov: inspected */
                }
            }
            Json_wrapper w(a);
            wr->steal(&w);
        }
        else // one path, no ellipsis or wildcard
        {
            // there should only be one match
            DBUG_ASSERT(v.size() == 1);
            wr->steal(&v[0]);
        }
        
    } CATCH_ALL("json_extract", return error_json()) /* purecov: inspected */
    
    null_value= false;
    return false;
}

/**
 If there is no parent in v, we must have a path that specifified either
 - the root ('$'), or
 - an array cell at index 0 that any non-array element at the top level could
 have been autowrapped to (since we got a hit), i.e. '$[0]' or
 $[0][0]...[0]'.
 
 @param[in] path the specified path which gave a match
 @param[in] v    the JSON item matched
 @return true if v is a top level item
 */
static inline bool wrapped_top_level_item(Json_path *path, Json_dom *v)
{
    if (v->parent())
        return false;
    
#ifndef DBUG_OFF
    for (size_t i= 0; i < path->leg_count(); i++)
    {
        DBUG_ASSERT(path->get_leg_at(i)->get_type() == jpl_array_cell);
        DBUG_ASSERT(path->get_leg_at(i)->get_array_cell_index() == 0);
    }
#endif
    
    return true;
}


bool Item_func_json_array_append::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    try
    {
        Json_wrapper docw;
        
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &docw))
            return error_json();
        if (args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        
        for (uint32 i= 1; i < arg_count; i += 2)
        {
            // Need a DOM to be able to manipulate arrays
            Json_dom *doc= docw.to_dom();
            if (!doc)
                return error_json();              /* purecov: inspected */
            
//            if (m_path_cache.parse_and_cache_path(args, i, true))
//            {
//                // empty path (error signalled already)
//                null_value= true;
//                return false;
//            }
//            Json_path *path= m_path_cache.get_path(i);
            
            Json_dom_vector hits(key_memory_JSON);
//            if (doc->seek(*path, &hits, true, true))
//                return error_json();                  /* purecov: inspected */
            
            if (hits.size() < 1)
            {
                continue;
            }
            
            /*
             Iterate backwards lest we get into trouble with replacing outer
             parts of the doc before we get to paths to inner parts when we have
             ellipses in the path. Make sure we do the most nested replacements
             first. Json_dom::seek returns outermost hits first.
             
             Note that, later on, we decide to forbid ellipses in the path
             arguments to json_array_append().
             */
            for (Json_dom_vector::iterator it= hits.end(); it != hits.begin();)
            {
                --it;
                Json_wrapper valuew;
                if (get_atom_null_as_null(args, i + 1, func_name(), &m_value,
                                          &m_conversion_buffer,
                                          &valuew))
                    return error_json();
                
                if ((*it)->json_type() == Json_dom::J_ARRAY)
                {
                    Json_array *arr= down_cast<Json_array *>(*it);
                    if (arr->append_alias(valuew.to_dom()))
                        return error_json();   /* purecov: inspected */
                    valuew.set_alias(); // we have taken over the DOM
                }
                else
                {
                    Json_array *arr= new (std::nothrow) Json_array();
                    if (!arr ||
                        arr->append_clone(*it) ||
                        arr->append_alias(valuew.to_dom()))
                    {
                        delete arr;                         /* purecov: inspected */
                        return error_json();          /* purecov: inspected */
                    }
                    valuew.set_alias(); // we have taken over the DOM
                    /*
                     This value will replace the old document we found using path, since
                     we did an auto-wrap. If this is root, this is trivial, but if it's
                     inside an array or object, we need to find the parent DOM to be
                     able to replace it in situ.
                     */
//                    if (wrapped_top_level_item(path, (*it)))
//                    {
//                        Json_wrapper newroot(arr);
//                        docw.steal(&newroot);
//                    }
//                    else
//                    {
//                        Json_dom *parent= (*it)->parent();
//                        parent->replace_dom_in_container(*it, arr);
//                    }
                }
            }
        }
        
        // docw still owns the augmented doc, so hand it over to result
        wr->steal(&docw);
        
    } CATCH_ALL("json_array_append", return error_json()) /* purecov: inspected */
    
    null_value= false;
    return false;
}


bool Item_func_json_insert::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    try
    {
        Json_wrapper docw;
        
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &docw))
            return error_json();
        
        if(args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        
        for (uint32 i= 1; i < arg_count; i += 2)
        {
            // Need a DOM to be able to manipulate arrays and objects
            Json_dom *doc= docw.to_dom();
            if (!doc)
                return error_json();              /* purecov: inspected */
            
//            if (m_path_cache.parse_and_cache_path(args, i, true))
//            {
//                // empty path (error signalled already)
//                null_value= true;
//                return false;
//            }
//            Json_path *current_path= m_path_cache.get_path(i);
            
            /**
             Clone the path so that we won't mess up the cached version
             when we pop the trailing leg below.
             */
//            m_path.set(current_path);
            
            {
                Json_dom_vector hits(key_memory_JSON);
                if (doc->seek(m_path, &hits, false, true))
                    return error_json();                /* purecov: inspected */
                
                if (hits.size() != 0 || // already exists
                    m_path.leg_count() == 0) // is root
                {
                    continue;
                }
            }
            
            /*
             Need to look one step up the path: if we are specifying an array slot
             we need to find the array. If we are specifying an object element, we
             need to find the object. In both cases so we can insert into them.
             
             Remove the first path leg and search again.
             */
            Json_dom_vector hits(key_memory_JSON);
            const Json_path_leg *leg= m_path.pop();
            if (doc->seek(m_path, &hits, false, true))
                return error_json();                  /* purecov: inspected */
            
            if (hits.size() < 1)
            {
                // no unique object found at parent position, so bail out
                continue;
            }
            
            Json_wrapper valuew;
            if (get_atom_null_as_null(args, i + 1, func_name(), &m_value,
                                      &m_conversion_buffer,
                                      &valuew))
            {
                return error_json();
            }
            
            /*
             Iterate backwards lest we get into trouble with replacing outer
             parts of the doc before we get to paths to inner parts when we have
             ellipses in the path. Make sure we do the most nested replacements
             first. Json_dom::seek returns outermost hits first.
             
             Note that, later on, we decided to forbid ellipses in the path
             arguments to json_insert().
             */
            for (Json_dom_vector::iterator it= hits.end(); it != hits.begin();)
            {
                --it;
                // We found *something* at that parent path
                
                // What did we specify in the path, object or array?
                if (leg->get_type() == jpl_array_cell)
                {
                    // We specified an array, what did we find at that position?
                    if ((*it)->json_type() == Json_dom::J_ARRAY)
                    {
                        Json_array *arr= down_cast<Json_array *>(*it);
                        DBUG_ASSERT(leg->get_type() == jpl_array_cell);
                        if (arr->insert_clone(leg->get_array_cell_index(), valuew.to_dom()))
                            return error_json();        /* purecov: inspected */
                    }
                    else if (leg->get_array_cell_index() > 0)
                    {
                        /*
                         Found a scalar or object and we didn't specify position 0:
                         auto-wrap it
                         */
                        Json_dom *a= *it;
                        Json_array *newarr= new (std::nothrow) Json_array();
                        if (!newarr ||
                            newarr->append_clone(a) /* auto-wrap this */ ||
                            newarr->insert_clone(leg->get_array_cell_index(),
                                                 valuew.to_dom()))
                        {
                            delete newarr;                    /* purecov: inspected */
                            return error_json();        /* purecov: inspected */
                        }
                        
                        /*
                         Now we need this value to replace the old document we found using
                         path. If this is root, this is trivial, but if it's inside an
                         array or object, we need to find the parent DOM to be able to
                         replace it in situ.
                         */
                        if (m_path.leg_count() == 0) // root
                        {
                            Json_wrapper newroot(newarr);
                            docw.steal(&newroot);
                        } else
                        {
                            Json_dom *parent= a->parent();
                            DBUG_ASSERT(parent);
                            
                            parent->replace_dom_in_container(a, newarr);
                        }
                    }
                }
                else if (leg->get_type() == jpl_member &&
                         (*it)->json_type() == Json_dom::J_OBJECT)
                {
                    Json_object *o= down_cast<Json_object *>(*it);
                    const char *ename= leg->get_member_name();
                    size_t enames= leg->get_member_name_length();
                    if (o->add_clone(std::string(ename, enames), valuew.to_dom()))
                        return error_json();          /* purecov: inspected */
                }
            }
            
        } // end of loop through paths
        // docw still owns the augmented doc, so hand it over to result
        wr->steal(&docw);
        
    } CATCH_ALL("json_insert", return error_json()) /* purecov: inspected */
    
    null_value= false;
    return false;
}

bool Item_func_json_array_insert::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    try
    {
        Json_wrapper docw;
        
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &docw))
            return error_json();
        
        if (args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        
        for (uint32 i= 1; i < arg_count; i+= 2)
        {
            // Need a DOM to be able to manipulate arrays and objects
            Json_dom *doc= docw.to_dom();
            if (!doc)
                return error_json();              /* purecov: inspected */
            
//            if (m_path_cache.parse_and_cache_path(args, i, true))
//            {
//                // empty path (error signalled already)
//                null_value= true;
//                return false;
//            }
//            Json_path *current_path= m_path_cache.get_path(i);
            
            /**
             Clone the path so that we won't mess up the cached version
             when we pop the trailing leg below.
             */
//            m_path.set(current_path);
            
            // the path must end in a cell identifier
            size_t leg_count= m_path.leg_count();
            if ((leg_count == 0) ||
                (m_path.get_leg_at(leg_count - 1)->get_type() != jpl_array_cell))
            {
                my_error(ER_INVALID_JSON_PATH_ARRAY_CELL, MYF(0));
                return error_json();
            }
            
            /*
             Need to look one step up the path: we need to find the array.
             
             Remove the last path leg and search again.
             */
            Json_dom_vector hits(key_memory_JSON);
            const Json_path_leg *leg= m_path.pop();
            if (doc->seek(m_path, &hits, false, true))
                return error_json();                  /* purecov: inspected */
            
            if (hits.empty())
            {
                // no unique object found at parent position, so bail out
                continue;
            }
            
            Json_wrapper valuew;
            if (get_atom_null_as_null(args, i + 1, func_name(),
                                      &m_value, &m_conversion_buffer,
                                      &valuew))
            {
                return error_json();
            }
            
            /*
             Iterate backwards lest we get into trouble with replacing outer
             parts of the doc before we get to paths to inner parts when we have
             ellipses in the path. Make sure we do the most nested replacements
             first. Json_dom::seek returns outermost hits first.
             
             Note that, later on, we decided to forbid ellipses in the path
             arguments to json_insert().
             */
            for (Json_dom_vector::iterator it= hits.end(); it != hits.begin();)
            {
                --it;
                // We found *something* at that parent path
                
                // NOP if parent is not an array
                
                if ((*it)->json_type() == Json_dom::J_ARRAY)
                {
                    // Excellent. Insert the value at that location.
                    Json_array *arr= down_cast<Json_array *>(*it);
                    DBUG_ASSERT(leg->get_type() == jpl_array_cell);
                    if (arr->insert_clone(leg->get_array_cell_index(), valuew.to_dom()))
                        return error_json();        /* purecov: inspected */
                }
            }
            
        } // end of loop through paths
        // docw still owns the augmented doc, so hand it over to result
        wr->steal(&docw);
        
    } CATCH_ALL("json_array_insert", return error_json()) /* purecov: inspected */
    
    null_value= false;
    return false;
}


/**
 Clone a source path to a target path, stripping out [0] legs
 which are made redundant by the auto-wrapping rule
 in the WL#7909 spec:
 
 "If a pathExpression identifies a non-array value,
 then pathExpression[ 0 ] evaluates to the same value
 as pathExpression."
 
 @param[in]      source_path The original path.
 @param[in,out]  target_path The clone to be filled in.
 @param[in]      doc The document to seek through.
 
 @returns True if an error occurred. False otherwise.
 */
static bool clone_without_autowrapping(Json_path *source_path,
                                       Json_path_clone *target_path,
                                       Json_dom *doc)
{
    Json_dom_vector hits(key_memory_JSON);
    
    target_path->clear();
    size_t leg_count= source_path->leg_count();
    for (size_t leg_idx= 0; leg_idx < leg_count; leg_idx++)
    {
        const Json_path_leg *path_leg= source_path->get_leg_at(leg_idx);
        if ((path_leg->get_type() == jpl_array_cell) &&
            (path_leg->get_array_cell_index() == 0))
        {
            /**
             We have a partial path of the form
             
             pathExpression[0]
             
             So see if pathExpression identifies a non-array value.
             */
            hits.clear();
            if (doc->seek(*target_path, &hits, false, true))
                return true;  /* purecov: inspected */
            
            if (!hits.empty())
            {
                Json_dom *candidate= hits.at(0);
                if (candidate->json_type() != Json_dom::J_ARRAY)
                {
                    /**
                     pathExpression identifies a non-array value.
                     We satisfy the conditions of the rule above.
                     So we can throw away the [0] leg.
                     */
                    continue;
                }
            }
        }
        // The rule above is NOT satisified. So add the leg.
        target_path->append(path_leg);
    }
    hits.clear();
    
    return false;
}


/**
 Common implementation for JSON_SET and JSON_REPLACE
 */
bool Item_func_json_set_replace::val_json(Json_wrapper *wr)
{
    try
    {
        Json_wrapper docw;
        
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &docw))
            return error_json();
        
        if(args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        
        for (uint32 i= 1; i < arg_count; i += 2)
        {
            // Need a DOM to be able to manipulate arrays and objects
            Json_dom *doc= docw.to_dom();
            if (!doc)
                return error_json();                    /* purecov: inspected */
            
//            if (m_path_cache.parse_and_cache_path(args, i, true))
//            {
//                // empty path (error signalled already)
//                null_value= true;
//                return false;
//            }
//            Json_path *current_path= m_path_cache.get_path(i);
//            
            /**
             Clone the path, stripping off redundant auto-wrapping.
             */
//            if (clone_without_autowrapping(current_path, &m_path, doc))
//            {
//                return error_json();
//            }
//            
            Json_dom_vector hits(key_memory_JSON);
            if (doc->seek(m_path, &hits, false, true))
                return error_json();                  /* purecov: inspected */
            
            Json_wrapper valuew;
            if (get_atom_null_as_null(args, i + 1, func_name(), &m_value,
                                      &m_conversion_buffer,
                                      &valuew))
                return error_json();
            
            if (hits.size() == 0)
            {
                /*
                 Need to look one step up the path: if we are specifying an array slot
                 we need to find the array. If we are specifying an object element, we
                 need to find the object. In both cases so we can insert into them.
                 
                 Remove the first path leg and search again.
                 */
                const Json_path_leg *leg= m_path.pop();
                if (doc->seek(m_path, &hits, false, true))
                    return error_json();                /* purecov: inspected */
                
                if (hits.size() < 1)
                {
                    // no unique object found at parent position, so bail out
                    continue;
                }
                
                /*
                 Iterate backwards lest we get into trouble with replacing outer
                 parts of the doc before we get to paths to inner parts when we have
                 ellipses in the path. Make sure we do the most nested replacements
                 first. Json_dom::seek returns outermost hits first.
                 */
                for (Json_dom_vector::iterator it= hits.end(); it != hits.begin();)
                {
                    --it;
                    // We now have either an array or an object in the parent's path
                    if (leg->get_type() == jpl_array_cell)
                    {
                        if ((*it)->json_type() == Json_dom::J_ARRAY)
                        {
                            if (!m_json_set) // replace semantics, so skip if path not present
                                continue;
                            
                            Json_array *arr= down_cast<Json_array *>(*it);
                            DBUG_ASSERT(leg->get_type() == jpl_array_cell);
                            if (arr->insert_clone(leg->get_array_cell_index(),
                                                  valuew.to_dom()))
                                return error_json();            /* purecov: inspected */
                        }
                        else
                        {
                            /*
                             Found a scalar or object, auto-wrap it and make it the first
                             element in a new array, unless the new value specifies position
                             0, in which case the old gets replaced.
                             */
                            Json_dom *a= *it;
                            Json_dom *res;
                            
                            if (leg->get_array_cell_index() == 0)
                            {
                                res= valuew.clone_dom();
                                if (!res)
                                    return error_json();          /* purecov: inspected */
                            }
                            else
                            {
                                // replace semantics, so we don't get larger array
                                if (!m_json_set)
                                    continue;
                                
                                Json_array *newarr= new (std::nothrow) Json_array();
                                if (!newarr ||
                                    newarr->append_clone(a) ||
                                    newarr->insert_clone(leg->get_array_cell_index(),
                                                         valuew.to_dom()))
                                {
                                    delete newarr;                /* purecov: inspected */
                                    return error_json();          /* purecov: inspected */
                                }
                                res= newarr;
                            }
                            
                            /*
                             Now we need this value to replace the old document we found
                             using path. If this is root, this is trivial, but if it's
                             inside an array or object, we need to find the parent DOM to be
                             able to replace it in situ.
                             */
                            if (m_path.leg_count() == 0) // root
                            {
                                Json_wrapper newroot(res);
                                docw.steal(&newroot);
                            } else
                            {
                                Json_dom *parent= a->parent();
                                DBUG_ASSERT(parent);
                                
                                parent->replace_dom_in_container(a, res);
                            }
                        }
                    }
                    else if (leg->get_type() == jpl_member &&
                             (*it)->json_type() == Json_dom::J_OBJECT)
                    {
                        if (!m_json_set) // replace semantics, so skip if path not present
                            continue;
                        
                        Json_object *o= down_cast<Json_object *>(*it);
                        const char *ename= leg->get_member_name();
                        size_t enames= leg->get_member_name_length();
                        if (o->add_clone(std::string(ename, enames), valuew.to_dom()))
                            return error_json();              /* purecov: inspected */
                    }
                } // end of loop through hits
                
            }
            else
            {
                // we found one or more value, so replace semantics.
                for (Json_dom_vector::iterator it= hits.begin(); it != hits.end(); ++it)
                {
                    Json_dom *child= *it;
                    
                    Json_dom *parent= child->parent();
                    if (!parent)
                    {
                        Json_dom *dom= valuew.clone_dom();
                        if (!dom)
                            return error_json();              /* purecov: inspected */
                        Json_wrapper w(dom);
                        docw.steal(&w);
                    }
                    else
                    {
                        Json_dom *dom= valuew.clone_dom();
                        if (!dom)
                            return error_json();              /* purecov: inspected */
                        parent->replace_dom_in_container(child, dom);
                    }
                }
            } // if: found 1 else more values
        } // do: functions argument list run-though
        
        // docw still owns the augmented doc, so hand it over to result
        wr->steal(&docw);
        
    } CATCH_ALL(func_name(), return error_json()) /* purecov: inspected */
    
    null_value= false;
    return false;
}


bool Item_func_json_array::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    try
    {
        Json_array *arr= new (std::nothrow) Json_array();
        if (!arr)
            return error_json();                /* purecov: inspected */
        Json_wrapper docw(arr);
        
        for (uint32 i= 0; i < arg_count; ++i)
        {
            Json_wrapper valuew;
            if (get_atom_null_as_null(args, i, func_name(), &m_value,
                                      &m_conversion_buffer,
                                      &valuew))
            {
                return error_json();
            }
            
            if (arr->append_alias(valuew.to_dom()))
                return error_json();              /* purecov: inspected */
            valuew.set_alias(); // release the DOM
        }
        
        // docw still owns the augmented doc, so hand it over to result
        wr->steal(&docw);
        
    } CATCH_ALL("json_array", return error_json()) /* purecov: inspected */
    
    null_value= false;
    return false;
}

bool Item_func_json_row_object::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    try
    {
        Json_object *object= new (std::nothrow) Json_object();
        if (!object)
            return error_json();                /* purecov: inspected */
        Json_wrapper docw(object);
        
        for (uint32 i= 0; i < arg_count; ++i)
        {
            /*
             arguments come in pairs. we have already verified that there
             are an even number of args.
             */
            uint32  key_idx= i++;
            uint32  value_idx= i;
            
            // key
            Item *key_item= args[key_idx];
            char buff[MAX_FIELD_WIDTH];
            String utf8_res(buff, sizeof(buff), &my_charset_utf8mb4_bin);
            const char *safep;         // contents of key_item, possibly converted
            size_t safe_length;        // length of safep
            
            if (get_json_string(key_item, &tmp_key_value, &utf8_res, func_name(),
                                &safep, &safe_length))
            {
                my_error(ER_JSON_DOCUMENT_NULL_KEY, MYF(0));
                return error_json();
            }
            
            std::string key(safep, safe_length);
            
            // value
            Json_wrapper valuew;
            if (get_atom_null_as_null(args, value_idx, func_name(), &m_value,
                                      &m_conversion_buffer, &valuew))
            {
                return error_json();
            }
            
            if (object->add_alias(key, valuew.to_dom()))
                return error_json();              /* purecov: inspected */
            valuew.set_alias(); // release the DOM
        }
        
        // docw still owns the augmented doc, so hand it over to result
        wr->steal(&docw);
        
    } CATCH_ALL("json_object", return error_json()) /* purecov: inspected */
    
    null_value= false;
    return false;
}


bool Item_func_json_search::fix_fields(THD *thd, Item **items)
{
    if (Item_json_func::fix_fields(thd, items))
        return true;
    
    // Fabricate a LIKE node
    
    m_source_string_item= new Item_string(&my_charset_utf8mb4_bin);
    Item_string *default_escape= new Item_string(&my_charset_utf8mb4_bin);
    if (m_source_string_item == NULL || default_escape == NULL)
        return true;                              /* purecov: inspected */
    
    Item *like_string_item= args[2];
    bool escape_initialized= false;
    
    // Get the escape character, if any
    if (arg_count > 3)
    {
        Item *orig_escape= args[3];
        
        /*
         Evaluate the escape clause. For a standalone LIKE expression,
         the escape clause only has to be constant during execution.
         However, we require a stronger condition: it must be constant.
         That means that we can evaluate the escape clause at resolution time
         and copy the results from the JSON_SEARCH() args into the arguments
         for the LIKE node which we're fabricating.
         */
        if (!orig_escape->const_item())
        {
            my_error(ER_WRONG_ARGUMENTS, MYF(0), "ESCAPE");
            return true;
        }
        
        String *escape_str= orig_escape->val_str(&m_escape);
        if (thd->is_error())
            return true;
        if (escape_str)
        {
            uint escape_length= static_cast<uint>(escape_str->length());
            default_escape->set_str_with_copy(escape_str->ptr(), escape_length);
            escape_initialized= true;
        }
    }
    
    if (!escape_initialized)
    {
        default_escape->set_str_with_copy("\\", 1);
    }
    
    m_like_node= new Item_func_like(m_source_string_item, like_string_item,
                                    default_escape, true);
    if (m_like_node == NULL)
        return true;                              /* purecov: inspected */
    
    Item *like_args[3];
    like_args[0]= m_source_string_item;
    like_args[1]= like_string_item;
    like_args[2]= default_escape;
    
    if (m_like_node->fix_fields(thd, like_args))
        return true;
    
    // resolving the LIKE node may overwrite its arguments
    Item **resolved_like_args= m_like_node->arguments();
    m_source_string_item= down_cast<Item_string *>(resolved_like_args[0]);
    
    return false;
}


void Item_func_json_search::cleanup()
{
    Item_json_func::cleanup();
    
    m_cached_ooa= ooa_uninitialized;
}

typedef Prealloced_array<std::string, 16, false> String_set;

/**
 Recursive function to find the string values, nested inside
 a json document, which satisfy the LIKE condition. As matches
 are found, their path locations are added to an evolving
 vector of matches.
 
 @param[in] subdoc A subdocument of the original document.
 @param[in] path The path location of the subdocument
 @param[in,out] matches The evolving vector of matches.
 @param[in,out] duplicates Set of paths found already.
 @param[in] one_match If true, then terminate search after first match.
 @param[in] like_node The LIKE node that's evaluated on the string values.
 @param[in] source_string The input string item of the LIKE node.
 @retval false on success
 @retval true on failure
 */
static bool find_matches(const Json_wrapper &wrapper, Json_path *path,
                         Json_dom_vector *matches, String_set *duplicates,
                         bool one_match, Item *like_node,
                         Item_string *source_string)
{
    switch (wrapper.type())
    {
        case Json_dom::J_STRING:
        {
            if (one_match && !matches->empty())
            {
                return false;
            }
            
            // Evaluate the LIKE node on the JSON string.
            const char *data= wrapper.get_data();
            uint len= static_cast<uint>(wrapper.get_data_length());
            source_string->set_str_with_copy(data, len);
            if (like_node->val_int())
            {
                // Got a match with the LIKE node. Save the path of the JSON string.
                char buff[STRING_BUFFER_USUAL_SIZE];
                String str(buff, sizeof(buff), &my_charset_utf8mb4_bin);
                str.length(0);
                if (path->to_string(&str))
                    return true;                        /* purecov: inspected */
                
                std::string string_contents(str.ptr(), str.length());
                std::pair<String_set::iterator, bool> res=
                duplicates->insert_unique(string_contents);
                
                if (res.second)
                {
                    Json_string *jstr= new (std::nothrow) Json_string(string_contents);
                    if (!jstr || matches->push_back(jstr))
                        return true;                      /* purecov: inspected */
                }
            }
            break;
        }
            
        case Json_dom::J_OBJECT:
        {
            for (Json_wrapper_object_iterator jwot(wrapper.object_iterator());
                 !jwot.empty(); jwot.next())
            {
                std::pair<const std::string, Json_wrapper> pair= jwot.elt();
                const std::string key= pair.first;
                Json_wrapper value= pair.second;
                Json_path_leg next_leg(key);
                
                // recurse
                if (path->append(next_leg) ||
                    find_matches(value, path, matches, duplicates, one_match,
                                 like_node, source_string))
                    return true;                        /* purecov: inspected */
                path->pop();
                
                if (one_match && !matches->empty())
                {
                    return false;
                }
            }
            break;
        }
            
        case Json_dom::J_ARRAY:
        {
            for (size_t idx= 0; idx < wrapper.length(); idx++)
            {
                Json_wrapper value= wrapper[idx];
                Json_path_leg next_leg(idx);
                
                // recurse
                if (path->append(next_leg) ||
                    find_matches(value, path, matches, duplicates, one_match,
                                 like_node, source_string))
                    return true;                        /* purecov: inspected */
                path->pop();
                
                if (one_match && !matches->empty())
                {
                    return false;
                }
            }
            break;
        }
            
        default:
        {
            break;
        }
    } // end switch on wrapper type
    
    return false;
}

bool Item_func_json_search::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    Json_dom_vector matches(key_memory_JSON);
    
    try
    {
        String_set duplicates(key_memory_JSON);
        Json_wrapper docw;
        
        // arg 0 is the document
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &docw))
            return error_json();
        
        if (args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        
        // arg 1 is the oneOrAll arg
        bool one_match;
        switch (parse_and_cache_ooa(args[1], &m_one_or_all_value,
                                    &m_cached_ooa, func_name()))
        {
            case ooa_all:
            {
                one_match= false;
                break;
            }
            case ooa_one:
            {
                one_match= true;
                break;
            }
            case ooa_null:
            {
                null_value= true;
                return false;
            }
            default:
            {
                return error_json();
            }
        }
        
        // arg 2 is the search string
        
        // arg 3 is the optional escape character
        
        // the remaining arguments are path expressions
        if (arg_count < 5) // no user-supplied path expressions
        {
            Json_path path;
            if (find_matches(docw, &path, &matches, &duplicates, one_match,
                             m_like_node, m_source_string_item))
                return error_json();            /* purecov: inspected */
        }
        else  // user-supplied path expressions
        {
            Json_wrapper_vector hits(key_memory_JSON);
            
            // validate the user-supplied path expressions
//            for (uint32 i= 4; i < arg_count; ++i)
//            {
//                if (m_path_cache.parse_and_cache_path(args, i, false))
//                {
//                    null_value= true;
//                    return false;
//                }
//            }
            
            // find the matches for each of the user-supplied path expressions
            for (uint32 i= 4; i < arg_count; ++i)
            {
                if (one_match && (matches.size() > 0))
                {
                    break;
                }
                
//                Json_path *path= m_path_cache.get_path(i);
//                
//                /*
//                 If there are wildcards in the path, then we need to
//                 compute the full path to the subdocument. We can only
//                 do this on doms.
//                 */
//                if (path->contains_wildcard_or_ellipsis())
//                {
//                    Json_dom *dom= docw.to_dom();
//                    if (!dom)
//                        return error_json();          /* purecov: inspected */
//                    Json_dom_vector dom_hits(key_memory_JSON);
//                    
//                    if (dom->seek(*path, &dom_hits, false, false))
//                        return error_json();              /* purecov: inspected */
//                    
//                    for (Json_dom_vector::iterator jdvi= dom_hits.begin();
//                         jdvi != dom_hits.end(); ++jdvi)
//                    {
//                        if (one_match && (matches.size() > 0))
//                        {
//                            break;
//                        }
//                        
//                        Json_dom *subdocument= *jdvi;
//                        Json_path subdocument_path= subdocument->get_location();
//                        Json_wrapper subdocument_wrapper(subdocument);
//                        subdocument_wrapper.set_alias();
//                        
//                        if (find_matches(subdocument_wrapper, &subdocument_path,
//                                         &matches, &duplicates, one_match,
//                                         m_like_node, m_source_string_item))
//                            return error_json();   /* purecov: inspected */
//                    } // end of loop through hits
//                }
//                else // no wildcards in the path
//                {
//                    hits.clear();
//                    if (docw.seek(*path, &hits, false, false))
//                        return error_json();          /* purecov: inspected */
//                    
//                    for (Json_wrapper_vector::iterator jwvi= hits.begin();
//                         jwvi != hits.end(); ++jwvi)
//                    {
//                        if (one_match && (matches.size() > 0))
//                        {
//                            break;
//                        }
//                        
//                        Json_wrapper  subdocument_wrapper= *jwvi;
//                        
//                        if (find_matches(subdocument_wrapper, path, &matches, &duplicates,
//                                         one_match, m_like_node, m_source_string_item))
//                            return error_json();   /* purecov: inspected */
//                    } // end of loop through hits
//                }  // end if the user-supplied path expression has wildcards
            }   // end of loop through user-supplied path expressions
        }     // end if there are user-supplied path expressions
        
    } CATCH_ALL("json_search", return error_json()) /* purecov: inspected */
    
    if (matches.size() == 0)
    {
        null_value= true;
        return false;
    }
    else if (matches.size() == 1)
    {
        Json_wrapper scalar_wrapper(matches[0]);
        wr->steal(&scalar_wrapper);
    }
    else
    {
        Json_array *array= new (std::nothrow) Json_array();
        if (!array)
            return error_json();                /* purecov: inspected */
        for (Json_dom_vector::iterator vsi= matches.begin();
             vsi != matches.end(); ++vsi)
        {
            if (array->append_alias(*vsi))
            {
                delete array;                           /* purecov: inspected */
                return error_json();              /* purecov: inspected */
            }
        }
        
        Json_wrapper  array_wrapper(array);
        wr->steal(&array_wrapper);
    }
    
    null_value= false;
    return false;
}


Item_func_json_remove::Item_func_json_remove(THD *thd, List<Item> a)
: Item_json_func(thd, a)
{}


bool Item_func_json_remove::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    Json_wrapper wrapper;
    uint32  path_count= arg_count - 1;
    bool  had_error= false;
    null_value= false;
    
    try
    {
        if (get_json_wrapper(args, 0, &m_doc_value, func_name(), &wrapper))
            return error_json();
        if (args[0]->null_value)
        {
            null_value= true;
            return false;
        }
        
//        for (uint path_idx= 0; path_idx < path_count; ++path_idx)
//        {
//            if (m_path_cache.parse_and_cache_path(args, path_idx + 1, true))
//            {
//                null_value= true;
//                break;
//            }
//        }
        
    } CATCH_ALL("json_remove", (had_error= true)) /* purecov: inspected */
    
    if (had_error || null_value)
    {
        return had_error ? error_json() : false;
    }
    
//    for (uint path_idx= 0; path_idx < path_count; ++path_idx)
//    {
//        Json_path *path= m_path_cache.get_path(path_idx + 1);
//        if (path->leg_count() == 0)
//        {
//            my_error(ER_JSON_VACUOUS_PATH, MYF(0));
//            return error_json();
//        }
//    }
    
    // good document, good paths. do some work
    
    // no binary support for removal. must convert to a dom.
    Json_dom *dom= wrapper.to_dom();
    
    // remove elements identified by the paths, one after the other
    Json_dom_vector hits(key_memory_JSON);
    for (uint path_idx= 0; path_idx < path_count; ++path_idx)
    {
//        Json_path *path= m_path_cache.get_path(path_idx + 1);
//        hits.clear();
        
        // now find the matches
//        if (dom->seek(*path, &hits, true, false))
//            return error_json();                    /* purecov: inspected */
        
        // now remove matches
        for (Json_dom_vector::iterator it= hits.begin(); it != hits.end(); ++it)
        {
            Json_dom *child= *it;
            Json_dom *parent= child->parent();
            
            // no parent means the root. the path is nonsense.
            if (parent == NULL)
            {
                continue;
            }
            
            Json_dom::enum_json_type type= parent->json_type();
            DBUG_ASSERT((type == Json_dom::J_OBJECT) || (type == Json_dom::J_ARRAY));
            
            if (type == Json_dom::J_OBJECT)
            {
                Json_object *object= down_cast<Json_object *>(parent);
                object->remove(child);
            }
            else if (type == Json_dom::J_ARRAY)
            {
                Json_array *array= down_cast<Json_array *>(parent);
                array->remove(child);
            }
        } // end of loop through matches on current path
    }   // end of loop through all paths
    
    // wrapper still owns the pruned doc, so hand it over to result
    wr->steal(&wrapper);
    
    return false;
}


bool Item_func_json_merge::val_json(Json_wrapper *wr)
{
    DBUG_ASSERT(fixed == 1);
    
    Json_dom *result_dom= NULL;
    bool had_error= false;
    null_value= false;
    
    try
    {
        for (uint idx= 0; idx < arg_count; idx++)
        {
            Json_wrapper next_wrapper;
            if (get_json_wrapper(args, idx, &m_value, func_name(), &next_wrapper))
            {
                had_error= true;
                break;
            }
            
            if (args[idx]->null_value)
            {
                null_value= true;
                break;
            }
            
            /*
             Grab the next DOM, release it from its wrapper, and merge it
             into the previous DOM.
             */
            Json_dom *next_dom= next_wrapper.to_dom();
            if (!next_dom)
            {
                delete result_dom;
                return error_json();              /* purecov: inspected */
            }
            next_wrapper.set_alias();
            result_dom= (idx == 0) ? next_dom : merge_doms(result_dom, next_dom);
        }
    } CATCH_ALL("json_merge", (had_error= true)) /* purecov: inspected */
    
    if (had_error || null_value)
    {
        delete result_dom;
        return had_error ? error_json() : false;
    }
    
    // if we couldn't allocate memory, fail now
    if (!result_dom)
    {
        return error_json();              /* purecov: inspected */
    }
    
    // fake a wrapper so that we can hand its dom to the return arg
    Json_wrapper tmp(result_dom);
    wr->steal(&tmp);
    return false;
}


String *Item_func_json_quote::val_str(String *str)
{
    DBUG_ASSERT(fixed == 1);
    
    String *res= args[0]->val_str(str);
    if (!res)
    {
        null_value= true;
        return NULL;
    }
    
    try
    {
        const char *safep;
        size_t safep_size;
        
        switch (args[0]->field_type())
        {
            case MYSQL_TYPE_STRING:
            case MYSQL_TYPE_VAR_STRING:
            case MYSQL_TYPE_VARCHAR:
            case MYSQL_TYPE_BLOB:
            case MYSQL_TYPE_LONG_BLOB:
            case MYSQL_TYPE_MEDIUM_BLOB:
            case MYSQL_TYPE_TINY_BLOB:
                break;
            default:
                my_error(ER_INCORRECT_TYPE, MYF(0), "1", func_name());
                return error_str();
        }
        
        if (ensure_utf8mb4(res, &m_value, &safep, &safep_size, true))
        {
            null_value= true;
            return NULL;
        }
        
        /*
         One of the string buffers (str or m_value) is no longer in use
         and can be reused as the result buffer. Which of them it is,
         depends on whether or not ensure_utf8mb4() needed to do charset
         conversion. Make res point to the available buffer.
         */
        res= (str->ptr() == safep) ? &m_value : str;
        
        res->length(0);
        res->set_charset(&my_charset_utf8mb4_bin);
        if (double_quote(safep, safep_size, res))
            return error_str();                 /* purecov: inspected */
    } CATCH_ALL("json_quote", return error_str()) /* purecov: inspected */
    
    null_value= false;
    return res;
}


String *Item_func_json_unquote::val_str(String *str)
{
    DBUG_ASSERT(fixed == 1);
    
    Json_dom *dom= NULL;
    
    try
    {
        if (args[0]->field_type() == MYSQL_TYPE_JSON)
        {
            Json_wrapper wr;
            if (get_json_wrapper(args, 0, str, func_name(), &wr))
            {
                return error_str();
            }
            
            if (args[0]->null_value)
            {
                null_value= true;
                return NULL;
            }
            
            m_value.length(0);
            
            if (wr.to_string(&m_value, false, func_name()))
            {
                return error_str();
            }
            
            null_value= false;
            return &m_value;
        }
        
        
        String *res= args[0]->val_str(str);
        
        if (!res)
        {
            null_value= true;
            return NULL;
        }
        
        /*
         We only allow a string argument, so get rid of any other
         type arguments.
         */
        switch (args[0]->field_type())
        {
            case MYSQL_TYPE_STRING:
            case MYSQL_TYPE_VAR_STRING:
            case MYSQL_TYPE_VARCHAR:
            case MYSQL_TYPE_BLOB:
            case MYSQL_TYPE_LONG_BLOB:
            case MYSQL_TYPE_MEDIUM_BLOB:
            case MYSQL_TYPE_TINY_BLOB:
                break;
            default:
                my_error(ER_INCORRECT_TYPE, MYF(0), "1", func_name());
                return error_str();
        }
        
        if (res->length() < 2 || *res->ptr() != '"' ||
            res->ptr()[res->length() - 1] != '"')
        {
            null_value= false;
            return res; // return string unchanged
        }
        
        bool parse_error= false;
        if (parse_json(res, 0, func_name(), &dom, true, &parse_error))
        {
            return error_str();
        }
        
        /*
         Extract the internal string representation as a MySQL string
         */
        DBUG_ASSERT(dom->json_type() == Json_dom::J_STRING);
        Json_wrapper wr(dom);
        if (str->copy(wr.get_data(), wr.get_data_length(), collation.collation))
            return error_str();                     /* purecov: inspected */
    } CATCH_ALL("json_unquote", return error_str()) /* purecov: inspected */
    
    
    null_value= false;
    return str;
}


Json_scalar_holder *create_json_scalar_holder()
{
    return new Json_scalar_holder();
}


void delete_json_scalar_holder(Json_scalar_holder *holder)
{
    delete holder;
}


Json_scalar *get_json_scalar_from_holder(Json_scalar_holder *holder)
{
//    return boost::polymorphic_get<Json_scalar>(&holder->m_val);
    return NULL;
}

// #ifdef HAVE_REPLICATION
// void Item_func_gtid_subtract::fix_length_and_dec()
// {
//   maybe_null= args[0]->maybe_null || args[1]->maybe_null;
//   collation.set(default_charset(), DERIVATION_COERCIBLE, MY_REPERTOIRE_ASCII);
//   /*
//     In the worst case, the string grows after subtraction. This
//     happens when a GTID in args[0] is split by a GTID in args[1],
//     e.g., UUID:1-6 minus UUID:3-4 becomes UUID:1-2,5-6.  The worst
//     case is UUID:1-100 minus UUID:9, where the two characters ":9" in
//     args[1] yield the five characters "-8,10" in the result.
//   */
//   fix_char_length_ulonglong(args[0]->max_length +
//                             max<ulonglong>(args[1]->max_length - 
//                                            Uuid::TEXT_LENGTH, 0) * 5 / 2);
// }
// 
// 
// String *Item_func_gtid_subtract::val_str_ascii(String *str)
// {
//   DBUG_ENTER("Item_func_gtid_subtract::val_str_ascii");
//   String *str1, *str2;
//   const char *charp1, *charp2;
//   enum_return_status status;
//   /*
//     We must execute args[*]->val_str_ascii() before checking
//     args[*]->null_value to ensure that them are updated when
//     this function is executed inside a stored procedure.
//   */
// //   if ((str1= args[0]->val_str_ascii(&buf1)) != NULL &&
// //       (charp1= str1->c_ptr_safe()) != NULL &&
// //       (str2= args[1]->val_str_ascii(&buf2)) != NULL &&
// //       (charp2= str2->c_ptr_safe()) != NULL &&
// //       !args[0]->null_value && !args[1]->null_value)
// //   {
// //     Sid_map sid_map(NULL/*no rwlock*/);
// //     // compute sets while holding locks
// //     Gtid_set set1(&sid_map, charp1, &status);
// //     if (status == RETURN_STATUS_OK)
// //     {
// //       Gtid_set set2(&sid_map, charp2, &status);
// //       int length;
// //       // subtract, save result, return result
// //       if (status == RETURN_STATUS_OK &&
// //           set1.remove_gtid_set(&set2) == 0 &&
// //           !str->realloc((length= set1.get_string_length()) + 1))
// //       {
// //         null_value= false;
// //         set1.to_string((char *)str->ptr());
// //         str->length(length);
// //         DBUG_RETURN(str);
// //       }
// //     }
// //   }
//   null_value= true;
//   DBUG_RETURN(NULL);
// }
// #endif // HAVE_REPLICATION
