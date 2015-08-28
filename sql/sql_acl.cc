/* Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

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


/*
  The privileges are saved in the following tables:
  mysql/user	 ; super user who are allowed to do almost anything
  mysql/host	 ; host privileges. This is used if host is empty in mysql/db.
  mysql/db	 ; database privileges / user

  data in tables is sorted according to how many not-wild-cards there is
  in the relevant fields. Empty strings comes last.
*/


#include "my_global.h"                          /* NO_EMBEDDED_ACCESS_CHECKS */
#include "sql_priv.h"
#include "sql_acl.h"         // MYSQL_DB_FIELD_COUNT, ACL_ACCESS
#include "sql_base.h"                           // close_mysql_tables
#include "key.h"             // key_copy, key_cmp_if_same, key_restore
#include "sql_show.h"        // append_identifier
#include "sql_table.h"                         // build_table_filename
#include "hash_filo.h"
#include "sql_parse.h"                          // check_access
#include "sql_view.h"                           // VIEW_ANY_ACL
#include "records.h"              // READ_RECORD, read_record_info,
#include <m_ctype.h>
#include <stdarg.h>
#include "sp_head.h"
#include "sp.h"
#include "transaction.h"
#include "lock.h"                               // MYSQL_LOCK_IGNORE_TIMEOUT
#include "records.h"             // init_read_record, end_read_record
#include <sql_common.h>
#include <mysql/plugin_auth.h>
#include "sql_connect.h"
#include "hostname.h"
#include "sql_db.h"
#include <mysql/plugin_validate_password.h>
#include "password.h"
#include "crypt_genhash_impl.h"
// 
#if defined(HAVE_OPENSSL) && !defined(HAVE_YASSL)
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#endif

using std::min;
using std::max;

bool mysql_user_table_is_in_short_password_format= false;
my_bool disconnect_on_expired_password= TRUE;
bool auth_plugin_is_built_in(const char *plugin_name);
bool auth_plugin_supports_expiration(const char *plugin_name);
void optimize_plugin_compare_by_pointer(LEX_STRING *plugin_name);


static const
TABLE_FIELD_TYPE mysql_db_table_fields[MYSQL_DB_FIELD_COUNT] = {
  {
    { C_STRING_WITH_LEN("Host") },            
    { C_STRING_WITH_LEN("char(60)") },
    {NULL, 0}
  }, 
  {
    { C_STRING_WITH_LEN("Db") },            
    { C_STRING_WITH_LEN("char(64)") },
    {NULL, 0}
  }, 
  {
    { C_STRING_WITH_LEN("User") },
    { C_STRING_WITH_LEN("char(16)") },
    {NULL, 0}
  },
  {
    { C_STRING_WITH_LEN("Select_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Insert_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Update_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Delete_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Create_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Drop_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Grant_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("References_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Index_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Alter_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Create_tmp_table_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Lock_tables_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Create_view_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Show_view_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Create_routine_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Alter_routine_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Execute_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Event_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Trigger_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  }
};

static const
TABLE_FIELD_TYPE mysql_user_table_fields[MYSQL_USER_FIELD_COUNT] = {
  {
    { C_STRING_WITH_LEN("Host") },            
    { C_STRING_WITH_LEN("char(60)") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("User") },            
    { C_STRING_WITH_LEN("char(16)") },
    { NULL, 0 }
  },
  {
    { C_STRING_WITH_LEN("Password") },            
    { C_STRING_WITH_LEN("char(41)") },
    { C_STRING_WITH_LEN("latin1") }
  }, 
  {
    { C_STRING_WITH_LEN("Select_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Insert_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Update_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Delete_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Create_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Drop_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Reload_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  {
    { C_STRING_WITH_LEN("Shutdown_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Process_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("File_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Grant_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("References_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Index_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Alter_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Show_db_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Super_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Create_tmp_table_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Lock_tables_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Execute_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Repl_slave_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Repl_client_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Create_view_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Show_view_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Create_routine_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Alter_routine_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Create_user_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Event_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Trigger_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("Create_tablespace_priv") },
    { C_STRING_WITH_LEN("enum('N','Y')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("ssl_type") },
    { C_STRING_WITH_LEN("enum('','ANY','X509','SPECIFIED')") },
    { C_STRING_WITH_LEN("utf8") }
  },
  { 
    { C_STRING_WITH_LEN("ssl_cipher") },
    { C_STRING_WITH_LEN("blob") },
    { NULL, 0 }
  },
  { 
    { C_STRING_WITH_LEN("x509_issuer") },
    { C_STRING_WITH_LEN("blob") },
    { NULL, 0 }
  },
  { 
    { C_STRING_WITH_LEN("x509_subject") },
    { C_STRING_WITH_LEN("blob") },
    { NULL, 0 }
  },
  { 
    { C_STRING_WITH_LEN("max_questions") },
    { C_STRING_WITH_LEN("int(11)") },
    { NULL, 0 }
  },
  { 
    { C_STRING_WITH_LEN("max_updates") },
    { C_STRING_WITH_LEN("int(11)") },
    { NULL, 0 }
  },
  { 
    { C_STRING_WITH_LEN("max_connections") },
    { C_STRING_WITH_LEN("int(11)") },
    { NULL, 0 }
  },
  { 
    { C_STRING_WITH_LEN("plugin") },
    { C_STRING_WITH_LEN("char(64)") },
    { NULL, 0 }
  },
  { 
    { C_STRING_WITH_LEN("authentication_string") },
    { C_STRING_WITH_LEN("text") },
    { NULL, 0 }
  } 
};

const TABLE_FIELD_DEF
  mysql_db_table_def= {MYSQL_DB_FIELD_COUNT, mysql_db_table_fields};

const TABLE_FIELD_DEF
  mysql_user_table_def= {MYSQL_USER_FIELD_COUNT, mysql_user_table_fields};

static LEX_STRING native_password_plugin_name= {
  C_STRING_WITH_LEN("mysql_native_password")
};
  
static LEX_STRING old_password_plugin_name= {
  C_STRING_WITH_LEN("mysql_old_password")
};

LEX_STRING sha256_password_plugin_name= {
  C_STRING_WITH_LEN("sha256_password")
};

static LEX_STRING validate_password_plugin_name= {
  C_STRING_WITH_LEN("validate_password")
};
  
LEX_STRING default_auth_plugin_name;

#ifndef NO_EMBEDDED_ACCESS_CHECKS
static plugin_ref old_password_plugin;
#endif
static plugin_ref native_password_plugin;

#define WARN_DEPRECATED_41_PWD_HASH(thd) \
  WARN_DEPRECATED(thd, "pre-4.1 password hash", "post-4.1 password hash")

/* Classes */

class ACL_HOST_AND_IP
{
  char *hostname;
  uint hostname_length;
  long ip, ip_mask; // Used with masked ip:s

  const char *calc_ip(const char *ip_arg, long *val, char end)
  {
    long ip_val,tmp;
    if (!(ip_arg=str2int(ip_arg,10,0,255,&ip_val)) || *ip_arg != '.')
      return 0;
    ip_val<<=24;
    if (!(ip_arg=str2int(ip_arg+1,10,0,255,&tmp)) || *ip_arg != '.')
      return 0;
    ip_val+=tmp<<16;
    if (!(ip_arg=str2int(ip_arg+1,10,0,255,&tmp)) || *ip_arg != '.')
      return 0;
    ip_val+=tmp<<8;
    if (!(ip_arg=str2int(ip_arg+1,10,0,255,&tmp)) || *ip_arg != end)
      return 0;
    *val=ip_val+tmp;
    return ip_arg;
  }

public:
  const char *get_host() const { return hostname; }
  int get_host_len() { return hostname_length; }

  bool has_wildcard()
  {
    return (strchr(hostname,wild_many) ||
            strchr(hostname,wild_one)  || ip_mask );
  }

  bool check_allow_all_hosts()
  {
    return (!hostname ||
            (hostname[0] == wild_many && !hostname[1]));
  }

  /**
    @brief Update the hostname. Updates ip and ip_mask accordingly.

    @param host_arg	Value to be stored
  */
  void update_hostname(const char *host_arg)
  {
    hostname=(char*) host_arg;     // This will not be modified!
    hostname_length= hostname ? strlen( hostname ) : 0;
    if (!host_arg ||
        (!(host_arg=(char*) calc_ip(host_arg,&ip,'/')) ||
         !(host_arg=(char*) calc_ip(host_arg+1,&ip_mask,'\0'))))
    {
      ip= ip_mask=0;               // Not a masked ip
    }
  }

  /*
    @brief Comparing of hostnames

    @param  host_arg    Hostname to be compared with
    @param  ip_arg      IP address to be compared with
  
    @notes
    A hostname may be of type:
      1) hostname   (May include wildcards);   monty.pp.sci.fi
      2) ip	   (May include wildcards);   192.168.0.0
      3) ip/netmask			      192.168.0.0/255.255.255.0
    A net mask of 0.0.0.0 is not allowed.

   @return
     true   if matched
     false  if not matched
  */

  bool compare_hostname(const char *host_arg, const char *ip_arg)
  {
    long tmp;
    if (ip_mask && ip_arg && calc_ip(ip_arg,&tmp,'\0'))
    {
      return (tmp & ip_mask) == ip;
    }
    return (!hostname ||
  	    (host_arg &&
             !wild_case_compare(system_charset_info, host_arg, hostname)) ||
  	    (ip_arg && !wild_compare(ip_arg, hostname, 0)));
  }

};

class ACL_ACCESS {
public:
  ACL_HOST_AND_IP host;
  ulong sort;
  ulong access;
};

/* ACL_HOST is used if no host is specified */

class ACL_HOST :public ACL_ACCESS
{
public:
  char *db;
};

class ACL_USER :public ACL_ACCESS
{
public:
  USER_RESOURCES user_resource;
  char *user;
  /**
    The salt variable is used as the password hash for
    native_password_authetication and old_password_authentication.
  */
  uint8 salt[SCRAMBLE_LENGTH + 1];       // scrambled password in binary form
  /**
    In the old protocol the salt_len indicated what type of autnetication
    protocol was used: 0 - no password, 4 - 3.20, 8 - 4.0,  20 - 4.1.1
  */
  uint8 salt_len;
  enum SSL_type ssl_type;
  const char *ssl_cipher, *x509_issuer, *x509_subject;
  LEX_STRING plugin;
  LEX_STRING auth_string;
  bool password_expired;

  ACL_USER *copy(MEM_ROOT *root)
  {
    ACL_USER *dst= (ACL_USER *) alloc_root(root, sizeof(ACL_USER));
    if (!dst)
      return 0;
    *dst= *this;
    dst->user= safe_strdup_root(root, user);
    dst->ssl_cipher= safe_strdup_root(root, ssl_cipher);
    dst->x509_issuer= safe_strdup_root(root, x509_issuer);
    dst->x509_subject= safe_strdup_root(root, x509_subject);
    /*
      If the plugin is built in we don't need to reallocate the name of the
      plugin.
    */
    if (auth_plugin_is_built_in(dst->plugin.str))
      dst->plugin= plugin;
    else
    {
      dst->plugin.str= strmake_root(root, plugin.str, plugin.length);
      dst->plugin.length= plugin.length;
    }
    dst->auth_string.str= safe_strdup_root(root, auth_string.str);
    dst->host.update_hostname(safe_strdup_root(root, host.get_host()));
    return dst;
  }
};

class ACL_DB :public ACL_ACCESS
{
public:
  char *user,*db;
};


#ifndef NO_EMBEDDED_ACCESS_CHECKS
static ulong get_sort(uint count,...);

class ACL_PROXY_USER :public ACL_ACCESS
{
  const char *user;
  ACL_HOST_AND_IP proxied_host;
  const char *proxied_user;
  bool with_grant;

  typedef enum { 
    MYSQL_PROXIES_PRIV_HOST, 
    MYSQL_PROXIES_PRIV_USER, 
    MYSQL_PROXIES_PRIV_PROXIED_HOST,
    MYSQL_PROXIES_PRIV_PROXIED_USER, 
    MYSQL_PROXIES_PRIV_WITH_GRANT,
    MYSQL_PROXIES_PRIV_GRANTOR,
    MYSQL_PROXIES_PRIV_TIMESTAMP } old_acl_proxy_users;
public:
  ACL_PROXY_USER () {};

  void init(const char *host_arg, const char *user_arg,
       const char *proxied_host_arg, const char *proxied_user_arg,
       bool with_grant_arg)
  {
    user= (user_arg && *user_arg) ? user_arg : NULL;
    host.update_hostname ((host_arg && *host_arg) ? host_arg : NULL);
    proxied_user= (proxied_user_arg && *proxied_user_arg) ? 
      proxied_user_arg : NULL;
    proxied_host.update_hostname ((proxied_host_arg && *proxied_host_arg) ?
                     proxied_host_arg : NULL);
    with_grant= with_grant_arg;
    sort= get_sort(4, host.get_host(), user,
                   proxied_host.get_host(), proxied_user);
  }

  void init(MEM_ROOT *mem, const char *host_arg, const char *user_arg,
       const char *proxied_host_arg, const char *proxied_user_arg,
       bool with_grant_arg)
  {
    init ((host_arg && *host_arg) ? strdup_root (mem, host_arg) : NULL,
          (user_arg && *user_arg) ? strdup_root (mem, user_arg) : NULL,
          (proxied_host_arg && *proxied_host_arg) ? 
            strdup_root (mem, proxied_host_arg) : NULL,
          (proxied_user_arg && *proxied_user_arg) ? 
            strdup_root (mem, proxied_user_arg) : NULL,
          with_grant_arg);
  }

  void init(TABLE *table, MEM_ROOT *mem)
  {
    init (get_field(mem, table->field[MYSQL_PROXIES_PRIV_HOST]),
          get_field(mem, table->field[MYSQL_PROXIES_PRIV_USER]),
          get_field(mem, table->field[MYSQL_PROXIES_PRIV_PROXIED_HOST]),
          get_field(mem, table->field[MYSQL_PROXIES_PRIV_PROXIED_USER]),
          table->field[MYSQL_PROXIES_PRIV_WITH_GRANT]->val_int() != 0);
  }

  bool get_with_grant() { return with_grant; }
  const char *get_user() { return user; }
  const char *get_proxied_user() { return proxied_user; }
  const char *get_proxied_host() { return proxied_host.get_host(); }
  void set_user(MEM_ROOT *mem, const char *user_arg) 
  { 
    user= user_arg && *user_arg ? strdup_root(mem, user_arg) : NULL;
  }

  bool check_validity(bool check_no_resolve)
  {
    if (check_no_resolve && 
        (hostname_requires_resolving(host.get_host()) ||
         hostname_requires_resolving(proxied_host.get_host())))
    {
      sql_print_warning("'proxies_priv' entry '%s@%s %s@%s' "
                        "ignored in --skip-name-resolve mode.",
                        proxied_user ? proxied_user : "",
                        proxied_host.get_host() ? proxied_host.get_host() : "",
                        user ? user : "",
                        host.get_host() ? host.get_host() : "");
      return TRUE;
    }
    return FALSE;
  }

  bool matches(const char *host_arg, const char *user_arg, const char *ip_arg,
                const char *proxied_user_arg)
  {
    DBUG_ENTER("ACL_PROXY_USER::matches");
    DBUG_PRINT("info", ("compare_hostname(%s,%s,%s) &&"
                        "compare_hostname(%s,%s,%s) &&"
                        "wild_compare (%s,%s) &&"
                        "wild_compare (%s,%s)",
                        host.get_host() ? host.get_host() : "<NULL>",
                        host_arg ? host_arg : "<NULL>",
                        ip_arg ? ip_arg : "<NULL>",
                        proxied_host.get_host() ? proxied_host.get_host() : "<NULL>",
                        host_arg ? host_arg : "<NULL>",
                        ip_arg ? ip_arg : "<NULL>",
                        user_arg ? user_arg : "<NULL>",
                        user ? user : "<NULL>",
                        proxied_user_arg ? proxied_user_arg : "<NULL>",
                        proxied_user ? proxied_user : "<NULL>"));
    DBUG_RETURN(host.compare_hostname(host_arg, ip_arg) &&
                proxied_host.compare_hostname(host_arg, ip_arg) &&
                (!user ||
                 (user_arg && !wild_compare(user_arg, user, TRUE))) &&
                (!proxied_user || 
                 (proxied_user && !wild_compare(proxied_user_arg, 
                                                proxied_user, TRUE))));
  }


  inline static bool auth_element_equals(const char *a, const char *b)
  {
    return (a == b || (a != NULL && b != NULL && !strcmp(a,b)));
  }


  bool pk_equals(ACL_PROXY_USER *grant)
  {
    DBUG_ENTER("pk_equals");
    DBUG_PRINT("info", ("strcmp(%s,%s) &&"
                        "strcmp(%s,%s) &&"
                        "wild_compare (%s,%s) &&"
                        "wild_compare (%s,%s)",
                        user ? user : "<NULL>",
                        grant->user ? grant->user : "<NULL>",
                        proxied_user ? proxied_user : "<NULL>",
                        grant->proxied_user ? grant->proxied_user : "<NULL>",
                        host.get_host() ? host.get_host() : "<NULL>",
                        grant->host.get_host() ? grant->host.get_host() : "<NULL>",
                        proxied_host.get_host() ? proxied_host.get_host() : "<NULL>",
                        grant->proxied_host.get_host() ? 
                        grant->proxied_host.get_host() : "<NULL>"));

    DBUG_RETURN(auth_element_equals(user, grant->user) &&
                auth_element_equals(proxied_user, grant->proxied_user) &&
                auth_element_equals(host.get_host(), grant->host.get_host()) &&
                auth_element_equals(proxied_host.get_host(), 
                                    grant->proxied_host.get_host()));
  }


  bool granted_on(const char *host_arg, const char *user_arg)
  {
    return (((!user && (!user_arg || !user_arg[0])) ||
             (user && user_arg && !strcmp(user, user_arg))) &&
            ((!host.get_host() && (!host_arg || !host_arg[0])) ||
             (host.get_host() && host_arg && !strcmp(host.get_host(), host_arg))));
  }


  void print_grant(String *str)
  {
    str->append(STRING_WITH_LEN("GRANT PROXY ON '"));
    if (proxied_user)
      str->append(proxied_user, strlen(proxied_user));
    str->append(STRING_WITH_LEN("'@'"));
    if (proxied_host.get_host())
      str->append(proxied_host.get_host(), strlen(proxied_host.get_host()));
    str->append(STRING_WITH_LEN("' TO '"));
    if (user)
      str->append(user, strlen(user));
    str->append(STRING_WITH_LEN("'@'"));
    if (host.get_host())
      str->append(host.get_host(), strlen(host.get_host()));
    str->append(STRING_WITH_LEN("'"));
    if (with_grant)
      str->append(STRING_WITH_LEN(" WITH GRANT OPTION"));
  }

  void set_data(ACL_PROXY_USER *grant)
  {
    with_grant= grant->with_grant;
  }

  static int store_pk(TABLE *table, 
                      const LEX_STRING *host, 
                      const LEX_STRING *user,
                      const LEX_STRING *proxied_host, 
                      const LEX_STRING *proxied_user)
  {
    DBUG_ENTER("ACL_PROXY_USER::store_pk");
    DBUG_PRINT("info", ("host=%s, user=%s, proxied_host=%s, proxied_user=%s",
                        host->str ? host->str : "<NULL>",
                        user->str ? user->str : "<NULL>",
                        proxied_host->str ? proxied_host->str : "<NULL>",
                        proxied_user->str ? proxied_user->str : "<NULL>"));
    if (table->field[MYSQL_PROXIES_PRIV_HOST]->store(host->str, 
                                                   host->length,
                                                   system_charset_info))
      DBUG_RETURN(TRUE);
    if (table->field[MYSQL_PROXIES_PRIV_USER]->store(user->str, 
                                                   user->length,
                                                   system_charset_info))
      DBUG_RETURN(TRUE);
    if (table->field[MYSQL_PROXIES_PRIV_PROXIED_HOST]->store(proxied_host->str,
                                                           proxied_host->length,
                                                           system_charset_info))
      DBUG_RETURN(TRUE);
    if (table->field[MYSQL_PROXIES_PRIV_PROXIED_USER]->store(proxied_user->str,
                                                           proxied_user->length,
                                                           system_charset_info))
      DBUG_RETURN(TRUE);

    DBUG_RETURN(FALSE);
  }

  static int store_data_record(TABLE *table,
                               const LEX_STRING *host,
                               const LEX_STRING *user,
                               const LEX_STRING *proxied_host,
                               const LEX_STRING *proxied_user,
                               bool with_grant,
                               const char *grantor)
  {
    DBUG_ENTER("ACL_PROXY_USER::store_pk");
    if (store_pk(table,  host, user, proxied_host, proxied_user))
      DBUG_RETURN(TRUE);
    DBUG_PRINT("info", ("with_grant=%s", with_grant ? "TRUE" : "FALSE"));
    if (table->field[MYSQL_PROXIES_PRIV_WITH_GRANT]->store(with_grant ? 1 : 0, 
                                                         TRUE))
      DBUG_RETURN(TRUE);
    if (table->field[MYSQL_PROXIES_PRIV_GRANTOR]->store(grantor, 
                                                        strlen(grantor),
                                                        system_charset_info))
      DBUG_RETURN(TRUE);

    DBUG_RETURN(FALSE);
  }
};

#define FIRST_NON_YN_FIELD 26

class acl_entry :public hash_filo_element
{
public:
  ulong access;
  uint16 length;
  char key[1];					// Key will be stored here
};


static uchar* acl_entry_get_key(acl_entry *entry, size_t *length,
                                my_bool not_used __attribute__((unused)))
{
  *length=(uint) entry->length;
  return (uchar*) entry->key;
}

#define IP_ADDR_STRLEN (3 + 1 + 3 + 1 + 3 + 1 + 3)
#define ACL_KEY_LENGTH (IP_ADDR_STRLEN + 1 + NAME_LEN + \
                        1 + USERNAME_LENGTH + 1)

/** Size of the header fields of an authentication packet. */
#define AUTH_PACKET_HEADER_SIZE_PROTO_41    32
#define AUTH_PACKET_HEADER_SIZE_PROTO_40    5  

static DYNAMIC_ARRAY acl_users, acl_dbs, acl_proxy_users;
static MEM_ROOT global_acl_memory, memex;
static bool initialized=0;
static bool allow_all_hosts=1;
static HASH acl_check_hosts, column_priv_hash, proc_priv_hash, func_priv_hash;
static DYNAMIC_ARRAY acl_wild_hosts;
static hash_filo *acl_cache;
static uint grant_version=0; /* Version of priv tables. incremented by acl_load */
static ulong get_access(TABLE *form,uint fieldnr, uint *next_field=0);
static int acl_compare(ACL_ACCESS *a,ACL_ACCESS *b);
static ulong get_sort(uint count,...);
static void init_check_host(void);
static void rebuild_check_host(void);
static ACL_USER *find_acl_user(const char *host, const char *user,
                               my_bool exact);
static bool update_user_table(THD *, TABLE *table, const char *host,
                              const char *user,
                              const char *new_password,
                              uint new_password_len,
                              enum mysql_user_table_field password_field,
                              bool password_expired);
static my_bool acl_load(THD *thd, TABLE_LIST *tables);
static my_bool grant_load(THD *thd, TABLE_LIST *tables);
static inline void get_grantor(THD *thd, char* grantor);
/*
 Enumeration of various ACL's and Hashes used in handle_grant_struct()
*/
enum enum_acl_lists
{
  USER_ACL= 0,
  DB_ACL,
  COLUMN_PRIVILEGES_HASH,
  PROC_PRIVILEGES_HASH,
  FUNC_PRIVILEGES_HASH,
  PROXY_USERS_ACL
};

/**
  Convert scrambled password to binary form, according to scramble type, 
  Binary form is stored in user.salt.
  
  @param acl_user The object where to store the salt
  @param password The password hash containing the salt
  @param password_len The length of the password hash
   
  Despite the name of the function it is used when loading ACLs from disk
  to store the password hash in the ACL_USER object.
  Note that it works only for native and "old" mysql authentication built-in
  plugins.
  
  @return Password hash validation
    @retval false Hash is of suitable length
    @retval true Hash is of wrong length or format
*/

static 
bool
set_user_salt(ACL_USER *acl_user, const char *password, uint password_len)
{
  bool result= false;
  /* Using old password protocol */
  if (password_len == SCRAMBLED_PASSWORD_CHAR_LENGTH)
  {
    get_salt_from_password(acl_user->salt, password);
    acl_user->salt_len= SCRAMBLE_LENGTH;
  }
  else if (password_len == SCRAMBLED_PASSWORD_CHAR_LENGTH_323)
  {
    get_salt_from_password_323((ulong *) acl_user->salt, password);
    acl_user->salt_len= SCRAMBLE_LENGTH_323;
  }
  else if (password_len == 0 || password == NULL)
  {
    /* This account doesn't use a password */
    acl_user->salt_len= 0;
  }
  else if (acl_user->plugin.str == native_password_plugin_name.str ||
           acl_user->plugin.str == old_password_plugin_name.str)
  {
    /* Unexpected format of the hash; login will probably be impossible */
    result= true;
  }

  /*
    Since we're changing the password for the user we need to reset the
    expiration flag.
  */
  acl_user->password_expired= false;
  
  return result;
}

/*
  Initialize structures responsible for user/db-level privilege checking and
  load privilege information for them from tables in the 'mysql' database.

  SYNOPSIS
    acl_init()
      dont_read_acl_tables  TRUE if we want to skip loading data from
                            privilege tables and disable privilege checking.

  NOTES
    This function is mostly responsible for preparatory steps, main work
    on initialization and grants loading is done in acl_reload().

  RETURN VALUES
    0	ok
    1	Could not initialize grant's
*/

my_bool acl_init(bool dont_read_acl_tables)
{
  THD  *thd;
  my_bool return_val;
  DBUG_ENTER("acl_init");

  acl_cache= new hash_filo(ACL_CACHE_SIZE, 0, 0,
                           (my_hash_get_key) acl_entry_get_key,
                           (my_hash_free_key) free,
                           &my_charset_utf8_bin);

  /*
    cache built-in native authentication plugins,
    to avoid hash searches and a global mutex lock on every connect
  */
  native_password_plugin= my_plugin_lock_by_name(0,
           &native_password_plugin_name, MYSQL_AUTHENTICATION_PLUGIN);
  old_password_plugin= my_plugin_lock_by_name(0,
           &old_password_plugin_name, MYSQL_AUTHENTICATION_PLUGIN);

  if (!native_password_plugin || !old_password_plugin)
    DBUG_RETURN(1);

  if (dont_read_acl_tables)
  {
    DBUG_RETURN(0); /* purecov: tested */
  }

  /*
    To be able to run this from boot, we allocate a temporary THD
  */
  if (!(thd=new THD))
    DBUG_RETURN(1); /* purecov: inspected */
  thd->thread_stack= (char*) &thd;
  thd->store_globals();
  /*
    It is safe to call acl_reload() since acl_* arrays and hashes which
    will be freed there are global static objects and thus are initialized
    by zeros at startup.
  */
  return_val= acl_reload(thd);
  delete thd;
  /* Remember that we don't have a THD */
  my_pthread_setspecific_ptr(THR_THD,  0);
  DBUG_RETURN(return_val);
}

/*
  Initialize structures responsible for user/db-level privilege checking
  and load information about grants from open privilege tables.

  SYNOPSIS
    acl_load()
      thd     Current thread
      tables  List containing open "mysql.host", "mysql.user",
              "mysql.db" and "mysql.proxies_priv" tables in that order.

  RETURN VALUES
    FALSE  Success
    TRUE   Error
*/

static my_bool acl_load(THD *thd, TABLE_LIST *tables)
{
  TABLE *table;
  READ_RECORD read_record_info;
  my_bool return_val= TRUE;
  bool check_no_resolve= specialflag & SPECIAL_NO_RESOLVE;
  char tmp_name[NAME_LEN+1];
  int password_length;
  sql_mode_t old_sql_mode= thd->variables.sql_mode;
  DBUG_ENTER("acl_load");

  thd->variables.sql_mode&= ~MODE_PAD_CHAR_TO_FULL_LENGTH;

  grant_version++; /* Privileges updated */

  
  acl_cache->clear(1);				// Clear locked hostname cache

  init_sql_alloc(&global_acl_memory, ACL_ALLOC_BLOCK_SIZE, 0);
  /*
    Prepare reading from the mysql.user table
  */
  if (init_read_record(&read_record_info, thd, table=tables[0].table,
                       NULL, 1, 1, FALSE))
    goto end;
  table->use_all_columns();
  (void) my_init_dynamic_array(&acl_users,sizeof(ACL_USER),50,100);
  
  allow_all_hosts=0;
  while (!(read_record_info.read_record(&read_record_info)))
  {
    /* Reading record from mysql.user */
    ACL_USER user;
    memset(&user, 0, sizeof(user));
    user.host.update_hostname(get_field(&global_acl_memory,
                                        table->field[MYSQL_USER_FIELD_HOST]));
    user.user= get_field(&global_acl_memory,
                         table->field[MYSQL_USER_FIELD_USER]);
    if (check_no_resolve && hostname_requires_resolving(user.host.get_host()))
    {
      sql_print_warning("'user' entry '%s@%s' "
                        "ignored in --skip-name-resolve mode.",
			user.user ? user.user : "",
			user.host.get_host() ? user.host.get_host() : "");
      continue;
    }

    /* Read legacy password */
    {
      char *password= get_field(&global_acl_memory,
                                table->field[MYSQL_USER_FIELD_PASSWORD]);
      uint password_len= password ? strlen(password) : 0;
      user.auth_string.str= password ? password : const_cast<char*>("");
      user.auth_string.length= password_len;
      /*
         Transform hex to octets and adjust the format.
       */
      if (set_user_salt(&user, password, password_len))
      {
        sql_print_warning("Found invalid password for user: '%s@%s'; "
                          "Ignoring user", user.user ? user.user : "",
                          user.host.get_host() ? user.host.get_host() : "");
        continue;
      }

      /*
        Set temporary plugin deduced from password length. If there are 
        enough fields in the user table the real plugin will be read later.
       */
      user.plugin= native_password_plugin_name;
      if (password_len == SCRAMBLED_PASSWORD_CHAR_LENGTH_323)
        user.plugin= old_password_plugin_name;
    } 

    {
      uint next_field;
      user.access= get_access(table,3,&next_field) & GLOBAL_ACLS;
      /*
        if it is pre 5.0.1 privilege table then map CREATE privilege on
        CREATE VIEW & SHOW VIEW privileges
      */
      if (table->s->fields <= 31 && (user.access & CREATE_ACL))
        user.access|= (CREATE_VIEW_ACL | SHOW_VIEW_ACL);

      /*
        if it is pre 5.0.2 privilege table then map CREATE/ALTER privilege on
        CREATE PROCEDURE & ALTER PROCEDURE privileges
      */
      if (table->s->fields <= 33 && (user.access & CREATE_ACL))
        user.access|= CREATE_PROC_ACL;
      if (table->s->fields <= 33 && (user.access & ALTER_ACL))
        user.access|= ALTER_PROC_ACL;

      /*
        pre 5.0.3 did not have CREATE_USER_ACL
      */
      if (table->s->fields <= 36 && (user.access & GRANT_ACL))
        user.access|= CREATE_USER_ACL;


      /*
        if it is pre 5.1.6 privilege table then map CREATE privilege on
        CREATE|ALTER|DROP|EXECUTE EVENT
      */
      if (table->s->fields <= 37 && (user.access & SUPER_ACL))
        user.access|= EVENT_ACL;

      /*
        if it is pre 5.1.6 privilege then map TRIGGER privilege on CREATE.
      */
      if (table->s->fields <= 38 && (user.access & SUPER_ACL))
        user.access|= TRIGGER_ACL;

      user.sort= get_sort(2,user.host.get_host(),user.user);

      /* Starting from 4.0.2 we have more fields */
      if (table->s->fields >= 31)
      {
        char *ssl_type=
          get_field(thd->mem_root, table->field[MYSQL_USER_FIELD_SSL_TYPE]);
        if (!ssl_type)
          user.ssl_type=SSL_TYPE_NONE;
        else if (!strcmp(ssl_type, "ANY"))
          user.ssl_type=SSL_TYPE_ANY;
        else if (!strcmp(ssl_type, "X509"))
          user.ssl_type=SSL_TYPE_X509;
        else  /* !strcmp(ssl_type, "SPECIFIED") */
          user.ssl_type=SSL_TYPE_SPECIFIED;

        user.ssl_cipher= 
          get_field(&global_acl_memory, table->field[MYSQL_USER_FIELD_SSL_CIPHER]);
        user.x509_issuer=
          get_field(&global_acl_memory, table->field[MYSQL_USER_FIELD_X509_ISSUER]);
        user.x509_subject=
          get_field(&global_acl_memory, table->field[MYSQL_USER_FIELD_X509_SUBJECT]);

        char *ptr= get_field(thd->mem_root,
                             table->field[MYSQL_USER_FIELD_MAX_QUESTIONS]);
        user.user_resource.questions=ptr ? atoi(ptr) : 0;
        ptr= get_field(thd->mem_root,
                       table->field[MYSQL_USER_FIELD_MAX_UPDATES]);
        user.user_resource.updates=ptr ? atoi(ptr) : 0;
        ptr= get_field(thd->mem_root,
                       table->field[MYSQL_USER_FIELD_MAX_CONNECTIONS]);
        user.user_resource.conn_per_hour= ptr ? atoi(ptr) : 0;
        if (user.user_resource.questions || user.user_resource.updates ||
            user.user_resource.conn_per_hour)
          mqh_used=1;

        if (table->s->fields > MYSQL_USER_FIELD_MAX_USER_CONNECTIONS)
        {
          /* Starting from 5.0.3 we have max_user_connections field */
          ptr= get_field(thd->mem_root,
                         table->field[MYSQL_USER_FIELD_MAX_USER_CONNECTIONS]);
          user.user_resource.user_conn= ptr ? atoi(ptr) : 0;
        }

        if (table->s->fields >= 41)
        {
          /* We may have plugin & auth_String fields */
          char *tmpstr= get_field(&global_acl_memory,
                                  table->field[MYSQL_USER_FIELD_PLUGIN]);
          if (tmpstr)
          {
            /*
              By comparing the plugin with the built in plugins it is possible
              to optimize the string allocation and comparision.
            */
            if (my_strcasecmp(system_charset_info, tmpstr,
                              native_password_plugin_name.str) == 0)
              user.plugin= native_password_plugin_name;
            else
              if (my_strcasecmp(system_charset_info, tmpstr,
                                old_password_plugin_name.str) == 0)
                user.plugin= old_password_plugin_name;
#if defined(HAVE_OPENSSL)
            else
              if (my_strcasecmp(system_charset_info, tmpstr,
                                sha256_password_plugin_name.str) == 0)
                user.plugin= sha256_password_plugin_name;
#endif
            else
              {
                user.plugin.str= tmpstr;
                user.plugin.length= strlen(tmpstr);
              }
            if (user.auth_string.length &&
                user.plugin.str != native_password_plugin_name.str &&
                user.plugin.str != old_password_plugin_name.str)
            {
              sql_print_warning("'user' entry '%s@%s' has both a password "
                                "and an authentication plugin specified. The "
                                "password will be ignored.",
                                user.user ? user.user : "",
                                user.host.get_host() ? user.host.get_host() : "");
            }
            user.auth_string.str=
              get_field(&global_acl_memory,
                        table->field[MYSQL_USER_FIELD_AUTHENTICATION_STRING]);
            if (!user.auth_string.str)
              user.auth_string.str= const_cast<char*>("");
            user.auth_string.length= strlen(user.auth_string.str);
          }
          else /* skip auth_string if there's no plugin */
            next_field++;
        }

        if (table->s->fields >= 43)
        {
          char *tmpstr= get_field(&global_acl_memory,
                                  table->field[MYSQL_USER_FIELD_PASSWORD_EXPIRED]);
          if (tmpstr && (*tmpstr == 'Y' || *tmpstr == 'y'))
          {
            user.password_expired= true;

            if (!auth_plugin_supports_expiration(user.plugin.str))
            {
              sql_print_warning("'user' entry '%s@%s' has the password ignore "
                                "flag raised, but its authentication plugin "
                                "doesn't support password expiration. "
                                "The user id will be ignored.",
                                user.user ? user.user : "",
                                user.host.get_host() ? user.host.get_host() : "");
              continue;
            }
          }
        }
      } // end if (table->s->fields >= 31)
      else
      {
        user.ssl_type=SSL_TYPE_NONE;
#ifndef TO_BE_REMOVED
        if (table->s->fields <= 13)
        {						// Without grant
          if (user.access & CREATE_ACL)
            user.access|=REFERENCES_ACL | INDEX_ACL | ALTER_ACL;
        }
        /* Convert old privileges */
        user.access|= LOCK_TABLES_ACL | CREATE_TMP_ACL | SHOW_DB_ACL;
        if (user.access & FILE_ACL)
          user.access|= REPL_CLIENT_ACL | REPL_SLAVE_ACL;
        if (user.access & PROCESS_ACL)
          user.access|= SUPER_ACL | EXECUTE_ACL;
#endif
      }
      (void) push_dynamic(&acl_users,(uchar*) &user);
      if (user.host.check_allow_all_hosts())
        allow_all_hosts=1;			// Anyone can connect
    }
  } // END while reading records from the mysql.user table
  
  my_qsort((uchar*) dynamic_element(&acl_users,0,ACL_USER*),acl_users.elements,
	   sizeof(ACL_USER),(qsort_cmp) acl_compare);
  end_read_record(&read_record_info);
  freeze_size(&acl_users);

  /* Legacy password integrity checks ----------------------------------------*/
  { 
    password_length= table->field[MYSQL_USER_FIELD_PASSWORD]->field_length /
      table->field[MYSQL_USER_FIELD_PASSWORD]->charset()->mbmaxlen;
    if (password_length < SCRAMBLED_PASSWORD_CHAR_LENGTH_323)
    {
      sql_print_error("Fatal error: mysql.user table is damaged or in "
                      "unsupported 3.20 format.");
      goto end;
    }
  
    DBUG_PRINT("info",("user table fields: %d, password length: %d",
  		     table->s->fields, password_length));

    mysql_mutex_lock(&LOCK_global_system_variables);
    if (password_length < SCRAMBLED_PASSWORD_CHAR_LENGTH)
    { 
      if (opt_secure_auth)
      {
        mysql_mutex_unlock(&LOCK_global_system_variables);
        sql_print_error("Fatal error: mysql.user table is in old format, "
                        "but server started with --secure-auth option.");
        goto end;
      }
      mysql_user_table_is_in_short_password_format= true;
      if (global_system_variables.old_passwords)
        mysql_mutex_unlock(&LOCK_global_system_variables);
      else
      {
        global_system_variables.old_passwords= 1;
        mysql_mutex_unlock(&LOCK_global_system_variables);
        sql_print_warning("mysql.user table is not updated to new password format; "
                          "Disabling new password usage until "
                          "mysql_fix_privilege_tables is run");
      }
      thd->variables.old_passwords= 1;
    }
    else
    {
      mysql_user_table_is_in_short_password_format= false;
      mysql_mutex_unlock(&LOCK_global_system_variables);
    }
  } /* End legacy password integrity checks ----------------------------------*/
  
  /*
    Prepare reading from the mysql.db table
  */
  if (init_read_record(&read_record_info, thd, table=tables[1].table,
                       NULL, 1, 1, FALSE))
    goto end;
  table->use_all_columns();
  (void) my_init_dynamic_array(&acl_dbs,sizeof(ACL_DB),50,100);
  while (!(read_record_info.read_record(&read_record_info)))
  {
    /* Reading record in mysql.db */
    ACL_DB db;
    db.host.update_hostname(get_field(&global_acl_memory, 
                            table->field[MYSQL_DB_FIELD_HOST]));
    db.db=get_field(&global_acl_memory, table->field[MYSQL_DB_FIELD_DB]);
    if (!db.db)
    {
      sql_print_warning("Found an entry in the 'db' table with empty database name; Skipped");
      continue;
    }
    db.user=get_field(&global_acl_memory, table->field[MYSQL_DB_FIELD_USER]);
    if (check_no_resolve && hostname_requires_resolving(db.host.get_host()))
    {
      sql_print_warning("'db' entry '%s %s@%s' "
		        "ignored in --skip-name-resolve mode.",
		        db.db,
			db.user ? db.user : "",
			db.host.get_host() ? db.host.get_host() : "");
      continue;
    }
    db.access=get_access(table,3);
    db.access=fix_rights_for_db(db.access);
    if (lower_case_table_names)
    {
      /*
        convert db to lower case and give a warning if the db wasn't
        already in lower case
      */
      (void)strmov(tmp_name, db.db);
      my_casedn_str(files_charset_info, db.db);
      if (strcmp(db.db, tmp_name) != 0)
      {
        sql_print_warning("'db' entry '%s %s@%s' had database in mixed "
                          "case that has been forced to lowercase because "
                          "lower_case_table_names is set. It will not be "
                          "possible to remove this privilege using REVOKE.",
		          db.db,
			  db.user ? db.user : "",
			  db.host.get_host() ? db.host.get_host() : "");
      }
    }
    db.sort=get_sort(3,db.host.get_host(),db.db,db.user);
#ifndef TO_BE_REMOVED
    if (table->s->fields <=  9)
    {						// Without grant
      if (db.access & CREATE_ACL)
	db.access|=REFERENCES_ACL | INDEX_ACL | ALTER_ACL;
    }
#endif
    (void) push_dynamic(&acl_dbs,(uchar*) &db);
  } // END reading records from mysql.db tables
  
  my_qsort((uchar*) dynamic_element(&acl_dbs,0,ACL_DB*),acl_dbs.elements,
	   sizeof(ACL_DB),(qsort_cmp) acl_compare);
  end_read_record(&read_record_info);
  freeze_size(&acl_dbs);

  /* Prepare to read records from the mysql.proxies_priv table */
  (void) my_init_dynamic_array(&acl_proxy_users, sizeof(ACL_PROXY_USER), 
                               50, 100);
  if (tables[2].table)
  {
    if (init_read_record(&read_record_info, thd, table= tables[2].table,
                         NULL, 1, 1, FALSE))
      goto end;
    table->use_all_columns();
    while (!(read_record_info.read_record(&read_record_info)))
    {
      /* Reading record in mysql.proxies_priv */
      ACL_PROXY_USER proxy;
      proxy.init(table, &global_acl_memory);
      if (proxy.check_validity(check_no_resolve))
        continue;
      if (push_dynamic(&acl_proxy_users, (uchar*) &proxy))
      {
        end_read_record(&read_record_info);
        goto end;
      }
    } // END reading records from the mysql.proxies_priv table

    my_qsort((uchar*) dynamic_element(&acl_proxy_users, 0, ACL_PROXY_USER*),
             acl_proxy_users.elements,
             sizeof(ACL_PROXY_USER), (qsort_cmp) acl_compare);
    end_read_record(&read_record_info);
  }
  else
  {
    sql_print_error("Missing system table mysql.proxies_priv; "
                    "please run mysql_upgrade to create it");
  }
  freeze_size(&acl_proxy_users);

  init_check_host();

  initialized=1;
  return_val= FALSE;

end:
  thd->variables.sql_mode= old_sql_mode;
  DBUG_RETURN(return_val);
}


void acl_free(bool end)
{
  free_root(&global_acl_memory,MYF(0));
  delete_dynamic(&acl_users);
  delete_dynamic(&acl_dbs);
  delete_dynamic(&acl_wild_hosts);
  delete_dynamic(&acl_proxy_users);
  my_hash_free(&acl_check_hosts);
  plugin_unlock(0, native_password_plugin);
  plugin_unlock(0, old_password_plugin);
  if (!end)
    acl_cache->clear(1); /* purecov: inspected */
  else
  {
    delete acl_cache;
    acl_cache=0;
  }
}


/**
  A helper function to commit statement transaction and close
  ACL tables after reading some data from them as part of FLUSH
  PRIVILEGES statement or during server initialization.

  @note We assume that we have only read from the tables so commit
        can't fail. @sa close_mysql_tables().
*/

void close_acl_tables(THD *thd)
{
// #ifndef DBUG_OFF
//   bool res=
// #endif
//     trans_commit_stmt(thd);
//   DBUG_ASSERT(res == false);

  close_mysql_tables(thd);
}


/*
  Forget current user/db-level privileges and read new privileges
  from the privilege tables.

  SYNOPSIS
    acl_reload()
      thd  Current thread

  NOTE
    All tables of calling thread which were open and locked by LOCK TABLES
    statement will be unlocked and closed.
    This function is also used for initialization of structures responsible
    for user/db-level privilege checking.

  RETURN VALUE
    FALSE  Success
    TRUE   Failure
*/

my_bool acl_reload(THD *thd)
{
  TABLE_LIST tables[3];
  DYNAMIC_ARRAY old_acl_users, old_acl_dbs, old_acl_proxy_users;
  MEM_ROOT old_mem;
  bool old_initialized;
  my_bool return_val= TRUE;
  DBUG_ENTER("acl_reload");

  /*
    To avoid deadlocks we should obtain table locks before
    obtaining acl_cache->lock mutex.
  */
  tables[0].init_one_table(C_STRING_WITH_LEN("mysql"),
                           C_STRING_WITH_LEN("user"), "user", TL_READ);
  tables[1].init_one_table(C_STRING_WITH_LEN("mysql"),
                           C_STRING_WITH_LEN("db"), "db", TL_READ);
  tables[2].init_one_table(C_STRING_WITH_LEN("mysql"),
                           C_STRING_WITH_LEN("proxies_priv"), 
                           "proxies_priv", TL_READ);
  tables[0].next_local= tables[0].next_global= tables + 1;
  tables[1].next_local= tables[1].next_global= tables + 2;
  tables[0].open_type= tables[1].open_type= tables[2].open_type= OT_BASE_ONLY;
  tables[2].open_strategy= TABLE_LIST::OPEN_IF_EXISTS;

  if (open_and_lock_tables(thd, tables, FALSE, MYSQL_LOCK_IGNORE_TIMEOUT))
  {
    /*
      Execution might have been interrupted; only print the error message
      if a user error condition has been raised.
    */
    if (thd->get_stmt_da()->is_error())
    {
      sql_print_error("Fatal error: Can't open and lock privilege tables: %s",
                      thd->get_stmt_da()->message());
    }
    goto end;
  }

  if ((old_initialized=initialized))
    mysql_mutex_lock(&acl_cache->lock);

  old_acl_users= acl_users;
  old_acl_proxy_users= acl_proxy_users;
  old_acl_dbs= acl_dbs;
  old_mem= global_acl_memory;
  delete_dynamic(&acl_wild_hosts);
  my_hash_free(&acl_check_hosts);

  if ((return_val= acl_load(thd, tables)))
  {					// Error. Revert to old list
    DBUG_PRINT("error",("Reverting to old privileges"));
    acl_free();				/* purecov: inspected */
    acl_users= old_acl_users;
    acl_proxy_users= old_acl_proxy_users;
    acl_dbs= old_acl_dbs;
    global_acl_memory= old_mem;
    init_check_host();
  }
  else
  {
    free_root(&old_mem,MYF(0));
    delete_dynamic(&old_acl_users);
    delete_dynamic(&old_acl_proxy_users);
    delete_dynamic(&old_acl_dbs);
  }
  if (old_initialized)
    mysql_mutex_unlock(&acl_cache->lock);
end:
  close_acl_tables(thd);
  DBUG_RETURN(return_val);
}


/*
  Get all access bits from table after fieldnr

  IMPLEMENTATION
  We know that the access privileges ends when there is no more fields
  or the field is not an enum with two elements.

  SYNOPSIS
    get_access()
    form        an open table to read privileges from.
                The record should be already read in table->record[0]
    fieldnr     number of the first privilege (that is ENUM('N','Y') field
    next_field  on return - number of the field next to the last ENUM
                (unless next_field == 0)

  RETURN VALUE
    privilege mask
*/

static ulong get_access(TABLE *form, uint fieldnr, uint *next_field)
{
  ulong access_bits=0,bit;
  char buff[2];
  String res(buff,sizeof(buff),&my_charset_latin1);
  Field **pos;

  for (pos=form->field+fieldnr, bit=1;
       *pos && (*pos)->real_type() == MYSQL_TYPE_ENUM &&
	 ((Field_enum*) (*pos))->typelib->count == 2 ;
       pos++, fieldnr++, bit<<=1)
  {
    (*pos)->val_str(&res);
    if (my_toupper(&my_charset_latin1, res[0]) == 'Y')
      access_bits|= bit;
  }
  if (next_field)
    *next_field=fieldnr;
  return access_bits;
}


/*
  Return a number which, if sorted 'desc', puts strings in this order:
    no wildcards
    wildcards
    empty string
*/

static ulong get_sort(uint count,...)
{
  va_list args;
  va_start(args,count);
  ulong sort=0;

  /* Should not use this function with more than 4 arguments for compare. */
  DBUG_ASSERT(count <= 4);

  while (count--)
  {
    char *start, *str= va_arg(args,char*);
    uint chars= 0;
    uint wild_pos= 0;           /* first wildcard position */

    if ((start= str))
    {
      for (; *str ; str++)
      {
        if (*str == wild_prefix && str[1])
          str++;
        else if (*str == wild_many || *str == wild_one)
        {
          wild_pos= (uint) (str - start) + 1;
          break;
        }
        chars= 128;                             // Marker that chars existed
      }
    }
    sort= (sort << 8) + (wild_pos ? min(wild_pos, 127U) : chars);
  }
  va_end(args);
  return sort;
}


static int acl_compare(ACL_ACCESS *a,ACL_ACCESS *b)
{
  if (a->sort > b->sort)
    return -1;
  if (a->sort < b->sort)
    return 1;
  return 0;
}


/*
  Gets user credentials without authentication and resource limit checks.

  SYNOPSIS
    acl_getroot()
      sctx               Context which should be initialized
      user               user name
      host               host name
      ip                 IP
      db                 current data base name

  RETURN
    FALSE  OK
    TRUE   Error
*/

bool acl_getroot(Security_context *sctx, char *user, char *host,
                 char *ip, char *db)
{
  int res= 1;
  uint i;
  ACL_USER *acl_user= 0;
  DBUG_ENTER("acl_getroot");

  DBUG_PRINT("enter", ("Host: '%s', Ip: '%s', User: '%s', db: '%s'",
                       (host ? host : "(NULL)"), (ip ? ip : "(NULL)"),
                       user, (db ? db : "(NULL)")));
  sctx->user= user;
  sctx->host= host;
  sctx->ip= ip;
  sctx->host_or_ip= host ? host : (ip ? ip : "");

  if (!initialized)
  {
    /*
      here if mysqld's been started with --skip-grant-tables option.
    */
    sctx->skip_grants();
    DBUG_RETURN(FALSE);
  }

  mysql_mutex_lock(&acl_cache->lock);

  sctx->master_access= 0;
  sctx->db_access= 0;
  *sctx->priv_user= *sctx->priv_host= 0;

  /*
     Find acl entry in user database.
     This is specially tailored to suit the check we do for CALL of
     a stored procedure; user is set to what is actually a
     priv_user, which can be ''.
  */
  for (i=0 ; i < acl_users.elements ; i++)
  {
    ACL_USER *acl_user_tmp= dynamic_element(&acl_users,i,ACL_USER*);
    if ((!acl_user_tmp->user && !user[0]) ||
        (acl_user_tmp->user && strcmp(user, acl_user_tmp->user) == 0))
    {
      if (acl_user_tmp->host.compare_hostname(host, ip))
      {
        acl_user= acl_user_tmp;
        res= 0;
        break;
      }
    }
  }

  if (acl_user)
  {
    for (i=0 ; i < acl_dbs.elements ; i++)
    {
      ACL_DB *acl_db= dynamic_element(&acl_dbs, i, ACL_DB*);
      if (!acl_db->user ||
	  (user && user[0] && !strcmp(user, acl_db->user)))
      {
	if (acl_db->host.compare_hostname(host, ip))
	{
	  if (!acl_db->db || (db && !wild_compare(db, acl_db->db, 0)))
	  {
	    sctx->db_access= acl_db->access;
	    break;
	  }
	}
      }
    }
    sctx->master_access= acl_user->access;

    if (acl_user->user)
      strmake(sctx->priv_user, user, USERNAME_LENGTH);
    else
      *sctx->priv_user= 0;

    if (acl_user->host.get_host())
      strmake(sctx->priv_host, acl_user->host.get_host(), MAX_HOSTNAME - 1);
    else
      *sctx->priv_host= 0;

    sctx->password_expired= acl_user->password_expired;
  }
  mysql_mutex_unlock(&acl_cache->lock);
  DBUG_RETURN(res);
}

static uchar* check_get_key(ACL_USER *buff, size_t *length,
                            my_bool not_used __attribute__((unused)))
{
  *length=buff->host.get_host_len();
  return (uchar*) buff->host.get_host();
}


static void acl_update_user(const char *user, const char *host,
			    const char *password, uint password_len,
			    enum SSL_type ssl_type,
			    const char *ssl_cipher,
			    const char *x509_issuer,
			    const char *x509_subject,
			    USER_RESOURCES  *mqh,
			    ulong privileges,
			    const LEX_STRING *plugin,
			    const LEX_STRING *auth)
{
  DBUG_ENTER("acl_update_user");
  mysql_mutex_assert_owner(&acl_cache->lock);
  for (uint i=0 ; i < acl_users.elements ; i++)
  {
    ACL_USER *acl_user=dynamic_element(&acl_users,i,ACL_USER*);
    if ((!acl_user->user && !user[0]) ||
	(acl_user->user && !strcmp(user,acl_user->user)))
    {
      if ((!acl_user->host.get_host() && !host[0]) ||
	  (acl_user->host.get_host() &&
	  !my_strcasecmp(system_charset_info, host, acl_user->host.get_host())))
      {
        if (plugin->length > 0)
        {
          acl_user->plugin= *plugin;
          optimize_plugin_compare_by_pointer(&acl_user->plugin);
          if (!auth_plugin_is_built_in(acl_user->plugin.str))
            acl_user->plugin.str= strmake_root(&global_acl_memory, plugin->str, plugin->length);
          acl_user->auth_string.str= auth->str ?
            strmake_root(&global_acl_memory, auth->str,
                         auth->length) : const_cast<char*>("");
          acl_user->auth_string.length= auth->length;
        }
	acl_user->access=privileges;
	if (mqh->specified_limits & USER_RESOURCES::QUERIES_PER_HOUR)
	  acl_user->user_resource.questions=mqh->questions;
	if (mqh->specified_limits & USER_RESOURCES::UPDATES_PER_HOUR)
	  acl_user->user_resource.updates=mqh->updates;
	if (mqh->specified_limits & USER_RESOURCES::CONNECTIONS_PER_HOUR)
	  acl_user->user_resource.conn_per_hour= mqh->conn_per_hour;
	if (mqh->specified_limits & USER_RESOURCES::USER_CONNECTIONS)
	  acl_user->user_resource.user_conn= mqh->user_conn;
	if (ssl_type != SSL_TYPE_NOT_SPECIFIED)
	{
	  acl_user->ssl_type= ssl_type;
	  acl_user->ssl_cipher= (ssl_cipher ? strdup_root(&global_acl_memory,
                                                    ssl_cipher) :	0);
	  acl_user->x509_issuer= (x509_issuer ? strdup_root(&global_acl_memory,
                                                      x509_issuer) : 0);
	  acl_user->x509_subject= (x509_subject ?
				   strdup_root(&global_acl_memory, x509_subject) : 0);
	}
  
  
        if (password)
        {
          /*
            We just assert the hash is valid here since it's already
            checked in replace_user_table().
          */
          int hash_not_ok= set_user_salt(acl_user, password, password_len);

          DBUG_ASSERT(hash_not_ok == 0);
          /* dummy addition to fool the compiler */
          password_len+= hash_not_ok;
        }
        /* search complete: */
	break;
      }
    }
  }
  DBUG_VOID_RETURN;
}


static void acl_insert_user(const char *user, const char *host,
			    const char *password, uint password_len,
			    enum SSL_type ssl_type,
			    const char *ssl_cipher,
			    const char *x509_issuer,
			    const char *x509_subject,
			    USER_RESOURCES *mqh,
			    ulong privileges,
			    const LEX_STRING *plugin,
			    const LEX_STRING *auth)
{
  DBUG_ENTER("acl_insert_user");
  ACL_USER acl_user;
  int hash_not_ok;

  mysql_mutex_assert_owner(&acl_cache->lock);

  acl_user.user= *user ? strdup_root(&global_acl_memory,user) : 0;
  acl_user.host.update_hostname(*host ? strdup_root(&global_acl_memory, host) : 0);
  if (plugin->str[0])
  {
    acl_user.plugin= *plugin;
    optimize_plugin_compare_by_pointer(&acl_user.plugin);
    if (!auth_plugin_is_built_in(acl_user.plugin.str))
      acl_user.plugin.str= strmake_root(&global_acl_memory, plugin->str, plugin->length);
    acl_user.auth_string.str= auth->str ?
      strmake_root(&global_acl_memory, auth->str,
                   auth->length) : const_cast<char*>("");
    acl_user.auth_string.length= auth->length;

    optimize_plugin_compare_by_pointer(&acl_user.plugin);
  }
  else
  {
    acl_user.plugin= password_len == SCRAMBLED_PASSWORD_CHAR_LENGTH_323 ?
      old_password_plugin_name : native_password_plugin_name;
    acl_user.auth_string.str= const_cast<char*>("");
    acl_user.auth_string.length= 0;
  }

  acl_user.access= privileges;
  acl_user.user_resource= *mqh;
  acl_user.sort= get_sort(2,acl_user.host.get_host(), acl_user.user);
  //acl_user.hostname_length=(uint) strlen(host);
  acl_user.ssl_type=
    (ssl_type != SSL_TYPE_NOT_SPECIFIED ? ssl_type : SSL_TYPE_NONE);
  acl_user.ssl_cipher=
    ssl_cipher ? strdup_root(&global_acl_memory, ssl_cipher) : 0;
  acl_user.x509_issuer=
    x509_issuer ? strdup_root(&global_acl_memory, x509_issuer) : 0;
  acl_user.x509_subject=
    x509_subject ? strdup_root(&global_acl_memory, x509_subject) : 0;

  hash_not_ok= set_user_salt(&acl_user, password, password_len);
  DBUG_ASSERT(hash_not_ok == 0);
  /* dummy addition to fool the compiler */
  password_len+= hash_not_ok;
  

  (void) push_dynamic(&acl_users,(uchar*) &acl_user);
  if (acl_user.host.check_allow_all_hosts())
    allow_all_hosts=1;		// Anyone can connect /* purecov: tested */
  my_qsort((uchar*) dynamic_element(&acl_users,0,ACL_USER*),acl_users.elements,
	   sizeof(ACL_USER),(qsort_cmp) acl_compare);

  /* Rebuild 'acl_check_hosts' since 'acl_users' has been modified */
  rebuild_check_host();
  DBUG_VOID_RETURN;
}


static void acl_update_db(const char *user, const char *host, const char *db,
			  ulong privileges)
{
  mysql_mutex_assert_owner(&acl_cache->lock);

  for (uint i=0 ; i < acl_dbs.elements ; i++)
  {
    ACL_DB *acl_db=dynamic_element(&acl_dbs,i,ACL_DB*);
    if ((!acl_db->user && !user[0]) ||
	(acl_db->user &&
	!strcmp(user,acl_db->user)))
    {
      if ((!acl_db->host.get_host() && !host[0]) ||
	  (acl_db->host.get_host() &&
          !strcmp(host, acl_db->host.get_host())))
      {
	if ((!acl_db->db && !db[0]) ||
	    (acl_db->db && !strcmp(db,acl_db->db)))
	{
	  if (privileges)
	    acl_db->access=privileges;
	  else
	    delete_dynamic_element(&acl_dbs,i);
	}
      }
    }
  }
}


/*
  Insert a user/db/host combination into the global acl_cache

  SYNOPSIS
    acl_insert_db()
    user		User name
    host		Host name
    db			Database name
    privileges		Bitmap of privileges

  NOTES
    acl_cache->lock must be locked when calling this
*/

static void acl_insert_db(const char *user, const char *host, const char *db,
			  ulong privileges)
{
  ACL_DB acl_db;
  mysql_mutex_assert_owner(&acl_cache->lock);
  acl_db.user= strdup_root(&global_acl_memory,user);
  acl_db.host.update_hostname(*host ? strdup_root(&global_acl_memory, host) : 0);
  acl_db.db= strdup_root(&global_acl_memory, db);
  acl_db.access= privileges;
  acl_db.sort= get_sort(3,acl_db.host.get_host(), acl_db.db, acl_db.user);
  (void) push_dynamic(&acl_dbs, (uchar*) &acl_db);
  my_qsort((uchar*) dynamic_element(&acl_dbs, 0, ACL_DB*), acl_dbs.elements,
	         sizeof(ACL_DB),(qsort_cmp) acl_compare);
}



/*
  Get privilege for a host, user and db combination

  as db_is_pattern changes the semantics of comparison,
  acl_cache is not used if db_is_pattern is set.
*/

ulong acl_get(const char *host, const char *ip,
              const char *user, const char *db, my_bool db_is_pattern)
{
  ulong host_access= ~(ulong)0, db_access= 0;
  uint i;
  size_t key_length, copy_length;
  char key[ACL_KEY_LENGTH],*tmp_db,*end;
  acl_entry *entry;
  DBUG_ENTER("acl_get");

  copy_length= (size_t) (strlen(ip ? ip : "") +
                 strlen(user ? user : "") +
                 strlen(db ? db : ""));
  /*
    Make sure that strmov() operations do not result in buffer overflow.
  */
  if (copy_length >= ACL_KEY_LENGTH)
    DBUG_RETURN(0);

  mysql_mutex_lock(&acl_cache->lock);
  end=strmov((tmp_db=strmov(strmov(key, ip ? ip : "")+1,user)+1),db);
  if (lower_case_table_names)
  {
    my_casedn_str(files_charset_info, tmp_db);
    db=tmp_db;
  }
  key_length= (size_t) (end-key);
  if (!db_is_pattern && (entry=(acl_entry*) acl_cache->search((uchar*) key,
                                                              key_length)))
  {
    db_access=entry->access;
    mysql_mutex_unlock(&acl_cache->lock);
    DBUG_PRINT("exit", ("access: 0x%lx", db_access));
    DBUG_RETURN(db_access);
  }

  /*
    Check if there are some access rights for database and user
  */
  for (i=0 ; i < acl_dbs.elements ; i++)
  {
    ACL_DB *acl_db=dynamic_element(&acl_dbs,i,ACL_DB*);
    if (!acl_db->user || !strcmp(user,acl_db->user))
    {
      if (acl_db->host.compare_hostname(host,ip))
      {
	if (!acl_db->db || !wild_compare(db,acl_db->db,db_is_pattern))
	{
	  db_access=acl_db->access;
	  if (acl_db->host.get_host())
	    goto exit;				// Fully specified. Take it
	  break; /* purecov: tested */
	}
      }
    }
  }
  if (!db_access)
    goto exit;					// Can't be better

exit:
  /* Save entry in cache for quick retrieval */
  if (!db_is_pattern &&
      (entry= (acl_entry*) malloc(sizeof(acl_entry)+key_length)))
  {
    entry->access=(db_access & host_access);
    entry->length=key_length;
    memcpy((uchar*) entry->key,key,key_length);
    acl_cache->add(entry);
  }
  mysql_mutex_unlock(&acl_cache->lock);
  DBUG_PRINT("exit", ("access: 0x%lx", db_access & host_access));
  DBUG_RETURN(db_access & host_access);
}

/*
  Check if there are any possible matching entries for this host

  NOTES
    All host names without wild cards are stored in a hash table,
    entries with wildcards are stored in a dynamic array
*/

static void init_check_host(void)
{
  DBUG_ENTER("init_check_host");
  (void) my_init_dynamic_array(&acl_wild_hosts,sizeof(class ACL_HOST_AND_IP),
			  acl_users.elements,1);
  (void) my_hash_init(&acl_check_hosts,system_charset_info,
                      acl_users.elements, 0, 0,
                      (my_hash_get_key) check_get_key, 0, 0);
  if (!allow_all_hosts)
  {
    for (uint i=0 ; i < acl_users.elements ; i++)
    {
      ACL_USER *acl_user=dynamic_element(&acl_users,i,ACL_USER*);
      if (acl_user->host.has_wildcard())
      {						// Has wildcard
	uint j;
	for (j=0 ; j < acl_wild_hosts.elements ; j++)
	{					// Check if host already exists
	  ACL_HOST_AND_IP *acl=dynamic_element(&acl_wild_hosts,j,
					       ACL_HOST_AND_IP *);
	  if (!my_strcasecmp(system_charset_info,
                             acl_user->host.get_host(), acl->get_host()))
	    break;				// already stored
	}
	if (j == acl_wild_hosts.elements)	// If new
	  (void) push_dynamic(&acl_wild_hosts,(uchar*) &acl_user->host);
      }
      else if (!my_hash_search(&acl_check_hosts,(uchar*)
                               acl_user->host.get_host(),
                               strlen(acl_user->host.get_host())))
      {
	if (my_hash_insert(&acl_check_hosts,(uchar*) acl_user))
	{					// End of memory
	  allow_all_hosts=1;			// Should never happen
	  DBUG_VOID_RETURN;
	}
      }
    }
  }
  freeze_size(&acl_wild_hosts);
  freeze_size(&acl_check_hosts.array);
  DBUG_VOID_RETURN;
}


/*
  Rebuild lists used for checking of allowed hosts

  We need to rebuild 'acl_check_hosts' and 'acl_wild_hosts' after adding,
  dropping or renaming user, since they contain pointers to elements of
  'acl_user' array, which are invalidated by drop operation, and use
  ACL_USER::host::hostname as a key, which is changed by rename.
*/
void rebuild_check_host(void)
{
  delete_dynamic(&acl_wild_hosts);
  my_hash_free(&acl_check_hosts);
  init_check_host();
}


/* Return true if there is no users that can match the given host */

bool acl_check_host(const char *host, const char *ip)
{
  if (allow_all_hosts)
    return 0;
  mysql_mutex_lock(&acl_cache->lock);

  if ((host && my_hash_search(&acl_check_hosts,(uchar*) host,strlen(host))) ||
      (ip && my_hash_search(&acl_check_hosts,(uchar*) ip, strlen(ip))))
  {
    mysql_mutex_unlock(&acl_cache->lock);
    return 0;					// Found host
  }
  for (uint i=0 ; i < acl_wild_hosts.elements ; i++)
  {
    ACL_HOST_AND_IP *acl=dynamic_element(&acl_wild_hosts,i,ACL_HOST_AND_IP*);
    if (acl->compare_hostname(host, ip))
    {
      mysql_mutex_unlock(&acl_cache->lock);
      return 0;					// Host ok
    }
  }
  mysql_mutex_unlock(&acl_cache->lock);
  if (ip != NULL)
  {
    /* Increment HOST_CACHE.COUNT_HOST_ACL_ERRORS. */
    Host_errors errors;
    errors.m_host_acl= 1;
    //inc_host_errors(ip, &errors);
  }
  return 1;					// Host is not allowed
}

/**
  Change a password hash for a user.

  @param thd Thread handle
  @param host Hostname
  @param user User name
  @param new_password New password hash for host@user
 
  Note : it will also reset the change_password flag.
  This is safe to do unconditionally since the simple userless form
  SET PASSWORD = PASSWORD('text') will be the only allowed form when
  this flag is on. So we don't need to check user names here.


  @see set_var_password::update(THD *thd)

  @return Error code
   @retval 0 ok
   @retval 1 ERROR; In this case the error is sent to the client.
*/

/*
  Find user in ACL

  SYNOPSIS
    is_acl_user()
    host                 host name
    user                 user name

  RETURN
   FALSE  user not fond
   TRUE   there are such user
*/

bool is_acl_user(const char *host, const char *user)
{
  bool res;

  /* --skip-grants */
  if (!initialized)
    return TRUE;

  mysql_mutex_lock(&acl_cache->lock);
  res= find_acl_user(host, user, TRUE) != NULL;
  mysql_mutex_unlock(&acl_cache->lock);
  return res;
}


/*
  Find first entry that matches the current user
*/

static ACL_USER *
find_acl_user(const char *host, const char *user, my_bool exact)
{
  DBUG_ENTER("find_acl_user");
  DBUG_PRINT("enter",("host: '%s'  user: '%s'",host,user));

  mysql_mutex_assert_owner(&acl_cache->lock);

  for (uint i=0 ; i < acl_users.elements ; i++)
  {
    ACL_USER *acl_user=dynamic_element(&acl_users,i,ACL_USER*);
    DBUG_PRINT("info",("strcmp('%s','%s'), compare_hostname('%s','%s'),",
                       user, acl_user->user ? acl_user->user : "",
                       host,
                       acl_user->host.get_host() ? acl_user->host.get_host() :
                       ""));
    if ((!acl_user->user && !user[0]) ||
	(acl_user->user && !strcmp(user,acl_user->user)))
    {
      if (exact ? !my_strcasecmp(system_charset_info, host,
                                 acl_user->host.get_host() ?
				 acl_user->host.get_host() : "") :
          acl_user->host.compare_hostname(host,host))
      {
	DBUG_RETURN(acl_user);
      }
    }
  }
  DBUG_RETURN(0);
}

/**
  Check if the given host name needs to be resolved or not.
  Host name has to be resolved if it actually contains *name*.

  For example:
    192.168.1.1               --> FALSE
    192.168.1.0/255.255.255.0 --> FALSE
    %                         --> FALSE
    192.168.1.%               --> FALSE
    AB%                       --> FALSE

    AAAAFFFF                  --> TRUE (Hostname)
    AAAA:FFFF:1234:5678       --> FALSE
    ::1                       --> FALSE

  This function does not check if the given string is a valid host name or
  not. It assumes that the argument is a valid host name.

  @param hostname   the string to check.

  @return a flag telling if the argument needs to be resolved or not.
  @retval TRUE the argument is a host name and needs to be resolved.
  @retval FALSE the argument is either an IP address, or a patter and
          should not be resolved.
*/

bool hostname_requires_resolving(const char *hostname)
{
  if (!hostname)
    return FALSE;

  /* Check if hostname is the localhost. */

  size_t hostname_len= strlen(hostname);
  size_t localhost_len= strlen(my_localhost);

  if (hostname == my_localhost ||
      (hostname_len == localhost_len &&
       !my_strnncoll(system_charset_info,
                     (const uchar *) hostname,  hostname_len,
                     (const uchar *) my_localhost, strlen(my_localhost))))
  {
    return FALSE;
  }

  /*
    If the string contains any of {':', '%', '_', '/'}, it is definitely
    not a host name:
      - ':' means that the string is an IPv6 address;
      - '%' or '_' means that the string is a pattern;
      - '/' means that the string is an IPv4 network address;
  */

  for (const char *p= hostname; *p; ++p)
  {
    switch (*p) {
      case ':':
      case '%':
      case '_':
      case '/':
        return FALSE;
    }
  }

  /*
    Now we have to tell a host name (ab.cd, 12.ab) from an IPv4 address
    (12.34.56.78). The assumption is that if the string contains only
    digits and dots, it is an IPv4 address. Otherwise -- a host name.
  */

  for (const char *p= hostname; *p; ++p)
  {
    if (*p != '.' && !my_isdigit(&my_charset_latin1, *p))
      return TRUE; /* a "letter" has been found. */
  }

  return FALSE; /* all characters are either dots or digits. */
}
/**
  Only the plugins that are known to use the mysql.user table 
  to store their passwords support password expiration atm.
  TODO: create a service and extend the plugin API to support
  password expiration for external plugins.

  @retval      false  expiration not supported
  @retval      true   expiration supported
*/
bool auth_plugin_supports_expiration(const char *plugin_name)
{
 return (!plugin_name || !*plugin_name ||
         plugin_name == native_password_plugin_name.str ||
#if defined(HAVE_OPENSSL)
         plugin_name == sha256_password_plugin_name.str ||
#endif
         plugin_name == old_password_plugin_name.str);
}


bool auth_plugin_is_built_in(const char *plugin_name)
{
 return (plugin_name == native_password_plugin_name.str ||
#if defined(HAVE_OPENSSL)
         plugin_name == sha256_password_plugin_name.str ||
#endif
         plugin_name == old_password_plugin_name.str);
}

void optimize_plugin_compare_by_pointer(LEX_STRING *plugin_name)
{
#if defined(HAVE_OPENSSL)
  if (my_strcasecmp(system_charset_info, sha256_password_plugin_name.str,
                    plugin_name->str) == 0)
  {
    plugin_name->str= sha256_password_plugin_name.str;
    plugin_name->length= sha256_password_plugin_name.length;
  }
  else
#endif
  if (my_strcasecmp(system_charset_info, native_password_plugin_name.str,
                    plugin_name->str) == 0)
  {
    plugin_name->str= native_password_plugin_name.str;
    plugin_name->length= native_password_plugin_name.length;
  }
  else
  if (my_strcasecmp(system_charset_info, old_password_plugin_name.str,
                    plugin_name->str) == 0)
  {
    plugin_name->str= old_password_plugin_name.str;
    plugin_name->length= old_password_plugin_name.length;
  }

  DBUG_ASSERT(auth_plugin_is_built_in(native_password_plugin_name.str));
}


static void  
acl_update_proxy_user(ACL_PROXY_USER *new_value, bool is_revoke)
{
  mysql_mutex_assert_owner(&acl_cache->lock);

  DBUG_ENTER("acl_update_proxy_user");
  for (uint i= 0; i < acl_proxy_users.elements; i++)
  {
    ACL_PROXY_USER *acl_user= 
      dynamic_element(&acl_proxy_users, i, ACL_PROXY_USER *);

    if (acl_user->pk_equals(new_value))
    {
      if (is_revoke)
      {
        DBUG_PRINT("info", ("delting ACL_PROXY_USER"));
        delete_dynamic_element(&acl_proxy_users, i);
      }
      else
      {
        DBUG_PRINT("info", ("updating ACL_PROXY_USER"));
        acl_user->set_data(new_value);
      }
      break;
    }
  }
  DBUG_VOID_RETURN;
}


static void  
acl_insert_proxy_user(ACL_PROXY_USER *new_value)
{
  DBUG_ENTER("acl_insert_proxy_user");
  mysql_mutex_assert_owner(&acl_cache->lock);
  (void) push_dynamic(&acl_proxy_users, (uchar *) new_value);
  my_qsort((uchar*) dynamic_element(&acl_proxy_users, 0, ACL_PROXY_USER *),
           acl_proxy_users.elements,
           sizeof(ACL_PROXY_USER), (qsort_cmp) acl_compare);
  DBUG_VOID_RETURN;
}


class GRANT_COLUMN :public Sql_alloc
{
public:
  char *column;
  ulong rights;
  uint key_length;
  GRANT_COLUMN(String &c,  ulong y) :rights (y)
  {
    column= (char*) memdup_root(&memex,c.ptr(), key_length=c.length());
  }
};


static uchar* get_key_column(GRANT_COLUMN *buff, size_t *length,
			    my_bool not_used __attribute__((unused)))
{
  *length=buff->key_length;
  return (uchar*) buff->column;
}


class GRANT_NAME :public Sql_alloc
{
public:
  ACL_HOST_AND_IP host;
  char *db, *user, *tname, *hash_key;
  ulong privs;
  ulong sort;
  size_t key_length;
  GRANT_NAME(const char *h, const char *d,const char *u,
             const char *t, ulong p, bool is_routine);
  GRANT_NAME (TABLE *form, bool is_routine);
  virtual ~GRANT_NAME() {};
  virtual bool ok() { return privs != 0; }
  void set_user_details(const char *h, const char *d,
                        const char *u, const char *t,
                        bool is_routine);
};


class GRANT_TABLE :public GRANT_NAME
{
public:
  ulong cols;
  HASH hash_columns;

  GRANT_TABLE(const char *h, const char *d,const char *u,
              const char *t, ulong p, ulong c);
  GRANT_TABLE (TABLE *form, TABLE *col_privs);
  ~GRANT_TABLE();
  bool ok() { return privs != 0 || cols != 0; }
};


void GRANT_NAME::set_user_details(const char *h, const char *d,
                                  const char *u, const char *t,
                                  bool is_routine)
{
  /* Host given by user */
  host.update_hostname(strdup_root(&memex, h));
  if (db != d)
  {
    db= strdup_root(&memex, d);
    if (lower_case_table_names)
      my_casedn_str(files_charset_info, db);
  }
  user = strdup_root(&memex,u);
  sort=  get_sort(3,host.get_host(),db,user);
  if (tname != t)
  {
    tname= strdup_root(&memex, t);
    if (lower_case_table_names || is_routine)
      my_casedn_str(files_charset_info, tname);
  }
  key_length= strlen(d) + strlen(u)+ strlen(t)+3;
  hash_key=   (char*) alloc_root(&memex,key_length);
  strmov(strmov(strmov(hash_key,user)+1,db)+1,tname);
}

GRANT_NAME::GRANT_NAME(const char *h, const char *d,const char *u,
                       const char *t, ulong p, bool is_routine)
  :db(0), tname(0), privs(p)
{
  set_user_details(h, d, u, t, is_routine);
}

GRANT_TABLE::GRANT_TABLE(const char *h, const char *d,const char *u,
                	 const char *t, ulong p, ulong c)
  :GRANT_NAME(h,d,u,t,p, FALSE), cols(c)
{
  (void) my_hash_init2(&hash_columns,4,system_charset_info,
                   0,0,0, (my_hash_get_key) get_key_column,0,0);
}


GRANT_NAME::GRANT_NAME(TABLE *form, bool is_routine)
{
  host.update_hostname(get_field(&memex, form->field[0]));
  db=    get_field(&memex,form->field[1]);
  user=  get_field(&memex,form->field[2]);
  if (!user)
    user= (char*) "";
  sort=  get_sort(3, host.get_host(), db, user);
  tname= get_field(&memex,form->field[3]);
  if (!db || !tname) {
    /* Wrong table row; Ignore it */
    privs= 0;
    return;					/* purecov: inspected */
  }
  if (lower_case_table_names)
  {
    my_casedn_str(files_charset_info, db);
  }
  if (lower_case_table_names || is_routine)
  {
    my_casedn_str(files_charset_info, tname);
  }
  key_length= (strlen(db) + strlen(user) + strlen(tname) + 3);
  hash_key=   (char*) alloc_root(&memex, key_length);
  strmov(strmov(strmov(hash_key,user)+1,db)+1,tname);
  privs = (ulong) form->field[6]->val_int();
  privs = fix_rights_for_table(privs);
}


GRANT_TABLE::GRANT_TABLE(TABLE *form, TABLE *col_privs)
  :GRANT_NAME(form, FALSE)
{
  uchar key[MAX_KEY_LENGTH];

  if (!db || !tname)
  {
    /* Wrong table row; Ignore it */
    my_hash_clear(&hash_columns);               /* allow for destruction */
    cols= 0;
    return;
  }
  cols= (ulong) form->field[7]->val_int();
  cols =  fix_rights_for_column(cols);

  (void) my_hash_init2(&hash_columns,4,system_charset_info,
                   0,0,0, (my_hash_get_key) get_key_column,0,0);
  if (cols)
  {
    uint key_prefix_len;
    KEY_PART_INFO *key_part= col_privs->key_info->key_part;
    col_privs->field[0]->store(host.get_host(),
                               host.get_host() ? (uint) host.get_host_len() : 0,
                               system_charset_info);
    col_privs->field[1]->store(db,(uint) strlen(db), system_charset_info);
    col_privs->field[2]->store(user,(uint) strlen(user), system_charset_info);
    col_privs->field[3]->store(tname,(uint) strlen(tname), system_charset_info);

    key_prefix_len= (key_part[0].store_length +
                     key_part[1].store_length +
                     key_part[2].store_length +
                     key_part[3].store_length);
    key_copy(key, col_privs->record[0], col_privs->key_info, key_prefix_len);
    col_privs->field[4]->store("",0, &my_charset_latin1);

    if (col_privs->file->ha_index_init(0, 1))
    {
      cols= 0;
      return;
    }

    if (col_privs->file->ha_index_read_map(col_privs->record[0], (uchar*) key,
                                           (key_part_map)15, HA_READ_KEY_EXACT))
    {
      cols = 0; /* purecov: deadcode */
      col_privs->file->ha_index_end();
      return;
    }
    do
    {
      String *res,column_name;
      GRANT_COLUMN *mem_check;
      /* As column name is a string, we don't have to supply a buffer */
      res=col_privs->field[4]->val_str(&column_name);
      ulong priv= (ulong) col_privs->field[6]->val_int();
      if (!(mem_check = new GRANT_COLUMN(*res,
                                         fix_rights_for_column(priv))))
      {
        /* Don't use this entry */
        privs = cols = 0;			/* purecov: deadcode */
        return;				/* purecov: deadcode */
      }
      if (my_hash_insert(&hash_columns, (uchar *) mem_check))
      {
        /* Invalidate this entry */
        privs= cols= 0;
        return;
      }
    } while (!col_privs->file->ha_index_next(col_privs->record[0]) &&
             !key_cmp_if_same(col_privs,key,0,key_prefix_len));
    col_privs->file->ha_index_end();
  }
}


GRANT_TABLE::~GRANT_TABLE()
{
  my_hash_free(&hash_columns);
}


static uchar* get_grant_table(GRANT_NAME *buff, size_t *length,
			     my_bool not_used __attribute__((unused)))
{
  *length=buff->key_length;
  return (uchar*) buff->hash_key;
}


void free_grant_table(GRANT_TABLE *grant_table)
{
  my_hash_free(&grant_table->hash_columns);
}


/* Search after a matching grant. Prefer exact grants before not exact ones */

static GRANT_NAME *name_hash_search(HASH *name_hash,
                                    const char *host,const char* ip,
                                    const char *db,
                                    const char *user, const char *tname,
                                    bool exact, bool name_tolower)
{
  char helping [NAME_LEN*2+USERNAME_LENGTH+3], *name_ptr;
  uint len;
  GRANT_NAME *grant_name,*found=0;
  HASH_SEARCH_STATE state;

  name_ptr= strmov(strmov(helping, user) + 1, db) + 1;
  len  = (uint) (strmov(name_ptr, tname) - helping) + 1;
  if (name_tolower)
    my_casedn_str(files_charset_info, name_ptr);
  for (grant_name= (GRANT_NAME*) my_hash_first(name_hash, (uchar*) helping,
                                               len, &state);
       grant_name ;
       grant_name= (GRANT_NAME*) my_hash_next(name_hash,(uchar*) helping,
                                              len, &state))
  {
    if (exact)
    {
      if (!grant_name->host.get_host() ||
          (host &&
	   !my_strcasecmp(system_charset_info, host,
                          grant_name->host.get_host())) ||
	  (ip && !strcmp(ip, grant_name->host.get_host())))
	return grant_name;
    }
    else
    {
      if (grant_name->host.compare_hostname(host, ip) &&
          (!found || found->sort < grant_name->sort))
	found=grant_name;					// Host ok
    }
  }
  return found;
}


inline GRANT_NAME *
routine_hash_search(const char *host, const char *ip, const char *db,
                 const char *user, const char *tname, bool proc, bool exact)
{
  return (GRANT_TABLE*)
    name_hash_search(proc ? &proc_priv_hash : &func_priv_hash,
		     host, ip, db, user, tname, exact, TRUE);
}


inline GRANT_TABLE *
table_hash_search(const char *host, const char *ip, const char *db,
		  const char *user, const char *tname, bool exact)
{
  return (GRANT_TABLE*) name_hash_search(&column_priv_hash, host, ip, db,
					 user, tname, exact, FALSE);
}


inline GRANT_COLUMN *
column_hash_search(GRANT_TABLE *t, const char *cname, uint length)
{
  return (GRANT_COLUMN*) my_hash_search(&t->hash_columns,
                                        (uchar*) cname, length);
}


static inline void get_grantor(THD *thd, char *grantor)
{
  const char *user= thd->security_ctx->user;
  const char *host= thd->security_ctx->host_or_ip;

#if defined(HAVE_REPLICATION)
  if (thd->slave_thread && thd->has_invoker())
  {
    user= thd->get_invoker_user().str;
    host= thd->get_invoker_host().str;
  }
#endif
  strxmov(grantor, user, "@", host, NullS);
}


#endif /*NO_EMBEDDED_ACCESS_CHECKS */

const char *command_array[]=
{
  "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "RELOAD",
  "SHUTDOWN", "PROCESS","FILE", "GRANT", "REFERENCES", "INDEX",
  "ALTER", "SHOW DATABASES", "SUPER", "CREATE TEMPORARY TABLES",
  "LOCK TABLES", "EXECUTE", "REPLICATION SLAVE", "REPLICATION CLIENT",
  "CREATE VIEW", "SHOW VIEW", "CREATE ROUTINE", "ALTER ROUTINE",
  "CREATE USER", "EVENT", "TRIGGER", "CREATE TABLESPACE"
};

uint command_lengths[]=
{
  6, 6, 6, 6, 6, 4, 6, 8, 7, 4, 5, 10, 5, 5, 14, 5, 23, 11, 7, 17, 18, 11, 9,
  14, 13, 11, 5, 7, 17
};


#ifndef NO_EMBEDDED_ACCESS_CHECKS
/*
  fill effective privileges for table

  SYNOPSIS
    fill_effective_table_privileges()
    thd     thread handler
    grant   grants table descriptor
    db      db name
    table   table name
*/

void fill_effective_table_privileges(THD *thd, GRANT_INFO *grant,
                                     const char *db, const char *table)
{
  Security_context *sctx= thd->security_ctx;
  DBUG_ENTER("fill_effective_table_privileges");
  DBUG_PRINT("enter", ("Host: '%s', Ip: '%s', User: '%s', table: `%s`.`%s`",
                       sctx->priv_host, (sctx->ip ? sctx->ip : "(NULL)"),
                       (sctx->priv_user ? sctx->priv_user : "(NULL)"),
                       db, table));
  /* --skip-grants */
  if (!initialized)
  {
    DBUG_PRINT("info", ("skip grants"));
    grant->privilege= ~NO_ACCESS;             // everything is allowed
    DBUG_PRINT("info", ("privilege 0x%lx", grant->privilege));
    DBUG_VOID_RETURN;
  }

  /* global privileges */
  grant->privilege= sctx->master_access;

  if (!sctx->priv_user)
  {
    DBUG_PRINT("info", ("privilege 0x%lx", grant->privilege));
    DBUG_VOID_RETURN;                         // it is slave
  }

  /* db privileges */
  grant->privilege|= acl_get(sctx->host, sctx->ip, sctx->priv_user, db, 0);

  /* table privileges */
  mysql_rwlock_rdlock(&LOCK_grant);
  if (grant->version != grant_version)
  {
    grant->grant_table=
      table_hash_search(sctx->host, sctx->ip, db,
			sctx->priv_user,
			table, 0);              /* purecov: inspected */
    grant->version= grant_version;              /* purecov: inspected */
  }
  if (grant->grant_table != 0)
  {
    grant->privilege|= grant->grant_table->privs;
  }
  mysql_rwlock_unlock(&LOCK_grant);

  DBUG_PRINT("info", ("privilege 0x%lx", grant->privilege));
  DBUG_VOID_RETURN;
}

#else /* NO_EMBEDDED_ACCESS_CHECKS */

/****************************************************************************
 Dummy wrappers when we don't have any access checks
****************************************************************************/

#endif

struct ACL_internal_schema_registry_entry
{
  const LEX_STRING *m_name;
  const ACL_internal_schema_access *m_access;
};

/**
  Internal schema registered.
  Currently, this is only:
  - performance_schema
  - information_schema,
  This can be reused later for:
  - mysql
*/
static ACL_internal_schema_registry_entry registry_array[2];
static uint m_registry_array_size= 0;

/**
  Add an internal schema to the registry.
  @param name the schema name
  @param access the schema ACL specific rules
*/
void ACL_internal_schema_registry::register_schema
  (const LEX_STRING *name, const ACL_internal_schema_access *access)
{
  DBUG_ASSERT(m_registry_array_size < array_elements(registry_array));

  /* Not thread safe, and does not need to be. */
  registry_array[m_registry_array_size].m_name= name;
  registry_array[m_registry_array_size].m_access= access;
  m_registry_array_size++;
}

/**
  Search per internal schema ACL by name.
  @param name a schema name
  @return per schema rules, or NULL
*/
const ACL_internal_schema_access *
ACL_internal_schema_registry::lookup(const char *name)
{
  DBUG_ASSERT(name != NULL);

  uint i;

  for (i= 0; i<m_registry_array_size; i++)
  {
    if (my_strcasecmp(system_charset_info, registry_array[i].m_name->str,
                      name) == 0)
      return registry_array[i].m_access;
  }
  return NULL;
}

/**
  Get a cached internal table access.
  @param grant_internal_info the cache
  @param schema_name the name of the internal schema
  @param table_name the name of the internal table
*/

/****************************************************************************
   AUTHENTICATION CODE
   including initial connect handshake, invoking appropriate plugins,
   client-server plugin negotiation, COM_CHANGE_USER, and native
   MySQL authentication plugins.
****************************************************************************/

/* few defines to have less ifdef's in the code below */
#ifdef EMBEDDED_LIBRARY
#undef HAVE_OPENSSL
#ifdef NO_EMBEDDED_ACCESS_CHECKS
#define initialized 0
#endif
#endif
#ifndef HAVE_OPENSSL
#define ssl_acceptor_fd 0
#define sslaccept(A,B,C) 1
#endif


class Thd_charset_adapter
{
  THD *thd;
public:
  Thd_charset_adapter(THD *thd_arg) : thd (thd_arg) {} 
  bool init_client_charset(uint cs_number)
  {
    if (thd_init_client_charset(thd, cs_number))
      return true;
    thd->update_charset();
    return thd->is_error();
  }

  const CHARSET_INFO *charset() { return thd->charset(); }
};


/**
  The internal version of what plugins know as MYSQL_PLUGIN_VIO,
  basically the context of the authentication session
*/
struct MPVIO_EXT :public MYSQL_PLUGIN_VIO
{
  MYSQL_SERVER_AUTH_INFO auth_info;
  const ACL_USER *acl_user;
  plugin_ref plugin;        ///< what plugin we're under
  LEX_STRING db;            ///< db name from the handshake packet
  /** when restarting a plugin this caches the last client reply */
  struct {
    char *plugin, *pkt;     ///< pointers into NET::buff
    uint pkt_len;
  } cached_client_reply;
  /** this caches the first plugin packet for restart request on the client */
  struct {
    char *pkt;
    uint pkt_len;
  } cached_server_packet;
  int packets_read, packets_written; ///< counters for send/received packets
  /** when plugin returns a failure this tells us what really happened */
  enum { SUCCESS, FAILURE, RESTART } status;

  /* encapsulation members */
  ulong client_capabilities;
  char *scramble;
  MEM_ROOT *mem_root;
  struct  rand_struct *rand;
  my_thread_id  thread_id;
  uint      *server_status;
  NET *net;
  ulong max_client_packet_length;
  char *ip;
  char *host;
  Thd_charset_adapter *charset_adapter;
  LEX_STRING acl_user_plugin;
  int vio_is_encrypted;
};

/**
 Sets the default default auth plugin value if no option was specified.
*/
void init_default_auth_plugin()
{
  default_auth_plugin_name.str= native_password_plugin_name.str;
  default_auth_plugin_name.length= native_password_plugin_name.length;
}

/**
  a helper function to report an access denied error in all the proper places
*/
static void login_failed_error(MPVIO_EXT *mpvio, int passwd_used)
{
  THD *thd= current_thd;
  if (passwd_used == 2)
  {
    my_error(ER_ACCESS_DENIED_NO_PASSWORD_ERROR, MYF(0),
             mpvio->auth_info.user_name,
             mpvio->auth_info.host_or_ip);
    general_log_print(thd, COM_CONNECT, ER(ER_ACCESS_DENIED_NO_PASSWORD_ERROR),
                      mpvio->auth_info.user_name,
                      mpvio->auth_info.host_or_ip);
    /* 
      Log access denied messages to the error log when log-warnings = 2
      so that the overhead of the general query log is not required to track 
      failed connections.
    */
    if (log_warnings > 1)
    {
      sql_print_warning(ER(ER_ACCESS_DENIED_NO_PASSWORD_ERROR),
                        mpvio->auth_info.user_name,
                        mpvio->auth_info.host_or_ip);      
    }
  }
  else
  {
    my_error(ER_ACCESS_DENIED_ERROR, MYF(0),
             mpvio->auth_info.user_name,
             mpvio->auth_info.host_or_ip,
             passwd_used ? ER(ER_YES) : ER(ER_NO));
    general_log_print(thd, COM_CONNECT, ER(ER_ACCESS_DENIED_ERROR),
                      mpvio->auth_info.user_name,
                      mpvio->auth_info.host_or_ip,
                      passwd_used ? ER(ER_YES) : ER(ER_NO));
    /* 
      Log access denied messages to the error log when log-warnings = 2
      so that the overhead of the general query log is not required to track 
      failed connections.
    */
    if (log_warnings > 1)
    {
      sql_print_warning(ER(ER_ACCESS_DENIED_ERROR),
                        mpvio->auth_info.user_name,
                        mpvio->auth_info.host_or_ip,
                        passwd_used ? ER(ER_YES) : ER(ER_NO));      
    }
  }
}

/**
  sends a server handshake initialization packet, the very first packet
  after the connection was established

  Packet format:
   
    Bytes       Content
    -----       ----
    1           protocol version (always 10)
    n           server version string, \0-terminated
    4           thread id
    8           first 8 bytes of the plugin provided data (scramble)
    1           \0 byte, terminating the first part of a scramble
    2           server capabilities (two lower bytes)
    1           server character set
    2           server status
    2           server capabilities (two upper bytes)
    1           length of the scramble
    10          reserved, always 0
    n           rest of the plugin provided data (at least 12 bytes)
    1           \0 byte, terminating the second part of a scramble

  @retval 0 ok
  @retval 1 error
*/
static bool send_server_handshake_packet(MPVIO_EXT *mpvio,
                                         const char *data, uint data_len)
{
  DBUG_ASSERT(mpvio->status == MPVIO_EXT::FAILURE);
  DBUG_ASSERT(data_len <= 255);

  char *buff= (char *) my_alloca(1 + SERVER_VERSION_LENGTH + data_len + 64);
  char scramble_buf[SCRAMBLE_LENGTH];
  char *end= buff;

  DBUG_ENTER("send_server_handshake_packet");
  *end++= protocol_version;

  mpvio->client_capabilities= CLIENT_BASIC_FLAGS;

  if (opt_using_transactions)
    mpvio->client_capabilities|= CLIENT_TRANSACTIONS;

  mpvio->client_capabilities|= CAN_CLIENT_COMPRESS;

  if (ssl_acceptor_fd)
  {
    mpvio->client_capabilities|= CLIENT_SSL;
    mpvio->client_capabilities|= CLIENT_SSL_VERIFY_SERVER_CERT;
  }

  if (data_len)
  {
    mpvio->cached_server_packet.pkt= (char*) memdup_root(mpvio->mem_root, 
                                                         data, data_len);
    mpvio->cached_server_packet.pkt_len= data_len;
  }

  if (data_len < SCRAMBLE_LENGTH)
  {
    if (data_len)
    {
      /*
        the first packet *must* have at least 20 bytes of a scramble.
        if a plugin provided less, we pad it to 20 with zeros
      */
      memcpy(scramble_buf, data, data_len);
      memset(scramble_buf + data_len, 0, SCRAMBLE_LENGTH - data_len);
      data= scramble_buf;
    }
    else
    {
      /*
        if the default plugin does not provide the data for the scramble at
        all, we generate a scramble internally anyway, just in case the
        user account (that will be known only later) uses a
        native_password_plugin (which needs a scramble). If we don't send a
        scramble now - wasting 20 bytes in the packet -
        native_password_plugin will have to send it in a separate packet,
        adding one more round trip.
      */
      create_random_string(mpvio->scramble, SCRAMBLE_LENGTH, mpvio->rand);
      data= mpvio->scramble;
    }
    data_len= SCRAMBLE_LENGTH;
  }

  end= strnmov(end, server_version, SERVER_VERSION_LENGTH) + 1;
  int4store((uchar*) end, mpvio->thread_id);
  end+= 4;

  /*
    Old clients does not understand long scrambles, but can ignore packet
    tail: that's why first part of the scramble is placed here, and second
    part at the end of packet.
  */
  end= (char*) memcpy(end, data, SCRAMBLE_LENGTH_323);
  end+= SCRAMBLE_LENGTH_323;
  *end++= 0;
 
  int2store(end, mpvio->client_capabilities);
  /* write server characteristics: up to 16 bytes allowed */
  end[2]= (char) default_charset_info->number;
  int2store(end + 3, mpvio->server_status[0]);
  int2store(end + 5, mpvio->client_capabilities >> 16);
  end[7]= data_len;
  DBUG_EXECUTE_IF("poison_srv_handshake_scramble_len", end[7]= -100;);
  memset(end + 8, 0, 10);
  end+= 18;
  /* write scramble tail */
  end= (char*) memcpy(end, data + SCRAMBLE_LENGTH_323,
                      data_len - SCRAMBLE_LENGTH_323);
  end+= data_len - SCRAMBLE_LENGTH_323;
  end= strmake(end, plugin_name(mpvio->plugin)->str,
                    plugin_name(mpvio->plugin)->length);

  int res= my_net_write(mpvio->net, (uchar*) buff, (size_t) (end - buff + 1)) ||
           net_flush(mpvio->net);
  my_afree(buff);
  DBUG_RETURN (res);
}

static bool secure_auth(MPVIO_EXT *mpvio)
{
  THD *thd;
  if (!opt_secure_auth)
    return 0;
  /*
    If the server is running in secure auth mode, short scrambles are 
    forbidden. Extra juggling to report the same error as the old code.
  */

  thd= current_thd;
  if (mpvio->client_capabilities & CLIENT_PROTOCOL_41)
  {
    my_error(ER_SERVER_IS_IN_SECURE_AUTH_MODE, MYF(0),
             mpvio->auth_info.user_name,
             mpvio->auth_info.host_or_ip);
    general_log_print(thd, COM_CONNECT, ER(ER_SERVER_IS_IN_SECURE_AUTH_MODE),
                      mpvio->auth_info.user_name,
                      mpvio->auth_info.host_or_ip);
  }
  else
  {
    my_error(ER_NOT_SUPPORTED_AUTH_MODE, MYF(0));
    general_log_print(thd, COM_CONNECT, ER(ER_NOT_SUPPORTED_AUTH_MODE));
  }
  return 1;
}

/**
  sends a "change plugin" packet, requesting a client to restart authentication
  using a different authentication plugin

  Packet format:
   
    Bytes       Content
    -----       ----
    1           byte with the value 254
    n           client plugin to use, \0-terminated
    n           plugin provided data

  In a special case of switching from native_password_plugin to
  old_password_plugin, the packet contains only one - the first - byte,
  plugin name is omitted, plugin data aren't needed as the scramble was
  already sent. This one-byte packet is identical to the "use the short
  scramble" packet in the protocol before plugins were introduced.

  @retval 0 ok
  @retval 1 error
*/
static bool send_plugin_request_packet(MPVIO_EXT *mpvio,
                                       const uchar *data, uint data_len)
{
  DBUG_ASSERT(mpvio->packets_written == 1);
  DBUG_ASSERT(mpvio->packets_read == 1);
  NET *net= mpvio->net;
  static uchar switch_plugin_request_buf[]= { 254 };

  DBUG_ENTER("send_plugin_request_packet");
  mpvio->status= MPVIO_EXT::FAILURE; // the status is no longer RESTART

  const char *client_auth_plugin=
    ((st_mysql_auth *) (plugin_decl(mpvio->plugin)->info))->client_auth_plugin;

  DBUG_ASSERT(client_auth_plugin);

  /*
    we send an old "short 4.0 scramble request", if we need to request a
    client to use 4.0 auth plugin (short scramble) and the scramble was
    already sent to the client

    below, cached_client_reply.plugin is the plugin name that client has used,
    client_auth_plugin is derived from mysql.user table, for the given
    user account, it's the plugin that the client need to use to login.
  */
  bool switch_from_long_to_short_scramble=
    native_password_plugin_name.str == mpvio->cached_client_reply.plugin &&
    client_auth_plugin == old_password_plugin_name.str;

  if (switch_from_long_to_short_scramble)
    DBUG_RETURN (secure_auth(mpvio) ||
                 my_net_write(net, switch_plugin_request_buf, 1) ||
                 net_flush(net));

  /*
    We never request a client to switch from a short to long scramble.
    Plugin-aware clients can do that, but traditionally it meant to
    ask an old 4.0 client to use the new 4.1 authentication protocol.
  */
  bool switch_from_short_to_long_scramble=
    old_password_plugin_name.str == mpvio->cached_client_reply.plugin && 
    client_auth_plugin == native_password_plugin_name.str;

  if (switch_from_short_to_long_scramble)
  {
    my_error(ER_NOT_SUPPORTED_AUTH_MODE, MYF(0));
    general_log_print(current_thd, COM_CONNECT, ER(ER_NOT_SUPPORTED_AUTH_MODE));
    DBUG_RETURN (1);
  }

  /*
    If we're dealing with an older client we can't just send a change plugin
    packet to re-initiate the authentication handshake, because the client 
    won't understand it. The good thing is that we don't need to : the old client
    expects us to just check the user credentials here, which we can do by just reading
    the cached data that are placed there by parse_com_change_user_packet() 
    In this case we just do nothing and behave as if normal authentication
    should continue.
  */
  if (!(mpvio->client_capabilities & CLIENT_PLUGIN_AUTH))
  {
    DBUG_PRINT("info", ("old client sent a COM_CHANGE_USER"));
    DBUG_ASSERT(mpvio->cached_client_reply.pkt);
    /* get the status back so the read can process the cached result */
    mpvio->status= MPVIO_EXT::RESTART; 
    DBUG_RETURN(0);
  }

  DBUG_PRINT("info", ("requesting client to use the %s plugin", 
                      client_auth_plugin));
  DBUG_RETURN(net_write_command(net, switch_plugin_request_buf[0],
                                (uchar*) client_auth_plugin,
                                strlen(client_auth_plugin) + 1,
                                (uchar*) data, data_len));
}

#ifndef NO_EMBEDDED_ACCESS_CHECKS
/**
   Finds acl entry in user database for authentication purposes.
   
   Finds a user and copies it into mpvio. Reports an authentication
   failure if a user is not found.

   @note find_acl_user is not the same, because it doesn't take into
   account the case when user is not empty, but acl_user->user is empty

   @retval 0    found
   @retval 1    not found
*/
static bool find_mpvio_user(MPVIO_EXT *mpvio)
{
  DBUG_ENTER("find_mpvio_user");
  DBUG_PRINT("info", ("entry: %s", mpvio->auth_info.user_name));
  DBUG_ASSERT(mpvio->acl_user == 0);
  mysql_mutex_lock(&acl_cache->lock);
  for (uint i=0; i < acl_users.elements; i++)
  {
    ACL_USER *acl_user_tmp= dynamic_element(&acl_users, i, ACL_USER*);
    if ((!acl_user_tmp->user || 
         !strcmp(mpvio->auth_info.user_name, acl_user_tmp->user)) &&
        acl_user_tmp->host.compare_hostname(mpvio->host, mpvio->ip))
    {
      mpvio->acl_user= acl_user_tmp->copy(mpvio->mem_root);

      /*
        When setting mpvio->acl_user_plugin we can save memory allocation if
        this is a built in plugin.
      */
      if (auth_plugin_is_built_in(acl_user_tmp->plugin.str))
        mpvio->acl_user_plugin= mpvio->acl_user->plugin;
      else
        make_lex_string_root(mpvio->mem_root, 
                             &mpvio->acl_user_plugin, 
                             acl_user_tmp->plugin.str, 
                             acl_user_tmp->plugin.length, 0);
      break;
    }
  }
  mysql_mutex_unlock(&acl_cache->lock);

  if (!mpvio->acl_user)
  {
    login_failed_error(mpvio, mpvio->auth_info.password_used);
    DBUG_RETURN (1);
  }

  if (my_strcasecmp(system_charset_info, mpvio->acl_user->plugin.str,
                    native_password_plugin_name.str) != 0 &&
      my_strcasecmp(system_charset_info, mpvio->acl_user->plugin.str,
                    old_password_plugin_name.str) != 0 &&
      !(mpvio->client_capabilities & CLIENT_PLUGIN_AUTH))
  {
    /* user account requires non-default plugin and the client is too old */
    DBUG_ASSERT(my_strcasecmp(system_charset_info, mpvio->acl_user->plugin.str,
                              native_password_plugin_name.str));
    DBUG_ASSERT(my_strcasecmp(system_charset_info, mpvio->acl_user->plugin.str,
                              old_password_plugin_name.str));
    my_error(ER_NOT_SUPPORTED_AUTH_MODE, MYF(0));
    general_log_print(current_thd, COM_CONNECT, ER(ER_NOT_SUPPORTED_AUTH_MODE));
    DBUG_RETURN (1);
  }

  mpvio->auth_info.auth_string= mpvio->acl_user->auth_string.str;
  mpvio->auth_info.auth_string_length= 
    (unsigned long) mpvio->acl_user->auth_string.length;
  strmake(mpvio->auth_info.authenticated_as, mpvio->acl_user->user ?
          mpvio->acl_user->user : "", USERNAME_LENGTH);
  DBUG_PRINT("info", ("exit: user=%s, auth_string=%s, authenticated as=%s"
                      ", plugin=%s",
                      mpvio->auth_info.user_name,
                      mpvio->auth_info.auth_string,
                      mpvio->auth_info.authenticated_as,
                      mpvio->acl_user->plugin.str));
  DBUG_RETURN(0);
}


static bool
read_client_connect_attrs(char **ptr, size_t *max_bytes_available,
                          const CHARSET_INFO *from_cs)
{
  size_t length, length_length;
  char *ptr_save;
  /* not enough bytes to hold the length */
  if (*max_bytes_available < 1)
    return true;

  /* read the length */
  ptr_save= *ptr;
  length= net_field_length_ll((uchar **) ptr);
  length_length= *ptr - ptr_save;
  if (*max_bytes_available < length_length)
    return true;

  *max_bytes_available-= length_length;

  /* length says there're more data than can fit into the packet */
  if (length > *max_bytes_available)
    return true;

  /* impose an artificial length limit of 64k */
  if (length > 65535)
    return true;

#ifdef HAVE_PSI_THREAD_INTERFACE
  if (PSI_THREAD_CALL(set_thread_connect_attrs)(*ptr, length, from_cs) && log_warnings)
    sql_print_warning("Connection attributes of length %lu were truncated",
                      (unsigned long) length);
#endif
  return false;
}


#endif

/* the packet format is described in send_change_user_packet() */
static bool parse_com_change_user_packet(MPVIO_EXT *mpvio, uint packet_length)
{
  NET *net= mpvio->net;

  char *user= (char*) net->read_pos;
  char *end= user + packet_length;
  /* Safe because there is always a trailing \0 at the end of the packet */
  char *passwd= strend(user) + 1;
  uint user_len= passwd - user - 1;
  char *db= passwd;
  char db_buff[NAME_LEN + 1];                 // buffer to store db in utf8
  char user_buff[USERNAME_LENGTH + 1];	      // buffer to store user in utf8
  uint dummy_errors;

  DBUG_ENTER ("parse_com_change_user_packet");
  if (passwd >= end)
  {
    my_message(ER_UNKNOWN_COM_ERROR, ER(ER_UNKNOWN_COM_ERROR), MYF(0));
    DBUG_RETURN (1);
  }

  /*
    Old clients send null-terminated string as password; new clients send
    the size (1 byte) + string (not null-terminated). Hence in case of empty
    password both send '\0'.

    This strlen() can't be easily deleted without changing protocol.

    Cast *passwd to an unsigned char, so that it doesn't extend the sign for
    *passwd > 127 and become 2**32-127+ after casting to uint.
  */
  uint passwd_len= (mpvio->client_capabilities & CLIENT_SECURE_CONNECTION ?
                    (uchar) (*passwd++) : strlen(passwd));

  db+= passwd_len + 1;
  /*
    Database name is always NUL-terminated, so in case of empty database
    the packet must contain at least the trailing '\0'.
  */
  if (db >= end)
  {
    my_message(ER_UNKNOWN_COM_ERROR, ER(ER_UNKNOWN_COM_ERROR), MYF(0));
    DBUG_RETURN (1);
  }

  uint db_len= strlen(db);

  char *ptr= db + db_len + 1;

  if (ptr + 1 < end)
  {
    if (mpvio->charset_adapter->init_client_charset(uint2korr(ptr)))
      DBUG_RETURN(1);
  }


  /* Convert database and user names to utf8 */
  db_len= copy_and_convert(db_buff, sizeof(db_buff) - 1, system_charset_info,
                           db, db_len, mpvio->charset_adapter->charset(),
                           &dummy_errors);
  db_buff[db_len]= 0;

  user_len= copy_and_convert(user_buff, sizeof(user_buff) - 1,
                                  system_charset_info, user, user_len,
                                  mpvio->charset_adapter->charset(),
                                  &dummy_errors);
  user_buff[user_len]= 0;

  /* we should not free mpvio->user here: it's saved by dispatch_command() */
  if (!(mpvio->auth_info.user_name= my_strndup(user_buff, user_len, MYF(MY_WME))))
    return 1;
  mpvio->auth_info.user_name_length= user_len;

  if (make_lex_string_root(mpvio->mem_root, 
                           &mpvio->db, db_buff, db_len, 0) == 0)
    DBUG_RETURN(1); /* The error is set by make_lex_string(). */

  if (!initialized)
  {
    // if mysqld's been started with --skip-grant-tables option
    strmake(mpvio->auth_info.authenticated_as, 
            mpvio->auth_info.user_name, USERNAME_LENGTH);

    mpvio->status= MPVIO_EXT::SUCCESS;
    DBUG_RETURN(0);
  }

#ifndef NO_EMBEDDED_ACCESS_CHECKS
  if (find_mpvio_user(mpvio))
    DBUG_RETURN(1);

  char *client_plugin;
  if (mpvio->client_capabilities & CLIENT_PLUGIN_AUTH)
  {
    client_plugin= ptr + 2;
    if (client_plugin >= end)
    {
      my_message(ER_UNKNOWN_COM_ERROR, ER(ER_UNKNOWN_COM_ERROR), MYF(0));
      DBUG_RETURN(1);
    }
  }
  else
  {
    if (mpvio->client_capabilities & CLIENT_SECURE_CONNECTION)
      client_plugin= native_password_plugin_name.str;
    else
    {
      client_plugin=  old_password_plugin_name.str;
      /*
        For a passwordless accounts we use native_password_plugin.
        But when an old 4.0 client connects to it, we change it to
        old_password_plugin, otherwise MySQL will think that server 
        and client plugins don't match.
      */
      if (mpvio->acl_user->salt_len == 0)
        mpvio->acl_user_plugin= old_password_plugin_name;
    }
  }

  size_t bytes_remaining_in_packet= end - ptr;

  if ((mpvio->client_capabilities & CLIENT_CONNECT_ATTRS) &&
      read_client_connect_attrs(&ptr, &bytes_remaining_in_packet,
                                mpvio->charset_adapter->charset()))
    return packet_error;

  DBUG_PRINT("info", ("client_plugin=%s, restart", client_plugin));
  /* 
    Remember the data part of the packet, to present it to plugin in 
    read_packet() 
  */
  mpvio->cached_client_reply.pkt= passwd;
  mpvio->cached_client_reply.pkt_len= passwd_len;
  mpvio->cached_client_reply.plugin= client_plugin;
  mpvio->status= MPVIO_EXT::RESTART;
#endif

  DBUG_RETURN (0);
}

#ifndef EMBEDDED_LIBRARY
/** Get a string according to the protocol of the underlying buffer. */
typedef char * (*get_proto_string_func_t) (char **, size_t *, size_t *);

/**
  Get a string formatted according to the 4.1 version of the MySQL protocol.

  @param buffer[in, out]    Pointer to the user-supplied buffer to be scanned.
  @param max_bytes_available[in, out]  Limit the bytes to scan.
  @param string_length[out] The number of characters scanned not including
                            the null character.

  @remark Strings are always null character terminated in this version of the
          protocol.

  @remark The string_length does not include the terminating null character.
          However, after the call, the buffer is increased by string_length+1
          bytes, beyond the null character if there still available bytes to
          scan.

  @return pointer to beginning of the string scanned.
    @retval NULL The buffer content is malformed
*/

static
char *get_41_protocol_string(char **buffer,
                             size_t *max_bytes_available,
                             size_t *string_length)
{
  char *str= (char *)memchr(*buffer, '\0', *max_bytes_available);

  if (str == NULL)
    return NULL;

  *string_length= (size_t)(str - *buffer);
  *max_bytes_available-= *string_length + 1;
  str= *buffer;
  *buffer += *string_length + 1;

  return str;
}


/**
  Get a string formatted according to the 4.0 version of the MySQL protocol.

  @param buffer[in, out]    Pointer to the user-supplied buffer to be scanned.
  @param max_bytes_available[in, out]  Limit the bytes to scan.
  @param string_length[out] The number of characters scanned not including
                            the null character.

  @remark If there are not enough bytes left after the current position of
          the buffer to satisfy the current string, the string is considered
          to be empty and a pointer to empty_c_string is returned.

  @remark A string at the end of the packet is not null terminated.

  @return Pointer to beginning of the string scanned, or a pointer to a empty
          string.
*/
static
char *get_40_protocol_string(char **buffer,
                             size_t *max_bytes_available,
                             size_t *string_length)
{
  char *str;
  size_t len;

  /* No bytes to scan left, treat string as empty. */
  if ((*max_bytes_available) == 0)
  {
    *string_length= 0;
    return empty_c_string;
  }

  str= (char *) memchr(*buffer, '\0', *max_bytes_available);

  /*
    If the string was not null terminated by the client,
    the remainder of the packet is the string. Otherwise,
    advance the buffer past the end of the null terminated
    string.
  */
  if (str == NULL)
    len= *string_length= *max_bytes_available;
  else
    len= (*string_length= (size_t)(str - *buffer)) + 1;

  str= *buffer;
  *buffer+= len;
  *max_bytes_available-= len;

  return str;
}

/**
  Get a length encoded string from a user-supplied buffer.

  @param buffer[in, out] The buffer to scan; updates position after scan.
  @param max_bytes_available[in, out] Limit the number of bytes to scan
  @param string_length[out] Number of characters scanned

  @remark In case the length is zero, then the total size of the string is
    considered to be 1 byte; the size byte.

  @return pointer to first byte after the header in buffer.
    @retval NULL The buffer content is malformed
*/

static
char *get_56_lenc_string(char **buffer,
                         size_t *max_bytes_available,
                         size_t *string_length)
{
  static char empty_string[1]= { '\0' };
  char *begin= *buffer;

  if (*max_bytes_available == 0)
    return NULL;

  /*
    If the length encoded string has the length 0
    the total size of the string is only one byte long (the size byte)
  */
  if (*begin == 0)
  {
    *string_length= 0;
    --*max_bytes_available;
    ++*buffer;
    /*
      Return a pointer to the \0 character so the return value will be
      an empty string.
    */
    return empty_string;
  }

  *string_length= (size_t)net_field_length_ll((uchar **)buffer);

  size_t len_len= (size_t)(*buffer - begin);
  
  if (*string_length + len_len > *max_bytes_available)
    return NULL;

  *max_bytes_available -= *string_length + len_len;
  *buffer += *string_length;
  return (char *)(begin + len_len);
}


/**
  Get a length encoded string from a user-supplied buffer.

  @param buffer[in, out] The buffer to scan; updates position after scan.
  @param max_bytes_available[in, out] Limit the number of bytes to scan
  @param string_length[out] Number of characters scanned

  @remark In case the length is zero, then the total size of the string is
    considered to be 1 byte; the size byte.

  @note the maximum size of the string is 255 because the header is always 
    1 byte.
  @return pointer to first byte after the header in buffer.
    @retval NULL The buffer content is malformed
*/

static
char *get_41_lenc_string(char **buffer,
                         size_t *max_bytes_available,
                         size_t *string_length)
{
 if (*max_bytes_available == 0)
    return NULL;

  /* Do double cast to prevent overflow from signed / unsigned conversion */
  size_t str_len= (size_t)(unsigned char)**buffer;

  /*
    If the length encoded string has the length 0
    the total size of the string is only one byte long (the size byte)
  */
  if (str_len == 0)
  {
    ++*buffer;
    *string_length= 0;
    /*
      Return a pointer to the 0 character so the return value will be
      an empty string.
    */
    return *buffer-1;
  }

  if (str_len >= *max_bytes_available)
    return NULL;

  char *str= *buffer+1;
  *string_length= str_len;
  *max_bytes_available-= *string_length + 1;
  *buffer+= *string_length + 1;
  return str;
}
#endif // EMBEDDED LIBRARY


/* the packet format is described in send_client_reply_packet() */
static ulong parse_client_handshake_packet(MPVIO_EXT *mpvio,
                                           uchar **buff, ulong pkt_len)
{
#ifndef EMBEDDED_LIBRARY
  NET *net= mpvio->net;
  char *end;
  bool packet_has_required_size= false;
  DBUG_ASSERT(mpvio->status == MPVIO_EXT::FAILURE);

  uint charset_code= 0;
  end= (char *)net->read_pos;
  /*
    In order to safely scan a head for '\0' string terminators
    we must keep track of how many bytes remain in the allocated
    buffer or we might read past the end of the buffer.
  */
  size_t bytes_remaining_in_packet= pkt_len;
  
  /*
    Peek ahead on the client capability packet and determine which version of
    the protocol should be used.
  */
  if (bytes_remaining_in_packet < 2)
    return packet_error;
    
  mpvio->client_capabilities= uint2korr(end);

  /*
    JConnector only sends server capabilities before starting SSL
    negotiation.  The below code is patch for this.
  */
  if (bytes_remaining_in_packet == 4 &&
      mpvio->client_capabilities & CLIENT_SSL)
  {
    mpvio->client_capabilities= uint4korr(end);
    mpvio->max_client_packet_length= 0xfffff;
    charset_code= default_charset_info->number;
    if (mpvio->charset_adapter->init_client_charset(charset_code))
      return packet_error;
    goto skip_to_ssl;
  }
  
  if (mpvio->client_capabilities & CLIENT_PROTOCOL_41)
    packet_has_required_size= bytes_remaining_in_packet >= 
      AUTH_PACKET_HEADER_SIZE_PROTO_41;
  else
    packet_has_required_size= bytes_remaining_in_packet >=
      AUTH_PACKET_HEADER_SIZE_PROTO_40;
  
  if (!packet_has_required_size)
    return packet_error;
  
  if (mpvio->client_capabilities & CLIENT_PROTOCOL_41)
  {
    mpvio->client_capabilities= uint4korr(end);
    mpvio->max_client_packet_length= uint4korr(end + 4);
    charset_code= (uint)(uchar)*(end + 8);
    /*
      Skip 23 remaining filler bytes which have no particular meaning.
    */
    end+= AUTH_PACKET_HEADER_SIZE_PROTO_41;
    bytes_remaining_in_packet-= AUTH_PACKET_HEADER_SIZE_PROTO_41;
  }
  else
  {
    mpvio->client_capabilities= uint2korr(end);
    mpvio->max_client_packet_length= uint3korr(end + 2);
    end+= AUTH_PACKET_HEADER_SIZE_PROTO_40;
    bytes_remaining_in_packet-= AUTH_PACKET_HEADER_SIZE_PROTO_40;
    /**
      Old clients didn't have their own charset. Instead the assumption
      was that they used what ever the server used.
    */
    charset_code= default_charset_info->number;
  }

  DBUG_PRINT("info", ("client_character_set: %u", charset_code));
  if (mpvio->charset_adapter->init_client_charset(charset_code))
    return packet_error;

skip_to_ssl:
#if defined(HAVE_OPENSSL)
  DBUG_PRINT("info", ("client capabilities: %lu", mpvio->client_capabilities));
  
  /*
    If client requested SSL then we must stop parsing, try to switch to SSL,
    and wait for the client to send a new handshake packet.
    The client isn't expected to send any more bytes until SSL is initialized.
  */
  if (mpvio->client_capabilities & CLIENT_SSL)
  {
    unsigned long errptr;

    /* Do the SSL layering. */
    if (!ssl_acceptor_fd)
      return packet_error;

    DBUG_PRINT("info", ("IO layer change in progress..."));
    if (sslaccept(ssl_acceptor_fd, net->vio, net->read_timeout, &errptr))
    {
      DBUG_PRINT("error", ("Failed to accept new SSL connection"));
      return packet_error;
    }

    DBUG_PRINT("info", ("Reading user information over SSL layer"));
    if ((pkt_len= my_net_read(net)) == packet_error)
    {
      DBUG_PRINT("error", ("Failed to read user information (pkt_len= %lu)",
			   pkt_len));
      return packet_error;
    }
    /* mark vio as encrypted */
    mpvio->vio_is_encrypted= 1;
  
    /*
      A new packet was read and the statistics reflecting the remaining bytes
      in the packet must be updated.
    */
    bytes_remaining_in_packet= pkt_len;

    /*
      After the SSL handshake is performed the client resends the handshake
      packet but because of legacy reasons we chose not to parse the packet
      fields a second time and instead only assert the length of the packet.
    */
    if (mpvio->client_capabilities & CLIENT_PROTOCOL_41)
    {
      packet_has_required_size= bytes_remaining_in_packet >= 
        AUTH_PACKET_HEADER_SIZE_PROTO_41;
      end= (char *)net->read_pos + AUTH_PACKET_HEADER_SIZE_PROTO_41;
      bytes_remaining_in_packet -= AUTH_PACKET_HEADER_SIZE_PROTO_41;
    }
    else
    {
      packet_has_required_size= bytes_remaining_in_packet >= 
        AUTH_PACKET_HEADER_SIZE_PROTO_40;
      end= (char *)net->read_pos + AUTH_PACKET_HEADER_SIZE_PROTO_40;
      bytes_remaining_in_packet -= AUTH_PACKET_HEADER_SIZE_PROTO_40;
    }
    
    if (!packet_has_required_size)
      return packet_error;
  }
#endif /* HAVE_OPENSSL */

  if ((mpvio->client_capabilities & CLIENT_TRANSACTIONS) &&
      opt_using_transactions)
    net->return_status= mpvio->server_status;

  /*
    The 4.0 and 4.1 versions of the protocol differ on how strings
    are terminated. In the 4.0 version, if a string is at the end
    of the packet, the string is not null terminated. Do not assume
    that the returned string is always null terminated.
  */
  get_proto_string_func_t get_string;

  if (mpvio->client_capabilities & CLIENT_PROTOCOL_41)
    get_string= get_41_protocol_string;
  else
    get_string= get_40_protocol_string;

  /*
    When the ability to change default plugin require that the initial password
   field can be of arbitrary size. However, the 41 client-server protocol limits
   the length of the auth-data-field sent from client to server to 255 bytes
   (CLIENT_SECURE_CONNECTION). The solution is to change the type of the field
   to a true length encoded string and indicate the protocol change with a new
   client capability flag: CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA.
  */
  get_proto_string_func_t get_length_encoded_string;

  if (mpvio->client_capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
    get_length_encoded_string= get_56_lenc_string;
  else
    get_length_encoded_string= get_41_lenc_string;

  /*
    The CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA capability depends on the
    CLIENT_SECURE_CONNECTION. Refuse any connection which have the first but
    not the latter.
  */
  if ((mpvio->client_capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) &&
      !(mpvio->client_capabilities & CLIENT_SECURE_CONNECTION))
    return packet_error;

  /*
    In order to safely scan a head for '\0' string terminators
    we must keep track of how many bytes remain in the allocated
    buffer or we might read past the end of the buffer.
  */
  bytes_remaining_in_packet= pkt_len - (end - (char *)net->read_pos);

  size_t user_len;
  char *user= get_string(&end, &bytes_remaining_in_packet, &user_len);
  if (user == NULL)
    return packet_error;

  /*
    Old clients send a null-terminated string as password; new clients send
    the size (1 byte) + string (not null-terminated). Hence in case of empty
    password both send '\0'.
  */
  size_t passwd_len= 0;
  char *passwd= NULL;

  if (mpvio->client_capabilities & CLIENT_SECURE_CONNECTION)
  {
    /*
      Get the password field.
    */
    passwd= get_length_encoded_string(&end, &bytes_remaining_in_packet,
                                      &passwd_len);
  }
  else
  {
    /*
      Old passwords are zero terminated strings.
    */
    passwd= get_string(&end, &bytes_remaining_in_packet, &passwd_len);
  }

  if (passwd == NULL)
    return packet_error;

  size_t db_len= 0;
  char *db= NULL;

  if (mpvio->client_capabilities & CLIENT_CONNECT_WITH_DB)
  {
    db= get_string(&end, &bytes_remaining_in_packet, &db_len);
    if (db == NULL)
      return packet_error;
  }

  /*
    Set the default for the password supplied flag for non-existing users
    as the default plugin (native passsword authentication) would do it
    for compatibility reasons.
  */
  if (passwd_len)
    mpvio->auth_info.password_used= PASSWORD_USED_YES;

  size_t client_plugin_len= 0;
  char *client_plugin= get_string(&end, &bytes_remaining_in_packet,
                                  &client_plugin_len);
  if (client_plugin == NULL)
    client_plugin= &empty_c_string[0];

  if ((mpvio->client_capabilities & CLIENT_CONNECT_ATTRS) &&
      read_client_connect_attrs(&end, &bytes_remaining_in_packet,
                                mpvio->charset_adapter->charset()))
    return packet_error;

  char db_buff[NAME_LEN + 1];           // buffer to store db in utf8
  char user_buff[USERNAME_LENGTH + 1];	// buffer to store user in utf8
  uint dummy_errors;


  /*
    Copy and convert the user and database names to the character set used
    by the server. Since 4.1 all database names are stored in UTF-8. Also,
    ensure that the names are properly null-terminated as this is relied
    upon later.
  */
  if (db)
  {
    db_len= copy_and_convert(db_buff, sizeof(db_buff) - 1, system_charset_info,
                             db, db_len, mpvio->charset_adapter->charset(),
                             &dummy_errors);
    db_buff[db_len]= '\0';
    db= db_buff;
  }

  user_len= copy_and_convert(user_buff, sizeof(user_buff) - 1,
                             system_charset_info, user, user_len,
                             mpvio->charset_adapter->charset(),
                             &dummy_errors);
  user_buff[user_len]= '\0';
  user= user_buff;

  /* If username starts and ends in "'", chop them off */
  if (user_len > 1 && user[0] == '\'' && user[user_len - 1] == '\'')
  {
    user[user_len - 1]= 0;
    user++;
    user_len-= 2;
  }

  if (make_lex_string_root(mpvio->mem_root, 
                           &mpvio->db, db, db_len, 0) == 0)
    return packet_error; /* The error is set by make_lex_string(). */
  if (mpvio->auth_info.user_name)
    my_free(mpvio->auth_info.user_name);
  if (!(mpvio->auth_info.user_name= my_strndup(user, user_len, MYF(MY_WME))))
    return packet_error; /* The error is set by my_strdup(). */
  mpvio->auth_info.user_name_length= user_len;

  if (!initialized)
  {
    // if mysqld's been started with --skip-grant-tables option
    mpvio->status= MPVIO_EXT::SUCCESS;
    return packet_error;
  }

  if (find_mpvio_user(mpvio))
    return packet_error;

  if (!(mpvio->client_capabilities & CLIENT_PLUGIN_AUTH))
  {
    /*
      An old client is connecting
    */
    if (mpvio->client_capabilities & CLIENT_SECURE_CONNECTION)
      client_plugin= native_password_plugin_name.str;
    else
    {
      /*
        A really old client is connecting
      */
      client_plugin= old_password_plugin_name.str;
      /*
        For a passwordless accounts we use native_password_plugin.
        But when an old 4.0 client connects to it, we change it to
        old_password_plugin, otherwise MySQL will think that server 
        and client plugins don't match.
      */
      if (mpvio->acl_user->salt_len == 0)
        mpvio->acl_user_plugin= old_password_plugin_name;
    }
  }
  
  /*
    if the acl_user needs a different plugin to authenticate
    (specified in GRANT ... AUTHENTICATED VIA plugin_name ..)
    we need to restart the authentication in the server.
    But perhaps the client has already used the correct plugin -
    in that case the authentication on the client may not need to be
    restarted and a server auth plugin will read the data that the client
    has just send. Cache them to return in the next server_mpvio_read_packet().
  */
  if (my_strcasecmp(system_charset_info, mpvio->acl_user_plugin.str,
                    plugin_name(mpvio->plugin)->str) != 0)
  {
    mpvio->cached_client_reply.pkt= passwd;
    mpvio->cached_client_reply.pkt_len= passwd_len;
    mpvio->cached_client_reply.plugin= client_plugin;
    mpvio->status= MPVIO_EXT::RESTART;
    return packet_error;
  }

  /*
    ok, we don't need to restart the authentication on the server.
    but if the client used the wrong plugin, we need to restart
    the authentication on the client. Do it here, the server plugin
    doesn't need to know.
  */
  const char *client_auth_plugin=
    ((st_mysql_auth *) (plugin_decl(mpvio->plugin)->info))->client_auth_plugin;

  if (client_auth_plugin &&
      my_strcasecmp(system_charset_info, client_plugin, client_auth_plugin))
  {
    mpvio->cached_client_reply.plugin= client_plugin;
    if (send_plugin_request_packet(mpvio,
                                   (uchar*) mpvio->cached_server_packet.pkt,
                                   mpvio->cached_server_packet.pkt_len))
      return packet_error;

    passwd_len= my_net_read(mpvio->net);
    passwd = (char*) mpvio->net->read_pos;
  }

  *buff= (uchar*) passwd;
  return passwd_len;
#else
  return 0;
#endif
}


/**
  Make sure that when sending plugin supplied data to the client they
  are not considered a special out-of-band command, like e.g. 
  \255 (error) or \254 (change user request packet) or \0 (OK).
  To avoid this the server will send all plugin data packets "wrapped" 
  in a command \1.
  Note that the client will continue sending its replies unrwapped.
*/

static inline int 
wrap_plguin_data_into_proper_command(NET *net, 
                                     const uchar *packet, int packet_len)
{
  return net_write_command(net, 1, (uchar *) "", 0, packet, packet_len);
}


/**
  vio->write_packet() callback method for server authentication plugins

  This function is called by a server authentication plugin, when it wants
  to send data to the client.

  It transparently wraps the data into a handshake packet,
  and handles plugin negotiation with the client. If necessary,
  it escapes the plugin data, if it starts with a mysql protocol packet byte.
*/
static int server_mpvio_write_packet(MYSQL_PLUGIN_VIO *param,
                                   const uchar *packet, int packet_len)
{
  MPVIO_EXT *mpvio= (MPVIO_EXT *) param;
  int res;

  DBUG_ENTER("server_mpvio_write_packet");
  /* 
    Reset cached_client_reply if not an old client doing mysql_change_user, 
    as this is where the password from COM_CHANGE_USER is stored.
  */
  if (!((!(mpvio->client_capabilities & CLIENT_PLUGIN_AUTH)) && 
        mpvio->status == MPVIO_EXT::RESTART &&
        mpvio->cached_client_reply.plugin == 
        ((st_mysql_auth *) (plugin_decl(mpvio->plugin)->info))->client_auth_plugin
        ))
    mpvio->cached_client_reply.pkt= 0;
  /* for the 1st packet we wrap plugin data into the handshake packet */
  if (mpvio->packets_written == 0)
    res= send_server_handshake_packet(mpvio, (char*) packet, packet_len);
  else if (mpvio->status == MPVIO_EXT::RESTART)
    res= send_plugin_request_packet(mpvio, packet, packet_len);
  else
    res= wrap_plguin_data_into_proper_command(mpvio->net, packet, packet_len);
  mpvio->packets_written++;
  DBUG_RETURN(res);
}

/**
  vio->read_packet() callback method for server authentication plugins

  This function is called by a server authentication plugin, when it wants
  to read data from the client.

  It transparently extracts the client plugin data, if embedded into
  a client authentication handshake packet, and handles plugin negotiation
  with the client, if necessary.
*/
static int server_mpvio_read_packet(MYSQL_PLUGIN_VIO *param, uchar **buf)
{
  MPVIO_EXT *mpvio= (MPVIO_EXT *) param;
  ulong pkt_len;

  DBUG_ENTER("server_mpvio_read_packet");
  if (mpvio->packets_written == 0)
  {
    /*
      plugin wants to read the data without sending anything first.
      send an empty packet to force a server handshake packet to be sent
    */
    if (mpvio->write_packet(mpvio, 0, 0))
      pkt_len= packet_error;
    else
      pkt_len= my_net_read(mpvio->net);
  }
  else if (mpvio->cached_client_reply.pkt)
  {
    DBUG_ASSERT(mpvio->status == MPVIO_EXT::RESTART);
    DBUG_ASSERT(mpvio->packets_read > 0);
    /*
      if the have the data cached from the last server_mpvio_read_packet
      (which can be the case if it's a restarted authentication)
      and a client has used the correct plugin, then we can return the
      cached data straight away and avoid one round trip.
    */
    const char *client_auth_plugin=
      ((st_mysql_auth *) (plugin_decl(mpvio->plugin)->info))->client_auth_plugin;
    if (client_auth_plugin == 0 ||
        my_strcasecmp(system_charset_info, mpvio->cached_client_reply.plugin,
                      client_auth_plugin) == 0)
    {
      mpvio->status= MPVIO_EXT::FAILURE;
      *buf= (uchar*) mpvio->cached_client_reply.pkt;
      mpvio->cached_client_reply.pkt= 0;
      mpvio->packets_read++;
      DBUG_RETURN ((int) mpvio->cached_client_reply.pkt_len);
    }

    /* older clients don't support change of client plugin request */
    if (!(mpvio->client_capabilities & CLIENT_PLUGIN_AUTH))
    {
      mpvio->status= MPVIO_EXT::FAILURE;
      pkt_len= packet_error;
      goto err;
    }

    /*
      But if the client has used the wrong plugin, the cached data are
      useless. Furthermore, we have to send a "change plugin" request
      to the client.
    */
    if (mpvio->write_packet(mpvio, 0, 0))
      pkt_len= packet_error;
    else
      pkt_len= my_net_read(mpvio->net);
  }
  else
    pkt_len= my_net_read(mpvio->net);

  if (pkt_len == packet_error)
    goto err;

  mpvio->packets_read++;

  /*
    the 1st packet has the plugin data wrapped into the client authentication
    handshake packet
  */
  if (mpvio->packets_read == 1)
  {
    pkt_len= parse_client_handshake_packet(mpvio, buf, pkt_len);
    if (pkt_len == packet_error)
      goto err;
  }
  else
    *buf= mpvio->net->read_pos;

  DBUG_RETURN((int)pkt_len);

err:
  if (mpvio->status == MPVIO_EXT::FAILURE)
  {
    my_error(ER_HANDSHAKE_ERROR, MYF(0));
  }
  DBUG_RETURN(-1);
}

/**
  fills MYSQL_PLUGIN_VIO_INFO structure with the information about the
  connection
*/
static void server_mpvio_info(MYSQL_PLUGIN_VIO *vio,
                              MYSQL_PLUGIN_VIO_INFO *info)
{
  MPVIO_EXT *mpvio= (MPVIO_EXT *) vio;
  mpvio_info(mpvio->net->vio, info);
}

#ifndef NO_EMBEDDED_ACCESS_CHECKS
static bool acl_check_ssl(THD *thd, const ACL_USER *acl_user)
{
#if defined(HAVE_OPENSSL)
  Vio *vio= thd->net.vio;
  SSL *ssl= (SSL *) vio->ssl_arg;
  X509 *cert;
#endif

  /*
    At this point we know that user is allowed to connect
    from given host by given username/password pair. Now
    we check if SSL is required, if user is using SSL and
    if X509 certificate attributes are OK
  */
  switch (acl_user->ssl_type) {
  case SSL_TYPE_NOT_SPECIFIED:                  // Impossible
  case SSL_TYPE_NONE:                           // SSL is not required
    return 0;
#if defined(HAVE_OPENSSL)
  case SSL_TYPE_ANY:                            // Any kind of SSL is ok
    return vio_type(vio) != VIO_TYPE_SSL;
  case SSL_TYPE_X509: /* Client should have any valid certificate. */
    /*
      Connections with non-valid certificates are dropped already
      in sslaccept() anyway, so we do not check validity here.

      We need to check for absence of SSL because without SSL
      we should reject connection.
    */
    if (vio_type(vio) == VIO_TYPE_SSL &&
        SSL_get_verify_result(ssl) == X509_V_OK &&
        (cert= SSL_get_peer_certificate(ssl)))
    {
      X509_free(cert);
      return 0;
    }
    return 1;
  case SSL_TYPE_SPECIFIED: /* Client should have specified attrib */
    /* If a cipher name is specified, we compare it to actual cipher in use. */
    if (vio_type(vio) != VIO_TYPE_SSL ||
        SSL_get_verify_result(ssl) != X509_V_OK)
      return 1;
    if (acl_user->ssl_cipher)
    {
      DBUG_PRINT("info", ("comparing ciphers: '%s' and '%s'",
                         acl_user->ssl_cipher, SSL_get_cipher(ssl)));
      if (strcmp(acl_user->ssl_cipher, SSL_get_cipher(ssl)))
      {
        if (log_warnings)
          sql_print_information("X509 ciphers mismatch: should be '%s' but is '%s'",
                            acl_user->ssl_cipher, SSL_get_cipher(ssl));
        return 1;
      }
    }
    /* Prepare certificate (if exists) */
    if (!(cert= SSL_get_peer_certificate(ssl)))
      return 1;
    /* If X509 issuer is specified, we check it... */
    if (acl_user->x509_issuer)
    {
      char *ptr= X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
      DBUG_PRINT("info", ("comparing issuers: '%s' and '%s'",
                         acl_user->x509_issuer, ptr));
      if (strcmp(acl_user->x509_issuer, ptr))
      {
        if (log_warnings)
          sql_print_information("X509 issuer mismatch: should be '%s' "
                            "but is '%s'", acl_user->x509_issuer, ptr);
        OPENSSL_free(ptr);
        X509_free(cert);
        return 1;
      }
      OPENSSL_free(ptr);
    }
    /* X509 subject is specified, we check it .. */
    if (acl_user->x509_subject)
    {
      char *ptr= X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
      DBUG_PRINT("info", ("comparing subjects: '%s' and '%s'",
                         acl_user->x509_subject, ptr));
      if (strcmp(acl_user->x509_subject, ptr))
      {
        if (log_warnings)
          sql_print_information("X509 subject mismatch: should be '%s' but is '%s'",
                          acl_user->x509_subject, ptr);
        OPENSSL_free(ptr);
        X509_free(cert);
        return 1;
      }
      OPENSSL_free(ptr);
    }
    X509_free(cert);
    return 0;
#else  /* HAVE_OPENSSL */
  default:
    /*
      If we don't have SSL but SSL is required for this user the 
      authentication should fail.
    */
    return 1;
#endif /* HAVE_OPENSSL */
  }
  return 1;
}
#endif


static int do_auth_once(THD *thd, LEX_STRING *auth_plugin_name,
                        MPVIO_EXT *mpvio)
{
  DBUG_ENTER("do_auth_once");
  int res= CR_OK, old_status= MPVIO_EXT::FAILURE;
  bool unlock_plugin= false;
  plugin_ref plugin= NULL;

  if (auth_plugin_name->str == native_password_plugin_name.str)
    plugin= native_password_plugin;
#ifndef EMBEDDED_LIBRARY
  else
  if (auth_plugin_name->str == old_password_plugin_name.str)
    plugin= old_password_plugin;
  else
  {
    if (auth_plugin_name->length == 0)
    {
      auth_plugin_name->str= default_auth_plugin_name.str;
      auth_plugin_name->length= default_auth_plugin_name.length;
    }
    if ((plugin= my_plugin_lock_by_name(thd, auth_plugin_name,
                                        MYSQL_AUTHENTICATION_PLUGIN)))
      unlock_plugin= true;
  }
#endif

    
  mpvio->plugin= plugin;
  old_status= mpvio->status;
  
  if (plugin)
  {
    st_mysql_auth *auth= (st_mysql_auth *) plugin_decl(plugin)->info;
    res= auth->authenticate_user(mpvio, &mpvio->auth_info);

    if (unlock_plugin)
      plugin_unlock(thd, plugin);
  }
  else
  {
    /* Server cannot load the required plugin. */
    Host_errors errors;
    errors.m_no_auth_plugin= 1;
    //inc_host_errors(mpvio->ip, &errors);
    my_error(ER_PLUGIN_IS_NOT_LOADED, MYF(0), auth_plugin_name->str);
    res= CR_ERROR;
  }

  /*
    If the status was MPVIO_EXT::RESTART before the authenticate_user() call
    it can never be MPVIO_EXT::RESTART after the call, because any call
    to write_packet() or read_packet() will reset the status.

    But (!) if a plugin never called a read_packet() or write_packet(), the
    status will stay unchanged. We'll fix it, by resetting the status here.
  */
  if (old_status == MPVIO_EXT::RESTART && mpvio->status == MPVIO_EXT::RESTART)
    mpvio->status= MPVIO_EXT::FAILURE; // reset to the default

  DBUG_RETURN(res);
}


static void
server_mpvio_initialize(THD *thd, MPVIO_EXT *mpvio,
                        Thd_charset_adapter *charset_adapter)
{
  memset(mpvio, 0, sizeof(MPVIO_EXT));
  mpvio->read_packet= server_mpvio_read_packet;
  mpvio->write_packet= server_mpvio_write_packet;
  mpvio->info= server_mpvio_info;
  mpvio->auth_info.host_or_ip= thd->security_ctx->host_or_ip;
  mpvio->auth_info.host_or_ip_length= 
    (unsigned int) strlen(thd->security_ctx->host_or_ip);
  mpvio->auth_info.user_name= NULL;
  mpvio->auth_info.user_name_length= 0;
#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
  if (thd->net.vio && thd->net.vio->ssl_arg)
    mpvio->vio_is_encrypted= 1;
  else
#endif /* HAVE_OPENSSL && !EMBEDDED_LIBRARY */
    mpvio->vio_is_encrypted= 0;
  mpvio->status= MPVIO_EXT::FAILURE;

  mpvio->client_capabilities= thd->client_capabilities;
  mpvio->mem_root= thd->mem_root;
  mpvio->scramble= thd->scramble;
  mpvio->rand= &thd->rand;
  mpvio->thread_id= thd->thread_id;
  mpvio->server_status= &thd->server_status;
  mpvio->net= &thd->net;
  mpvio->ip= thd->security_ctx->ip;
  mpvio->host= thd->security_ctx->host;
  mpvio->charset_adapter= charset_adapter;
}


static void
server_mpvio_update_thd(THD *thd, MPVIO_EXT *mpvio)
{
  thd->client_capabilities= mpvio->client_capabilities;
  thd->max_client_packet_length= mpvio->max_client_packet_length;
  if (mpvio->client_capabilities & CLIENT_INTERACTIVE)
    thd->variables.net_wait_timeout= thd->variables.net_interactive_timeout;
  thd->security_ctx->user= mpvio->auth_info.user_name;
  if (thd->client_capabilities & CLIENT_IGNORE_SPACE)
    thd->variables.sql_mode|= MODE_IGNORE_SPACE;
}

/**
  Perform the handshake, authorize the client and update thd sctx variables.

  @param thd                     thread handle
  @param com_change_user_pkt_len size of the COM_CHANGE_USER packet
                                 (without the first, command, byte) or 0
                                 if it's not a COM_CHANGE_USER (that is, if
                                 it's a new connection)

  @retval 0  success, thd is updated.
  @retval 1  error
*/
int
acl_authenticate(THD *thd, uint com_change_user_pkt_len)
{
  int res= CR_OK;
  MPVIO_EXT mpvio;
  Thd_charset_adapter charset_adapter(thd);

  LEX_STRING auth_plugin_name= default_auth_plugin_name;
  enum  enum_server_command command= com_change_user_pkt_len ? COM_CHANGE_USER
                                                             : COM_CONNECT;

  DBUG_ENTER("acl_authenticate");
  compile_time_assert(MYSQL_USERNAME_LENGTH == USERNAME_LENGTH);

  server_mpvio_initialize(thd, &mpvio, &charset_adapter);

  DBUG_PRINT("info", ("com_change_user_pkt_len=%u", com_change_user_pkt_len));

  /*
    Clear thd->db as it points to something, that will be freed when
    connection is closed. We don't want to accidentally free a wrong
    pointer if connect failed.
  */
  thd->reset_db(NULL, 0);

  if (command == COM_CHANGE_USER)
  {
    mpvio.packets_written++; // pretend that a server handshake packet was sent
    mpvio.packets_read++;    // take COM_CHANGE_USER packet into account

    /* Clear variables that are allocated */
    thd->set_user_connect(NULL);

    if (parse_com_change_user_packet(&mpvio, com_change_user_pkt_len))
    {
      server_mpvio_update_thd(thd, &mpvio);
      DBUG_RETURN(1);
    }

    DBUG_ASSERT(mpvio.status == MPVIO_EXT::RESTART ||
                mpvio.status == MPVIO_EXT::SUCCESS);
  }
  else
  {
    /* mark the thd as having no scramble yet */
    mpvio.scramble[SCRAMBLE_LENGTH]= 1;
    
    /*
     perform the first authentication attempt, with the default plugin.
     This sends the server handshake packet, reads the client reply
     with a user name, and performs the authentication if everyone has used
     the correct plugin.
    */

    res= do_auth_once(thd, &auth_plugin_name, &mpvio);  
  }

  /*
   retry the authentication, if - after receiving the user name -
   we found that we need to switch to a non-default plugin
  */
  if (mpvio.status == MPVIO_EXT::RESTART)
  {
    DBUG_ASSERT(mpvio.acl_user);
    DBUG_ASSERT(command == COM_CHANGE_USER ||
                my_strcasecmp(system_charset_info, auth_plugin_name.str,
                              mpvio.acl_user->plugin.str));
    auth_plugin_name= mpvio.acl_user->plugin;
    res= do_auth_once(thd, &auth_plugin_name, &mpvio);
    if (res <= CR_OK)
    {
      if (auth_plugin_name.str == native_password_plugin_name.str)
        thd->variables.old_passwords= 0;
      if (auth_plugin_name.str == old_password_plugin_name.str)
        thd->variables.old_passwords= 1;
      if (auth_plugin_name.str == sha256_password_plugin_name.str)
        thd->variables.old_passwords= 2;
    }
  }

  server_mpvio_update_thd(thd, &mpvio);

  Security_context *sctx= thd->security_ctx;
  const ACL_USER *acl_user= mpvio.acl_user;

  thd->password= mpvio.auth_info.password_used;  // remember for error messages 

  /*
    Log the command here so that the user can check the log
    for the tried logins and also to detect break-in attempts.

    if sctx->user is unset it's protocol failure, bad packet.
  */
  if (mpvio.auth_info.user_name)
  {
    if (strcmp(mpvio.auth_info.authenticated_as, mpvio.auth_info.user_name))
    {
      general_log_print(thd, command, "%s@%s as %s on %s",
                        mpvio.auth_info.user_name, mpvio.auth_info.host_or_ip,
                        mpvio.auth_info.authenticated_as ? 
                          mpvio.auth_info.authenticated_as : "anonymous",
                        mpvio.db.str ? mpvio.db.str : (char*) "");
    }
    else
      general_log_print(thd, command, (char*) "%s@%s on %s",
                        mpvio.auth_info.user_name, mpvio.auth_info.host_or_ip,
                        mpvio.db.str ? mpvio.db.str : (char*) "");
  }

  if (res > CR_OK && mpvio.status != MPVIO_EXT::SUCCESS)
  {
    Host_errors errors;
    DBUG_ASSERT(mpvio.status == MPVIO_EXT::FAILURE);
    switch (res)
    {
    case CR_AUTH_PLUGIN_ERROR:
      errors.m_auth_plugin= 1;
      break;
    case CR_AUTH_HANDSHAKE:
      errors.m_handshake= 1;
      break;
    case CR_AUTH_USER_CREDENTIALS:
      errors.m_authentication= 1;
      break;
    case CR_ERROR:
    default:
      /* Unknown of unspecified auth plugin error. */
      errors.m_auth_plugin= 1;
      break;
    }
    //inc_host_errors(mpvio.ip, &errors);
    //if (!thd->is_error())
    //  login_failed_error(&mpvio, mpvio.auth_info.password_used);
    DBUG_RETURN (0);
  }

  sctx->proxy_user[0]= 0;

//   if (initialized) // if not --skip-grant-tables
//   {
//     sctx->master_access= acl_user->access;
//     if (acl_user->user)
//       strmake(sctx->priv_user, acl_user->user, USERNAME_LENGTH - 1);
//     else
//       *sctx->priv_user= 0;
// 
//     if (acl_user->host.get_host())
//       strmake(sctx->priv_host, acl_user->host.get_host(), MAX_HOSTNAME - 1);
//     else
//       *sctx->priv_host= 0;
//   }
//   else
    sctx->skip_grants();

  const USER_CONN *uc;
  if ((uc= thd->get_user_connect()) &&
      (uc->user_resources.conn_per_hour || uc->user_resources.user_conn ||
       global_system_variables.max_user_connections) &&
       check_for_max_user_connections(thd, uc))
  {
    DBUG_RETURN(1); // The error is set in check_for_max_user_connections()
  }

  DBUG_PRINT("info",
             ("Capabilities: %lu  packet_length: %ld  Host: '%s'  "
              "Login user: '%s' Priv_user: '%s'  Using password: %s "
              "Access: %lu  db: '%s'",
              thd->client_capabilities, thd->max_client_packet_length,
              sctx->host_or_ip, sctx->user, sctx->priv_user,
              thd->password ? "yes": "no",
              sctx->master_access, mpvio.db.str));

  if (command == COM_CONNECT &&
      !(thd->main_security_ctx.master_access & SUPER_ACL))
  {
    mysql_mutex_lock(&LOCK_connection_count);
    bool count_ok= (connection_count <= max_connections);
    mysql_mutex_unlock(&LOCK_connection_count);
    if (!count_ok)
    {                                         // too many connections
      release_user_connection(thd);
      statistic_increment(connection_errors_max_connection, &LOCK_status);
      my_error(ER_CON_COUNT_ERROR, MYF(0));
      DBUG_RETURN(1);
    }
  }

  /*
    This is the default access rights for the current database.  It's
    set to 0 here because we don't have an active database yet (and we
    may not have an active database to set.
  */
  sctx->db_access=0;

  /* Change a database if necessary */
//   if (mpvio.db.length)
//   {
//     if (mysql_change_db(thd, &mpvio.db, FALSE))
//     {
//       /* mysql_change_db() has pushed the error message. */
//       release_user_connection(thd);
//       Host_errors errors;
//       errors.m_default_database= 1;
//       inc_host_errors(mpvio.ip, &errors);
//       DBUG_RETURN(1);
//     }
//   }

  if (mpvio.auth_info.external_user[0])
    sctx->external_user= my_strdup(mpvio.auth_info.external_user, MYF(0));


  if (res == CR_OK_HANDSHAKE_COMPLETE)
    thd->get_stmt_da()->disable_status();
  else
    my_ok(thd);

#ifdef HAVE_PSI_THREAD_INTERFACE
  PSI_THREAD_CALL(set_thread_user_host)
    (thd->main_security_ctx.user, strlen(thd->main_security_ctx.user),
    thd->main_security_ctx.host_or_ip, strlen(thd->main_security_ctx.host_or_ip));
#endif

  /* Ready to handle queries */
  DBUG_RETURN(0);
}

/**
  MySQL Server Password Authentication Plugin

  In the MySQL authentication protocol:
  1. the server sends the random scramble to the client
  2. client sends the encrypted password back to the server
  3. the server checks the password.
*/
static int native_password_authenticate(MYSQL_PLUGIN_VIO *vio,
                                        MYSQL_SERVER_AUTH_INFO *info)
{
  uchar *pkt;
  int pkt_len;
  MPVIO_EXT *mpvio= (MPVIO_EXT *) vio;

  DBUG_ENTER("native_password_authenticate");

  /* generate the scramble, or reuse the old one */
  if (mpvio->scramble[SCRAMBLE_LENGTH])
    create_random_string(mpvio->scramble, SCRAMBLE_LENGTH, mpvio->rand);

  /* send it to the client */
  if (mpvio->write_packet(mpvio, (uchar*) mpvio->scramble, SCRAMBLE_LENGTH + 1))
    DBUG_RETURN(CR_AUTH_HANDSHAKE);

  /* reply and authenticate */

  /*
    <digression>
      This is more complex than it looks.

      The plugin (we) may be called right after the client was connected -
      and will need to send a scramble, read reply, authenticate.

      Or the plugin may be called after another plugin has sent a scramble,
      and read the reply. If the client has used the correct client-plugin,
      we won't need to read anything here from the client, the client
      has already sent a reply with everything we need for authentication.

      Or the plugin may be called after another plugin has sent a scramble,
      and read the reply, but the client has used the wrong client-plugin.
      We'll need to sent a "switch to another plugin" packet to the
      client and read the reply. "Use the short scramble" packet is a special
      case of "switch to another plugin" packet.

      Or, perhaps, the plugin may be called after another plugin has
      done the handshake but did not send a useful scramble. We'll need
      to send a scramble (and perhaps a "switch to another plugin" packet)
      and read the reply.

      Besides, a client may be an old one, that doesn't understand plugins.
      Or doesn't even understand 4.0 scramble.

      And we want to keep the same protocol on the wire  unless non-native
      plugins are involved.

      Anyway, it still looks simple from a plugin point of view:
      "send the scramble, read the reply and authenticate"
      All the magic is transparently handled by the server.
    </digression>
  */

  /* read the reply with the encrypted password */
  if ((pkt_len= mpvio->read_packet(mpvio, &pkt)) < 0)
    DBUG_RETURN(CR_AUTH_HANDSHAKE);
  DBUG_PRINT("info", ("reply read : pkt_len=%d", pkt_len));

#ifdef NO_EMBEDDED_ACCESS_CHECKS
  DBUG_RETURN(CR_OK);
#endif

  DBUG_EXECUTE_IF("native_password_bad_reply",
                  {
                    pkt_len= 12;
                  }
                  );

  if (pkt_len == 0) /* no password */
    DBUG_RETURN(mpvio->acl_user->salt_len != 0 ? CR_AUTH_USER_CREDENTIALS : CR_OK);

  info->password_used= PASSWORD_USED_YES;
  if (pkt_len == SCRAMBLE_LENGTH)
  {
    if (!mpvio->acl_user->salt_len)
      DBUG_RETURN(CR_AUTH_USER_CREDENTIALS);

    DBUG_RETURN(check_scramble(pkt, mpvio->scramble, mpvio->acl_user->salt) ?
                CR_AUTH_USER_CREDENTIALS : CR_OK);
  }

  my_error(ER_HANDSHAKE_ERROR, MYF(0));
  DBUG_RETURN(CR_AUTH_HANDSHAKE);
}

static int old_password_authenticate(MYSQL_PLUGIN_VIO *vio, 
                                     MYSQL_SERVER_AUTH_INFO *info)
{
  uchar *pkt;
  int pkt_len;
  MPVIO_EXT *mpvio= (MPVIO_EXT *) vio;

  /* generate the scramble, or reuse the old one */
  if (mpvio->scramble[SCRAMBLE_LENGTH])
    create_random_string(mpvio->scramble, SCRAMBLE_LENGTH, mpvio->rand);

  /* send it to the client */
  if (mpvio->write_packet(mpvio, (uchar*) mpvio->scramble, SCRAMBLE_LENGTH + 1))
    return CR_AUTH_HANDSHAKE;

  /* read the reply and authenticate */
  if ((pkt_len= mpvio->read_packet(mpvio, &pkt)) < 0)
    return CR_AUTH_HANDSHAKE;

#ifdef NO_EMBEDDED_ACCESS_CHECKS
  return CR_OK;
#endif

  /*
    legacy: if switch_from_long_to_short_scramble,
    the password is sent \0-terminated, the pkt_len is always 9 bytes.
    We need to figure out the correct scramble length here.
  */
  if (pkt_len == SCRAMBLE_LENGTH_323 + 1)
    pkt_len= strnlen((char*)pkt, pkt_len);

  if (pkt_len == 0) /* no password */
    return mpvio->acl_user->salt_len != 0 ? CR_AUTH_USER_CREDENTIALS : CR_OK;

  if (secure_auth(mpvio))
    return CR_AUTH_HANDSHAKE;

  info->password_used= PASSWORD_USED_YES;

  if (pkt_len == SCRAMBLE_LENGTH_323)
  {
    if (!mpvio->acl_user->salt_len)
      return CR_AUTH_USER_CREDENTIALS;

    return check_scramble_323(pkt, mpvio->scramble,
                             (ulong *) mpvio->acl_user->salt) ?
                             CR_AUTH_USER_CREDENTIALS : CR_OK;
  }

  my_error(ER_HANDSHAKE_ERROR, MYF(0));
  return CR_AUTH_HANDSHAKE;
}


/**
  Interface for querying the MYSQL_PUBLIC_VIO about encryption state.
 
*/

int my_vio_is_encrypted(MYSQL_PLUGIN_VIO *vio)
{
  MPVIO_EXT *mpvio= (MPVIO_EXT *) vio;
  return (mpvio->vio_is_encrypted);
}

#if defined(HAVE_OPENSSL)
#define MAX_CIPHER_LENGTH 1024
#if !defined(HAVE_YASSL)
#define AUTH_DEFAULT_RSA_PRIVATE_KEY "private_key.pem"
#define AUTH_DEFAULT_RSA_PUBLIC_KEY "public_key.pem"

char *auth_rsa_private_key_path;
char *auth_rsa_public_key_path;

class Rsa_authentication_keys
{
private:
  RSA *m_public_key;
  RSA *m_private_key;
  int m_cipher_len;
  char *m_pem_public_key;
public:
  Rsa_authentication_keys()
  {
    m_cipher_len= 0;
    m_private_key= 0;
    m_public_key= 0;
  }
  
  ~Rsa_authentication_keys()
  {
  }

  void free_memory()
  {
    if (m_private_key)
    {
      RSA_free(m_private_key);
      RSA_free(m_public_key);
    }
    if (m_pem_public_key)
      delete [] m_pem_public_key;
  }

  void *allocate_pem_buffer(size_t buffer_len)
  {
    m_pem_public_key= new char[buffer_len];
    return m_pem_public_key;
  }

  RSA *get_private_key()
  {
    return m_private_key;
  }

  RSA *get_public_key()
  {
    return m_public_key;
  }

  int get_cipher_length()
  {
    return (m_cipher_len= RSA_size(m_public_key));
  }

  int set_private_key(RSA *pk)
  {
    m_private_key= pk;
    return 0;
  }

  int set_public_key(RSA *pk)
  {
    m_public_key= pk;
    return 0;
  }

  const char *get_public_key_as_pem(void)
  {
    return m_pem_public_key;
  }
  
};

static Rsa_authentication_keys g_rsa_keys;

/**
 
*/
int show_rsa_public_key(THD *thd, SHOW_VAR *var, char *buff)
{ 
  var->type= SHOW_CHAR;
  var->value= const_cast<char *>(g_rsa_keys.get_public_key_as_pem());
    
  return 0;
}

void deinit_rsa_keys(void)
{
  g_rsa_keys.free_memory();  
}

// Wraps a FILE handle, to ensure we always close it when returning.
class FileCloser
{
  FILE *m_file;
public:
  FileCloser(FILE *to_be_closed) : m_file(to_be_closed) {}
  ~FileCloser()
  {
    if (m_file != NULL)
      fclose(m_file);
  }
};

/**
  Loads the RSA key pair from disk and store them in a global variable. 
 
 @see init_ssl()
 
 @return Error code
   @retval 0 Success
   @retval 1 Error
*/

int init_rsa_keys(void)
{
  FILE *priv_key_file;
  FILE *public_key_file;
  String priv_keypath;
  String pub_keypath;
  int auth_rsa_private_key_path_len;
  int auth_rsa_public_key_path_len;
  
  auth_rsa_private_key_path_len= strlen(auth_rsa_private_key_path);
  auth_rsa_public_key_path_len= strlen(auth_rsa_public_key_path);
  if (auth_rsa_private_key_path_len == 0 || auth_rsa_public_key_path_len == 0)
  {
     sql_print_information("RSA key files not found."
                          " Some authentication plugins will not work.");
    return 0;
  }

  /*
     If a fully qualified path is entered use that, else assume the keys are 
     stored in the data directory.
  */
  if (strchr(auth_rsa_private_key_path, FN_LIBCHAR) != NULL ||
      strchr(auth_rsa_private_key_path, FN_LIBCHAR2) != NULL)
    priv_keypath.set_quick(auth_rsa_private_key_path,
                           auth_rsa_private_key_path_len, 
                           system_charset_info);
  else
  {
    priv_keypath.append(mysql_real_data_home, strlen(mysql_real_data_home));
    if (priv_keypath[pub_keypath.length()] != FN_LIBCHAR)
      priv_keypath.append(FN_LIBCHAR);
    priv_keypath.append(auth_rsa_private_key_path);
  }

  if ((priv_key_file= fopen(priv_keypath.c_ptr(), "r")) == NULL)
  {
    sql_print_information("RSA private key file not found: %s."
                          " Some authentication plugins will not work.",
                          priv_keypath.c_ptr());
    /* Don't return an error; server will still be able to operate. */
    return 0;
  }
  FileCloser close_priv(priv_key_file);

  if (strchr(auth_rsa_public_key_path, FN_LIBCHAR) != NULL ||
      strchr(auth_rsa_public_key_path, FN_LIBCHAR2) != NULL)
    pub_keypath.set_quick(auth_rsa_public_key_path,
                          auth_rsa_public_key_path_len, 
                          system_charset_info);
  else
  {
    pub_keypath.append(mysql_real_data_home, strlen(mysql_real_data_home));
    if (pub_keypath[pub_keypath.length()] != FN_LIBCHAR)
      pub_keypath.append(FN_LIBCHAR);
    pub_keypath.append(auth_rsa_public_key_path);
  }

  if ((public_key_file= fopen(pub_keypath.c_ptr(), "r")) == NULL)
  {
    sql_print_information("RSA public key file not found: %s."
                          " Some authentication plugins will not work.",
                          pub_keypath.c_ptr());
    /* Don't return an error; server will still be able to operate. */
    return 0;
  }
  FileCloser close_public(public_key_file);

  RSA *rsa_private_key= RSA_new();
  if (g_rsa_keys.set_private_key(PEM_read_RSAPrivateKey(priv_key_file,
                                                        &rsa_private_key,
                                                        0, 0)))
  {
    sql_print_error("Failure to parse RSA private key (file exists): %s",
                    auth_rsa_private_key_path);
    /* An intention has been made clear which can't be fulfilled; stop server.*/
    return 1;
    
  }
  
  int filesize;
  fseek(public_key_file, 0, SEEK_END);
  filesize= ftell(public_key_file);
  fseek(public_key_file, 0, SEEK_SET);
  char *pem_file_buffer= (char *)g_rsa_keys.allocate_pem_buffer(filesize + 1);
  (void) fread(pem_file_buffer, filesize, 1, public_key_file);
  pem_file_buffer[filesize]= '\0';

  if (int err= ferror(public_key_file))
  {
    sql_print_error("Failure code %d when reading RSA public key (%d bytes): %s",
                    err, filesize, auth_rsa_private_key_path);
    /* An intention has been made clear which can't be fulfilled; stop server.*/
    return 1;
  }
  fseek(public_key_file, 0, SEEK_SET);

  RSA *rsa_public_key= RSA_new();
  if (g_rsa_keys.set_public_key(PEM_read_RSA_PUBKEY(public_key_file,
                                                    &rsa_public_key,
                                                    0, 0)))
  {
     sql_print_error("Failure to parse RSA public key (file exists): %s",
                    auth_rsa_public_key_path);
    /* An intention has been made clear which can't be fulfilled; stop server.*/
    return 1;
  }

  return 0;
}
#endif // ifndef HAVE_YASSL

static MYSQL_PLUGIN plugin_info_ptr;

int init_sha256_password_handler(MYSQL_PLUGIN plugin_ref)
{
  plugin_info_ptr= plugin_ref;
  return 0;
}

/** 
 
 @param vio Virtual input-, output interface
 @param info[out] Connection information
 
 Authenticate the user by recieving a RSA or TLS encrypted password and
 calculate a hash digest which should correspond to the user record digest
 
 RSA keys are assumed to be pre-generated and supplied when server starts. If
 the client hasn't got a public key it can request one.
 
 TLS certificates and keys are assumed to be pre-generated and supplied when
 server starts.
 
*/

static int sha256_password_authenticate(MYSQL_PLUGIN_VIO *vio,
                                        MYSQL_SERVER_AUTH_INFO *info)
{
  uchar *pkt;
  int pkt_len;
  char  *user_salt_begin;
  char  *user_salt_end;
  char scramble[SCRAMBLE_LENGTH + 1];
  char stage2[CRYPT_MAX_PASSWORD_SIZE + 1];
  String scramble_response_packet;
#if !defined(HAVE_YASSL)
  int cipher_length= 0;
  unsigned char plain_text[MAX_CIPHER_LENGTH];
  RSA *private_key= NULL;
  RSA *public_key= NULL;
#endif

  DBUG_ENTER("sha256_password_authenticate");

  generate_user_salt(scramble, SCRAMBLE_LENGTH + 1);

  if (vio->write_packet(vio, (unsigned char *) scramble, SCRAMBLE_LENGTH))
    DBUG_RETURN(CR_ERROR);

  /*
    After the call to read_packet() the user name will appear in
    mpvio->acl_user and info will contain current data.
  */
  if ((pkt_len= vio->read_packet(vio, &pkt)) == -1)
    DBUG_RETURN(CR_ERROR);

  /*
    If first packet is a 0 byte then the client isn't sending any password
    else the client will send a password.
  */
  if (pkt_len == 1 && *pkt == 0)
  {
    info->password_used= PASSWORD_USED_NO;
    /*
      Send OK signal; the authentication might still be rejected based on
      host mask.
    */
    if (info->auth_string_length == 0)
      DBUG_RETURN(CR_OK);
    else
      DBUG_RETURN(CR_ERROR);
  }
  else    
    info->password_used= PASSWORD_USED_YES;

  if (!my_vio_is_encrypted(vio))
  {
 #if !defined(HAVE_YASSL)
    /*
      Since a password is being used it must be encrypted by RSA since no 
      other encryption is being active.
    */
    private_key= g_rsa_keys.get_private_key();
    public_key=  g_rsa_keys.get_public_key();

    /*
      Without the keys encryption isn't possible.
    */
    if (private_key == NULL || public_key == NULL)
    {
      my_plugin_log_message(&plugin_info_ptr, MY_ERROR_LEVEL, 
        "Authentication requires either RSA keys or SSL encryption");
      DBUG_RETURN(CR_ERROR);
    }
      

    if ((cipher_length= g_rsa_keys.get_cipher_length()) > MAX_CIPHER_LENGTH)
    {
      my_plugin_log_message(&plugin_info_ptr, MY_ERROR_LEVEL, 
        "RSA key cipher length of %u is too long. Max value is %u.",
        g_rsa_keys.get_cipher_length(), MAX_CIPHER_LENGTH);
      DBUG_RETURN(CR_ERROR);
    }

    /*
      Client sent a "public key request"-packet ?
      If the first packet is 1 then the client will require a public key before
      encrypting the password.
    */
    if (pkt_len == 1 && *pkt == 1)
    {
      uint pem_length= strlen(g_rsa_keys.get_public_key_as_pem());
      if (vio->write_packet(vio,
                            (unsigned char *)g_rsa_keys.get_public_key_as_pem(),
                            pem_length))
        DBUG_RETURN(CR_ERROR);
      /* Get the encrypted response from the client */
      if ((pkt_len= vio->read_packet(vio, &pkt)) == -1)
        DBUG_RETURN(CR_ERROR);
    }

    /*
      The packet will contain the cipher used. The length of the packet
      must correspond to the expected cipher length.
    */
    if (pkt_len != cipher_length)
      DBUG_RETURN(CR_ERROR);
    
    /* Decrypt password */
    RSA_private_decrypt(cipher_length, pkt, plain_text, private_key,
                        RSA_PKCS1_OAEP_PADDING);

    plain_text[cipher_length]= '\0'; // safety
    xor_string((char *) plain_text, cipher_length,
               (char *) scramble, SCRAMBLE_LENGTH);

    /*
      Set packet pointers and length for the hash digest function below 
    */
    pkt= plain_text;
    pkt_len= strlen((char *) plain_text) + 1; // include \0 intentionally.

    if (pkt_len == 1)
      DBUG_RETURN(CR_ERROR);
#else
    DBUG_RETURN(CR_ERROR);
#endif
  } // if(!my_vio_is_encrypter())

  /* A password was sent to an account without a password */
  if (info->auth_string_length == 0)
    DBUG_RETURN(CR_ERROR);
  
  /*
    Fetch user authentication_string and extract the password salt
  */
  user_salt_begin= (char *) info->auth_string;
  user_salt_end= (char *) (info->auth_string + info->auth_string_length);
  if (extract_user_salt(&user_salt_begin, &user_salt_end) != CRYPT_SALT_LENGTH)
  {
    /* User salt is not correct */
    my_plugin_log_message(&plugin_info_ptr, MY_ERROR_LEVEL, 
      "Password salt for user '%s' is corrupt.",
      info->user_name);
    DBUG_RETURN(CR_ERROR);
  }

  /* Create hash digest */
  my_crypt_genhash(stage2,
                     CRYPT_MAX_PASSWORD_SIZE,
                     (char *) pkt,
                     pkt_len-1, 
                     (char *) user_salt_begin,
                     (const char **) 0);

  /* Compare the newly created hash digest with the password record */
  int result= memcmp(info->auth_string,
                     stage2,
                     info->auth_string_length);

  if (result == 0)
    DBUG_RETURN(CR_OK);

  DBUG_RETURN(CR_ERROR);
}

#if !defined(HAVE_YASSL)
static MYSQL_SYSVAR_STR(private_key_path, auth_rsa_private_key_path,
        PLUGIN_VAR_READONLY,
        "A fully qualified path to the private RSA key used for authentication",
        NULL, NULL, AUTH_DEFAULT_RSA_PRIVATE_KEY);
static MYSQL_SYSVAR_STR(public_key_path, auth_rsa_public_key_path,
        PLUGIN_VAR_READONLY,
        "A fully qualified path to the public RSA key used for authentication",
        NULL, NULL, AUTH_DEFAULT_RSA_PUBLIC_KEY);

static struct st_mysql_sys_var* sha256_password_sysvars[]= {
  MYSQL_SYSVAR(private_key_path),
  MYSQL_SYSVAR(public_key_path),
  0
};
#endif // HAVE_YASSL
#endif // HAVE_OPENSSL

static struct st_mysql_auth native_password_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  native_password_plugin_name.str,
  native_password_authenticate
};

static struct st_mysql_auth old_password_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  old_password_plugin_name.str,
  old_password_authenticate
};

#if defined(HAVE_OPENSSL)
static struct st_mysql_auth sha256_password_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  sha256_password_plugin_name.str,
  sha256_password_authenticate
};
#endif

mysql_declare_plugin(mysql_password)
{
  MYSQL_AUTHENTICATION_PLUGIN,                  /* type constant    */
  &native_password_handler,                     /* type descriptor  */
  native_password_plugin_name.str,              /* Name             */
  "R.J.Silk, Sergei Golubchik",                 /* Author           */
  "Native MySQL authentication",                /* Description      */
  PLUGIN_LICENSE_GPL,                           /* License          */
  NULL,                                         /* Init function    */
  NULL,                                         /* Deinit function  */
  0x0100,                                       /* Version (1.0)    */
  NULL,                                         /* status variables */
  NULL,                                         /* system variables */
  NULL,                                         /* config options   */
  0,                                            /* flags            */
},
{
  MYSQL_AUTHENTICATION_PLUGIN,                  /* type constant    */
  &old_password_handler,                        /* type descriptor  */
  old_password_plugin_name.str,                 /* Name             */
  "R.J.Silk, Sergei Golubchik",                 /* Author           */
  "Old MySQL-4.0 authentication",               /* Description      */
  PLUGIN_LICENSE_GPL,                           /* License          */
  NULL,                                         /* Init function    */
  NULL,                                         /* Deinit function  */
  0x0100,                                       /* Version (1.0)    */
  NULL,                                         /* status variables */
  NULL,                                         /* system variables */
  NULL,                                         /* config options   */
  0,                                            /* flags            */
}
#if defined(HAVE_OPENSSL)
,
{
  MYSQL_AUTHENTICATION_PLUGIN,                  /* type constant    */
  &sha256_password_handler,                     /* type descriptor  */
  sha256_password_plugin_name.str,              /* Name             */
  "Oracle",                                     /* Author           */
  "SHA256 password authentication",             /* Description      */
  PLUGIN_LICENSE_GPL,                           /* License          */
  &init_sha256_password_handler,                /* Init function    */
  NULL,                                         /* Deinit function  */
  0x0100,                                       /* Version (1.0)    */
  NULL,                                         /* status variables */
#if !defined(HAVE_YASSL)
  sha256_password_sysvars,                      /* system variables */
#else
  NULL,
#endif
  NULL,                                         /* config options   */
  0                                             /* flags            */
}
#endif
mysql_declare_plugin_end;

/*  
 PASSWORD_VALIDATION_CODE, invoking appropriate plugin to validate
 the password strength.
*/

/* for validate_password_strength SQL function */
int check_password_strength(String *password)
{
  int res= 0;
  DBUG_ASSERT(password != NULL);
  plugin_ref plugin= my_plugin_lock_by_name(0, &validate_password_plugin_name,
                                            MYSQL_VALIDATE_PASSWORD_PLUGIN);
  if (plugin)
  {
    st_mysql_validate_password *password_strength=
                      (st_mysql_validate_password *) plugin_decl(plugin)->info;

    res= password_strength->get_password_strength(password);
    plugin_unlock(0, plugin);
  }
  return(res);
}

/* called when new user is created or exsisting password is changed */
int check_password_policy(String *password)
{
  plugin_ref plugin= my_plugin_lock_by_name(0, &validate_password_plugin_name,
                                            MYSQL_VALIDATE_PASSWORD_PLUGIN);
  DBUG_ASSERT(password != NULL);
  if (plugin)
  {
    st_mysql_validate_password *password_validate=
                      (st_mysql_validate_password *) plugin_decl(plugin)->info;

    if (!password_validate->validate_password(password))
    {  
      my_error(ER_NOT_VALID_PASSWORD, MYF(0));
      plugin_unlock(0, plugin);
      return (1);
    }
    plugin_unlock(0, plugin);
  }
  return (0);
}
