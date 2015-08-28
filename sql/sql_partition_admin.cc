/* Copyright (c) 2010, 2012, Oracle and/or its affiliates. All rights reserved.

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

#include "sql_parse.h"                      // check_access,
                                            // check_merge_table_access
                                            // check_one_table_access
#include "sql_table.h"                      // mysql_alter_table, etc.
#include "sql_cmd.h"                        // Sql_cmd
#include "sql_alter.h"                      // Sql_cmd_alter_table
#include "sql_partition.h"                  // struct partition_info, etc.
#include "sql_base.h"                       // open_and_lock_tables, etc
#include "debug_sync.h"                     // DEBUG_SYNC
#include "sql_truncate.h"                   // mysql_truncate_table,
                                            // Sql_cmd_truncate_table
#include "sql_admin.h"                      // Sql_cmd_Analyze/Check/.._table
#include "sql_partition_admin.h"            // Alter_table_*_partition
#ifdef WITH_PARTITION_STORAGE_ENGINE
#include "ha_partition.h"                   // ha_partition
#endif
#include "sql_base.h"                       // open_and_lock_tables

#ifndef WITH_PARTITION_STORAGE_ENGINE

bool Sql_cmd_partition_unsupported::execute(THD *)
{
  DBUG_ENTER("Sql_cmd_partition_unsupported::execute");
  /* error, partitioning support not compiled in... */
  my_error(ER_FEATURE_DISABLED, MYF(0), "partitioning",
           "--with-plugin-partition");
  DBUG_RETURN(TRUE);
}

#endif /* WITH_PARTITION_STORAGE_ENGINE */
