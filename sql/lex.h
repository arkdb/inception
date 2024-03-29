#ifndef LEX_INCLUDED
#define LEX_INCLUDED

/* Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */


/* This file includes all reserved words and functions */

#include "lex_symbol.h"

SYM_GROUP sym_group_common= {"", ""};
SYM_GROUP sym_group_geom= {"Spatial extentions", "HAVE_SPATIAL"};
SYM_GROUP sym_group_rtree= {"RTree keys", "HAVE_RTREE_KEYS"};

/* We don't want to include sql_yacc.h into gen_lex_hash */
#ifdef NO_YACC_SYMBOLS
#define SYM_OR_NULL(A) 0
#else
#define SYM_OR_NULL(A) A
#endif

#define SYM(A) SYM_OR_NULL(A),0,&sym_group_common

/*
  Symbols are broken into separated arrays to allow field names with
  same name as functions.
  These are kept sorted for human lookup (the symbols are hashed).

  NOTE! The symbol tables should be the same regardless of what features
  are compiled into the server. Don't add ifdef'ed symbols to the
  lists
*/

static SYMBOL symbols[] = {
{ "&&", SYM(AND_AND_SYM), TOK_RESERVE },
{ "<", SYM(LT), TOK_RESERVE },
{ "<=", SYM(LE), TOK_RESERVE },
{ "<>", SYM(NE), TOK_RESERVE },
{ "!=", SYM(NE), TOK_RESERVE },
{ "=", SYM(EQ), TOK_RESERVE },
{ ">", SYM(GT_SYM), TOK_RESERVE },
{ ">=", SYM(GE), TOK_RESERVE },
{ "<<", SYM(SHIFT_LEFT), TOK_RESERVE },
{ ">>", SYM(SHIFT_RIGHT), TOK_RESERVE },
{ "<=>", SYM(EQUAL_SYM), TOK_RESERVE },
{ "ACCESSIBLE", SYM(ACCESSIBLE_SYM), TOK_RESERVE },
{ "ACTION", SYM(ACTION), TOK_KEYWORD },
{ "ADD", SYM(ADD), TOK_RESERVE },
{ "AFTER", SYM(AFTER_SYM), TOK_KEYWORD },
{ "AGAINST", SYM(AGAINST), TOK_KEYWORD },
{ "AGGREGATE", SYM(AGGREGATE_SYM), TOK_KEYWORD },
{ "ALL", SYM(ALL), TOK_RESERVE },
{ "ALGORITHM", SYM(ALGORITHM_SYM), TOK_KEYWORD },
{ "ALTER", SYM(ALTER), TOK_RESERVE },
{ "ANALYSE", SYM(ANALYSE_SYM), TOK_KEYWORD },
{ "ANALYZE", SYM(ANALYZE_SYM), TOK_RESERVE },
{ "AND", SYM(AND_SYM), TOK_RESERVE },
{ "ANY", SYM(ANY_SYM), TOK_KEYWORD },
{ "AS", SYM(AS), TOK_RESERVE },
{ "ASC", SYM(ASC), TOK_RESERVE },
{ "ASCII", SYM(ASCII_SYM), TOK_KEYWORD },
{ "ASENSITIVE", SYM(ASENSITIVE_SYM), TOK_RESERVE },
{ "AT", SYM(AT_SYM), TOK_KEYWORD },
{ "AUTO_INCREMENT", SYM(AUTO_INC), TOK_KEYWORD },
{ "AUTOEXTEND_SIZE", SYM(AUTOEXTEND_SIZE_SYM), TOK_KEYWORD },
{ "AVG", SYM(AVG_SYM), TOK_KEYWORD },
{ "AVG_ROW_LENGTH", SYM(AVG_ROW_LENGTH), TOK_KEYWORD },
{ "BACKUP", SYM(BACKUP_SYM), TOK_KEYWORD },
{ "BEFORE", SYM(BEFORE_SYM), TOK_RESERVE },
{ "BEGIN", SYM(BEGIN_SYM), TOK_KEYWORD },
{ "INCEPTION", SYM(INCEPTION_SYM), TOK_KEYWORD },
{ "INCEPTION_MAGIC_START", SYM(INCEPTION_START_SYM), TOK_RESERVE },
{ "INCEPTION_MAGIC_COMMIT", SYM(INCEPTION_COMMIT_SYM), TOK_RESERVE },
{ "BETWEEN", SYM(BETWEEN_SYM), TOK_RESERVE },
{ "BIGINT", SYM(BIGINT), TOK_RESERVE },
{ "BINARY", SYM(BINARY), TOK_RESERVE },
{ "BINLOG", SYM(BINLOG_SYM), TOK_KEYWORD },
{ "BIT", SYM(BIT_SYM), TOK_KEYWORD },
{ "BLOB", SYM(BLOB_SYM), TOK_RESERVE },
{ "BLOCK", SYM(BLOCK_SYM), TOK_KEYWORD },
{ "BOOL", SYM(BOOL_SYM), TOK_KEYWORD },
{ "BOOLEAN", SYM(BOOLEAN_SYM), TOK_KEYWORD },
{ "BOTH", SYM(BOTH), TOK_RESERVE },
{ "BTREE", SYM(BTREE_SYM), TOK_KEYWORD },
{ "BY", SYM(BY), TOK_RESERVE },
{ "BYTE", SYM(BYTE_SYM), TOK_KEYWORD },
{ "CACHE", SYM(CACHE_SYM), TOK_KEYWORD },
{ "CALL", SYM(CALL_SYM), TOK_RESERVE },
{ "CASCADE", SYM(CASCADE), TOK_RESERVE },
{ "CASCADED", SYM(CASCADED), TOK_KEYWORD },
{ "CASE", SYM(CASE_SYM), TOK_RESERVE },
{ "CATALOG_NAME", SYM(CATALOG_NAME_SYM), TOK_KEYWORD },
{ "CHAIN", SYM(CHAIN_SYM), TOK_KEYWORD },
{ "CHANGE", SYM(CHANGE), TOK_RESERVE },
{ "CHANGED", SYM(CHANGED), TOK_KEYWORD },
{ "CHAR", SYM(CHAR_SYM), TOK_RESERVE },
{ "CHARACTER", SYM(CHAR_SYM), TOK_RESERVE },
{ "CHARSET", SYM(CHARSET), TOK_KEYWORD },
{ "CHECK", SYM(CHECK_SYM), TOK_RESERVE },
{ "CHECKSUM", SYM(CHECKSUM_SYM), TOK_KEYWORD },
{ "CIPHER", SYM(CIPHER_SYM), TOK_KEYWORD },
{ "CLASS_ORIGIN", SYM(CLASS_ORIGIN_SYM), TOK_KEYWORD },
{ "CLIENT", SYM(CLIENT_SYM), TOK_KEYWORD },
{ "CLOSE", SYM(CLOSE_SYM), TOK_KEYWORD },
{ "COALESCE", SYM(COALESCE), TOK_KEYWORD },
{ "CODE", SYM(CODE_SYM), TOK_KEYWORD },
{ "COLLATE", SYM(COLLATE_SYM), TOK_RESERVE },
{ "COLLATION", SYM(COLLATION_SYM), TOK_KEYWORD },
{ "COLUMN", SYM(COLUMN_SYM), TOK_RESERVE },
{ "COLUMN_FORMAT", SYM(COLUMN_FORMAT_SYM), TOK_KEYWORD },
{ "COLUMN_NAME", SYM(COLUMN_NAME_SYM), TOK_KEYWORD },
{ "COLUMNS", SYM(COLUMNS), TOK_KEYWORD },
{ "COMMENT", SYM(COMMENT_SYM), TOK_KEYWORD },
{ "COMMIT", SYM(COMMIT_SYM), TOK_KEYWORD },
{ "COMMITTED", SYM(COMMITTED_SYM), TOK_KEYWORD },
{ "COMPACT", SYM(COMPACT_SYM), TOK_KEYWORD },
{ "COMPLETION", SYM(COMPLETION_SYM), TOK_KEYWORD },
{ "COMPRESSED", SYM(COMPRESSED_SYM), TOK_KEYWORD },
{ "CONCURRENT", SYM(CONCURRENT), TOK_KEYWORD },
{ "CONDITION", SYM(CONDITION_SYM), TOK_RESERVE },
{ "CONNECTION", SYM(CONNECTION_SYM), TOK_KEYWORD },
{ "CONSISTENT", SYM(CONSISTENT_SYM), TOK_KEYWORD },
{ "CONSTRAINT", SYM(CONSTRAINT), TOK_RESERVE },
{ "CONSTRAINT_CATALOG", SYM(CONSTRAINT_CATALOG_SYM), TOK_KEYWORD },
{ "CONSTRAINT_NAME", SYM(CONSTRAINT_NAME_SYM), TOK_KEYWORD },
{ "CONSTRAINT_SCHEMA", SYM(CONSTRAINT_SCHEMA_SYM), TOK_KEYWORD },
{ "CONTAINS", SYM(CONTAINS_SYM), TOK_KEYWORD },
{ "CONTEXT", SYM(CONTEXT_SYM), TOK_KEYWORD },
{ "CONTINUE", SYM(CONTINUE_SYM), TOK_RESERVE },
{ "CONVERT", SYM(CONVERT_SYM), TOK_RESERVE },
{ "CPU", SYM(CPU_SYM), TOK_KEYWORD },
{ "CREATE", SYM(CREATE), TOK_RESERVE },
{ "CROSS", SYM(CROSS), TOK_RESERVE },
{ "CUBE", SYM(CUBE_SYM), TOK_KEYWORD },
{ "CURRENT", SYM(CURRENT_SYM), TOK_KEYWORD },
{ "CURRENT_DATE", SYM(CURDATE), TOK_RESERVE },
{ "CURRENT_TIME", SYM(CURTIME), TOK_RESERVE },
{ "CURRENT_TIMESTAMP", SYM(NOW_SYM), TOK_RESERVE },
{ "CURRENT_USER", SYM(CURRENT_USER), TOK_RESERVE },
{ "CURSOR", SYM(CURSOR_SYM), TOK_RESERVE },
{ "CURSOR_NAME", SYM(CURSOR_NAME_SYM), TOK_KEYWORD },
{ "COLLECTOR", SYM(COLLECTOR_SYM), TOK_RESERVE },
{ "DATA", SYM(DATA_SYM), TOK_KEYWORD },
{ "DATACENTER", SYM(DATACENTER_SYM), TOK_RESERVE },
{ "DATABASE", SYM(DATABASE), TOK_RESERVE },
{ "DATABASES", SYM(DATABASES), TOK_RESERVE },
{ "DATAFILE", SYM(DATAFILE_SYM), TOK_KEYWORD },
{ "DATE", SYM(DATE_SYM), TOK_KEYWORD },
{ "DATETIME", SYM(DATETIME), TOK_KEYWORD },
{ "DAY", SYM(DAY_SYM), TOK_KEYWORD },
{ "DAY_HOUR", SYM(DAY_HOUR_SYM), TOK_RESERVE },
{ "DAY_MICROSECOND", SYM(DAY_MICROSECOND_SYM), TOK_RESERVE },
{ "DAY_MINUTE", SYM(DAY_MINUTE_SYM), TOK_RESERVE },
{ "DAY_SECOND", SYM(DAY_SECOND_SYM), TOK_RESERVE },
{ "DEALLOCATE", SYM(DEALLOCATE_SYM), TOK_KEYWORD },
{ "DEC", SYM(DECIMAL_SYM), TOK_RESERVE },
{ "DECIMAL", SYM(DECIMAL_SYM), TOK_RESERVE },
{ "DECLARE", SYM(DECLARE_SYM), TOK_RESERVE },
{ "DEFAULT", SYM(DEFAULT), TOK_RESERVE },
{ "DEFAULT_AUTH", SYM(DEFAULT_AUTH_SYM), TOK_KEYWORD },
{ "DEFINER", SYM(DEFINER_SYM), TOK_KEYWORD },
{ "DELAYED", SYM(DELAYED_SYM), TOK_RESERVE },
{ "DELAY_KEY_WRITE", SYM(DELAY_KEY_WRITE_SYM), TOK_KEYWORD },
{ "DELETE", SYM(DELETE_SYM), TOK_RESERVE },
{ "DESC", SYM(DESC), TOK_RESERVE },
{ "DESCRIBE", SYM(DESCRIBE), TOK_RESERVE },
{ "DES_KEY_FILE", SYM(DES_KEY_FILE), TOK_KEYWORD },
{ "DETERMINISTIC", SYM(DETERMINISTIC_SYM), TOK_RESERVE },
{ "DIAGNOSTICS", SYM(DIAGNOSTICS_SYM), TOK_KEYWORD },
{ "DIRECTORY", SYM(DIRECTORY_SYM), TOK_KEYWORD },
{ "DISABLE", SYM(DISABLE_SYM), TOK_KEYWORD },
{ "DISCARD", SYM(DISCARD), TOK_KEYWORD },
{ "DISK", SYM(DISK_SYM), TOK_KEYWORD },
{ "DISTINCT", SYM(DISTINCT), TOK_RESERVE },
{ "DISTINCTROW", SYM(DISTINCT), TOK_RESERVE },
{ "DIV", SYM(DIV_SYM), TOK_RESERVE },
{ "DO", SYM(DO_SYM), TOK_KEYWORD },
{ "DOUBLE", SYM(DOUBLE_SYM), TOK_RESERVE },
{ "DROP", SYM(DROP), TOK_RESERVE },
{ "DUAL", SYM(DUAL_SYM), TOK_RESERVE },
{ "DUMPFILE", SYM(DUMPFILE), TOK_KEYWORD },
{ "DUPLICATE", SYM(DUPLICATE_SYM), TOK_KEYWORD },
{ "DYNAMIC", SYM(DYNAMIC_SYM), TOK_KEYWORD },
{ "EACH", SYM(EACH_SYM), TOK_RESERVE },
{ "ELSE", SYM(ELSE), TOK_RESERVE },
{ "ELSEIF", SYM(ELSEIF_SYM), TOK_RESERVE },
{ "ENABLE", SYM(ENABLE_SYM), TOK_KEYWORD },
{ "ENCLOSED", SYM(ENCLOSED), TOK_RESERVE },
{ "END", SYM(END), TOK_KEYWORD },
{ "ENDS", SYM(ENDS_SYM), TOK_KEYWORD },
{ "ENGINE", SYM(ENGINE_SYM), TOK_KEYWORD },
{ "ENGINES", SYM(ENGINES_SYM), TOK_KEYWORD },
{ "ENUM", SYM(ENUM), TOK_KEYWORD },
{ "ERROR", SYM(ERROR_SYM), TOK_KEYWORD },
{ "ERRORS", SYM(ERRORS), TOK_KEYWORD },
{ "ESCAPE", SYM(ESCAPE_SYM), TOK_KEYWORD },
{ "ESCAPED", SYM(ESCAPED), TOK_RESERVE },
{ "EVENT", SYM(EVENT_SYM), TOK_KEYWORD },
{ "EVENTS", SYM(EVENTS_SYM), TOK_KEYWORD },
{ "EVERY", SYM(EVERY_SYM), TOK_KEYWORD },
{ "EXCHANGE", SYM(EXCHANGE_SYM), TOK_KEYWORD },
{ "EXECUTE", SYM(EXECUTE_SYM), TOK_KEYWORD },
{ "EXISTS", SYM(EXISTS), TOK_RESERVE },
{ "EXIT", SYM(EXIT_SYM), TOK_RESERVE },
{ "EXPANSION", SYM(EXPANSION_SYM), TOK_KEYWORD },
{ "EXPORT", SYM(EXPORT_SYM), TOK_KEYWORD },
{ "EXPIRE", SYM(EXPIRE_SYM), TOK_KEYWORD },
{ "EXPLAIN", SYM(DESCRIBE), TOK_RESERVE },
{ "EXTENDED", SYM(EXTENDED_SYM), TOK_KEYWORD },
{ "EXTENT_SIZE", SYM(EXTENT_SIZE_SYM), TOK_KEYWORD },
{ "FALSE", SYM(FALSE_SYM), TOK_RESERVE },
{ "FAST", SYM(FAST_SYM), TOK_KEYWORD },
{ "FAULTS", SYM(FAULTS_SYM), TOK_KEYWORD },
{ "FETCH", SYM(FETCH_SYM), TOK_RESERVE },
{ "FIELDS", SYM(COLUMNS), TOK_KEYWORD },
{ "FILE", SYM(FILE_SYM), TOK_KEYWORD },
{ "FIRST", SYM(FIRST_SYM), TOK_KEYWORD },
{ "FIXED", SYM(FIXED_SYM), TOK_KEYWORD },
{ "FLOAT", SYM(FLOAT_SYM), TOK_RESERVE },
{ "FLOAT4", SYM(FLOAT_SYM), TOK_RESERVE },
{ "FLOAT8", SYM(DOUBLE_SYM), TOK_RESERVE },
{ "FLUSH", SYM(FLUSH_SYM), TOK_KEYWORD },
{ "FOR", SYM(FOR_SYM), TOK_RESERVE },
{ "FORCE", SYM(FORCE_SYM), TOK_RESERVE },
{ "FOREIGN", SYM(FOREIGN), TOK_RESERVE },
{ "FORMAT", SYM(FORMAT_SYM), TOK_KEYWORD },
{ "FOUND", SYM(FOUND_SYM), TOK_KEYWORD },
{ "FROM", SYM(FROM), TOK_RESERVE },
{ "FULL", SYM(FULL), TOK_KEYWORD },
{ "FULLTEXT", SYM(FULLTEXT_SYM), TOK_RESERVE },
{ "FUNCTION", SYM(FUNCTION_SYM), TOK_KEYWORD },
{ "GENERAL", SYM(GENERAL), TOK_KEYWORD },
{ "GEOMETRY", SYM(GEOMETRY_SYM), TOK_KEYWORD },
{ "GEOMETRYCOLLECTION", SYM(GEOMETRYCOLLECTION), TOK_KEYWORD },
{ "GET_FORMAT", SYM(GET_FORMAT), TOK_KEYWORD },
{ "GET", SYM(GET_SYM), TOK_RESERVE },
{ "GLOBAL", SYM(GLOBAL_SYM), TOK_KEYWORD },
{ "GRANT", SYM(GRANT), TOK_RESERVE },
{ "GRANTS", SYM(GRANTS), TOK_KEYWORD },
{ "GROUP", SYM(GROUP_SYM), TOK_RESERVE },
{ "HANDLER", SYM(HANDLER_SYM), TOK_KEYWORD },
{ "HASH", SYM(HASH_SYM), TOK_KEYWORD },
{ "HAVING", SYM(HAVING), TOK_RESERVE },
{ "HELP", SYM(HELP_SYM), TOK_KEYWORD },
{ "HIGH_PRIORITY", SYM(HIGH_PRIORITY), TOK_RESERVE },
{ "HOST", SYM(HOST_SYM), TOK_KEYWORD },
{ "HOSTS", SYM(HOSTS_SYM), TOK_KEYWORD },
{ "HOUR", SYM(HOUR_SYM), TOK_KEYWORD },
{ "HOUR_MICROSECOND", SYM(HOUR_MICROSECOND_SYM), TOK_RESERVE },
{ "HOUR_MINUTE", SYM(HOUR_MINUTE_SYM), TOK_RESERVE },
{ "HOUR_SECOND", SYM(HOUR_SECOND_SYM), TOK_RESERVE },
{ "IDENTIFIED", SYM(IDENTIFIED_SYM), TOK_KEYWORD },
{ "IF", SYM(IF), TOK_RESERVE },
{ "IGNORE", SYM(IGNORE_SYM), TOK_RESERVE },
{ "IGNORE_SERVER_IDS", SYM(IGNORE_SERVER_IDS_SYM), TOK_KEYWORD },
{ "IMPORT", SYM(IMPORT), TOK_KEYWORD },
{ "IN", SYM(IN_SYM), TOK_RESERVE },
{ "INDEX", SYM(INDEX_SYM), TOK_RESERVE },
{ "INDEXES", SYM(INDEXES), TOK_KEYWORD },
{ "INFILE", SYM(INFILE), TOK_RESERVE },
{ "INITIAL_SIZE", SYM(INITIAL_SIZE_SYM), TOK_KEYWORD },
{ "INNER", SYM(INNER_SYM), TOK_RESERVE },
{ "INOUT", SYM(INOUT_SYM), TOK_RESERVE },
{ "INSENSITIVE", SYM(INSENSITIVE_SYM), TOK_RESERVE },
{ "INSERT", SYM(INSERT), TOK_RESERVE },
{ "INSERT_METHOD", SYM(INSERT_METHOD), TOK_KEYWORD },
{ "INSTALL", SYM(INSTALL_SYM), TOK_KEYWORD },
{ "INSTANCE", SYM(INSTANCE_SYM), TOK_RESERVE },
{ "INT", SYM(INT_SYM), TOK_RESERVE },
{ "INT1", SYM(TINYINT), TOK_RESERVE },
{ "INT2", SYM(SMALLINT), TOK_RESERVE },
{ "INT3", SYM(MEDIUMINT), TOK_RESERVE },
{ "INT4", SYM(INT_SYM), TOK_RESERVE },
{ "INT8", SYM(BIGINT), TOK_RESERVE },
{ "INTEGER", SYM(INT_SYM), TOK_RESERVE },
{ "INTERVAL", SYM(INTERVAL_SYM), TOK_RESERVE },
{ "INTO", SYM(INTO), TOK_RESERVE },
{ "IO", SYM(IO_SYM), TOK_KEYWORD },
{ "IO_AFTER_GTIDS", SYM(IO_AFTER_GTIDS), TOK_RESERVE },
{ "IO_BEFORE_GTIDS", SYM(IO_BEFORE_GTIDS), TOK_RESERVE },
{ "IO_THREAD", SYM(RELAY_THREAD), TOK_KEYWORD },
{ "IPC", SYM(IPC_SYM), TOK_KEYWORD },
{ "IS", SYM(IS), TOK_RESERVE },
{ "ISOLATION", SYM(ISOLATION), TOK_KEYWORD },
{ "ISSUER", SYM(ISSUER_SYM), TOK_KEYWORD },
{ "ITERATE", SYM(ITERATE_SYM), TOK_RESERVE },
{ "INVOKER", SYM(INVOKER_SYM), TOK_KEYWORD },
{ "JOIN", SYM(JOIN_SYM), TOK_RESERVE },
{ "JSON", SYM(JSON_SYM), TOK_RESERVE },
{ "KEY", SYM(KEY_SYM), TOK_RESERVE },
{ "KEYS", SYM(KEYS), TOK_RESERVE },
{ "KEY_BLOCK_SIZE", SYM(KEY_BLOCK_SIZE), TOK_KEYWORD },
{ "KILL", SYM(KILL_SYM), TOK_RESERVE },
{ "LANGUAGE", SYM(LANGUAGE_SYM), TOK_KEYWORD },
{ "LAST", SYM(LAST_SYM), TOK_KEYWORD },
{ "LEADING", SYM(LEADING), TOK_RESERVE },
{ "LEAVE", SYM(LEAVE_SYM), TOK_RESERVE },
{ "LEAVES", SYM(LEAVES), TOK_KEYWORD },
{ "LEFT", SYM(LEFT), TOK_RESERVE },
{ "LESS", SYM(LESS_SYM), TOK_KEYWORD },
{ "LEVEL", SYM(LEVEL_SYM), TOK_KEYWORD },
{ "LIKE", SYM(LIKE), TOK_RESERVE },
{ "LIMIT", SYM(LIMIT), TOK_RESERVE },
{ "LINEAR", SYM(LINEAR_SYM), TOK_RESERVE },
{ "LINES", SYM(LINES), TOK_RESERVE },
{ "LINESTRING", SYM(LINESTRING), TOK_KEYWORD },
{ "LIST", SYM(LIST_SYM), TOK_KEYWORD },
{ "LOAD", SYM(LOAD), TOK_RESERVE },
{ "LOCAL", SYM(LOCAL_SYM), TOK_KEYWORD },
{ "LOCALTIME", SYM(NOW_SYM), TOK_RESERVE },
{ "LOCALTIMESTAMP", SYM(NOW_SYM), TOK_RESERVE },
{ "LOCK", SYM(LOCK_SYM), TOK_RESERVE },
{ "LOCKS", SYM(LOCKS_SYM), TOK_KEYWORD },
{ "LOGFILE", SYM(LOGFILE_SYM), TOK_KEYWORD },
{ "LOGS", SYM(LOGS_SYM), TOK_KEYWORD },
{ "LONG", SYM(LONG_SYM), TOK_RESERVE },
{ "LONGBLOB", SYM(LONGBLOB), TOK_RESERVE },
{ "LONGTEXT", SYM(LONGTEXT), TOK_RESERVE },
{ "LOOP", SYM(LOOP_SYM), TOK_RESERVE },
{ "LOW_PRIORITY", SYM(LOW_PRIORITY), TOK_RESERVE },
{ "MASTER", SYM(MASTER_SYM), TOK_KEYWORD },
{ "MASTER_AUTO_POSITION", SYM(MASTER_AUTO_POSITION_SYM), TOK_KEYWORD },
{ "MASTER_BIND", SYM(MASTER_BIND_SYM), TOK_RESERVE },
{ "MASTER_CONNECT_RETRY", SYM(MASTER_CONNECT_RETRY_SYM), TOK_KEYWORD },
{ "MASTER_DELAY", SYM(MASTER_DELAY_SYM), TOK_KEYWORD },
{ "MASTER_HOST", SYM(MASTER_HOST_SYM), TOK_KEYWORD },
{ "MASTER_LOG_FILE", SYM(MASTER_LOG_FILE_SYM), TOK_KEYWORD },
{ "MASTER_LOG_POS", SYM(MASTER_LOG_POS_SYM), TOK_KEYWORD },
{ "MASTER_PASSWORD", SYM(MASTER_PASSWORD_SYM), TOK_KEYWORD },
{ "MASTER_PORT", SYM(MASTER_PORT_SYM), TOK_KEYWORD },
{ "MASTER_RETRY_COUNT", SYM(MASTER_RETRY_COUNT_SYM), TOK_KEYWORD },
{ "MASTER_SERVER_ID", SYM(MASTER_SERVER_ID_SYM), TOK_KEYWORD },
{ "MASTER_SSL", SYM(MASTER_SSL_SYM), TOK_KEYWORD },
{ "MASTER_SSL_CA", SYM(MASTER_SSL_CA_SYM), TOK_KEYWORD },
{ "MASTER_SSL_CAPATH", SYM(MASTER_SSL_CAPATH_SYM), TOK_KEYWORD },
{ "MASTER_SSL_CERT", SYM(MASTER_SSL_CERT_SYM), TOK_KEYWORD },
{ "MASTER_SSL_CIPHER", SYM(MASTER_SSL_CIPHER_SYM), TOK_KEYWORD },
{ "MASTER_SSL_CRL", SYM(MASTER_SSL_CRL_SYM), TOK_KEYWORD },
{ "MASTER_SSL_CRLPATH", SYM(MASTER_SSL_CRLPATH_SYM), TOK_KEYWORD },
{ "MASTER_SSL_KEY", SYM(MASTER_SSL_KEY_SYM), TOK_KEYWORD },
{ "MASTER_SSL_VERIFY_SERVER_CERT", SYM(MASTER_SSL_VERIFY_SERVER_CERT_SYM), TOK_RESERVE },
{ "MASTER_USER", SYM(MASTER_USER_SYM), TOK_KEYWORD },
{ "MASTER_HEARTBEAT_PERIOD", SYM(MASTER_HEARTBEAT_PERIOD_SYM), TOK_KEYWORD },
{ "MATCH", SYM(MATCH), TOK_RESERVE },
{ "MAX_CONNECTIONS_PER_HOUR", SYM(MAX_CONNECTIONS_PER_HOUR), TOK_KEYWORD },
{ "MAX_QUERIES_PER_HOUR", SYM(MAX_QUERIES_PER_HOUR), TOK_KEYWORD },
{ "MAX_ROWS", SYM(MAX_ROWS), TOK_KEYWORD },
{ "MAX_SIZE", SYM(MAX_SIZE_SYM), TOK_KEYWORD },
{ "MAX_UPDATES_PER_HOUR", SYM(MAX_UPDATES_PER_HOUR), TOK_KEYWORD },
{ "MAX_USER_CONNECTIONS", SYM(MAX_USER_CONNECTIONS_SYM), TOK_KEYWORD },
{ "MAXVALUE", SYM(MAX_VALUE_SYM), TOK_RESERVE },
{ "MEDIUM", SYM(MEDIUM_SYM), TOK_KEYWORD },
{ "MEDIUMBLOB", SYM(MEDIUMBLOB), TOK_RESERVE },
{ "MEDIUMINT", SYM(MEDIUMINT), TOK_RESERVE },
{ "MEDIUMTEXT", SYM(MEDIUMTEXT), TOK_RESERVE },
{ "MEMORY", SYM(MEMORY_SYM), TOK_KEYWORD },
{ "MERGE", SYM(MERGE_SYM), TOK_KEYWORD },
{ "MESSAGE_TEXT", SYM(MESSAGE_TEXT_SYM), TOK_KEYWORD },
{ "MICROSECOND", SYM(MICROSECOND_SYM), TOK_KEYWORD },
{ "MIDDLEINT", SYM(MEDIUMINT), TOK_RESERVE },
{ "MIGRATE", SYM(MIGRATE_SYM), TOK_KEYWORD },
{ "MINUTE", SYM(MINUTE_SYM), TOK_KEYWORD },
{ "MINUTE_MICROSECOND", SYM(MINUTE_MICROSECOND_SYM), TOK_RESERVE },
{ "MINUTE_SECOND", SYM(MINUTE_SECOND_SYM), TOK_RESERVE },
{ "MIN_ROWS", SYM(MIN_ROWS), TOK_KEYWORD },
{ "MOD", SYM(MOD_SYM), TOK_RESERVE },
{ "MODE", SYM(MODE_SYM), TOK_KEYWORD },
{ "MODIFIES", SYM(MODIFIES_SYM), TOK_RESERVE },
{ "MODIFY", SYM(MODIFY_SYM), TOK_KEYWORD },
{ "MONTH", SYM(MONTH_SYM), TOK_KEYWORD },
{ "MULTILINESTRING", SYM(MULTILINESTRING), TOK_KEYWORD },
{ "MULTIPOINT", SYM(MULTIPOINT), TOK_KEYWORD },
{ "MULTIPOLYGON", SYM(MULTIPOLYGON), TOK_KEYWORD },
{ "MUTEX", SYM(MUTEX_SYM), TOK_KEYWORD },
{ "MYSQL_ERRNO", SYM(MYSQL_ERRNO_SYM), TOK_KEYWORD },
{ "NAME", SYM(NAME_SYM), TOK_KEYWORD },
{ "NAMES", SYM(NAMES_SYM), TOK_KEYWORD },
{ "NATIONAL", SYM(NATIONAL_SYM), TOK_KEYWORD },
{ "NATURAL", SYM(NATURAL), TOK_RESERVE },
{ "NDB", SYM(NDBCLUSTER_SYM), TOK_KEYWORD },
{ "NDBCLUSTER", SYM(NDBCLUSTER_SYM), TOK_KEYWORD },
{ "NCHAR", SYM(NCHAR_SYM), TOK_KEYWORD },
{ "NEW", SYM(NEW_SYM), TOK_KEYWORD },
{ "NEXT", SYM(NEXT_SYM), TOK_KEYWORD },
{ "NO", SYM(NO_SYM), TOK_KEYWORD },
{ "NO_WAIT", SYM(NO_WAIT_SYM), TOK_KEYWORD },
{ "NODEGROUP", SYM(NODEGROUP_SYM), TOK_KEYWORD },
{ "NONE", SYM(NONE_SYM), TOK_KEYWORD },
{ "NOT", SYM(NOT_SYM), TOK_RESERVE },
{ "NO_WRITE_TO_BINLOG", SYM(NO_WRITE_TO_BINLOG), TOK_RESERVE },
{ "NULL", SYM(NULL_SYM), TOK_RESERVE },
{ "NUMBER", SYM(NUMBER_SYM), TOK_KEYWORD },
{ "NUMERIC", SYM(NUMERIC_SYM), TOK_RESERVE },
{ "NVARCHAR", SYM(NVARCHAR_SYM), TOK_KEYWORD },
{ "OFFSET", SYM(OFFSET_SYM), TOK_KEYWORD },
{ "OLD_PASSWORD", SYM(OLD_PASSWORD), TOK_KEYWORD },
{ "ON", SYM(ON), TOK_RESERVE },
{ "ONE", SYM(ONE_SYM), TOK_KEYWORD },
{ "ONLY", SYM(ONLY_SYM), TOK_KEYWORD },
{ "OPEN", SYM(OPEN_SYM), TOK_KEYWORD },
{ "OPTIMIZE", SYM(OPTIMIZE), TOK_RESERVE },
{ "OPTIONS", SYM(OPTIONS_SYM), TOK_KEYWORD },
{ "OPTION", SYM(OPTION), TOK_RESERVE },
{ "OPTIONALLY", SYM(OPTIONALLY), TOK_RESERVE },
{ "OR", SYM(OR_SYM), TOK_RESERVE },
{ "ORDER", SYM(ORDER_SYM), TOK_RESERVE },
{ "OSC_PERCENT", SYM(OSC_PERCENT_SYM), TOK_RESERVE },
{ "OSC", SYM(OSC_SYM), TOK_RESERVE },
{ "OUT", SYM(OUT_SYM), TOK_RESERVE },
{ "OUTER", SYM(OUTER), TOK_RESERVE },
{ "OUTFILE", SYM(OUTFILE), TOK_RESERVE },
{ "OWNER", SYM(OWNER_SYM), TOK_KEYWORD },
{ "PACK_KEYS", SYM(PACK_KEYS_SYM), TOK_KEYWORD },
{ "PARSER", SYM(PARSER_SYM), TOK_KEYWORD },
{ "PAGE", SYM(PAGE_SYM), TOK_KEYWORD },
{ "PARTIAL", SYM(PARTIAL), TOK_KEYWORD },
{ "PARTITION", SYM(PARTITION_SYM), TOK_RESERVE },
{ "PARTITIONING", SYM(PARTITIONING_SYM), TOK_KEYWORD },
{ "PARTITIONS", SYM(PARTITIONS_SYM), TOK_KEYWORD },
{ "PASSWORD", SYM(PASSWORD), TOK_KEYWORD },
{ "PAUSE", SYM(PAUSE_SYM), TOK_KEYWORD },
{ "PHASE", SYM(PHASE_SYM), TOK_KEYWORD },
{ "PLUGIN", SYM(PLUGIN_SYM), TOK_KEYWORD },
{ "PLUGINS", SYM(PLUGINS_SYM), TOK_KEYWORD },
{ "PLUGIN_DIR", SYM(PLUGIN_DIR_SYM), TOK_KEYWORD },
{ "POINT", SYM(POINT_SYM), TOK_KEYWORD },
{ "POLYGON", SYM(POLYGON), TOK_KEYWORD },
{ "PORT", SYM(PORT_SYM), TOK_KEYWORD },
{ "PRECISION", SYM(PRECISION), TOK_RESERVE },
{ "PREPARE", SYM(PREPARE_SYM), TOK_KEYWORD },
{ "PRESERVE", SYM(PRESERVE_SYM), TOK_KEYWORD },
{ "PREV", SYM(PREV_SYM), TOK_KEYWORD },
{ "PRIMARY", SYM(PRIMARY_SYM), TOK_RESERVE },
{ "PRIVILEGES", SYM(PRIVILEGES), TOK_KEYWORD },
{ "PROCEDURE", SYM(PROCEDURE_SYM), TOK_RESERVE },
{ "PROCESS", SYM(PROCESS), TOK_KEYWORD },
{ "PROCESSLIST", SYM(PROCESSLIST_SYM), TOK_KEYWORD },
{ "PROFILE", SYM(PROFILE_SYM), TOK_KEYWORD },
{ "PROFILES", SYM(PROFILES_SYM), TOK_KEYWORD },
{ "PROXY", SYM(PROXY_SYM), TOK_KEYWORD },
{ "PURGE", SYM(PURGE), TOK_RESERVE },
{ "QUARTER", SYM(QUARTER_SYM), TOK_KEYWORD },
{ "QUERY", SYM(QUERY_SYM), TOK_KEYWORD },
{ "QUICK", SYM(QUICK), TOK_KEYWORD },
{ "RANGE", SYM(RANGE_SYM), TOK_RESERVE },
{ "READ", SYM(READ_SYM), TOK_RESERVE },
{ "READ_ONLY", SYM(READ_ONLY_SYM), TOK_KEYWORD },
{ "READ_WRITE", SYM(READ_WRITE_SYM), TOK_RESERVE },
{ "READS", SYM(READS_SYM), TOK_RESERVE },
{ "REAL", SYM(REAL), TOK_RESERVE },
{ "REBUILD", SYM(REBUILD_SYM), TOK_KEYWORD },
{ "RECOVER", SYM(RECOVER_SYM), TOK_KEYWORD },
{ "REDO_BUFFER_SIZE", SYM(REDO_BUFFER_SIZE_SYM), TOK_KEYWORD },
{ "REDOFILE", SYM(REDOFILE_SYM), TOK_KEYWORD },
{ "REDUNDANT", SYM(REDUNDANT_SYM), TOK_KEYWORD },
{ "REFERENCES", SYM(REFERENCES), TOK_RESERVE },
{ "REGEXP", SYM(REGEXP), TOK_RESERVE },
{ "RELAY", SYM(RELAY), TOK_KEYWORD },
{ "RELAYLOG", SYM(RELAYLOG_SYM), TOK_KEYWORD },
{ "RELAY_LOG_FILE", SYM(RELAY_LOG_FILE_SYM), TOK_KEYWORD },
{ "RELAY_LOG_POS", SYM(RELAY_LOG_POS_SYM), TOK_KEYWORD },
{ "RELAY_THREAD", SYM(RELAY_THREAD), TOK_KEYWORD },
{ "RELEASE", SYM(RELEASE_SYM), TOK_RESERVE },
{ "RELOAD", SYM(RELOAD), TOK_KEYWORD },
{ "REMOVE", SYM(REMOVE_SYM), TOK_KEYWORD },
{ "RENAME", SYM(RENAME), TOK_RESERVE },
{ "REORGANIZE", SYM(REORGANIZE_SYM), TOK_KEYWORD },
{ "REPAIR", SYM(REPAIR), TOK_KEYWORD },
{ "REPEATABLE", SYM(REPEATABLE_SYM), TOK_KEYWORD },
{ "REPLACE", SYM(REPLACE), TOK_RESERVE },
{ "REPLICATION", SYM(REPLICATION), TOK_KEYWORD },
{ "REPEAT", SYM(REPEAT_SYM), TOK_RESERVE },
{ "REQUIRE", SYM(REQUIRE_SYM), TOK_RESERVE },
{ "RESET", SYM(RESET_SYM), TOK_KEYWORD },
{ "RESIGNAL", SYM(RESIGNAL_SYM), TOK_RESERVE },
{ "RESTORE", SYM(RESTORE_SYM), TOK_KEYWORD },
{ "RESTRICT", SYM(RESTRICT), TOK_RESERVE },
{ "RESUME", SYM(RESUME_SYM), TOK_KEYWORD },
{ "RETURNED_SQLSTATE", SYM(RETURNED_SQLSTATE_SYM), TOK_KEYWORD },
{ "RETURN", SYM(RETURN_SYM), TOK_RESERVE },
{ "RETURNS", SYM(RETURNS_SYM), TOK_KEYWORD },
{ "REVERSE", SYM(REVERSE_SYM), TOK_KEYWORD },
{ "REVOKE", SYM(REVOKE), TOK_RESERVE },
{ "RIGHT", SYM(RIGHT), TOK_RESERVE },
{ "RLIKE", SYM(REGEXP), TOK_RESERVE },
{ "ROLLBACK", SYM(ROLLBACK_SYM), TOK_KEYWORD },
{ "ROLLUP", SYM(ROLLUP_SYM), TOK_KEYWORD },
{ "ROUTINE", SYM(ROUTINE_SYM), TOK_KEYWORD },
{ "ROW", SYM(ROW_SYM), TOK_KEYWORD },
{ "ROW_COUNT", SYM(ROW_COUNT_SYM), TOK_KEYWORD },
{ "ROWS", SYM(ROWS_SYM), TOK_KEYWORD },
{ "ROW_FORMAT", SYM(ROW_FORMAT_SYM), TOK_KEYWORD },
{ "RTREE", SYM(RTREE_SYM), TOK_KEYWORD },
{ "SAVEPOINT", SYM(SAVEPOINT_SYM), TOK_KEYWORD },
{ "SCHEDULE", SYM(SCHEDULE_SYM), TOK_KEYWORD },
{ "SCHEMA", SYM(DATABASE), TOK_RESERVE },
{ "SCHEMA_NAME", SYM(SCHEMA_NAME_SYM), TOK_KEYWORD },
{ "SCHEMAS", SYM(DATABASES), TOK_RESERVE },
{ "SECOND", SYM(SECOND_SYM), TOK_KEYWORD },
{ "SECOND_MICROSECOND", SYM(SECOND_MICROSECOND_SYM), TOK_RESERVE },
{ "SECURITY", SYM(SECURITY_SYM), TOK_KEYWORD },
{ "SELECT", SYM(SELECT_SYM), TOK_RESERVE },
{ "SENSITIVE", SYM(SENSITIVE_SYM), TOK_RESERVE },
{ "SEPARATOR", SYM(SEPARATOR_SYM), TOK_RESERVE },
{ "SERIAL", SYM(SERIAL_SYM), TOK_KEYWORD },
{ "SERIALIZABLE", SYM(SERIALIZABLE_SYM), TOK_KEYWORD },
{ "SESSION", SYM(SESSION_SYM), TOK_KEYWORD },
{ "SERVER", SYM(SERVER_SYM), TOK_KEYWORD },
{ "SET", SYM(SET), TOK_RESERVE },
{ "SHARE", SYM(SHARE_SYM), TOK_KEYWORD },
{ "SHOW", SYM(SHOW), TOK_RESERVE },
{ "SHUTDOWN", SYM(SHUTDOWN), TOK_KEYWORD },
{ "SIGNAL", SYM(SIGNAL_SYM), TOK_RESERVE },
{ "SIGNED", SYM(SIGNED_SYM), TOK_KEYWORD },
{ "SIMPLE", SYM(SIMPLE_SYM), TOK_KEYWORD },
{ "SLAVE", SYM(SLAVE), TOK_KEYWORD },
{ "SLOW", SYM(SLOW), TOK_KEYWORD },
{ "SNAPSHOT", SYM(SNAPSHOT_SYM), TOK_KEYWORD },
{ "SMALLINT", SYM(SMALLINT), TOK_RESERVE },
{ "SOCKET", SYM(SOCKET_SYM), TOK_KEYWORD },
{ "SOME", SYM(ANY_SYM), TOK_KEYWORD },
{ "SONAME", SYM(SONAME_SYM), TOK_KEYWORD },
{ "SOUNDS", SYM(SOUNDS_SYM), TOK_KEYWORD },
{ "SOURCE", SYM(SOURCE_SYM), TOK_KEYWORD },
{ "SPATIAL", SYM(SPATIAL_SYM), TOK_RESERVE },
{ "SPECIFIC", SYM(SPECIFIC_SYM), TOK_RESERVE },
{ "SQL", SYM(SQL_SYM), TOK_RESERVE },
{ "SQLEXCEPTION", SYM(SQLEXCEPTION_SYM), TOK_RESERVE },
{ "SQLSTATE", SYM(SQLSTATE_SYM), TOK_RESERVE },
{ "SQLWARNING", SYM(SQLWARNING_SYM), TOK_RESERVE },
{ "SQL_AFTER_GTIDS", SYM(SQL_AFTER_GTIDS), TOK_KEYWORD },
{ "SQL_AFTER_MTS_GAPS", SYM(SQL_AFTER_MTS_GAPS), TOK_KEYWORD },
{ "SQL_BEFORE_GTIDS", SYM(SQL_BEFORE_GTIDS), TOK_KEYWORD },
{ "SQL_BIG_RESULT", SYM(SQL_BIG_RESULT), TOK_RESERVE },
{ "SQL_BUFFER_RESULT", SYM(SQL_BUFFER_RESULT), TOK_KEYWORD },
{ "SQL_CACHE", SYM(SQL_CACHE_SYM), TOK_KEYWORD },
{ "SQL_CALC_FOUND_ROWS", SYM(SQL_CALC_FOUND_ROWS), TOK_RESERVE },
{ "SQL_NO_CACHE", SYM(SQL_NO_CACHE_SYM), TOK_KEYWORD },
{ "SQL_SMALL_RESULT", SYM(SQL_SMALL_RESULT), TOK_RESERVE },
{ "SQL_THREAD", SYM(SQL_THREAD), TOK_KEYWORD },
{ "SQL_TSI_SECOND", SYM(SECOND_SYM), TOK_KEYWORD },
{ "SQL_TSI_MINUTE", SYM(MINUTE_SYM), TOK_KEYWORD },
{ "SQL_TSI_HOUR", SYM(HOUR_SYM), TOK_KEYWORD },
{ "SQL_TSI_DAY", SYM(DAY_SYM), TOK_KEYWORD },
{ "SQL_TSI_WEEK", SYM(WEEK_SYM), TOK_KEYWORD },
{ "SQL_TSI_MONTH", SYM(MONTH_SYM), TOK_KEYWORD },
{ "SQL_TSI_QUARTER", SYM(QUARTER_SYM), TOK_KEYWORD },
{ "SQL_TSI_YEAR", SYM(YEAR_SYM), TOK_KEYWORD },
{ "SSL", SYM(SSL_SYM), TOK_RESERVE },
{ "START", SYM(START_SYM), TOK_KEYWORD },
{ "STARTING", SYM(STARTING), TOK_RESERVE },
{ "STARTS", SYM(STARTS_SYM), TOK_KEYWORD },
{ "STATS_AUTO_RECALC", SYM(STATS_AUTO_RECALC_SYM), TOK_KEYWORD },
{ "STATS_PERSISTENT", SYM(STATS_PERSISTENT_SYM), TOK_KEYWORD },
{ "STATS_SAMPLE_PAGES", SYM(STATS_SAMPLE_PAGES_SYM), TOK_KEYWORD },
{ "STATUS", SYM(STATUS_SYM), TOK_KEYWORD },
{ "STOP", SYM(STOP_SYM), TOK_KEYWORD },
{ "STORAGE", SYM(STORAGE_SYM), TOK_KEYWORD },
{ "STRAIGHT_JOIN", SYM(STRAIGHT_JOIN), TOK_RESERVE },
{ "STRING", SYM(STRING_SYM), TOK_KEYWORD },
{ "SUBCLASS_ORIGIN", SYM(SUBCLASS_ORIGIN_SYM), TOK_KEYWORD },
{ "SUBJECT", SYM(SUBJECT_SYM), TOK_KEYWORD },
{ "SUBPARTITION", SYM(SUBPARTITION_SYM), TOK_KEYWORD },
{ "SUBPARTITIONS", SYM(SUBPARTITIONS_SYM), TOK_KEYWORD },
{ "SUPER", SYM(SUPER_SYM), TOK_KEYWORD },
{ "SUSPEND", SYM(SUSPEND_SYM), TOK_KEYWORD },
{ "SWAPS", SYM(SWAPS_SYM), TOK_KEYWORD },
{ "SWITCHES", SYM(SWITCHES_SYM), TOK_KEYWORD },
{ "TABLE", SYM(TABLE_SYM), TOK_RESERVE },
{ "TABLE_NAME", SYM(TABLE_NAME_SYM), TOK_KEYWORD },
{ "TABLES", SYM(TABLES), TOK_KEYWORD },
{ "TABLESPACE", SYM(TABLESPACE), TOK_KEYWORD },
{ "TABLE_CHECKSUM", SYM(TABLE_CHECKSUM_SYM), TOK_KEYWORD },
{ "TEMPORARY", SYM(TEMPORARY), TOK_KEYWORD },
{ "TEMPTABLE", SYM(TEMPTABLE_SYM), TOK_KEYWORD },
{ "TERMINATED", SYM(TERMINATED), TOK_RESERVE },
{ "TEXT", SYM(TEXT_SYM), TOK_KEYWORD },
{ "THAN", SYM(THAN_SYM), TOK_KEYWORD },
{ "THEN", SYM(THEN_SYM), TOK_RESERVE },
{ "THREADS", SYM(THREADS_SYM), TOK_RESERVE },
{ "TIME", SYM(TIME_SYM), TOK_KEYWORD },
{ "TIMESTAMP", SYM(TIMESTAMP), TOK_KEYWORD },
{ "TIMESTAMPADD", SYM(TIMESTAMP_ADD), TOK_KEYWORD },
{ "TIMESTAMPDIFF", SYM(TIMESTAMP_DIFF), TOK_KEYWORD },
{ "TINYBLOB", SYM(TINYBLOB), TOK_RESERVE },
{ "TINYINT", SYM(TINYINT), TOK_RESERVE },
{ "TINYTEXT", SYM(TINYTEXT), TOK_RESERVE },
{ "TO", SYM(TO_SYM), TOK_RESERVE },
{ "TRAILING", SYM(TRAILING), TOK_RESERVE },
{ "TRANSACTION", SYM(TRANSACTION_SYM), TOK_KEYWORD },
{ "TRANSFER", SYM(TRANSFER_SYM), TOK_RESERVE },
{ "TRIGGER", SYM(TRIGGER_SYM), TOK_RESERVE },
{ "TRIGGERS", SYM(TRIGGERS_SYM), TOK_KEYWORD },
{ "TRUE", SYM(TRUE_SYM), TOK_RESERVE },
{ "TRUNCATE", SYM(TRUNCATE_SYM), TOK_KEYWORD },
{ "TYPE", SYM(TYPE_SYM), TOK_KEYWORD },
{ "TYPES", SYM(TYPES_SYM), TOK_KEYWORD },
{ "UNCOMMITTED", SYM(UNCOMMITTED_SYM), TOK_KEYWORD },
{ "UNDEFINED", SYM(UNDEFINED_SYM), TOK_KEYWORD },
{ "UNDO_BUFFER_SIZE", SYM(UNDO_BUFFER_SIZE_SYM), TOK_KEYWORD },
{ "UNDOFILE", SYM(UNDOFILE_SYM), TOK_KEYWORD },
{ "UNDO", SYM(UNDO_SYM), TOK_RESERVE },
{ "UNICODE", SYM(UNICODE_SYM), TOK_KEYWORD },
{ "UNION", SYM(UNION_SYM), TOK_RESERVE },
{ "UNIQUE", SYM(UNIQUE_SYM), TOK_RESERVE },
{ "UNKNOWN", SYM(UNKNOWN_SYM), TOK_KEYWORD },
{ "UNLOCK", SYM(UNLOCK_SYM), TOK_RESERVE },
{ "UNINSTALL", SYM(UNINSTALL_SYM), TOK_KEYWORD },
{ "UNSIGNED", SYM(UNSIGNED), TOK_RESERVE },
{ "UNTIL", SYM(UNTIL_SYM), TOK_KEYWORD },
{ "UPDATE", SYM(UPDATE_SYM), TOK_RESERVE },
{ "UPGRADE", SYM(UPGRADE_SYM), TOK_KEYWORD },
{ "USAGE", SYM(USAGE), TOK_RESERVE },
{ "USE", SYM(USE_SYM), TOK_RESERVE },
{ "USER", SYM(USER), TOK_KEYWORD },
{ "USER_RESOURCES", SYM(RESOURCES), TOK_KEYWORD },
{ "USE_FRM", SYM(USE_FRM), TOK_KEYWORD },
{ "USING", SYM(USING), TOK_RESERVE },
{ "UTC_DATE", SYM(UTC_DATE_SYM), TOK_RESERVE },
{ "UTC_TIME", SYM(UTC_TIME_SYM), TOK_RESERVE },
{ "UTC_TIMESTAMP", SYM(UTC_TIMESTAMP_SYM), TOK_RESERVE },
{ "VALUE", SYM(VALUE_SYM), TOK_KEYWORD },
{ "VALUES", SYM(VALUES), TOK_RESERVE },
{ "VARBINARY", SYM(VARBINARY), TOK_RESERVE },
{ "VARCHAR", SYM(VARCHAR), TOK_RESERVE },
{ "VARCHARACTER", SYM(VARCHAR), TOK_RESERVE },
{ "VARIABLES", SYM(VARIABLES), TOK_KEYWORD },
{ "VARYING", SYM(VARYING), TOK_RESERVE },
{ "WAIT", SYM(WAIT_SYM), TOK_KEYWORD },
{ "WARNINGS", SYM(WARNINGS), TOK_KEYWORD },
{ "WEEK", SYM(WEEK_SYM), TOK_KEYWORD },
{ "WEIGHT_STRING", SYM(WEIGHT_STRING_SYM), TOK_KEYWORD },
{ "WHEN", SYM(WHEN_SYM), TOK_RESERVE },
{ "WHERE", SYM(WHERE), TOK_RESERVE },
{ "WHILE", SYM(WHILE_SYM), TOK_RESERVE },
{ "VIEW", SYM(VIEW_SYM), TOK_KEYWORD },
{ "WITH", SYM(WITH), TOK_RESERVE },
{ "WORK", SYM(WORK_SYM), TOK_KEYWORD },
{ "WRAPPER", SYM(WRAPPER_SYM), TOK_KEYWORD },
{ "WRITE", SYM(WRITE_SYM), TOK_RESERVE },
{ "X509", SYM(X509_SYM), TOK_KEYWORD },
{ "XOR", SYM(XOR), TOK_RESERVE },
{ "XA", SYM(XA_SYM), TOK_KEYWORD },
{ "XML", SYM(XML_SYM), TOK_KEYWORD },
{ "YEAR", SYM(YEAR_SYM), TOK_KEYWORD },
{ "YEAR_MONTH", SYM(YEAR_MONTH_SYM), TOK_RESERVE },
{ "ZEROFILL", SYM(ZEROFILL), TOK_RESERVE },
{ "||", SYM(OR_OR_SYM), TOK_RESERVE },
};

static SYMBOL sql_functions[] = {
  { "ADDDATE",		SYM(ADDDATE_SYM), TOK_KEYWORD},
  { "BIT_AND",		SYM(BIT_AND), TOK_KEYWORD},
  { "BIT_OR",		SYM(BIT_OR), TOK_KEYWORD},
  { "BIT_XOR",		SYM(BIT_XOR), TOK_KEYWORD},
  { "CAST",		SYM(CAST_SYM), TOK_KEYWORD},
  { "COUNT",		SYM(COUNT_SYM), TOK_KEYWORD},
  { "CURDATE",		SYM(CURDATE), TOK_KEYWORD},
  { "CURTIME",		SYM(CURTIME), TOK_KEYWORD},
  { "DATE_ADD",		SYM(DATE_ADD_INTERVAL), TOK_KEYWORD},
  { "DATE_SUB",		SYM(DATE_SUB_INTERVAL), TOK_KEYWORD},
  { "EXTRACT",		SYM(EXTRACT_SYM), TOK_KEYWORD},
  { "GROUP_CONCAT",	SYM(GROUP_CONCAT_SYM), TOK_KEYWORD},
  { "MAX",		SYM(MAX_SYM), TOK_KEYWORD},
  { "MID",		SYM(SUBSTRING), TOK_KEYWORD},	/* unireg function */
  { "MIN",		SYM(MIN_SYM), TOK_KEYWORD},
  { "NOW",		SYM(NOW_SYM), TOK_KEYWORD},
  { "POSITION",		SYM(POSITION_SYM), TOK_KEYWORD},
  { "SESSION_USER",     SYM(USER), TOK_KEYWORD},
  { "STD",		SYM(STD_SYM), TOK_KEYWORD},
  { "STDDEV",		SYM(STD_SYM), TOK_KEYWORD},
  { "STDDEV_POP",	SYM(STD_SYM), TOK_KEYWORD},
  { "STDDEV_SAMP",	SYM(STDDEV_SAMP_SYM), TOK_KEYWORD},
  { "SUBDATE",		SYM(SUBDATE_SYM), TOK_KEYWORD},
  { "SUBSTR",		SYM(SUBSTRING), TOK_KEYWORD},
  { "SUBSTRING",	SYM(SUBSTRING), TOK_KEYWORD},
  { "SUM",		SYM(SUM_SYM), TOK_KEYWORD},
  { "SYSDATE",		SYM(SYSDATE), TOK_KEYWORD},
  { "SYSTEM_USER",      SYM(USER), TOK_KEYWORD},
  { "TRIM",		SYM(TRIM), TOK_KEYWORD},
  { "VARIANCE",		SYM(VARIANCE_SYM), TOK_KEYWORD},
  { "VAR_POP",		SYM(VARIANCE_SYM), TOK_KEYWORD},
  { "VAR_SAMP",		SYM(VAR_SAMP_SYM), TOK_KEYWORD},
};

#endif /* LEX_INCLUDED */
