/* Copyright (C) 2013 Codership Oy <info@codership.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */

#ifndef WSREP_UTILS_H
#define WSREP_UTILS_H

#include "sql_class.h"

/* A small class to run external programs. */
class string
{
public:
    string() : string_(0) {}
    void set(char* str) { if (string_) free (string_); string_ = str; }
    ~string() { set (0); }
private:
    char* string_;
};

#endif /* WSREP_UTILS_H */
