/* Copyright 2010 Codership Oy <http://www.codership.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

//! @file some utility functions and classes not directly related to replication

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // POSIX_SPAWN_USEVFORK flag
#endif

#include "ptosc.h"

#include <sql_class.h>

#include <spawn.h>    // posix_spawn()
#include <unistd.h>   // pipe()
#include <errno.h>    // errno
#include <string.h>   // strerror()
#include <sys/wait.h> // waitpid()
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>    // getaddrinfo()

extern char** environ; // environment variables

#define PIPE_READ  0
#define PIPE_WRITE 1
#define STDIN_FD   0
#define STDOUT_FD  1

#ifndef POSIX_SPAWN_USEVFORK
# define POSIX_SPAWN_USEVFORK 0
#endif

extern char** environ; // environment variables

void
osc_prepend_PATH (
    const char* path,
    THD* thd, 
    sql_cache_node_t* node)
{
    int count = 0;
    char    errmsg[1024];

    while (environ[count])
    {
        if (strncmp (environ[count], "PATH=", 5))
        {
            count++;
            continue;
        }

        char* const old_path (environ[count]);

        if (strstr (old_path, path)) return; // path already there

        size_t const new_path_len(strlen(old_path) + strlen(":") +
                                  strlen(path) + 1);

        char* const new_path (reinterpret_cast<char*>(malloc(new_path_len)));

        if (new_path)
        {
            snprintf (new_path, new_path_len, "PATH=%s:%s", path,
                      old_path + strlen("PATH="));

            environ[count] = new_path;
        }
        else
        {
            sprintf(errmsg, "Failed to allocate 'PATH' environment variable "
                         "buffer of size %zu.", new_path_len);
            mysql_errmsg_append_without_errno(thd, node, errmsg);
        }

        return;
    }
}

process::process (
    THD* thd_in, 
    sql_cache_node_t* sql_cache_node_in, 
    char** argv,
    const char* type
) : io_(NULL), err_(EINVAL), pid_(0)
{
    char errmsg[5120];

    thd = thd_in;
    sql_cache_node = sql_cache_node_in;
    if (NULL == argv[0])
        return;

    if (NULL == type || (strcmp (type, "w") && strcmp(type, "r")))
    {
        sprintf(errmsg,"type argument should be either \"r\" or \"w\".");
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        return;
    }

    int pipe_fds[2] = { -1, };
    if (::pipe(pipe_fds))
    {
        err_ = errno;
        sprintf(errmsg,"pipe() failed: %d (%s)", err_, strerror(err_));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        return;
    }

    // which end of pipe will be returned to parent
    int const parent_end (strcmp(type,"w") ? PIPE_READ : PIPE_WRITE);
    int const child_end  (parent_end == PIPE_READ ? PIPE_WRITE : PIPE_READ);
    int const close_fd   (parent_end == PIPE_READ ? STDOUT_FD : STDIN_FD);

    posix_spawnattr_t attr;
    err_ = posix_spawnattr_init (&attr);
    if (err_)
    {
        sprintf(errmsg,"posix_spawnattr_init() failed: %d (%s)",
                     err_, strerror(err_));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        goto cleanup_pipe;
    }

    err_ = posix_spawnattr_setflags (&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_USEVFORK);
    if (err_)
    {
        sprintf(errmsg,"posix_spawnattr_setflags() failed: %d (%s)",
                     err_, strerror(err_));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        goto cleanup_attr;
    }

    posix_spawn_file_actions_t fact;
    err_ = posix_spawn_file_actions_init (&fact);
    if (err_)
    {
        sprintf(errmsg,"posix_spawn_file_actions_init() failed: %d (%s)",
                     err_, strerror(err_));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        goto cleanup_attr;
    }

    // close child's stdout|stdin depending on what we returning
    //需要把错误输出重定向到标准输出中，所以在这里设置一下
    if ((err_ = posix_spawn_file_actions_addclose (&fact, close_fd)) ||
        (err_ = posix_spawn_file_actions_addclose (&fact, 2)))
    {
        sprintf(errmsg,"posix_spawn_file_actions_addclose() failed: %d (%s)",
            err_, strerror(err_));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        goto cleanup_fact;
    }

    // substitute our pipe descriptor in place of the closed one
    //需要把错误输出重定向到标准输出中，所以在这里设置一下
    if ((err_ = posix_spawn_file_actions_adddup2 (&fact, pipe_fds[child_end], close_fd)) ||
        (err_ = posix_spawn_file_actions_adddup2 (&fact, pipe_fds[child_end], 2)))
    {
        sprintf(errmsg,"posix_spawn_file_actions_addup2() failed: %d (%s)",
            err_, strerror(err_));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        goto cleanup_fact;
    }

    err_ = posix_spawnp (&pid_, argv[0], &fact, &attr, argv, environ);
    if (err_)
    {
        sprintf(errmsg,"posix_spawnp(%s) failed: %d (%s)",
                     argv[0], err_, strerror(err_));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        pid_ = 0; // just to make sure it was not messed up in the call
        goto cleanup_fact;
    }

    io_ = fdopen (pipe_fds[parent_end], type);

    if (io_)
    {
        pipe_fds[parent_end] = -1; // skip close on cleanup
    }
    else
    {
        err_ = errno;
        sprintf(errmsg,"fdopen() failed: %d (%s)", err_, strerror(err_));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
    }

cleanup_fact:
    int err; // to preserve err_ code
    err = posix_spawn_file_actions_destroy (&fact);
    if (err)
    {
        sprintf(errmsg,"posix_spawn_file_actions_destroy() failed: %d (%s)\n",
                     err, strerror(err));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
    }

cleanup_attr:
    err = posix_spawnattr_destroy (&attr);
    if (err)
    {
        sprintf(errmsg,"posix_spawnattr_destroy() failed: %d (%s)",
                     err, strerror(err));
        mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
    }

cleanup_pipe:
    if (pipe_fds[0] >= 0) close (pipe_fds[0]);
    if (pipe_fds[1] >= 0) close (pipe_fds[1]);
}

process::~process ()
{
    char errmsg[512];
    if (io_)
    {
        assert (pid_);

        // WSREP_WARN("Closing pipe to child process: %s, PID(%ld) "
        //            "which might still be running.", str_, (long)pid_);

        if (fclose (io_) == -1)
        {
            err_ = errno;
            sprintf(errmsg,"fclose() failed: %d (%s)", err_, strerror(err_));
            mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
        }
    }
}

int
process::wait ()
{
    char errmsg[5120];
    if (pid_)
    {
      int status;
      if (-1 == waitpid(pid_, &status, 0))
      {
          err_ = errno; assert (err_);
          sprintf(errmsg,"Waiting for process failed: %s, PID(%ld): %d (%s)",
                      "pt-online-schema-change", (long)pid_, err_, strerror (err_));
          mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
      }
      else
      {                // command completed, check exit status
          if (WIFEXITED (status)) {
              err_ = WEXITSTATUS (status);
          }
          else {       // command didn't complete with exit()
              sprintf(errmsg,"Process was aborted.");
              mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
              err_ = errno ? errno : ECHILD;
          }

          if (err_) {
              switch (err_) /* Translate error codes to more meaningful */
              {
              case 126: err_ = EACCES; break; /* Permission denied */
              case 127: err_ = ENOENT; break; /* No such file or directory */
              }
              sprintf(errmsg,"Process completed with error: %s: %d (%s)",
                          "pt-online-schema-change", err_, strerror(err_));
              mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
          }

          pid_ = 0;
          if (io_) fclose (io_);
          io_ = NULL;
      }
  }
  else {
      assert (NULL == io_);
      sprintf(errmsg,"Command did not run: %s", "pt-online-schema-change");
      mysql_errmsg_append_without_errno(thd, sql_cache_node, errmsg);
  }

  return err_;
}

int
process::killpid ()
{
    if (pid_)
      kill(pid_, SIGKILL);
}

