/*
 * libccon - Utilities for ccon (shared between ccon and ccon-cli)
 * Copyright (C) 2016 W. Trevor King <wking@tremily.us>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _libccon_h
#define _libccon_h

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>

#define CCON_VERSION "0.4.0"
#define MAX_PATH 1024

/* client messages passed through the --socket */
#define CLIENT_MESSAGE_SIZE 1024

/* logging */
extern int verbose;
extern int log_fd;
#define LOG(...) do {if (verbose && log_fd >= 0) {dprintf(log_fd, __VA_ARGS__);}} while(0)
#define PERROR(s) do {LOG("%s: %s\n", s, strerror(errno));} while(0)

extern int get_host_exec_fd(json_t * process, int *exec_fd);
extern int open_in_path(const char *name, int flags);
extern int sendfd(int socket, int *fd, int close_fd);
extern int recvfd(int socket, int *fd);

#endif				/* _libccon_h */
