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

#define _GNU_SOURCE
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <jansson.h>
#include "libccon.h"

int verbose = 0;
int log_fd = STDERR_FILENO;
#define LOG(...) do {if (verbose && log_fd >= 0) {dprintf(log_fd, __VA_ARGS__);}} while(0)
#define PERROR(s) do {LOG("%s: %s\n", s, strerror(errno));} while(0)

int get_host_exec_fd(json_t * process, int *exec_fd)
{
	json_t *v1, *v2;
	const char *arg0;

	*exec_fd = -1;

	v1 = json_object_get(process, "host");
	if (!v1 || !json_boolean_value(v1)) {
		return 0;
	}

	v1 = json_object_get(process, "path");
	if (v1) {
		arg0 = json_string_value(v1);
		if (!arg0) {
			LOG("failed to extract process.path\n");
			return -1;
		}
	} else {
		v1 = json_object_get(process, "args");
		if (!v1) {
			return 0;
		}
		v2 = json_array_get(v1, 0);
		if (!v2) {
			LOG("failed to extract process.args[0]\n");
			return -1;
		}
		arg0 = json_string_value(v2);
		if (!arg0) {
			LOG("failed to extract process.args[0]\n");
			return -1;
		}
	}

	*exec_fd = open_in_path(arg0, O_PATH | O_CLOEXEC);
	if (*exec_fd == -1) {
		return -1;
	}

	return 0;
}

int open_in_path(const char *name, int flags)
{
	const char *p;
	char *paths = NULL, *paths2, *path;
	size_t i;
	int fd;

	if (name[0] == '/') {
		LOG("open container-process executable from host %s\n", name);
		fd = open(name, flags);
		if (fd == -1) {
			PERROR("open");
			return -1;
		}
		return fd;
	}

	path = malloc(sizeof(char) * MAX_PATH);
	if (!path) {
		PERROR("malloc");
		return -1;
	}
	memset(path, 0, sizeof(char) * MAX_PATH);

	p = strchr(name, '/');
	if (p) {
		if (!getcwd(path, MAX_PATH)) {
			PERROR("getcwd");
			goto cleanup;
		}
		i = strlen(path);
		if (i + strlen(name) + 2 > MAX_PATH) {
			LOG("failed to format relative path (needed a buffer with %d byes)\n", (int)(i + strlen(name) + 2));
			goto cleanup;
		}
		path[i++] = '/';
		strcpy(path + i, name);
		LOG("open container-process executable from host %s\n", path);
		fd = open(path, flags);
		if (fd == -1) {
			PERROR("open");
			return -1;
		}
		free(path);
		return fd;
	}

	paths = getenv("PATH");
	if (!paths) {
		LOG("failed to get host PATH\n");
		goto cleanup;
	}
	paths = strdup(paths);
	if (!paths) {
		PERROR("strdup");
		goto cleanup;
	}

	paths2 = paths;
	while ((p = strtok(paths2, ":"))) {
		paths2 = NULL;
		i = strlen(p);
		if (i + strlen(name) + 2 > MAX_PATH) {
			LOG("failed to format relative path (needed a buffer with %d byes)\n", (int)(i + strlen(name) + 2));
			goto cleanup;
		}
		strcpy(path, p);
		path[i++] = '/';
		strcpy(path + i, name);
		fd = open(path, flags);
		if (fd >= 0) {
			LOG("open container-process executable from host %s\n",
			    path);
			free(path);
			return fd;
		}
	}

	LOG("failed to find %s in the host PATH\n", name);

 cleanup:
	if (paths) {
		free(paths);
	}
	free(path);
	return -1;
}

int sendfd(int socket, int *fd, int close_fd)
{
	struct cmsghdr *cmsg;
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr msg = { 0 };
	int *fdptr;

	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf), cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	fdptr = (int *)CMSG_DATA(cmsg);
	*fdptr = *fd;
	if (sendmsg(socket, &msg, 0) == -1) {
		PERROR("sendmsg");
		return -1;
	}

	if (close_fd) {
		if (close(*fd)) {
			PERROR("close");
			*fd = -1;
			return 1;
		}
		*fd = -1;
	}

	return 0;
}

int recvfd(int socket, int *fd)
{
	struct cmsghdr *cmsg;
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr msg = { 0 };
	int *fdptr;

	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	if (recvmsg(socket, &msg, 0) == -1) {
		PERROR("recvmsg");
		return -1;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS) {
		LOG("unexpected message (no file descriptor)\n");
		return -1;
	}
	fdptr = (int *)CMSG_DATA(cmsg);
	*fd = *fdptr;

	return 0;
}
