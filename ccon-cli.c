/*
 * ccon-cli(1) - Client for the ccon --socket
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <jansson.h>
#include "libccon.h"

static int parse_args(int argc, char **argv, int *get_pid,
		      const char **config_path, const char **config_string,
		      const char **socket_path);
static void usage(FILE * stream, char *path);
static void version();
static char *read_file(const char *path);

int main(int argc, char **argv)
{
	const char *config_path = NULL;
	const char *config_string = NULL;
	const char *socket_path = NULL;
	struct sockaddr_un name;
	struct ucred ucred;
	socklen_t len;
	char buf[CLIENT_MESSAGE_SIZE];
	struct iovec iov = { buf, CLIENT_MESSAGE_SIZE };
	struct msghdr msg = { NULL, 0, &iov, 1, NULL, 0, 0 };
	json_t *process;
	json_error_t error;
	ssize_t n;
	int sock = -1, get_pid = 0, exec_fd = -1;

	if (parse_args
	    (argc, argv, &get_pid, &config_path, &config_string,
	     &socket_path)) {
		return 1;
	}

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock == -1) {
		PERROR("socket");
		return 1;
	}

	memset(&name, 0, sizeof(struct sockaddr_un));
	name.sun_family = AF_UNIX;
	strncpy(name.sun_path, socket_path, sizeof(name.sun_path) - 1);
	LOG("connecting to %s\n", socket_path);
	if (connect
	    (sock, (const struct sockaddr *)&name,
	     sizeof(struct sockaddr_un)) == -1) {
		PERROR("connect");
		return 1;
	}

	if (get_pid) {
		LOG("get peer PID\n");
		if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len) ==
		    -1) {
			PERROR("getsockopt");
			return 1;
		}
		printf("%ld\n", (long)ucred.pid);
	}

	if (config_path) {
		LOG("read configuration from %s\n", config_path);
		config_string = read_file(config_path);
		if (!config_string) {
			return 1;
		}
	}

	if (config_string) {
		if (strlen(config_string) == 0) {
			config_string = "\0";
		} else {
			process =
			    json_loads(config_string, JSON_REJECT_DUPLICATES,
				       &error);
			if (!process) {
				LOG("error on %s:%d:%d: %s\n", config_path,
				    error.line, error.column, error.text);
				return 1;
			}

			if (get_host_exec_fd(process, &exec_fd) == -1) {
				return 1;
			}
		}

		iov.iov_base = (void *)config_string;
		if (config_string[0] == '\0') {
			iov.iov_len = 1;
		} else {
			iov.iov_len = strlen(config_string) + 1;
		}
		if (iov.iov_len > CLIENT_MESSAGE_SIZE) {
			LOG("configuration string is too long for a ccon socket message (%d > %d)\n", (int)iov.iov_len, CLIENT_MESSAGE_SIZE);
			return 1;
		}
		LOG("send start message\n");
		if (sendmsg(sock, &msg, 0) == -1) {
			PERROR("sendmsg");
			return 1;
		}
		if (exec_fd >= 0) {
			if (sendfd(sock, &exec_fd, 1)) {
				return 1;
			}
		}

		iov.iov_base = (void *)buf;
		iov.iov_len = CLIENT_MESSAGE_SIZE;
		LOG("wait for response\n");
		n = recvmsg(sock, &msg, 0);
		if (n == -1) {
			PERROR("recvmsg");
			return 1;
		}
		if (n != 1 || ((char *)iov.iov_base)[0] != '\0') {
			LOG("unexpected message from container (%d): %.*s\n",
			    (int)n, (int)n, (char *)iov.iov_base);
			return 1;
		}
		LOG("received response\n");
	}

	if (config_path) {
		free((void *)config_string);
	}

	return 0;
}

static int parse_args(int argc, char **argv, int *get_pid,
		      const char **config_path, const char **config_string,
		      const char **socket_path)
{
	int c, option_index;
	static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, &verbose, 1},
		{"version", no_argument, NULL, 'v'},
		{"config", required_argument, NULL, 'c'},
		{"config-string", required_argument, NULL, 's'},
		{"socket", required_argument, NULL, 'S'},
		{"pid", no_argument, NULL, 'p'},
		{NULL},
	};

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "hVvc:s:S:p", long_options,
				&option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 0:
			break;	/* long-option flag was set */
		case 'h':
			usage(stdout, argv[0]);
			exit(0);
		case 'V':
			verbose = 1;	/* set short-option flag */
			break;
		case 'v':
			version();
			exit(0);
		case 'c':
			*config_path = optarg;
			*config_string = NULL;
			break;
		case 's':
			*config_path = NULL;
			*config_string = optarg;
			break;
		case 'S':
			*socket_path = optarg;
			break;
		case 'p':
			*get_pid = 1;
			break;
		default:	/* '?' */
			usage(stderr, argv[0]);
			exit(1);
		}
	}

	if (!*socket_path) {
		LOG("missing --socket PATH\n");
		exit(1);
	}

	return 0;
}

static void usage(FILE * stream, char *path)
{
	fprintf(stream, "usage: %s [OPTION]...\n\n", path);
	fprintf(stream, "Options:\n");
	fprintf(stream, "  -h, --help\tShow this usage information and exit\n");
	fprintf(stream,
		"  -v, --version\tPrint version information and exit\n");
	fprintf(stream, "  -c, --config=PATH\tFile containing process JSON\n");
	fprintf(stream,
		"  -s, --config-string=JSON\tProcess JSON from the argument\n");
	fprintf(stream, "  -S, --socket=PATH\tCcon socket path\n");
	fprintf(stream,
		"  -p, --pid\tPrint the container process's PID to stdout\n");
}

static void version()
{
	printf("ccon-cli %s\n", CCON_VERSION);
}

static char *read_file(const char *path)
{
	char *buf = NULL;
	ssize_t rc;
	size_t pos = 0, len = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		PERROR("open");
		return NULL;
	}

	while (1) {
		if (pos >= len - 1) {
			len += 1024;
			buf = realloc(buf, sizeof(char) * len);
			if (!buf) {
				PERROR("realloc");
				return NULL;
			}
		}
		rc = read(fd, buf + pos, len - pos - 1);
		if (rc == -1) {
			PERROR("read");
			return NULL;
		}
		if (rc == 0) {
			return buf;
		}
		pos += rc;
		buf[pos] = '\0';
	}
}
