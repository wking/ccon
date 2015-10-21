/*
 * ccon(1) - Open Container Specification runtime in C.
 * Copyright (C) 2015 W. Trevor King <wking@tremily.us>
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
#include <fcntl.h>
#include <libgen.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cap-ng.h>
#include <jansson.h>

#define STACK_SIZE (1024 * 1024)
#define MAX_PATH 1024

/* messages passed between the host and container */
#define USER_NAMESPACE_MAPPING_COMPLETE "user-namespace-mapping-complete\n"
#define CONTAINER_SETUP_COMPLETE "container-setup-complete\n"
#define EXEC_PROCESS "exec-process\n"

typedef struct child_func_args {
	json_t *config;
	int pipe_in[2];
	int pipe_out[2];
} child_func_args_t;

extern char **environ;

static int validate_config(json_t * config);
static int validate_version(json_t * config);
static int run_container(json_t * config);
static int handle_parent(json_t * config, pid_t cpid, int *to_child,
			 int *from_child);
static int child_func(void *arg);
static int handle_child(json_t * config, int *to_parent, int *from_parent);
static int set_working_directory(json_t * config);
static int set_user_group(json_t * config);
static int _capng_name_to_capability(const char *name);
static int set_capabilities(json_t * config);
static void exec_container_process(json_t * config, int exec_fd);
static void exec_process(json_t * process, int exec_fd);
static int get_host_exec_fd(json_t * config, int *exec_fd);
static int run_hooks(json_t * config, const char *name, pid_t cpid);
static void block_forever();
static int get_namespace_type(const char *name, int *nstype);
static int get_clone_flags(json_t * config, int *flags);
static int join_namespaces(json_t * config);
static int set_user_namespace_mappings(json_t * config, pid_t cpid);
static int set_user_map(json_t * user, pid_t cpid, const char *key,
			const char *filename);
static int set_user_setgroups(json_t * user, pid_t cpid);
static int get_mount_flag(const char *name, unsigned long *flag);
static int handle_mounts(json_t * config);
static int pivot_root_remove_old(const char *new_root);
static int open_in_path(const char *name, int flags);
static int _wait(pid_t pid, const char *name);
static ssize_t getline_fd(char **buf, size_t * n, int fd);
static char **json_array_of_strings_value(json_t * array);
static int close_pipe(int pipe_fd[]);

int main(int argc, char **argv)
{
	const char *config_path = "config.json";
	int err;
	json_t *config;
	json_error_t error;

	if (argc == 2) {
		config_path = argv[1];
	} else if (argc > 2) {
		fprintf(stderr, "usage: %s [CONFIG_PATH]\n", argv[0]);
		return 1;
	}

	config = json_load_file(config_path, JSON_REJECT_DUPLICATES, &error);
	if (!config) {
		fprintf(stderr, "error on %s:%d: %s\n", config_path, error.line,
			error.text);
		return 1;
	}

	err = validate_config(config);
	if (err) {
		fprintf(stderr, "%s invalid\n", config_path);
		goto cleanup;
	}

	err = run_container(config);

 cleanup:
	if (config) {
		json_decref(config);
	}

	return err;
}

int validate_config(json_t * config)
{
	json_t *value;
	int err;

	if (!json_is_object(config)) {
		fprintf(stderr, "config JSON is not an object\n");
		return 1;
	}

	value = json_object_get(config, "version");
	if (!value) {
		fprintf(stderr, "failed to get version from config\n");
		return 1;
	}
	err = validate_version(value);
	if (err) {
		return err;
	}
	// TODO: actually validate the data
	return 0;
}

static int validate_version(json_t * config)
{
	const char *version = json_string_value(config);
	const char *supported_versions[] = {
		"0.1.0",
		NULL,
	};
	int i, err;

	for (i = 0; supported_versions[i]; i++) {
		err =
		    strncmp(supported_versions[i], version,
			    strlen(supported_versions[i]));
		if (!err) {
			return 0;
		}
	}
	fprintf(stderr, "config version %s is not supported\n", version);
	return 1;
}

static int run_container(json_t * config)
{
	child_func_args_t child_args;
	char *stack = NULL, *stack_top;
	int pipe_in[2], pipe_out[2];
	int flags = SIGCHLD;
	pid_t cpid;
	int err = 0;

	if (get_clone_flags(config, &flags)) {
		return 1;
	}

	if (pipe(pipe_in) == -1) {
		perror("pipe");
		return 1;
	}

	if (pipe(pipe_out) == -1) {
		perror("pipe");
		err = 1;
		goto cleanup;
	}

	child_args.config = config;
	child_args.pipe_in[0] = pipe_in[0];
	child_args.pipe_in[1] = pipe_in[1];
	child_args.pipe_out[0] = pipe_out[0];
	child_args.pipe_out[1] = pipe_out[1];

	stack = malloc(STACK_SIZE);
	if (!stack) {
		perror("malloc");
		err = 1;
		goto cleanup;
	}
	stack_top = stack + STACK_SIZE;	/* assume stack grows downward */

	cpid = clone(&child_func, stack_top, flags, &child_args);
	if (cpid == -1) {
		perror("clone");
		err = 1;
		goto cleanup;
	}

	fprintf(stderr, "launched container process with PID %d\n", cpid);
	if (close(pipe_in[0]) == -1) {
		perror("close host-to-container pipe read-end");
		pipe_in[0] = -1;
		goto cleanup;
	}
	pipe_in[0] = -1;
	if (close(pipe_out[1]) == -1) {
		perror("close container-to-host pipe write-end");
		pipe_out[1] = -1;
		goto cleanup;
	}
	pipe_out[1] = -1;
	err = handle_parent(config, cpid, &pipe_in[1], &pipe_out[0]);

 cleanup:
	if (close_pipe(pipe_in)) {
		err = 1;
	}
	if (close_pipe(pipe_out)) {
		err = 1;
	}
	if (stack) {
		free(stack);
	}
	return err;
}

static int handle_parent(json_t * config, pid_t cpid, int *to_child,
			 int *from_child)
{
	char *line = NULL;
	size_t allocated = 0, len;
	ssize_t n;
	int err = 0;

	if (set_user_namespace_mappings(config, cpid)) {
		return 1;
	}

	line = USER_NAMESPACE_MAPPING_COMPLETE;
	len = strlen(line);
	n = write(*to_child, line, len);
	if (n < 0 || (size_t) n != len) {
		perror("write to container");
		return 1;
	}
	line = NULL;

	n = getline_fd(&line, &allocated, *from_child);
	if (n == -1) {
		err = 1;
		goto cleanup;
	}
	len = (size_t) n;
	if (strncmp
	    (CONTAINER_SETUP_COMPLETE, line,
	     strlen(CONTAINER_SETUP_COMPLETE)) != 0) {
		fprintf(stderr, "unexpected message from container(%d): %.*s\n",
			(int)len, (int)len - 1, line);
		goto cleanup;
	}
	free(line);
	line = NULL;

	if (close(*from_child) == -1) {
		perror("close container-to-host pipe read-end");
		*from_child = -1;
		return 1;
	}
	*from_child = -1;

	if (run_hooks(config, "pre-start", cpid)) {
		err = 1;
		fprintf(stderr, "SIGKILL the container process\n");
		if (kill(cpid, SIGKILL)) {
			perror("kill");
		}
		goto wait;
	}

	line = EXEC_PROCESS;
	len = strlen(line);
	n = write(*to_child, line, len);
	if (n < 0 || (size_t) n != len) {
		perror("write to container");
		return 1;
	}
	line = NULL;

 wait:
	if (close(*to_child) == -1) {
		perror("close host-to-container pipe write-end");
		*to_child = -1;
		return 1;
	}
	*to_child = -1;

	err = _wait(cpid, "container");

	(void)run_hooks(config, "post-stop", 0);

 cleanup:
	if (line != NULL) {
		free(line);
	}
	return err;
}

static int child_func(void *arg)
{
	child_func_args_t *child_args = (child_func_args_t *) arg;
	int err = 0;

	if (close(child_args->pipe_in[1]) == -1) {
		perror("close host-to-container pipe write-end");
		child_args->pipe_in[1] = -1;
		err = 1;
		goto cleanup;
	}
	child_args->pipe_in[1] = -1;
	if (close(child_args->pipe_out[0]) == -1) {
		perror("close container-to-host pipe read-end");
		child_args->pipe_out[0] = -1;
		err = 1;
		goto cleanup;
	}
	child_args->pipe_out[0] = -1;
	err =
	    handle_child(child_args->config, &child_args->pipe_out[1],
			 &child_args->pipe_in[0]);
	if (err) {
		fprintf(stderr, "child failed\n");
	}

 cleanup:
	if (close_pipe(child_args->pipe_in)) {
		err = 1;
	}
	if (close_pipe(child_args->pipe_out)) {
		err = 1;
	}
	return err;
}

static int handle_child(json_t * config, int *to_parent, int *from_parent)
{
	char *line = NULL;
	size_t allocated = 0, len;
	ssize_t n;
	int err = 0, exec_fd = -1;

	n = getline_fd(&line, &allocated, *from_parent);
	if (n == -1) {
		err = 1;
		goto cleanup;
	}
	len = (size_t) n;
	if (strncmp
	    (USER_NAMESPACE_MAPPING_COMPLETE, line,
	     strlen(USER_NAMESPACE_MAPPING_COMPLETE)) != 0) {
		fprintf(stderr, "unexpected message from container(%d): %.*s\n",
			(int)len, (int)len - 1, line);
		goto cleanup;
	}
	free(line);
	allocated = 0;
	line = NULL;

	if (get_host_exec_fd(config, &exec_fd)) {
		return 1;
	}

	if (join_namespaces(config)) {
		err = 1;
		goto cleanup;
	}

	if (handle_mounts(config)) {
		err = 1;
		goto cleanup;
	}

	line = CONTAINER_SETUP_COMPLETE;
	len = strlen(line);
	n = write(*to_parent, line, len);
	if (n < 0 || (size_t) n != len) {
		perror("write to host");
		line = NULL;	// don't free a string literal
		err = 1;
		goto cleanup;
	}
	line = NULL;

	if (close(*to_parent) == -1) {
		perror("close container-to-host pipe write-end");
		err = 1;
		*to_parent = -1;
		goto cleanup;
	}
	*to_parent = -1;

	/* block while parent runs pre-start hooks */

	n = getline_fd(&line, &allocated, *from_parent);
	if (n == -1) {
		err = 1;
		goto cleanup;
	}
	len = (size_t) n;
	if (strncmp(EXEC_PROCESS, line, strlen(EXEC_PROCESS)) != 0) {
		fprintf(stderr, "unexpected message from host(%d): %.*s\n",
			(int)len, (int)len - 1, line);
		goto cleanup;
	}
	free(line);
	allocated = 0;
	line = NULL;

	if (close(*from_parent) == -1) {
		perror("close host-to-container pipe read-end");
		*from_parent = -1;
		err = 1;
		goto cleanup;
	}
	*from_parent = -1;

	if (set_working_directory(config)) {
		err = 1;
		goto cleanup;
	}

	if (set_user_group(config)) {
		err = 1;
		goto cleanup;
	}

	if (set_capabilities(config)) {
		err = 1;
		goto cleanup;
	}

	exec_container_process(config, exec_fd);
	err = 1;

 cleanup:
	if (exec_fd >= 0) {
		if (close(exec_fd)) {
			perror("close user-specified executable file");
			err = 1;
		}
	}
	if (line != NULL) {
		free(line);
	}
	return err;
}

static int set_working_directory(json_t * config)
{
	const char *path;
	json_t *process, *cwd;

	process = json_object_get(config, "process");
	if (!process) {
		return 0;
	}

	cwd = json_object_get(process, "cwd");
	if (!cwd) {
		return 0;
	}

	path = json_string_value(cwd);
	if (!path) {
		return 0;
	}

	fprintf(stderr, "change working directory to %s\n", path);
	if (chdir(path) == -1) {
		perror("chdir");
		return 1;
	}

	return 0;
}

static int set_user_group(json_t * config)
{
	uid_t uid;
	gid_t gid, *groups = NULL;
	json_t *process, *user, *v1, *v2;
	size_t i, n = 0;
	int err = 0;

	process = json_object_get(config, "process");
	if (!process) {
		return 0;
	}

	user = json_object_get(process, "user");
	if (!user) {
		goto cleanup;
	}

	v1 = json_object_get(user, "gid");
	if (v1) {
		gid = (gid_t) json_integer_value(v1);
		fprintf(stderr, "set GID to %d\n", (int)gid);
		if (setgid(gid) == -1) {
			perror("setgid");
			err = 1;
			goto cleanup;
		}
	}

	v1 = json_object_get(user, "additionalGids");
	if (v1) {
		n = json_array_size(v1);
		groups = malloc(sizeof(gid_t) * n);
		if (!groups) {
			perror("malloc");
			err = 1;
			goto cleanup;
		}
		json_array_foreach(v1, i, v2) {
			groups[i] = (gid_t) json_integer_value(v2);
		}
		v1 = NULL;
		fprintf(stderr, "set additional GIDs to [");
		for (i = 0; i < n; i++) {
			fprintf(stderr, "%d", (int)groups[i]);
			if (i < n - 1) {
				fprintf(stderr, ", ");
			}
		}
		fprintf(stderr, "]\n");
		if (setgroups(n, groups) == -1) {
			perror("setgroups");
			err = 1;
			goto cleanup;
		}
		free(groups);
		groups = NULL;
	}

	v1 = json_object_get(user, "uid");
	if (v1) {
		uid = (uid_t) json_integer_value(v1);
		fprintf(stderr, "set UID to %d\n", (int)uid);
		if (setuid(uid) == -1) {
			perror("setuid");
			err = 1;
			goto cleanup;
		}
	}

 cleanup:
	if (groups) {
		free(groups);
	}
	return err;
}

/* wrap capng_name_to_capability to handle CAP_-prefixed names */
static int _capng_name_to_capability(const char *name)
{
	if (strlen(name) < 4) {
		return -1;
	}
	return capng_name_to_capability(name + 4);
}

static int set_capabilities(json_t * config)
{
	json_t *process, *capabilities, *value;
	const char *name;
	size_t i;
	int cap;

	process = json_object_get(config, "process");
	if (!process) {
		return 0;
	}

	capabilities = json_object_get(process, "capabilities");
	if (!capabilities) {
		return 0;
	}

	fprintf(stderr, "remove all capabilities from the scratch space\n");
	capng_clear(CAPNG_SELECT_BOTH);

	json_array_foreach(capabilities, i, value) {
		name = json_string_value(value);
		if (!name) {
			fprintf(stderr,
				"failed to extract process.capabilities[%d]\n",
				(int)i);
			return 1;
		}
		cap = _capng_name_to_capability(name);
		if (cap < 0) {
			fprintf(stderr, "unrecognized capability name: %s\n",
				name);
		}
		fprintf(stderr, "restore %s capability to scratch space\n",
			name);
		if (capng_update
		    (CAPNG_ADD,
		     CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_INHERITABLE |
		     CAPNG_BOUNDING_SET, cap)) {
			fprintf(stderr, "failed to restore the %s capability\n",
				name);
			return 1;
		}
	}

	fprintf(stderr,
		"apply specified capabilities to bounding and traditional sets\n");
	if (capng_apply(CAPNG_SELECT_BOTH)) {
		fprintf(stderr, "failed to apply capabilities\n");
		return 1;
	}

	return 0;
}

static void exec_container_process(json_t * config, int exec_fd)
{
	json_t *process;

	process = json_object_get(config, "process");
	if (!process) {
		fprintf(stderr, "process not defined, blocking forever\n");
		block_forever();
		fprintf(stderr, "container block failed\n");
		return;
	}

	exec_process(process, exec_fd);
	return;
}

static void exec_process(json_t * process, int exec_fd)
{
	char *path = NULL;
	char **argv = NULL, **env = NULL;
	json_t *value;
	size_t i;

	value = json_object_get(process, "args");
	if (!value) {
		fprintf(stderr, "args not specified, blocking forever\n");
		block_forever();
		fprintf(stderr, "container block failed\n");
		goto cleanup;
	}

	argv = json_array_of_strings_value(value);
	if (!argv) {
		fprintf(stderr, "failed to extract args\n");
		goto cleanup;
	}

	value = json_object_get(process, "env");
	if (value) {
		env = json_array_of_strings_value(value);
		if (!env) {
			fprintf(stderr, "failed to extract env\n");
			goto cleanup;
		}
	} else {
		env = environ;
	}

	if (exec_fd >= 0) {
		fprintf(stderr, "execute host executable:");
		for (i = 0; argv[i]; i++) {
			fprintf(stderr, " %s", argv[i]);
		}
		fprintf(stderr, "\n");
		fexecve(exec_fd, argv, env);
		perror("fexecve");
		goto cleanup;
	}

	value = json_object_get(process, "path");
	if (value) {
		path = strdup(json_string_value(value));
		if (!path) {
			perror("strdup");
			goto cleanup;
		}

		fprintf(stderr, "execute [%s]:", path);
		for (i = 0; argv[i]; i++) {
			fprintf(stderr, " %s", argv[i]);
		}
		fprintf(stderr, "\n");
		execvpe(path, argv, env);
		perror("execvpe");
	} else {

		fprintf(stderr, "execute:");
		for (i = 0; argv[i]; i++) {
			fprintf(stderr, " %s", argv[i]);
		}
		fprintf(stderr, "\n");
		execvpe(argv[0], argv, env);
		perror("execvpe");
	}

 cleanup:
	if (argv) {
		for (i = 0; argv[i] != NULL; i++) {
			free(argv[i]);
		}
		free(argv);
	}
	if (env && env != environ) {
		for (i = 0; env[i] != NULL; i++) {
			free(env[i]);
		}
		free(env);
	}
	if (path) {
		free(path);
	}
	return;
}

static int get_host_exec_fd(json_t * config, int *exec_fd)
{
	json_t *process, *v1, *v2;
	const char *arg0;

	process = json_object_get(config, "process");
	if (!process) {
		return 0;
	}

	v1 = json_object_get(process, "host");
	if (!v1 || !json_boolean_value(v1)) {
		return 0;
	}

	v1 = json_object_get(process, "path");
	if (v1) {
		arg0 = json_string_value(v1);
		if (!arg0) {
			fprintf(stderr, "failed to extract process.path\n");
			return 1;
		}
	} else {
		v1 = json_object_get(process, "args");
		if (!v1) {
			return 0;
		}
		v2 = json_array_get(v1, 0);
		if (!v2) {
			fprintf(stderr, "failed to extract process.args[0]\n");
			return 1;
		}
		arg0 = json_string_value(v2);
		if (!arg0) {
			fprintf(stderr, "failed to extract process.args[0]\n");
			return 1;
		}
	}

	*exec_fd = open_in_path(arg0, O_RDONLY | O_CLOEXEC);
	if (*exec_fd == -1) {
		return 1;
	}

	return 0;
}

static int run_hooks(json_t * config, const char *name, pid_t cpid)
{
	pid_t hpid;
	json_t *hooks, *hook_array, *hook;
	size_t i;
	int pipe_fd[2], err;

	hooks = json_object_get(config, "hooks");
	if (!hooks) {
		return 0;
	}

	hook_array = json_object_get(hooks, name);
	if (!hook_array) {
		return 0;
	}

	json_array_foreach(hook_array, i, hook) {
		fprintf(stderr, "run %s hook %d\n", name, (int)i);

		if (cpid) {
			if (pipe(pipe_fd) == -1) {
				perror("pipe");
				return 1;
			}

			/* write to kernel buffer, this is less than PIPE_BUF */
			if (dprintf(pipe_fd[1], "%d\n", cpid) < 0) {
				perror("dprintf");
				close_pipe(pipe_fd);
				return 1;
			}

			if (close(pipe_fd[1])) {
				perror("close host-to-hook pipe write-end");
				close_pipe(pipe_fd);
				return 1;
			}
			pipe_fd[1] = -1;
		}

		hpid = fork();
		if (hpid == -1) {
			perror("fork");
			if (cpid) {
				close_pipe(pipe_fd);
			}
			return 1;
		}

		if (hpid == 0) {	/* child */
			if (cpid) {
				if (dup2(pipe_fd[0], STDIN_FILENO) == -1) {
					perror("dup2");
					return 1;
				}
				if (close(pipe_fd[0])) {
					perror
					    ("close host-to-hook pipe read-end after stdin dup");
					return 1;
				}
			}
			exec_process(hook, -1);
			close_pipe(pipe_fd);
			return 1;
		}

		fprintf(stderr, "launched hook %d with PID %d\n", (int)i, hpid);

		if (cpid && close_pipe(pipe_fd)) {
			return 1;
		}

		err = _wait(hpid, "hook");
		if (cpid && err) {
			return 1;	/* abort failed pre-start execution */
		}
	}

	return 0;
}

static void block_forever()
{
	sigset_t mask;

	if (sigemptyset(&mask) == -1) {
		perror("sigemptyset");
		return;
	}
	sigsuspend(&mask);
	perror("sigsuspend");
	return;
}

static int get_namespace_type(const char *name, int *nstype)
{
	if (strncmp("mount", name, strlen("mount") + 1) == 0) {
		*nstype = CLONE_NEWNS;
	} else if (strncmp("uts", name, strlen("uts") + 1) == 0) {
		*nstype = CLONE_NEWUTS;
	} else if (strncmp("ipc", name, strlen("ipc") + 1) == 0) {
		*nstype = CLONE_NEWIPC;
	} else if (strncmp("net", name, strlen("net") + 1) == 0) {
		*nstype = CLONE_NEWNET;
	} else if (strncmp("pid", name, strlen("pid") + 1) == 0) {
		*nstype = CLONE_NEWPID;
	} else if (strncmp("user", name, strlen("user") + 1) == 0) {
		*nstype = CLONE_NEWUSER;
	} else {
		fprintf(stderr, "unrecognized namespace '%s'\n", name);
		return 1;
	}

	return 0;
}

static int get_clone_flags(json_t * config, int *flags)
{
	json_t *namespace, *value, *path;
	const char *key;
	int nstype;

	namespace = json_object_get(config, "namespaces");
	if (!namespace) {
		return 0;
	}

	json_object_foreach(namespace, key, value) {
		path = json_object_get(value, "path");
		if (path) {
			continue;
		}
		if (get_namespace_type(key, &nstype)) {
			return 1;
		}
		*flags |= nstype;
	}

	return 0;
}

static int join_namespaces(json_t * config)
{
	json_t *namespace, *value, *path;
	const char *key, *p;
	int fd, nstype;

	namespace = json_object_get(config, "namespaces");
	if (!namespace) {
		return 0;
	}

	json_object_foreach(namespace, key, value) {
		path = json_object_get(value, "path");
		if (!path) {
			continue;
		}
		p = json_string_value(path);
		if (get_namespace_type(key, &nstype)) {
			return 1;
		}
		fprintf(stderr, "join %s namespace at %s\n", key, p);
		fd = open(p, O_RDONLY);
		if (fd == -1) {
			perror("open");
			return 1;
		}
		if (setns(fd, nstype) == -1) {
			perror("setns");
			if (close(fd) == -1) {
				perror("close");
			}
			return 1;
		}
		if (close(fd) == -1) {
			perror("close");
			return 1;
		}
	}

	return 0;
}

static int set_user_namespace_mappings(json_t * config, pid_t cpid)
{
	json_t *namespace, *user, *v1, *v2;

	namespace = json_object_get(config, "namespaces");
	if (!namespace) {
		return 0;
	}

	user = json_object_get(namespace, "user");
	if (!user) {
		return 0;
	}

	if (set_user_map(user, cpid, "uidMappings", "uid_map")) {
		return 1;
	}

	if (set_user_setgroups(user, cpid)) {
		return 1;
	}

	if (set_user_map(user, cpid, "gidMappings", "gid_map")) {
		return 1;
	}

	return 0;
}

static int set_user_map(json_t * user, pid_t cpid, const char *key,
			const char *filename)
{
	json_t *mappings, *mapping, *value;
	char path[MAX_PATH];
	size_t i;
	uid_t host, container;
	int err = 0, fd = -1, size;

	mappings = json_object_get(user, key);
	if (!mappings) {
		return 0;
	}

	size =
	    snprintf(path, MAX_PATH, "/proc/%lu/%s", (unsigned long int)cpid,
		     filename);
	if (size < 0) {
		fprintf(stderr, "failed to format /proc/%lu/%s\n",
			(unsigned long int)cpid, filename);
		return 1;
	}
	if (size >= MAX_PATH) {
		fprintf(stderr,
			"failed to format /proc/%lu/%s (needed a buffer with %d bytes)\n",
			(unsigned long int)cpid, filename, size);
		return 1;
	}

	fd = open(path, O_WRONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}

	json_array_foreach(mappings, i, mapping) {
		value = json_object_get(mapping, "containerID");
		if (!value) {
			fprintf(stderr,
				"failed to get namespaces.user.%s[%d].containerID\n",
				key, (int)i);
			err = 1;
			goto cleanup;
		}
		container = json_integer_value(value);

		value = json_object_get(mapping, "hostID");
		if (!value) {
			fprintf(stderr,
				"failed to get namespaces.user.%s[%d].hostID\n",
				key, (int)i);
			err = 1;
			goto cleanup;
		}
		host = json_integer_value(value);

		value = json_object_get(mapping, "size");
		if (!value) {
			fprintf(stderr,
				"failed to get namespaces.user.%s[%d].size\n",
				key, (int)i);
			err = 1;
			goto cleanup;
		}
		size = json_integer_value(value);

		fprintf(stderr, "write '%u %u %d' to %s\n",
			(unsigned int)container, (unsigned int)host, size,
			path);
		if (dprintf
		    (fd, "%u %u %d\n", (unsigned int)container,
		     (unsigned int)host, size) < 0) {
			fprintf(stderr, "failed to write '%u %u %d' to %s\n",
				(unsigned int)container, (unsigned int)host,
				size, path);
			err = 1;
			goto cleanup;
		}
	}

 cleanup:
	if (fd >= 0) {
		if (close(fd) == -1) {
			perror("close");
			err = 1;
		}
	}
	return err;
}

static int set_user_setgroups(json_t * user, pid_t cpid)
{
	json_t *setgroups;
	const char *value;
	char path[MAX_PATH];
	int err = 0, fd = -1, size;

	setgroups = json_object_get(user, "setgroups");
	if (!setgroups) {
		return 0;
	}

	if (json_boolean_value(setgroups)) {
		value = "allow";
	} else {
		value = "deny";
	}

	size =
	    snprintf(path, MAX_PATH, "/proc/%lu/setgroups",
		     (unsigned long int)cpid);
	if (size < 0) {
		fprintf(stderr, "failed to format /proc/%lu/setgroups\n",
			(unsigned long int)cpid);
		return 1;
	}
	if (size >= MAX_PATH) {
		fprintf(stderr,
			"failed to format /proc/%lu/setgroups (needed a buffer with %d bytes)\n",
			(unsigned long int)cpid, size);
		return 1;
	}

	fprintf(stderr, "write '%s' to %s\n", value, path);
	fd = open(path, O_WRONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}

	if (write(fd, value, strlen(value)) == -1) {
		perror("write");
		err = 1;
		goto cleanup;
	}

 cleanup:
	if (fd >= 0) {
		if (close(fd) == -1) {
			perror("close");
			err = 1;
		}
	}
	return err;
}

static int get_mount_flag(const char *name, unsigned long *flag)
{
	if (strncmp("MS_BIND", name, strlen("MS_BIND") + 1) == 0) {
		*flag = MS_BIND;
	} else if (strncmp("MS_DIRSYNC", name, strlen("MS_DIRSYNC") + 1) == 0) {
		*flag = MS_DIRSYNC;
	} else if (strncmp("MS_I_VERSION", name, strlen("MS_I_VERSION") + 1) ==
		   0) {
		*flag = MS_I_VERSION;
#ifdef MS_LAZYTIME
	} else if (strncmp("MS_LAZYTIME", name, strlen("MS_LAZYTIME") + 1) == 0) {
		*flag = MS_LAZYTIME;
#endif
	} else if (strncmp("MS_MANDLOCK", name, strlen("MS_MANDLOCK") + 1) == 0) {
		*flag = MS_MANDLOCK;
	} else if (strncmp("MS_MOVE", name, strlen("MS_MOVE") + 1) == 0) {
		*flag = MS_MOVE;
	} else if (strncmp("MS_NOATIME", name, strlen("MS_NOATIME") + 1) == 0) {
		*flag = MS_NOATIME;
	} else if (strncmp("MS_NODEV", name, strlen("MS_NODEV") + 1) == 0) {
		*flag = MS_NODEV;
	} else if (strncmp("MS_NODIRATIME", name, strlen("MS_NODIRATIME") + 1)
		   == 0) {
		*flag = MS_NODIRATIME;
	} else if (strncmp("MS_NOEXEC", name, strlen("MS_NOEXEC") + 1) == 0) {
		*flag = MS_NOEXEC;
	} else if (strncmp("MS_NOSUID", name, strlen("MS_NOSUID") + 1) == 0) {
		*flag = MS_NOSUID;
	} else if (strncmp("MS_PRIVATE", name, strlen("MS_PRIVATE") + 1) == 0) {
		*flag = MS_PRIVATE;
	} else if (strncmp("MS_RDONLY", name, strlen("MS_RDONLY") + 1) == 0) {
		*flag = MS_RDONLY;
	} else if (strncmp("MS_REC", name, strlen("MS_REC") + 1) == 0) {
		*flag = MS_REC;
	} else if (strncmp("MS_RELATIME", name, strlen("MS_RELATIME") + 1) == 0) {
		*flag = MS_RELATIME;
	} else if (strncmp("MS_REMOUNT", name, strlen("MS_REMOUNT") + 1) == 0) {
		*flag = MS_REMOUNT;
	} else if (strncmp("MS_SHARED", name, strlen("MS_SHARED") + 1) == 0) {
		*flag = MS_SHARED;
	} else if (strncmp("MS_SILENT", name, strlen("MS_SILENT") + 1) == 0) {
		*flag = MS_SILENT;
	} else if (strncmp("MS_SLAVE", name, strlen("MS_SLAVE") + 1) == 0) {
		*flag = MS_SLAVE;
	} else if (strncmp("MS_STRICTATIME", name, strlen("MS_STRICTATIME") + 1)
		   == 0) {
		*flag = MS_STRICTATIME;
#ifdef MS_SYNC
	} else if (strncmp("MS_SYNC", name, strlen("MS_SYNC") + 1) == 0) {
		*flag = MS_SYNC;
#endif
	} else if (strncmp("MS_SYNCHRONOUS", name, strlen("MS_SYNCHRONOUS") + 1)
		   == 0) {
		*flag = MS_SYNCHRONOUS;
	} else if (strncmp("MS_UNBINDABLE", name, strlen("MS_UNBINDABLE") + 1)
		   == 0) {
		*flag = MS_UNBINDABLE;
#ifdef MS_VERBOSE
	} else if (strncmp("MS_VERBOSE", name, strlen("MS_VERBOSE") + 1) == 0) {
		*flag = MS_VERBOSE;
#endif
	} else {
		fprintf(stderr, "unrecognized mount flag '%s'\n", name);
		return 1;
	}

	return 0;
}

static int handle_mounts(json_t * config)
{
	json_t *namespaces, *mt_ns, *mounts, *mt, *v1, *v2;
	const char *source, *target, *type, *data, *flag;
	char cwd[MAX_PATH], full_source[MAX_PATH], full_target[MAX_PATH];
	unsigned long flags, f;
	size_t i, j;
	int size;

	namespaces = json_object_get(config, "namespaces");
	if (!namespaces) {
		return 0;
	}

	mt_ns = json_object_get(namespaces, "mount");
	if (!mt_ns) {
		return 0;
	}

	mounts = json_object_get(mt_ns, "mounts");
	if (!mounts) {
		return 0;
	}

	if (!getcwd(cwd, MAX_PATH)) {
		perror("getcwd");
		return 1;
	}
	if (cwd[0] != '/') {
		fprintf(stderr,
			"current working directory is unreachable: %s\n", cwd);
		return 1;
	}

	json_array_foreach(mounts, i, mt) {
		source = target = type = data = NULL;
		v1 = json_object_get(mt, "source");
		if (v1) {
			source = json_string_value(v1);
			if (source[0] == '/') {
				if (strlen(source) >= MAX_PATH) {
					fprintf(stderr,
						"mount path %s is too long (%d >= %d)\n",
						source, (int)strlen(source),
						MAX_PATH);
					return 1;
				}
				memcpy(full_source, source, strlen(source));
			} else {
				size =
				    snprintf(full_source, MAX_PATH, "%s/%s",
					     cwd, source);
				if (size < 0) {
					fprintf(stderr,
						"failed to format %s/%s\n", cwd,
						source);
					return 1;
				}
				if (size >= MAX_PATH) {
					fprintf(stderr,
						"failed to format %s/%s (needed a buffer with %d bytes)\n",
						cwd, source, size);
					return 1;
				}
				source = full_source;
			}
		}

		v1 = json_object_get(mt, "target");
		if (v1) {
			target = json_string_value(v1);
			if (target[0] == '/') {
				if (strlen(target) >= MAX_PATH) {
					fprintf(stderr,
						"mount path %s is too long (%d >= %d)\n",
						target, (int)strlen(target),
						MAX_PATH);
					return 1;
				}
			} else {
				size =
				    snprintf(full_target, MAX_PATH, "%s/%s",
					     cwd, target);
				if (size < 0) {
					fprintf(stderr,
						"failed to format %s/%s\n", cwd,
						target);
					return 1;
				}
				if (size >= MAX_PATH) {
					fprintf(stderr,
						"failed to format %s/%s (needed a buffer with %d bytes)\n",
						cwd, target, size);
					return 1;
				}
				target = full_target;
			}
		}

		v1 = json_object_get(mt, "type");
		if (v1) {
			type = json_string_value(v1);
		}

		v1 = json_object_get(mt, "data");
		if (v1) {
			data = json_string_value(v1);
		}

		flags = 0;
		v1 = json_object_get(mt, "flags");
		if (v1) {
			json_array_foreach(v1, j, v2) {
				flag = json_string_value(v2);
				if (!flag) {
					fprintf(stderr,
						"failed to extract namespaces.mount.mounts[%d].flags[%d]\n",
						(int)i, (int)j);
					return 1;
				}
				if (get_mount_flag(flag, &f)) {
					return 1;
				}
				flags |= f;
			}
		}

		if (type
		    && strncmp("pivot-root", type, strlen("pivot-root")) == 0) {
			if (pivot_root_remove_old(source)) {
				return 1;
			}
		} else {
			fprintf(stderr,
				"mount %lu: %s to %s (type: %s, flags: %lu, data %s)\n",
				(unsigned long int)i, source, target, type,
				flags, data);
			if (mount(source, target, type, flags, data) == -1) {
				perror("mount");
				return 1;
			}
		}
	}

	return 0;
}

static int open_in_path(const char *name, int flags)
{
	const char *p;
	char *paths = NULL, *paths2, *path;
	size_t i;
	int fd;

	if (name[0] == '/') {
		fprintf(stderr,
			"open container-process executable from host %s\n",
			name);
		fd = open(name, flags);
		if (fd == -1) {
			perror("open");
			return -1;
		}
		return fd;
	}

	path = malloc(sizeof(char) * MAX_PATH);
	if (!path) {
		perror("malloc");
		return -1;
	}
	memset(path, 0, sizeof(char) * MAX_PATH);

	p = strchr(name, '/');
	if (p) {
		if (!getcwd(path, MAX_PATH)) {
			perror("getcwd");
			goto cleanup;
		}
		i = strlen(path);
		if (i + strlen(name) + 2 > MAX_PATH) {
			fprintf(stderr,
				"failed to format relative path (needed a buffer with %d byes)\n",
				(int)(i + strlen(name) + 2));
			goto cleanup;
		}
		path[i++] = '/';
		strcpy(path + i, name);
		fprintf(stderr,
			"open container-process executable from host %s\n",
			path);
		fd = open(path, flags);
		if (fd == -1) {
			perror("open");
			return -1;
		}
		free(path);
		return fd;
	}

	paths = getenv("PATH");
	if (!paths) {
		fprintf(stderr, "failed to get host PATH\n");
		goto cleanup;
	}
	paths = strdup(paths);
	if (!paths) {
		perror("strdup");
		goto cleanup;
	}

	paths2 = paths;
	while ((p = strtok(paths2, ":"))) {
		paths2 = NULL;
		i = strlen(p);
		if (i + strlen(name) + 2 > MAX_PATH) {
			fprintf(stderr,
				"failed to format relative path (needed a buffer with %d byes)\n",
				(int)(i + strlen(name) + 2));
			goto cleanup;
		}
		strcpy(path, p);
		path[i++] = '/';
		strcpy(path + i, name);
		fd = open(path, flags);
		if (fd >= 0) {
			fprintf(stderr,
				"open container-process executable from host %s\n",
				path);
			free(path);
			return fd;
		}
	}

	fprintf(stderr, "failed to find %s in the host PATH\n", name);

 cleanup:
	if (paths) {
		free(paths);
	}
	free(path);
	return -1;
}

static int _wait(pid_t pid, const char *name)
{
	siginfo_t siginfo;
	int err;

	err = waitid(P_PID, pid, &siginfo, WEXITED);
	if (err == -1) {
		perror("waitid");
		return 1;
	}

	err = 1;
	switch (siginfo.si_code) {
	case CLD_EXITED:
		err = siginfo.si_status;
		fprintf(stderr, "%s process %d exited with %d\n", name,
			(int)pid, err);
		break;
	case CLD_KILLED:
		fprintf(stderr, "%s killed (%s, %d)\n", name,
			strsignal(siginfo.si_status), siginfo.si_status);
		break;
	case CLD_DUMPED:
		fprintf(stderr, "%s killed by signal %d and dumped core\n",
			name, siginfo.si_status);
		break;
	default:
		fprintf(stderr, "unrecognized %s exit condition: %d\n", name,
			siginfo.si_code);
	}

	return err;
}

static int pivot_root_remove_old(const char *new_root)
{
	char put_old[MAX_PATH];
	char *old_basename;
	int err = 0, fd, size;

	size = snprintf(put_old, MAX_PATH, "%s/pivot-root.XXXXXX", new_root);
	if (size < 0) {
		fprintf(stderr, "failed to format %s/pivot-root.XXXXXX",
			new_root);
		return 1;
	}
	if (size >= MAX_PATH) {
		fprintf(stderr,
			"failed to format %s/.pivot-root.XXXXXX (needed a buffer with %d bytes)\n",
			new_root, size);
		return 1;
	}

	if (!mkdtemp(put_old)) {
		perror("mkdtemp");
		return 1;
	}

	if (chdir(new_root)) {
		perror("chdir");
		err = 1;
		goto cleanup;
	}

	fprintf(stderr, "pivot root to %s\n", new_root);
	if (syscall(SYS_pivot_root, new_root, put_old)) {
		perror("pivot_root");
		if (rmdir(put_old)) {
			perror("rmdir");
		}
		return 1;
	}

	old_basename = basename(put_old);

	if (chdir("/")) {
		perror("chdir");
		err = 1;
		goto cleanup;
	}

	fprintf(stderr, "unmount old root from %s\n", old_basename);
	if (umount2(old_basename, MNT_DETACH)) {
		perror("umount");
		err = 1;
		goto cleanup;
	}

 cleanup:
	if (rmdir(old_basename)) {
		perror("rmdir");
		err = 1;
	}

	return err;
}

// getline(3) but reading from a file descriptor
static ssize_t getline_fd(char **buf, size_t * n, int fd)
{
	ssize_t size = 0, max = 16384, s;
	char delim = '\n';
	size_t block = 512;
	do {
		if (size == *n) {
			char *b = realloc(*buf, *n + block);
			if (b == NULL) {
				perror("realloc");
				return -1;
			}
			*buf = b;
			*n += block;
		}
		s = read(fd, (*buf) + size, 1);
		if (s == -1) {
			perror("read");
			return -1;
		}
		if (s != 1) {
			return -1;
		}
		size += s;
		if (size >= max) {
			return -1;
		}
	} while ((*buf)[size - 1] != delim);
	return size;
}

// Allocate a null-terminated array of strings from a JSON array.
static char **json_array_of_strings_value(json_t * array)
{
	char **a = NULL;
	json_t *value;
	size_t i;
	int err = 0;

	i = json_array_size(array);
	a = malloc(sizeof(char *) * (i + 1));
	if (!a) {
		perror("malloc");
		err = 1;
		goto cleanup;
	}
	memset(a, 0, sizeof(char *) * (i + 1));
	json_array_foreach(array, i, value) {
		a[i] = strdup(json_string_value(value));
		if (!a[i]) {
			perror("strdup");
			err = 1;
			break;
		}
	}
	return a;

 cleanup:
	if (a) {
		for (i = 0; a[i] != NULL; i++) {
			free(a[i]);
		}
		free(a);
		a = NULL;
	}
	return a;
}

static int close_pipe(int pipe_fd[])
{
	int err = 0;

	if (pipe_fd[0] >= 0) {
		if (close(pipe_fd[0]) == -1) {
			perror("close pipe read-end");
			err = 1;
		}
		pipe_fd[0] = -1;
	}

	if (pipe_fd[1] >= 0) {
		if (close(pipe_fd[1]) == -1) {
			perror("close pipe write-end");
			err = 1;
		}
		pipe_fd[1] = -1;
	}

	return err;
}
