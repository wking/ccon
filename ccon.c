#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <jansson.h>

typedef int (*config_handler_t) (json_t * config);

typedef struct config_entry {
	const char *key;
	config_handler_t handler;
} config_entry_t;

int validate_config(json_t * config);
int handle_version(json_t * config);
int handle_process(json_t * config);
int handle_parent(json_t * config, pid_t cpid, int *to_child, int *from_child);
int handle_child(json_t * config, int *to_parent, int *from_parent);
int _wait(pid_t pid);
ssize_t getline_fd(char **buf, size_t * n, int fd);

config_entry_t config_handlers[] = {
	{
	 .key = "version",
	 .handler = &handle_version,
	 },
	{
	 .key = "process",
	 .handler = &handle_process,
	 },
	{},
};

int main(int argc, char **argv)
{
	char *config_path = "config.json";
	int i, err;
	json_t *config, *value;
	json_error_t error;

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

	for (i = 0; config_handlers[i].key; i++) {
		value = json_object_get(config, config_handlers[i].key);
		if (!value) {
			fprintf(stderr, "failed to get %s from config\n",
				config_handlers[i].key);
			err = 1;
			goto cleanup;
		}
		err = (*config_handlers[i].handler) (value);
		if (err) {
			fprintf(stderr, "failed to handle %s\n",
				config_handlers[i].key);
			goto cleanup;
		}
	}

 cleanup:
	if (config) {
		json_decref(config);
	}

	return err;
}

int validate_config(json_t * config)
{
	if (!json_is_object(config)) {
		fprintf(stderr, "config JSON is not an object\n");
		return 1;
	}
	// TODO: actually validate the data
	return 0;
}

int handle_version(json_t * config)
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

int handle_process(json_t * config)
{
	int pipe_in[2], pipe_out[2];
	pid_t cpid;
	int err = 0;

	if (pipe(pipe_in) == -1) {
		perror("pipe");
		return 1;
	}

	if (pipe(pipe_out) == -1) {
		perror("pipe");
		err = 1;
		goto cleanup;
	}

	cpid = fork();
	if (cpid == -1) {
		perror("fork");
		err = 1;
		goto cleanup;
	}

	if (cpid == 0) {	/* child */
		if (close(pipe_in[1]) == -1) {
			perror("close host-to-container pipe write-end");
			pipe_in[1] = -1;
			goto cleanup;
		}
		pipe_in[1] = -1;
		if (close(pipe_out[0]) == -1) {
			perror("close container-to-host pipe read-end");
			pipe_out[0] = -1;
			goto cleanup;
		}
		pipe_out[0] = -1;
		err = handle_child(config, &pipe_out[1], &pipe_in[0]);
		if (err) {
			fprintf(stderr, "child failed\n");
		}
	} else {		/* parent */
		fprintf(stderr, "launched container process with PID %d\n",
			cpid);
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
	}

 cleanup:
	if (pipe_in[0] >= 0) {
		if (close(pipe_in[0]) == -1) {
			perror("close host-to-container pipe read-end");
		}
	}
	if (pipe_in[1] >= 0) {
		if (close(pipe_in[1]) == -1) {
			perror("close host-to-container pipe write-end");
		}
	}
	if (pipe_out[0] >= 0) {
		if (close(pipe_out[0]) == -1) {
			perror("close container-to-host pipe read-end");
		}
	}
	if (pipe_out[1] >= 0) {
		if (close(pipe_out[1]) == -1) {
			perror("close container-to-host pipe write-end");
		}
	}
	return err;
}

int handle_parent(json_t * config, pid_t cpid, int *to_child, int *from_child)
{
	char *line = NULL;
	size_t n = 0;
	char buf[] = "hello\n";
	size_t len = strlen(buf);
	int err = 0;

	if (write(*to_child, buf, len) != len) {
		perror("write to container");
		goto cleanup;
	}

	len = getline_fd(&line, &n, *from_child);
	if (len == -1) {
		err = 1;
		goto cleanup;
	}
	fprintf(stderr, "read from container (%d): %.*s\n", (int)len,
		(int)len - 1, line);

	err = _wait(cpid);

 cleanup:
	if (line != NULL) {
		free(line);
	}
	return err;
}

int handle_child(json_t * config, int *to_parent, int *from_parent)
{
	char *line = NULL;
	size_t n = 0, len;
	int err = 0;

	len = getline_fd(&line, &n, *from_parent);
	if (len == -1) {
		err = 1;
		goto cleanup;
	}
	fprintf(stderr, "read from host (%d): %.*s\n", (int)len, (int)len - 1,
		line);
	line[3] = 'X';
	if (write(*to_parent, line, len) != len) {
		perror("write to host");
	}

 cleanup:
	if (line != NULL) {
		free(line);
	}
	return err;
}

int _wait(pid_t pid)
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
		fprintf(stderr, "process %d exited with %d\n", (int)pid, err);
		break;
	case CLD_KILLED:
		fprintf(stderr, "child killed (%s, %d)\n",
			strsignal(siginfo.si_status), siginfo.si_status);
		break;
	case CLD_DUMPED:
		fprintf(stderr, "child killed by signal %d and dumped core\n",
			siginfo.si_status);
		break;
	default:
		fprintf(stderr, "unrecognized child exit condition: %d\n",
			siginfo.si_code);
	}

	return err;
}

// getline(3) but reading from a file descriptor
ssize_t getline_fd(char **buf, size_t * n, int fd)
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
