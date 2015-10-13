#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <jansson.h>

/* messages passed between the host and container */
#define CONTAINER_SETUP_COMPLETE "container-setup-complete\n"

int validate_config(json_t * config);
int validate_version(json_t * config);
int run_container(json_t * config);
int handle_parent(json_t * config, pid_t cpid, int *to_child, int *from_child);
int handle_child(json_t * config, int *to_parent, int *from_parent);
int exec_process(json_t * config);
void block_forever();
int _wait(pid_t pid);
ssize_t getline_fd(char **buf, size_t * n, int fd);

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
		err = 1;
		goto cleanup;
	}
	err = validate_version(value);
	if (err) {
		goto cleanup;
	}
	// TODO: actually validate the data

 cleanup:
	if (value) {
		json_decref(value);
	}
	return 0;
}

int validate_version(json_t * config)
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

int run_container(json_t * config)
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
	size_t allocated = 0, len;
	int err = 0;

	line = CONTAINER_SETUP_COMPLETE;
	len = strlen(line);

	if (close(*from_child) == -1) {
		perror("close container-to-host pipe read-end");
		err = 1;
		*from_child = -1;
		goto cleanup;
	}
	*from_child = -1;

	if (write(*to_child, line, len) != len) {
		perror("write to container");
		return 1;
	}
	line = NULL;

	if (close(*to_child) == -1) {
		perror("close host-to-container pipe write-end");
		*to_child = -1;
		return 1;
	}
	*to_child = -1;

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
	size_t allocated = 0, len;
	int err = 0;

	if (close(*to_parent) == -1) {
		perror("close host-to-container pipe read-end");
		err = 1;
		*to_parent = -1;
		goto cleanup;
	}
	*to_parent = -1;

	len = getline_fd(&line, &allocated, *from_parent);
	if (len == -1) {
		err = 1;
		goto cleanup;
	}
	if (strncmp
	    (CONTAINER_SETUP_COMPLETE, line,
	     strlen(CONTAINER_SETUP_COMPLETE)) != 0) {
		fprintf(stderr, "unexpected message from host(%d): %.*s\n",
			(int)len, (int)len - 1, line);
		goto cleanup;
	}

	if (close(*from_parent) == -1) {
		perror("close container-to-host pipe read-end");
		err = 1;
		*from_parent = -1;
		goto cleanup;
	}
	*from_parent = -1;

	err = exec_process(config);

 cleanup:
	if (line != NULL) {
		free(line);
	}
	return err;
}

int exec_process(json_t * config)
{
	json_t *value;
	int err = 0;

	value = json_object_get(config, "process");
	if (!value) {
		block_forever();
		err = 1;
	}

 cleanup:
	if (value) {
		json_decref(value);
	}
	return err;
}

void block_forever()
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
