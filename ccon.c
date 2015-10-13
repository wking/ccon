#include <stdio.h>
#include <string.h>

#include <jansson.h>

typedef int (*config_handler_t) (json_t * config);

typedef struct config_entry {
	const char *key;
	config_handler_t handler;
} config_entry_t;

int validate_config(json_t * config);
int handle_version(json_t * config);

config_entry_t config_handlers[] = {
	{
	 .key = "version",
	 .handler = &handle_version,
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
