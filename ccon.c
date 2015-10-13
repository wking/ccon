#include <stdio.h>

#include <jansson.h>

int validate_config(json_t * config)
{
	if (!json_is_object(config)) {
		fprintf(stderr, "config JSON is not an object\n");
		return 1;
	}
	// TODO: actually validate the data
	return 0;
}

int main(int argc, char **argv)
{
	char *config_path = "config.json";
	int err;
	json_t *config;
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

 cleanup:
	if (config) {
		json_decref(config);
	}

	return err;
}
