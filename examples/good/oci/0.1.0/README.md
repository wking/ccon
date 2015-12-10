Launch a container process from an [OCI v0.1.0][oci] bundle.

Copy a statically-compiled [BusyBox][] to `rootfs/bin/busybox`,
install `ccon` in your host `PATH`, and launch the container with the
[ccon-oci][] wrapper:

    $ ccon-oci start

which will translate the OCI v0.1.0 config to a ccon config and
execute `ccon` with the ccon config.

[BusyBox]: http://www.busybox.net/
[oci]: https://github.com/opencontainers/specs/tree/v0.1.1
[ccon-oci]: ../../../../ccon-oci
