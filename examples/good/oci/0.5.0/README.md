Launch a container process from an [OCI v0.5.0][oci] bundle.

Copy a statically-compiled [BusyBox][] to `rootfs/bin/busybox`,
install the following dependencies in your `PATH`:

* [Python][] v3.3+, for running ccon-oci.
* The [`ccon-oci`][ccon-oci] wrapper.
* `ccon`, which does all the heavy lifting.

Some functionality requires additional tools in the host `PATH`:

* `config.json`'s [**`hostname`**][oci-hostname]
  * [net-tools][] for [`hostname`][hostname.1].
* `config.json`'s hook [**`timeout`**][oci-hook]
  * [GNU Core Utilities][coreutils] for [`timeout`][timeout.1].

and launch the container:

    $ echo 'echo hi; exit' | ccon-oci start

which will translate the OCI config to a ccon config and execute
`ccon` with the ccon config.

[oci]: https://github.com/opencontainers/specs/tree/v0.5.0
[ccon-oci]: ../../../../ccon-oci
[oci-hook]: https://github.com/opencontainers/specs/blob/v0.5.0/config.md#hooks
[oci-hostname]: https://github.com/opencontainers/specs/blob/v0.5.0/config.md#hostname

[BusyBox]: http://www.busybox.net/
[coreutils]: http://www.gnu.org/software/coreutils/coreutils.html
[net-tools]: http://net-tools.sourceforge.net/
[Python]: https://www.python.org/

[hostname.1]: http://man7.org/linux/man-pages/man1/hostname.1.html
[timeout.1]: http://man7.org/linux/man-pages/man1/timeout.1.html
