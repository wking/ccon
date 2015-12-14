Create a container, execute a process inside it, and delete the
container with separate steps.

Install the following dependencies in your `PATH`:

* [Python][] v3.3+, for running ccon-ced.
* The [`ccon-ced`][ccon-ced] wrapper.
* `ccon`, which does all the heavy lifting.
* [util-linux][] for [`mount`][mount.8] and [`umount`][umount.8].

Create the container:

    # ccon-ced create --id abc

Execute a process inside the container (you can do this as many times
as you like, to execute additional processes inside the container):

    # ccon-ced exec --id abc

Delete the container:

    # ccon-ced delete --id abc

The only portion of the container that cannot be created by `create`
is a new [PID namespace][pid_namespaces.7] (and its associated
[`/proc` mounts][pid-proc]), because new PID namespaces only survive
as long as their init process.  To execute processes within a new PID
namespace, you must either create a new PID namespace with the `exec`
call (as we do in this [`exec.json`](exec.json-pid)) or execute a
persistent container process to hold the PID namespace open and then
have your worker processes join that PID namespace.

[oci]: https://github.com/opencontainers/specs/tree/v0.1.1
[ccon-ced]: ../../../../ccon-ced

[Python]: https://www.python.org/
[util-linux]: https://www.kernel.org/pub/linux/utils/util-linux/

[pid_namespaces.7]: http://man7.org/linux/man-pages/man7/pid_namespaces.7.html
[mount.8]: http://man7.org/linux/man-pages/man8/mount.8.html
[umount.8]: http://man7.org/linux/man-pages/man8/umount.8.html

[pid-proc]: ../../../../README.md#pid-namespace
[exec.json-pid]: exec.json#L28
