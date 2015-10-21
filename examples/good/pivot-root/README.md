Launch a container process that [pivots][pivot_root.2] to a local
root.

The container launches a static [BusyBox][] from your *host* mount
namespace, you you'll have to have `busybox` somewhere in your host
[`PATH`][environ.7].  Alternatively, you can remove
[**`process.host`**](../../../README.md#host) and copy `busybox` into
`rootfs/bin` before executing the bundle.

This example creates several new namespaces:

* A [user namespace][user_namespaces.7], so we can create new
  namespaces as an unprivileged user.

* A [mount namespace][namespaces.7], because we're going to be
  pivoting the root.

* A [PID namespace][pid_namespaces.7], so we gain temporary
  [`CAP_SYS_ADMIN`][capabilities.7] to [mount
  `/proc`][e51db735-proc-cap-pidns].

We mount `rootfs/proc` before the pivot to pass the `fs_fully_visible`
check that landed in [e51db735][] ([userns: Better restrictions on
when proc and sysfs can be mounted][e51db735-thread], 2013-08-27) and
is explicitly applied to proc in [1b852bce][] ([mnt: Refactor the
logic for mounting sysfs and proc in a user
namespace][1b852bce-thread], 2015-05-09).

## Mounts

1. The inital rootfs bind-mount is the “trick” from
   [`switch_root(8)`][switch_root.8.notes] which we need for the later
   pivot.
2. [`/dev`] (recursively bound from the host mount namespace) for
   compliance with the [FHS 3.0][FHS-3.0].  This seems to be the only
   option for unprivileged users.  Mounting a new [devtmpfs][] seems
   to require [`CAP_SYS_ADMIN`][capabilities.7] in the root user
   namespace (but I can't find docs for that).  Calling
   [`mknod`][mknod.1] requires [`CAP_MKNOD`][capabilities.7] in the
   root user namespace, not the current one (see the unapplied [fs:
   allow mknod in user namespaces][mknod-user-namespace]).
3. `/proc` for tools like [`ps`][ps.1] and [`sysctl`][sysctl.8] that
   need entries in the proc filesytem.
4. [`/sys`][sys] for tools like [`lm_sensors`][lm_sensors] that need
   access to kernel subsystem information.  This is recursively bound
   from the host mount namespace to pull in submounts like
   [`/sys/fs/cgroup`][cgroups].
5. `/etc/resolv.conf` in case [someone sets up a veth route out of the
   network namespace](../net-veth-root).
6. `/root` for a writable scratch space that's persisted on disk.
7. [Pivot][pivot_root.2] to the local root.
8. Remount the new root read-only so we can share the same `roofs`
   between several containers without fear of cross-contamination.
9. [`/run`][run] for compliance with the [FHS 3.0][FHS-3.0].
10. [`/tmp`][tmp] for compliance with the [FHS 3.0][FHS-3.0].

[BusyBox]: http://www.busybox.net/
[cgroups]: https://www.kernel.org/doc/Documentation/cgroups/cgroups.txt
[dev]: http://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s06.html
[devtmpfs]: http://thread.gmane.org/gmane.linux.kernel/830032
[FHS-3.0]: http://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html
[lm_sensors]: http://www.lm-sensors.org/
[run]: http://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s15.html
[sys]: http://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch06.html#sysKernelAndSystemInformation
[tmp]: http://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s18.html

[mknod-user-namespace]: http://thread.gmane.org/gmane.linux.file-systems/72682/focus=72684
[e51db735]: https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=e51db73532955dc5eaba4235e62b74b460709d5b
[e51db735-thread]: http://thread.gmane.org/gmane.linux.file-systems/77413
[e51db735-proc-cap-pidns]: https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/diff/fs/proc/root.c?id=e51db73532955dc5eaba4235e62b74b460709d5b
[1b852bce]: https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1b852bceb0d111e510d1a15826ecc4a19358d512
[1b852bce-thread]: http://thread.gmane.org/gmane.linux.kernel.containers/29284/focus=29285

[mknod.1]: http://man7.org/linux/man-pages/man1/mknod.1.html
[ps.1]: http://man7.org/linux/man-pages/man1/ps.1.html
[pivot_root.2]: http://man7.org/linux/man-pages/man2/pivot_root.2.html
[capabilities.7]: http://man7.org/linux/man-pages/man7/capabilities.7.html
[environ.7]: http://man7.org/linux/man-pages/man7/environ.7.html
[namespaces.7]: http://man7.org/linux/man-pages/man7/namespaces.7.html
[pid_namespaces.7]: http://man7.org/linux/man-pages/man7/pid_namespaces.7.html
[user_namespaces.7]: http://man7.org/linux/man-pages/man7/user_namespaces.7.html
[switch_root.8.notes]: http://man7.org/linux/man-pages/man8/switch_root.8.html#NOTES
[sysctl.8]: http://man7.org/linux/man-pages/man8/sysctl.8.html
