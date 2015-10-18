Launch a container process in a new [freezer][] [cgroup][cgroups],
removing that cgroup on exit.  This example creates several new
namespaces:

* A [user namespace][user_namespaces.7], so we can create new
  namespaces as an unprivileged user (although see
  [here](#unprivileged-cgroups) for more on creating cgroups as an
  unprivileged user).

* A [PID namespace][namespaces.7], to automatically kill any other
  processes in this container when the container process dies.  You
  can't remove cgroups when they still contain processes or
  subcgroups.  Having a PID namespace doesn't guarantee that
  additional processes won't join the freezer cgroup without also
  joining the PID namespace, but having the PID namespace available
  makes it easy for cooperative processes to play nice.

* A [mount namespace][namespaces.7], to [get a local `/proc` for the
  PID namespace](../../../README.md#pid-namespace).

The process is just a [`ps`][ps.1] (from [procps][]), and it will
produce output like:

    PID COMMAND         CGROUP
      1 ps              8:freezer:/ccon-ex/ps-ex

## Unprivileged cgroups

[Cgroups use a virtual filesystem][cgroups] with the usual Unix
permissions, so you can create subgroups with [`mkdir`][mkdir.1],
remove them with [`rmdir`][rmdir.1], change their permissions with
[`chmod`][chmod.1], and change their owners with [`chown`][chown.1].
Most systems will probably keep the root cgroups restricted to root.
To create a space for unprivileged users to manage their own cgroups,
the sysadmin will need to create subgroups that the user can control.
For example:

    # mkdir /sys/fs/cgroup/freezer/ccon-ex
    # chown wking:wking /sys/fs/cgroup/freezer/ccon-ex

Will create a `ccon-ex` [freezer][] subgroup that I can manipulate
without elevated permissions:

    $ mkdir /sys/fs/cgroup/freezer/ccon-ex/ps-ex
    $ rmdir /sys/fs/cgroup/freezer/ccon-ex/ps-ex

If you have an existing subgroup like `ccon-ex`, you can run this
example as an unprivileged user.  If you don't, you'll need to elevate
your privileges (with [`sudo`][sudo.8] or by asking your sysadmin) to
create such a subgroup.

## Hook dependencies

* [GNU Core Utilities][coreutils] for [`mkdir`][mkdir.1] and
  [`tee`][tee.1].
* [GNU Find Utilities][findutils] for [`find`][find.1].

[coreutils]: http://www.gnu.org/software/coreutils/coreutils.html
[findutils]: http://www.gnu.org/software/findutils/findutils.html
[procps]: https://gitlab.com/procps-ng/procps

[cgroups]: https://www.kernel.org/doc/Documentation/cgroups/cgroups.txt
[freezer]: https://www.kernel.org/doc/Documentation/cgroups/freezer-subsystem.txt

[chmod.1]: http://man7.org/linux/man-pages/man1/chmod.1.html
[chown.1]: http://man7.org/linux/man-pages/man1/chown.1.html
[find.1]: http://man7.org/linux/man-pages/man1/find.1.html
[mkdir.1]: http://man7.org/linux/man-pages/man1/mkdir.1.html
[ps.1]: http://man7.org/linux/man-pages/man1/ps.1.html
[rmdir.1]: http://man7.org/linux/man-pages/man1/rmdir.1.html
[tee.1]: http://man7.org/linux/man-pages/man1/tee.1.html
[namespaces.7]: http://man7.org/linux/man-pages/man7/namespaces.7.html
[user_namespaces.7]: http://man7.org/linux/man-pages/man7/user_namespaces.7.html
[sudo.8]: http://www.sudo.ws/man/1.8.14/sudo.man.html
