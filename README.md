# ccon

A single binary to handle basic container creation.  The goal is to
produce a lightweight tool in C that can serve as a test-bed for [Open
Container Specification][ocs] development.  Ccon is thin wrapper
around the underlying syscalls and kernel primitives.  It makes it
easy to apply a given configuration, but does not have an opinion
about what a container should look like.

## Table of contents

* [Lifecycle](#lifecycle)
* [Configuration](#configuration)
  * [Version](#version)
  * [Namespaces](#namespaces)
    * [User namespace](#user-namespace)
    * [Mount namespace](#mount-namespace)
    * [PID namespace](#pid-namespace)
    * [Network namespace](#network-namespace)
    * [IPC namespace](#ipc-namespace)
    * [UTS namespace](#uts-namespace)
  * [Process](#process)
    * [User](#user)
    * [Current working directory](#current-working-directory)
    * [Capabilities](#capabilities)
    * [Arguments](#arguments)
    * [Path](#path)
    * [Environment variables](#environment-variables)
* [Dependencies](#dependencies)
  * [Build dependencies](#build-dependencies)
  * [Development dependencies](#development-dependencies)
* [Licensing](#licensing)

## Lifecycle

When you invoke it from the command line, ccon [`clone`][clone.2]'s a
child process to create any new namespaces declared in the config
file.  The parent process continues running in the host namespace.
When the child process exits, the host process collects its exit
status and returns it to the caller.  During an initial setup phase,
the two processes pass messages on pipes to synchronize the container
setup.  Here's an outline of the lifecycle:

| Host process              | Container process           |
| ------------------------- | --------------------------- |
| clone's child →           | (clone unshares namespaces) |
| set user-ns mappings      | blocks on user-ns mappings  |
| sends mappings-complete → |                             |
| blocks on full namespace  | joins namespaces            |
|                           | mounts filesystems          |
|                           | ← sends namespaces-complete |
| runs pre-start hooks      | blocks on exec-message      |
| sends exec-message →      |                             |
| waits on child death      | executes user process       |
|                           | …                           |
|                           | dies                        |
| collects child exit code  |                             |
| exits with same code      |                             |

A number of those steps are optional.  For details, see the relevant
section in the [configuration specification](#configuration).  In
general, leaving out a particular value
(e.g. **`namespaces.user.setgroups`** or **`namespaces.mounts`**) will
result in that potential action (e.g. writing to
[`/proc/{pid}/setgroups`][user_namespaces.7] or calling
[`mount`][mount.2] being skipped, while the rest of ccon carries on as
usual.

## Configuration

Ccon is similar to an [Open Container Specification][ocs] runtime in
that it reads a configuration file named `config.json` from its
current working directory.  However the JSON content is a bit
different to highlight how the components relate to each-other on
Linux.  For example, setting per-container mounts requires a mount
namespace, so ccon's mount listing falls under
**`namespaces.mount.mounts`**.  There's an example in
[`config.json`](config.json) that unprivileged users should be able to
launch an interactive [BusyBox][] shell in new namespaces (you may
need to adjust the **`hostID`** entries to match `id -u` and `id -g`).

### Version

The ccon version represented in the config file.

* **`version`** (required, [SemVer 2.0.0][semver] string)

#### Example

```json
"version": "0.1.0"
```

### Namespaces

A set of namespaces to be created or joined by the container process.
Keys match the long-form options from [`unshare`][unshare.1] and
[`nsenter`][nsenter.1] without their leading hyphens.  For each
namespace entry, the presence of a ``*path*`` key means the container
process will join an existing namespace at the absolute path specified
by the ``*path*`` value.  The absence of a ``*path*`` key means a new
namespace will be created.  For new namespaces, there may be
per-namespace configuration in the namespace object.  If there is no
``*namespace*`` entry or its value is an empty object, the container
process will inherit all its namespaces from the host process.

* **`namespaces`** (optional, object) containing entries for each new
  or joined namespace.

#### Example

```json
"namespaces": {
  "uts": {},
  "net": {"path": "/proc/2186/ns/net"},
  "user": {"setgroups": false}
}
```

Which will create new [UTS][namespaces.7] and
[user][user_namespaces.7] namespaces, join the network namespace at
`/proc/2186/ns/net`, and disable [`setgroups`][getgroups.2] in the new
user namespace.

#### User namespace

New [user namespaces][user_namespaces.7] support the
`/proc/{pid}/{path}` files `setgroups`, `uid_map`, and `gid_map`
discussed in [`user_namespaces(7)`][user_namespaces.7].

* **`mount`** (optional, object) which may contain:
  * **`path`** (optional, string, incompatible with other siblings)
    the absolute path to a network namespace which the container
    process should join.
  * **`setgroups`** (optional, boolean, incompatible with a **`path`**
    sibling) whether to enable or disable [`setgroups`][getgroups.2].
    Implemented by writing to
    [`/proc/{pid}/setgroups`][user_namespaces.7].
  * **`uidMappings`** (optional, array of objects, incompatible with a
    **`path`** sibling) maps user IDs between the new namespace and
    its parent namespace.  Implemented by writing to
    [`/proc/{pid}/uid_map`][user_namespaces.7].  Array entries are
    objects with the following fields:
    * **`containerID`** (required, integer) is the start of the mapped
      UID range in the new namespace.
    * **`hostID`** (required, integer) is the start of the mapped UID
      range in the parent namespace.
    * **`size`** (required, integer) is the length of the range of
      mapped UIDs.
  * **`gidMappings`** (optional, array of objects, incompatible with a
    **`path`** sibling) maps group IDs between the new namespace and
    its parent namespace.  Implemented by writing to
    [`/proc/{pid}/gid_map`][user_namespaces.7].  Array entries are
    objects with the following fields:
    * **`containerID`** (required, integer) is the start of the mapped
      GID range in the new namespace.
    * **`hostID`** (required, integer) is the start of the mapped GID
      range in the parent namespace.
    * **`size`** (required, integer) is the length of the range of
      mapped GIDs.

##### Example

```json
"user": {
  "setgroups": false,
  "uidMappings": [
    {
      "containerID": 0,
      "hostID": 1000,
      "size": 1
    }
  ],
  "gidMappings": [
    {
      "containerID": 0,
      "hostID": 1000,
      "size": 1
    }
  ]
},
```

Which will disable [`setgroups`][getgroups.2] and map the host user
and group 1000 to the container user and group 0.

#### Mount namespace

New [mount namespace][namespaces.7] support the creation of arbitrary
mounts, assuming the caller has sufficient privileges for the
underlying [syscall][syscall.2].  The [user namepace
documentation][user_namespaces.7] outlines the mount permissions for
processes inside a user namespace.

* **`mount`** (optional, object) which may contain:
  * **`path`** (optional, string, incompatible with a **`mounts`**
    sibling) the absolute path to a network namespace which the
    container process should join.
  * **`mount`** (optional, array, incompatible with a **`path`**
    sibling) an ordered list of mounts to perform.  Array entries are
    objects with fields based on the [`mount`][mount.2] call:
    * **`type`** (string) of mount (see
      [`filesystems(5)`][filesystems.5]).
    * **`source`** (string) path of mount.  This may be optional or
      required depending on **`type`**.
    * **`target`** (string, required) path of the mount being created
      or manipulated.
    * **`flags`** (array of strings, optional) [`MS_*`][mount.2] flags
      to set.
    * **`data`** (string, optional) type-specific data for the
      mount.

If they don't start with a slash, **`source`** and **`target`** are
interpreted as paths relative to ccon's [current working
directory][getcwd.3].

In addition to the usual types supported by [`mount`][mount.2], ccon
supports a `pivot-root` **`type`** that invokes the
[`pivot_root`][pivot_root.2] [syscall][syscall.2], shifting the old
root to a temporary (after which it is unmounted and the temporary
directory is removed).  In that case, the only other field that
matters is **`source`**, which specifies

##### Example

```json
"mount": {
  "mounts": [
    {
      "source": "rootfs",
      "target": "rootfs",
      "flags": [
        "MS_BIND"
      ]
    },
    {
      "source": "/etc/resolv.conf",
      "target": "rootfs/etc/resolv.conf",
      "flags": [
        "MS_BIND"
      ]
    },
    {
      "source": "root",
      "target": "rootfs/root",
      "flags": [
        "MS_BIND"
      ]
    },
    {
      "source": "rootfs",
      "type": "pivot-root"
    }
  ]
}
```

Which will bind `${PWD}/rootfs` to itself (the “trick” mentioned in
[`switch_root(8)`][switch_root.8.notes] which we need for the later
pivot), bind the host's `resolv.conf` onto
`${PWD}/rootfs/etc/resolv.conf`, bind `${PWD}/root` onto
`${PWD}/rootfs/root`, and pivot to make `${PWD}/rootfs` the container
root.

#### PID namespace

There is no special configuration for the [PID
namespace][pid_namespaces.7], although if you are creating both a PID
and a [mount](#mount-namespace) namespace, you probably want mount
entries along the lines of:

```json
{
  "target": "/proc",
  "type": "proc",
  "flags": [
    "MS_PRIVATE",
    "MS_REC"
  ]
},
{
  "target": "/proc",
  "type": "proc",
  "flags": [
    "MS_NOSUID",
    "MS_NOEXEC",
    "MS_NODEV"
  ]
}
```

For more details, see the “/proc and PID namespaces” section of
[`pid_namespaces(7)`][pid_namespaces.7].

* **`pid`** (optional, object) which may contain:
  * **`path`** (optional, string) the absolute path to a PID namespace
    which the container process should join.

#### Network namespace

There is no special configuration for the [network
namespace][namespaces.7].

* **`net`** (optional, object) which may contain:
  * **`path`** (optional, string) the absolute path to a network
    namespace which the container process should join.

#### IPC namespace

There is no special configuration for the [IPC
namespace][namespaces.7].

* **`ipc`** (optional, object) which may contain:
  * **`path`** (optional, string) the absolute path to an IPC
    namespace which the container process should join.

#### UTS namespace

There is no special configuration for the [UTS
namespace][namespaces.7], although future work might build in support
for [`sethostname`][gethostname.2].

* **`uts`** (optional, object) which may contain:
  * **`path`** (optional, string) the absolute path to a UTS namespace
    which the container process should join.

### Process

After the container setup is finished, the container process can
optionally adjust its state and execute the configured code.  If
**`process`** isn't specified, the container process will block until
killed by an external signal (which can be useful to hold a container
open while other processes join and do the real work).

* **`process`** (optional, object) configuring the container process
  after the container is setup.

#### Example

```json
"process": {
  "args": ["busybox", "sh"]
}
```

Which will [`execvpe`][exec.3] a [BusyBox][] shell with the host
process's user and group (possibly mapped by the [user
namespace](#user-namespace)), working directory, and environment.

#### User

Adjust the user and group IDs before executing the user-specified
code.

* **`uid`** (optional, integer) to [`setuid`][setuid.2] a different
  user.
* **`gid`** (optional, integer) to [`setgid`][setgid.2] a different
  group.
* **`additionalGids`** (optional, array of integers) for
  [`setgroups`][getgroups.2].  See also
  [**`namespaces.user.setgroups`**](#user-namespace).

##### Example

```json
"user": {
  "uid": 0,
  "gid": 0,
  "additionalGids": [5, 6]
}
```

Which will lead to a container process with [`id`][id.1] output like:

```
uid=0(root) gid=0(root) groups=0(root),5(tty),6(disk)
```

#### Current working directory

Change to a different directory before executing the configured code.

* **`cwd`** (optional, string) to [`chdir`][chdir.2] to a different
  directory.  If unset, the current directory will remain the same as
  the caller's working directory, unless there is a `pivot-root` entry
  in **`namespaces.mount.mounts`**, in which case the default working
  directory will be the new root.

##### Example

```json
"cwd": "/root"
```

#### Capabilities

Define the minimum set of [capabilities][capabilities.7] required for
the container process.  All other capabilities are dropped from all
capabilities sets, including the bounding set, before executing the
configured code.

* **`capabilities`** (optional, array of strings) Set of
  [`CAP_*`][capabilities.7] flags to set.

If unset, the container process will continue with the caller's
capabilities (potentially increased in a child [user
namespace][user_namespaces.7]).

##### Example

```json
"cwd": "/root"
```

#### Arguments

The command that the container process executes after container setup
is complete.  The process will inherit any open file descriptors
(e.g. the [standard streams][stdin.3] or [systemd's
`SD_LISTEN_FDS_START`][sd_listen_fds]).

* **`args`** (optional, array of strings) holds command-line arguments
  passed to [`execvpe`][exec.3].  The first argument (**`args[0]`**)
  is also used as the path, unless [**`path`**](#path) is set.

If unset, the container process will block until killed by an external
signal (see [Process](#process)).

##### Example

```json
"args": [
  "nginx",
  "-c",
  "/nginx.conf"
]
```

Which will execute an [Nginx][] server using the configuration in
`/nginx.conf`.

#### Path

Override **`args[0]`** with an alternate path (but the executed code
will still see **`args[0]`** as its first argument).

* **`path`** (optional, string) sets the path to the
  [executed][exec.3] command.  Paths without slashes will be resolved
  using the `PATH` environment variable.

##### Example

```json
"args": ["sh"],
"path": "busybox"
```

Which will execute the first [`busybox`][BusyBox] executable found in
your `PATH` with its `argv[0]` set to `sh`.

#### Environment variables

Override the host environment.

* **`env`** (optional, array of strings) holds environment settings
  for [`execvpe`][exec.3].

If unset, the container process will use the [`environ`][environ.3p]
it inherited from the host.

##### Example

```json
"env": [
  "PATH=/bin:/usr/bin",
  "TERM=xterm"
]
```

Which will set `PATH` and `TERM`.

## Dependencies

* [The GNU C Library][glibc] ([sys-libs/glibc][] on [Gentoo][]).
* [Jansson][] for JSON parsing ([dev-libs/jansson][] on [Gentoo][]).
* [libcap-ng][] for adjusting [capabilities][capabilities.7]
  ([sys-libs/libcap-ng][] on [Gentoo][]).

### Build dependencies

Ccon is pretty easy to compile, but to use the stock
[Makefile](Makefile), you'll need:

* A C compiler like [GCC][] ([sys-devel/gcc][] on [Gentoo][]).
* [GNU Make][make] ([sys-devel/make][] on [Gentoo][]).
* [pkg-config][] ([dev-util/pkgconfig][] on [Gentoo][]).

### Development dependencies

* [indent][] ([dev-util/indent][] on [Gentoo][]).  Invoke with `make
  fmt`.

## Licensing

* Ccon is under the [GPLv3+](COPYING).
* [Glibc is under][glibc-license] the [LGPL-2.1+][glibc-license].
* [Jansson is under][jansson-license] the [MIT license][mit].
* [libcap-ng is under][libcap-ng-license] the [LGPL-2.1+][glibc-license].

Because all the dependencies are [GPL-compatible][], ccon binaries can
be distributed under the GPLv3+.

[ocs]: https://github.com/opencontainers/specs

[BusyBox]: http://www.busybox.net/
[GCC]: http://gcc.gnu.org/
[glibc-license]: https://sourceware.org/git/?p=glibc.git;a=blob;f=COPYING.LIB;hb=glibc-2.22
[glibc]: https://www.gnu.org/software/libc/
[indent]: https://www.gnu.org/software/indent/
[Jansson]: http://www.digip.org/jansson/
[jansson-license]: https://github.com/akheron/jansson/blob/v2.7/LICENSE
[libcap-ng]: http://people.redhat.com/sgrubb/libcap-ng/
[libcap-ng-license]: https://fedorahosted.org/libcap-ng/browser/tags/libcap-ng-0.7.7/COPYING.LIB
[make]: https://www.gnu.org/software/make/
[Nginx]: http://nginx.org/
[pkg-config]: http://www.freedesktop.org/wiki/Software/pkg-config/
[semver]: http://semver.org/spec/v2.0.0.html

[GPL-compatible]: https://www.gnu.org/licenses/license-list.html#GPLCompatibleLicenses
[mit]: https://www.gnu.org/licenses/license-list.html#Expat
[lgpl-2.1]: https://www.gnu.org/licenses/license-list.html#LGPLv2.1

[Gentoo]: https://gentoo.org
[dev-libs/jansson]: https://packages.gentoo.org/package/dev-libs/jansson
[dev-util/indent]: https://packages.gentoo.org/package/dev-util/indent
[dev-util/pkgconfig]: https://packages.gentoo.org/package/dev-util/pkgconfig
[sys-devel/gcc]: https://packages.gentoo.org/package/sys-devel/gcc
[sys-devel/make]: https://packages.gentoo.org/package/sys-devel/make
[sys-libs/glibc]: https://packages.gentoo.org/package/sys-libs/glibc

[id.1]: http://man7.org/linux/man-pages/man1/id.1.html
[nsenter.1]: http://man7.org/linux/man-pages/man1/nsenter.1.html
[unshare.1]: http://man7.org/linux/man-pages/man1/unshare.1.html
[chdir.2]: http://man7.org/linux/man-pages/man2/chdir.2.html
[clone.2]: http://man7.org/linux/man-pages/man2/clone.2.html
[getgroups.2]: http://man7.org/linux/man-pages/man2/getgroups.2.html
[gethostname.2]: http://man7.org/linux/man-pages/man2/gethostname.2.html
[mount.2]: http://man7.org/linux/man-pages/man2/mount.2.html
[pivot_root.2]: http://man7.org/linux/man-pages/man2/pivot_root.2.html
[setgid.2]: http://man7.org/linux/man-pages/man2/setgid.2.html
[setuid.2]: http://man7.org/linux/man-pages/man2/setuid.2.html
[syscall.2]: http://man7.org/linux/man-pages/man2/syscall.2.html
[environ.3p]: https://www.kernel.org/pub/linux/docs/man-pages/man-pages-posix/
[exec.3]: http://man7.org/linux/man-pages/man3/exec.3.html
[getcwd.3]: http://man7.org/linux/man-pages/man3/getcwd.3.html
[stdin.3]: http://man7.org/linux/man-pages/man3/stdin.3.html
[filesystems.5]: http://man7.org/linux/man-pages/man5/filesystems.5.html
[capabilities.7]: http://man7.org/linux/man-pages/man7/capabilities.7.html
[namespaces.7]: http://man7.org/linux/man-pages/man7/namespaces.7.html
[pid_namespaces.7]: http://man7.org/linux/man-pages/man7/pid_namespaces.7.html
[user_namespaces.7]: http://man7.org/linux/man-pages/man7/user_namespaces.7.html
[switch_root.8.notes]: http://man7.org/linux/man-pages/man8/switch_root.8.html#NOTES

[sd_listen_fds]: http://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
