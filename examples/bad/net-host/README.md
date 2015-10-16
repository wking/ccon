Launch [netcat][]'s echo listener in the host [network
namespace][namespaces.7] listening on port 80.

Create a [user namespace][user_namespaces.7] mapping the host user and
group 1000 (adjust to match your `id -u` and `id -g` settings) to the
container user and group zero and keep
[`CAP_NET_BIND_SERVICE`][capabilities.7] to try and give a user
without sufficient privileges in the host namespace the ability to
[`bind`][bind.2] a [low numbered port][services.5].

Fails with:

```
$ ccon
launched container process with PID 16149
write '0 1000 1' to /proc/16149/uid_map
write 'deny' to /proc/16149/setgroups
write '0 1000 1' to /proc/16149/gid_map
set GID to 0
set UID to 0
remove all capabilities from the scratch space
restore CAP_NET_BIND_SERVICE capability to scratch space
apply specified capabilities to bounding and traditional sets
execute nc
Can't grab 0.0.0.0:80 with bind : Permission denied
container process 16149 exited with 1
```

[`user_namespaces(7)`][user_namespaces.7] discusses this limitation in
its “Capabilities” and “Interaction of user namespaces and other types
of namespaces” sections, with the key sentences being:

> When a user namespace is created, the kernel records the effective
> user ID of the creating process as being the “owner” of the
> namespace.

and

> When a process in the new namespace subsequently performs privileged
> operations that operate on global resources isolated by the
> namespace, the permission checks are performed according to the
> process's capabilities in the user namespace that the kernel
> associated with the new namespace.

So the host network namespace does not belong to the container's new
user namespace (it belongs a preexisting user namespace).  The fact
that we have UID zero and `CAP_NET_BIND_SERVICE` in the *container's*
user namespace doesn't matter.

[netcat]: http://nc110.sourceforge.net/

[bind.2]: http://man7.org/linux/man-pages/man2/bind.2.html
[services.5]: http://man7.org/linux/man-pages/man5/services.5.html
[capabilities.7]: http://man7.org/linux/man-pages/man7/capabilities.7.html
[namespaces.7]: http://man7.org/linux/man-pages/man7/namespaces.7.html
[user_namespaces.7]: http://man7.org/linux/man-pages/man7/user_namespaces.7.html
