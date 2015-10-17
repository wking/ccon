Launch [netcat][]'s echo listener in the host [network
namespace][namespaces.7] listening on port 80.

Keep [`CAP_NET_BIND_SERVICE`][capabilities.7], which we need to
[`bind`][bind.2] a [low numbered port][services.5].

The caller must have [`CAP_NET_BIND_SERVICE`][capabilities.7] in the
[user namespace][user_namespaces.7] that owns the network namespace.
For example, with a namespace tree like

* Root user and network namespaces
  * Child user namespace (call it `user1`)
    * Child network namespace (call it `net2`)

then a caller starting in `net2` must already have
[`CAP_NET_BIND_SERVICE`][capabilities.7] in `user1` to successfully
execute this configuration.

Because we're not creating a new [user namespace][user_namespaces.7],
the caller must also have [`CAP_SYS_ADMIN`][capabilities.7] to create
the new [network namespace][namespaces.7].  For an examples creating
new network and user namespaces at the same time, see the [veth
example](../net-veth-root) and the [unpriviledged net
example](../net-new).

[netcat]: http://nc110.sourceforge.net/

[bind.2]: http://man7.org/linux/man-pages/man2/bind.2.html
[services.5]: http://man7.org/linux/man-pages/man5/services.5.html
[capabilities.7]: http://man7.org/linux/man-pages/man7/capabilities.7.html
[namespaces.7]: http://man7.org/linux/man-pages/man7/namespaces.7.html
[user_namespaces.7]: http://man7.org/linux/man-pages/man7/user_namespaces.7.html
