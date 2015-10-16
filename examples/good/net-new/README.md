Launch [netcat][]'s echo listener in a new [network
namespace][namespaces.7] listening on port 80.

Create a [user namespace][user_namespaces.7] mapping the host user and
group 1000 (adjust to match your `id -u` and `id -g` settings) to the
container user and group 0, create a new [network
namespace][namespaces.7], and keep
[`CAP_NET_BIND_SERVICE`][capabilities.7] to give an unprivileged host
user the ability to [`bind`][bind.2] a [low numbered
port][services.5].

This example currently skips the virtual network device (“veth”) setup
described in the “Network namespaces” section of
[namespaces(7)][namespaces.7], so external users can't actually
*connect* to netcat without entering the container's network
namespace.  Once we get support for pre-start hooks, that would be a
good place to put the veth and bridging configuration.

[netcat]: http://nc110.sourceforge.net/

[bind.2]: http://man7.org/linux/man-pages/man2/bind.2.html
[services.5]: http://man7.org/linux/man-pages/man5/services.5.html
[capabilities.7]: http://man7.org/linux/man-pages/man7/capabilities.7.html
[namespaces.7]: http://man7.org/linux/man-pages/man7/namespaces.7.html
[user_namespaces.7]: http://man7.org/linux/man-pages/man7/user_namespaces.7.html
