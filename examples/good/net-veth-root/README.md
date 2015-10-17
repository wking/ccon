Launch [netcat][]'s echo listener in new [network][namespaces.7] and
[user][user_namespaces.7] namespaces listening on an internal bridge.

Once the container process has launched `nc`, you can ping it from
your host with:

    $ echo 'hello' | nc -q 1 10.0.0.2 80

The caller must have [`CAP_NET_ADMIN`][capabilities.7] in the [user
namespace][user_namespaces.7] that owns the host network namespace
(more detail on capability inheritance in the [host-networking
example](../net-host-root)).

The new user namespace (and `-U --preserve-credentials` options passed
to [`nsenter`][nsenter.1]) allow you to create the new network
namespace without having [`CAP_SYS_ADMIN`][capabilities.7].

The hooks touch a few portions of your host network namespace, so feel
free to adjust the config if any of the values conflict with your host
system.  Pre-start actions:

1. Create a new bridge, `ccon-ex-bridge`.
2. Assign it `10.0.0.1/24` ([`10/8` is private IPv4 address
   space][rfc1918.3], and `10.0.0.0` is [the network as a
   whole][rfc922.7]).
3. Enable it.
4. Create a new [veth pair][namespaces.7], `ccon-ex-veth0` and
   `ccon-ex-veth1`.
5. Set `ccon-ex-veth0`'s master to `ccon-ex-bridge` and enable it.
6. Move `ccon-ex-veth1` to the container's network namespace.
8. Enable `lo` in the new namespace.
9. Assign `10.0.0.2/24` to `ccon-ex-veth1`.  
10. Assign `00:00:6c:00:00:00` to `ccon-ex-veth1` and enable it
    (`00:00:6a` is the lowest-numbered private listing in the [IEEE
    MA-L][MA-L], and [all lower entries are assigned][MA-L.txt]).
11. Set 10.0.0.1 (`ccon-ex-bridge`) as the container's default route.

Post-stop actions:

1. Delete `ccon-ex-veth0`.  In most cases the veth pair is removed by
   the kernel with the death the container process and subsequent
   removal of the network namespace holding `ccon-ex-veth1`.  However,
   it's possible that a pre-start hook failed between veth creation
   and shifting `ccon-ex-veth1` into the child namespace.  It's also
   possible that the kernel is still in the process of cleaning up the
   network namespace and hasn't gotten around to removing the the veth
   pair yet.  This hook cleans up the veth pair if `ccon-ex-veth0`
   still exists, and fails without adverse side effects if it has
   already been removed.
2. Disable `ccon-ex-bridge`.
3. Delete `ccon-ex-bridge`.

## Hook dependencies

* [bridge-utils][] for [`brctl`][brctl.8].
* [iproute2][] for [`ip`][ip.8].
* [util-linux][] for [`nsenter`][nsenter.1] ([`ip link set DEVICE netns
  PID`][ip-link.8] accepts PIDs instead of network namespace names,
  but [`ip netns exec NETNSNAME …`][ip-netns.8] does not, probably
  because it needs a name to setup its [`/etc/netns/NETNSNAME/…` bind
  mounts][ip-netns.8]).

## External access

In order to reach the container network from *outside* the host
system, you'll need to enable [forwarding][ip.7] on the bridge and
your external interface with something like (using
[`sysctl`][sysctl.8] from [procps][]):

    # sysctl net.ipv4.conf.ccon-ex-bridge.forwarding=1
    # sysctl net.ipv4.conf.enp2s0.forwarding=1

The remote host will need a [route][ip-route.8] like:

    # ip route add 10.0.0.0/24 via 192.168.0.2

where 192.168.0.2 is the IP address of the ccon-running host.

[MA-L]: http://standards.ieee.org/develop/regauth/oui/
[MA-L.txt]: https://services13.ieee.org/RST/standards-ra-web/rest/assignments/download/?registry=MA-L&format=txt
[rfc922.7]: https://tools.ietf.org/html/rfc922#section-7
[rfc1918.3]: https://tools.ietf.org/html/rfc1918#section-3

[bridge-utils]: http://www.linuxfoundation.org/collaborate/workgroups/networking/bridge
[iproute2]: http://www.linuxfoundation.org/collaborate/workgroups/networking/iproute2
[netcat]: http://nc110.sourceforge.net/
[procps]: https://gitlab.com/procps-ng/procps
[util-linux]: https://www.kernel.org/pub/linux/utils/util-linux/

[nsenter.1]: http://www.man7.org/linux/man-pages/man1/nsenter.1.html
[capabilities.7]: http://man7.org/linux/man-pages/man7/capabilities.7.html
[ip.7]: http://man7.org/linux/man-pages/man7/ip.7.html
[namespaces.7]: http://man7.org/linux/man-pages/man7/namespaces.7.html
[user_namespaces.7]: http://man7.org/linux/man-pages/man7/user_namespaces.7.html
[brctl.8]: http://man7.org/linux/man-pages/man8/brctl.8.html
[ip.8]: http://man7.org/linux/man-pages/man8/ip.8.html
[ip-link.8]: https://git.kernel.org/cgit/linux/kernel/git/shemminger/iproute2.git/tree/man/man8/ip-link.8.in?id=v4.2.0
[ip-netns.8]: http://man7.org/linux/man-pages/man8/ip-netns.8.html
[ip-route.8]: http://man7.org/linux/man-pages/man8/ip-route.8.html
[iptables.8]: http://man7.org/linux/man-pages/man8/iptables.8.html
[sysctl.8]: http://man7.org/linux/man-pages/man8/sysctl.8.html
