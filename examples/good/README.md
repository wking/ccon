Examples of successful patterns:

* Privileged user calling ccon:
  * [Bind to a low numbered port in the host network
    namespace](net-host-root).
  * [Create a new network namespace bridged to the host and bind to a
    low numbered port in the new network namespace](net-veth-root).

* Unprivileged user calling ccon:
  * [Bind to a low numbered port in a new network namespace](net-new)
    (via a new user namespace).
  * [Launch a container process in a new freezer cgroup, removing that
    cgroup on exit](cgroups).
