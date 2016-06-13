Examples of successful patterns:

* Privileged user calling ccon:
  * [Bind to a low numbered port in the host network
    namespace](net-host-root).
  * [Create a new network namespace bridged to the host and bind to a
    low numbered port in the new network namespace](net-veth-root).
  * [Create a container, execute a process inside it, and delete the
    container with separate steps](create-exec-delete-root).

* Unprivileged user calling ccon:
  * [Launch a container process that pivots to a local
    root](pivot-root).
  * [Bind to a low numbered port in a new network namespace](net-new)
    (via a new user namespace).
  * [Launch a container process in a new freezer cgroup, removing that
    cgroup on exit](cgroups).
  * Launch a container from an OCI bundle
    * [OCI v0.1.0](oci/0.1.0)
    * [OCI v0.5.0](oci/0.5.0)
    * [OCI v1.0.0-rc1](oci/1.0.0-rc1)
