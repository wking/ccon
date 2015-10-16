Examples of successful patterns:

* Privileged user calling ccon:
  * [Bind to a low numbered port in the host network
    namespace](net-host-root).

* Unprivileged user calling ccon:
  * [Bind to a low numbered port in a new network namespace](net-new)
    (via a new user namespace).
