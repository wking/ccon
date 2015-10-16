Examples are organized in two classes:

* [good](good) examples show how to successfully accomplish a
  particular task (e.g. [bind to a low numbered port in a new
  network namespace](good/net-new)).

* [bad](bad) examples explain why some tasks are not possible
  (e.g. [bind to a low numbered port in a host network namespace where
  the caller doesn't already have
  `CAP_NET_BIND_SERVICE`](bad/net-host)).
