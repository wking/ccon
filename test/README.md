# Ccon test suite

Ccon uses the [Sharness][] test harness, installed as a [Git
submodule][submodule].  To setup the test installation after a clone,
run:

    $ git submodule update --init

which will checkout the appropriate Sharness commit in the `sharness`
directory (after which the `Makefile`, `sharness.sh`, etc. symlinks
will resolve successfully).

Run the tests with:

    $ make

And read the `Makefile` source to find other useful targets
(e.g. [`prove`][prove]).

## Naming

Tests are named `tNNNN-short-description.t`, where N is a decimal
digit.  The first digit classifies the test:

0 - Basic ccon functionality like command-line argument parsing.

1 - Process-configuration compliance.

2 - Namespace-configuration compliance.

3 - Interactions with related tools (like
    [`ccon-cli`](../README.md#socket-communication)).

## Dependencies

* A [POSIX shell][sh.1] for `sh` and [`wait`][wait.1].
* [GNU Core Utilities][coreutils] for [`cat`][cat.1], [`echo`][echo.1],
  [`env`][env.1], [`head`][head.1], [`id`][id.1], [`printf`][printf.1],
  [`pwd`][pwd.1], [`readlink`][readlink.1], [`sleep`][sleep.1],
  [`touch`][touch.1], [`test`][test.1], [`timeout`][timeout.1], and
  [`tty`][tty.1].
* [Grep][] for [`grep`][grep.1].
* [net-tools][] for [`hostname`][hostname.1].
* [Sed][] for [`sed`][sed.1].
* [BusyBox][] for `busybox`.
* [iproute2][] for [`ip`][ip.8].
* [inotify-tools][] for [`inotifywait.1`][inotifywait.1].
* [libcap-ng][] for [`captest`][captest.8].

[BusyBox]: http://www.busybox.net/
[coreutils]: https://www.gnu.org/software/coreutils/coreutils.html
[Grep]: https://www.gnu.org/software/grep/
[iproute2]: https://wiki.linuxfoundation.org/networking/iproute2
[inotify-tools]: https://github.com/rvoicilas/inotify-tools/wiki
[libcap-ng]: http://people.redhat.com/sgrubb/libcap-ng/
[net-tools]: http://net-tools.sourceforge.net/
[prove]: http://perldoc.perl.org/prove.html
[sed]: http://sed.sourceforge.net/
[Sharness]: https://chriscool.github.io/sharness/
[submodule]: https://git-scm.com/docs/git-submodule

[cat.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/cat.html
[echo.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/echo.html
[env.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/env.html
[grep.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/grep.html
[head.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/head.html
[hostname.1]: http://man7.org/linux/man-pages/man1/hostname.1.html
[id.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/id.html
[inotifywait.1]: http://man7.org/linux/man-pages/man1/inotifywait.1.html
[printf.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/printf.html
[pwd.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pwd.html
[sed.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/sed.html
[sh.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html
[sleep.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/sleep.html
[readlink.1]: http://man7.org/linux/man-pages/man1/readlink.1.html
[test.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/test.html
[timeout.1]: http://man7.org/linux/man-pages/man1/timeout.1.html
[touch.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/touch.html
[tty.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/tty.html
[wait.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/wait.html
[captest.8]: https://github.com/stevegrubb/libcap-ng/blob/v0.7.9/utils/captest.8
[ip.8]: https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/man/man8/ip.8?h=v4.2.0
