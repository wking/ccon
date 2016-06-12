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

## Dependencies

* A [POSIX shell][sh.1] for `sh`.
* [GNU Core Utilities][coreutils] for [`cat`][cat.1], [`echo`][echo.1],
  [`env`][env.1], [`head`][head.1], [`id`][id.1], [`pwd`][pwd.1],
  [`readlink`][readlink.1], [`touch`][touch.1], [`test`][test.1], and
  [`tty`][tty.1].
* [Grep][] for [`grep`][grep.1].
* [net-tools][] for [`hostname`][hostname.1].
* [Sed][] for [`sed`][sed.1].
* [BusyBox][] for `busybox`.
* [iproute2][] for [`ip`][ip.8].
* [libcap-ng][] for [`captest`][captest.8].

[BusyBox]: http://www.busybox.net/
[coreutils]: http://www.gnu.org/software/coreutils/coreutils.html
[Grep]: https://www.gnu.org/software/grep/
[iproute2]: http://www.linuxfoundation.org/collaborate/workgroups/networking/iproute2
[libcap-ng]: http://people.redhat.com/sgrubb/libcap-ng/
[net-tools]: http://net-tools.sourceforge.net/
[prove]: http://perldoc.perl.org/prove.html
[sed]: http://sed.sourceforge.net/
[Sharness]: http://mlafeldt.github.io/sharness/
[submodule]: http://git-scm.com/docs/git-submodule

[cat.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/cat.html
[echo.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/echo.html
[env.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/env.html
[grep.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/grep.html
[head.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/head.html
[hostname.1]: http://man7.org/linux/man-pages/man1/hostname.1.html
[id.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/id.html
[pwd.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pwd.html
[sed.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/sed.html
[sh.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html
[readlink.1]: http://man7.org/linux/man-pages/man1/readlink.1.html
[test.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/test.html
[touch.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/touch.html
[tty.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/tty.html
[captest.8]: https://fedorahosted.org/libcap-ng/browser/trunk/utils/captest.8
[ip.8]: https://git.kernel.org/cgit/linux/kernel/git/shemminger/iproute2.git/tree/man/man8/ip.8?id=v4.2.0