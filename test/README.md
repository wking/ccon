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

## Dependencies

* A [POSIX shell][sh.1] for `sh`.
* [GNU Core Utilities][coreutils] for [`cat`][cat.1], [`echo`][echo.1],
  [`head`][head.1], [`id`][id.1], [`pwd`][pwd.1], [`test`][test.1],
  and [`tty`][tty.1].
* [Grep][] for [`grep`][grep.1].
* [Sed][] for [`sed`][sed.1].
* [BusyBox][] for `busybox`.
* [libcap-ng][] for [`captest`][captest.8].

[BusyBox]: http://www.busybox.net/
[coreutils]: http://www.gnu.org/software/coreutils/coreutils.html
[Grep]: https://www.gnu.org/software/grep/
[libcap-ng]: http://people.redhat.com/sgrubb/libcap-ng/
[prove]: http://perldoc.perl.org/prove.html
[sed]: http://sed.sourceforge.net/
[Sharness]: http://mlafeldt.github.io/sharness/
[submodule]: http://git-scm.com/docs/git-submodule

[cat.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/cat.html
[echo.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/echo.html
[grep.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/grep.html
[head.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/head.html
[id.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/id.html
[pwd.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pwd.html
[sed.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/sed.html
[sh.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html
[test.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/test.html
[tty.1]: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/tty.html
[captest.8]: https://fedorahosted.org/libcap-ng/browser/trunk/utils/captest.8
