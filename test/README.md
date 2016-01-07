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

[prove]: http://perldoc.perl.org/prove.html
[Sharness]: http://mlafeldt.github.io/sharness/
[submodule]: http://git-scm.com/docs/git-submodule
