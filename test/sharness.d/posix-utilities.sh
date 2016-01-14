# Copyright (C) 2016 W. Trevor King <wking@tremily.us>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

command -v cat >/dev/null 2>/dev/null && test_set_prereq CAT
command -v echo >/dev/null 2>/dev/null && test_set_prereq ECHO
command -v grep >/dev/null 2>/dev/null && test_set_prereq GREP
command -v head >/dev/null 2>/dev/null && test_set_prereq HEAD
command -v id >/dev/null 2>/dev/null && test_set_prereq ID
command -v pwd >/dev/null 2>/dev/null && test_set_prereq PWD
command -v sed >/dev/null 2>/dev/null && test_set_prereq SED
command -v test >/dev/null 2>/dev/null && test_set_prereq TEST
command -v tty >/dev/null 2>/dev/null && test_set_prereq TTY

true
