#!/bin/sh
#
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

test_description='Test process terminal'

. ./sharness.sh

test_expect_success TTY 'Test process.terminal unset' "
	test_expect_code 1 ccon --config-string '{
		  \"version\": \"0.4.0\",
		  \"process\": {
		    \"args\": [\"tty\"]
		  }
		}' >actual &&
	test_expect_code 1 tty >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,SED,TTY 'Test process.terminal' "
	ccon --config-string '{
		  \"version\": \"0.4.0\",
		  \"process\": {
		    \"terminal\": true,
		    \"args\": [\"tty\"]
		  }
		}' >actual &&
	sed 's/[0-9][0-9]*[[:space:]]*$/###/g' actual >actual-no-number &&
	echo '/dev/pts/###' >expected &&
	test_cmp expected actual-no-number
"

test_expect_success TTY 'Test pre-start hook terminal unset' "
	test_expect_code 1 ccon --config-string '{
		  \"version\": \"0.4.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"args\": [\"tty\"]
		      }
		    ]
		  }
		}' >actual &&
	test_expect_code 1 tty >expected &&
	test_cmp expected actual
"

test_expect_success SED,TTY 'Test pre-start hook terminal stdin not a TTY' "
	test_expect_code 1 ccon --config-string '{
		  \"version\": \"0.4.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"terminal\": true,
		        \"args\": [\"tty\"]
		      }
		    ]
		  }
		}' >actual &&
	sed 's/[[:space:]]*$//' actual >actual-newlines &&
	test_expect_code 1 tty >expected &&
	test_cmp expected actual-newlines
"

test_expect_success CAT,GREP,SED 'Test pre-start hook terminal stdin has container PID' "
	ccon --verbose --config-string '{
		  \"version\": \"0.4.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"terminal\": true,
		        \"args\": [\"cat\"]
		      }
		    ]
		  }
		}' >actual 2>&1 &&
	CONTAINER_PID=\$(sed -n 's/launched container process with PID //p' actual) &&
	sed 's/[[:space:]]*$//' actual >actual-newlines &&
	grep -A1 'execute: cat' actual-newlines >actual-hook &&
	cat <<-EOF >expected &&
		execute: cat
		\${CONTAINER_PID}
	EOF
	test_cmp expected actual-hook
"

test_expect_success TEST 'Test pre-start hook terminal stdout' "
	ccon --config-string '{
		  \"version\": \"0.4.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"terminal\": true,
		        \"args\": [\"test\", \"-t\", \"1\"]
		      }
		    ]
		  }
		}'
"

test_expect_success TTY 'Test post-stop hook terminal unset' "
	ccon --config-string '{
		  \"version\": \"0.4.0\",
		  \"hooks\": {
		    \"post-stop\": [
		      {
		        \"args\": [\"tty\"]
		      }
		    ]
		  }
		}' >actual &&
	test_expect_code 1 tty >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,SED,TTY 'Test post-stop hook terminal' "
	ccon --config-string '{
		  \"version\": \"0.4.0\",
		  \"hooks\": {
		    \"post-stop\": [
		      {
		        \"terminal\": true,
		        \"args\": [\"tty\"]
		      }
		    ]
		  }
		}' >actual &&
	sed 's/[0-9][0-9]*[[:space:]]*$/###/g' actual >actual-no-number &&
	echo '/dev/pts/###' >expected &&
	test_cmp expected actual-no-number
"

test_done
