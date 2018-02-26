#!/bin/sh
#
# Copyright (C) 2018 W. Trevor King <wking@tremily.us>
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

test_description='Test console (and its interaction with process terminal)'

. ./sharness.sh

test_expect_success BUSYBOX,!ROOT 'Test unprivileged console unset' "
	test_expect_code 1 ccon --config-string '{
		  \"version\": \"0.5.0\",
		  \"process\": {
		    \"args\": [\"busybox\", \"sh\", \"-c\", \"test -t 3 3>>/dev/console\"]
		  }
		}' >actual &&
	test_expect_code 1 busybox sh -c 'test -t 3 3>>/dev/console' >expected &&
	test_cmp expected actual
"

test_expect_success BUSYBOX,ROOT 'Test privileged console unset' "
	ccon --config-string '{
		  \"version\": \"0.5.0\",
		  \"process\": {
		    \"args\": [\"busybox\", \"sh\", \"-c\", \"test -t 3 3>>/dev/console\"]
		  }
		}' >actual &&
	busybox sh -c 'test -t 3 3>>/dev/console' >expected &&
	test_cmp expected actual
"

test_expect_success PRINTF,SHELL 'Test console' "
	ccon --verbose --config-string '{
		  \"version\": \"0.5.0\",
		  \"namespaces\": {
		    \"user\": {},
		    \"mount\": {}
		  },
		  \"console\": true,
		  \"process\": {
		    \"args\": [\"sh\", \"-c\", \"echo hello >>/dev/console\"]
		  }
		}' >actual &&
	printf 'hello\r\n' >expected &&
	test_cmp expected actual
"

test_expect_success PRINTF,SHELL 'Test console and terminal' "
	ccon --verbose --config-string '{
		  \"version\": \"0.5.0\",
		  \"namespaces\": {
		    \"user\": {},
		    \"mount\": {}
		  },
		  \"console\": true,
		  \"process\": {
		    \"terminal\": true,
		    \"args\": [\"sh\", \"-c\", \"echo hello >>/dev/console && echo goodbye\"]
		  }
		}' >actual &&
	printf 'hello\r\ngoodbye\r\n' >expected &&
	test_cmp expected actual
"

test_done
