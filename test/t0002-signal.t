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

test_description='Test signal handling'

. ./sharness.sh

test_expect_success ECHO,KILL,SHELL 'Test SIGTERM forwarding to dummy process' "
	test_expect_code 1 ccon --verbose --config-string '{
		  \"version\": \"0.5.0\",
		  \"hooks\": {
		    \"post-create\": [
		      {\"args\": [\"sh\", \"-c\", \"kill -TERM \$(ps -o ppid= -p \$(cat))\"]}
		    ]
		  }
		}' 2>actual &&
	grep 'container killed' actual >actual-killed &&
	echo 'container killed (Terminated, 15)' >expected &&
	test_cmp expected actual-killed
"

test_done
