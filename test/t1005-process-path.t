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

test_description='Test process path'

. ./sharness.sh

test_expect_success ECHO,SHELL 'Test process.path unset' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"sh\", \"-c\", \"echo \${0}\"]
		  }
		}' >actual &&
	echo 'sh' >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,SHELL 'Test process.path' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"path\": \"sh\",
		    \"args\": [\"shellac\", \"-c\", \"echo \${0}\"]
		  }
		}' >actual &&
	echo 'shellac' >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,SHELL 'Test hook path' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"path\": \"sh\",
		        \"args\": [\"shellac\", \"-c\", \"echo \${0}\"]
		      }
		    ]
		  }
		}' >actual &&
	echo 'shellac' >expected &&
	test_cmp expected actual
"

test_done
