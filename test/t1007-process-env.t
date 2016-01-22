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

test_description='Test process environment'

. ./sharness.sh

test_expect_success ENV,GREP 'Test process.env unset' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"env\"]
		  }
		}' >actual &&
	grep -v '^_' actual >actual-no-underscores &&
	env >expected &&
	grep -v '^_' expected >expected-no-underscores &&
	test_cmp expected-no-underscores actual-no-underscores
"

test_expect_success CAT,ENV 'Test process.env' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"env\"],
		    \"env\": [
		      \"PATH=/bin:/usr/bin\",
		      \"TERM=xterm\"
		    ]
		  }
		}' >actual &&
	cat <<-EOF >expected &&
		PATH=/bin:/usr/bin
		TERM=xterm
	EOF
	test_cmp expected actual
"

test_expect_success ENV 'Test process.env empty' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"env\"],
		    \"env\": []
		  }
		}' >actual &&
	>expected &&
	test_cmp expected actual
"

test_expect_success ENV,GREP 'Test hook env unset' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"args\": [\"env\"]
		      }
		    ]
		  }
		}' >actual &&
	grep -v '^_' actual >actual-no-underscores &&
	env >expected &&
	grep -v '^_' expected >expected-no-underscores &&
	test_cmp expected-no-underscores actual-no-underscores
"

test_expect_success CAT,ENV 'Test hook env' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"args\": [\"env\"],
		        \"env\": [
		          \"PATH=/bin:/usr/bin\",
		          \"TERM=xterm\"
		        ]
		      }
		    ]
		  }
		}' >actual &&
	cat <<-EOF >expected &&
		PATH=/bin:/usr/bin
		TERM=xterm
	EOF
	test_cmp expected actual
"

test_expect_success ENV 'Test hook env empty' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"args\": [\"env\"],
		        \"env\": []
		      }
		    ]
		  }
		}' >actual &&
	>expected &&
	test_cmp expected actual
"

test_done
