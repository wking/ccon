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

test_description='Test process cwd'

. ./sharness.sh

test_expect_success PWD 'Test process.cwd unset' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"pwd\"]
		  }
		}' >actual &&
	pwd >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,PWD 'Test process.cwd' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"cwd\": \"/tmp\",
		    \"args\": [\"pwd\"]
		  }
		}' >actual &&
	echo '/tmp' >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,PWD 'Test hook cwd' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"cwd\": \"/tmp\",
		        \"args\": [\"pwd\"]
		      }
		    ]
		  }
		}' >actual &&
	echo '/tmp' >expected &&
	test_cmp expected actual
"

test_done
