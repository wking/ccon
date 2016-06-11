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

test_description='Test UTS namespaces'

. ./sharness.sh

command -v hostname >/dev/null 2>/dev/null && test_set_prereq HOSTNAME

test_expect_success HOSTNAME,ID,SHELL 'Test UTS namespace creation' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"namespaces\": {
		    \"user\": {
		      \"setgroups\": false,
		      \"uidMappings\": [
		        {
		          \"containerID\": 0,
		          \"hostID\": $(id -u),
		          \"size\": 1
		        }
		      ],
		      \"gidMappings\": [
		        {
		          \"containerID\": 0,
		          \"hostID\": $(id -u),
		          \"size\": 1
		        }
		      ]
		    },
		    \"uts\": {}
		  },
		  \"process\": {
		    \"args\": [
		      \"sh\", \"-c\",
		      \"hostname ccon && hostname\"
		    ]
		  }
		}' >actual &&
	echo 'ccon' >expected
	test_cmp expected actual
"

test_done
