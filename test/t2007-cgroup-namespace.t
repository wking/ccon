#!/bin/sh
#
# Copyright (C) 2016-2018 W. Trevor King <wking@tremily.us>
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

test_description='Test cgroup namespaces'

. ./sharness.sh

test_expect_success ID,READLINK 'Test cgroup namespace creation' "
	ccon --config-string '{
		  \"version\": \"0.5.0\",
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
		    \"cgroup\": {}
		  },
		  \"process\": {
		    \"args\": [
		      \"readlink\",
		      \"/proc/self/ns/cgroup\"
		    ]
		  }
		}' >container &&
	readlink /proc/self/ns/cgroup >host &&
	test_must_fail test_cmp host container
"

test_done
