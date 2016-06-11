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

test_description='Test network namespaces'

. ./sharness.sh

command -v ip >/dev/null 2>/dev/null && test_set_prereq IP

test_expect_success IP 'Test network namespace creation' "
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
		    \"net\": {}
		  },
		  \"process\": {
		    \"args\": [\"ip\", \"address\"]
		  }
		}' >actual &&
	ip address >expected &&
	test_must_fail test_cmp expected actual
"

test_expect_success IP 'Test network namespace create veth pair' "
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
		    \"net\": {}
		  },
		  \"process\": {
		    \"args\": [
		      \"ip\", \"link\", \"add\", \"dev\", \"veth0\",
		      \"type\", \"veth\", \"peer\", \"name\", \"veth1\"
		    ]
		  }
		}'
"

test_done
