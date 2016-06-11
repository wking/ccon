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

test_description='Test PID namespaces'

. ./sharness.sh

test_expect_success ECHO,ID,SHELL 'Test PID namespace creation' "
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
		    \"pid\": {}
		  },
		  \"process\": {
		    \"args\": [\"sh\", \"-c\", \"echo \$\$\"]
		  }
		}' >actual &&
	echo 1 >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,ID,SHELL 'Test PID namespace mount proc' "
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
		    \"pid\": {},
		    \"mount\": {
		      \"mounts\": [
		        {
		          \"target\": \"/proc\",
		          \"flags\": [
		            \"MS_PRIVATE\",
		            \"MS_REC\"
		          ]
		        },
		        {
		          \"target\": \"/proc\",
		          \"type\": \"proc\",
		          \"flags\": [
		            \"MS_NOSUID\",
		            \"MS_NOEXEC\",
		            \"MS_NODEV\"
		          ]
		        }
		      ]
		    }
		  },
		  \"process\": {
		    \"args\": [\"sh\", \"-c\", \"echo /proc/[0-9]*\"]
		  }
		}' >actual &&
	echo /proc/1 >expected &&
	test_cmp expected actual
"

test_done
