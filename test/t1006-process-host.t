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

test_description='Test process host'

. ./sharness.sh

command -v busybox && test_set_prereq BUSYBOX

test_expect_success BUSYBOX,CAT,GREP,ID 'Test process.host unset' "
	test_expect_code 1 ccon --verbose --config-string '{
		  \"version\": \"0.2.0\",
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
		    \"mount\": {
		      \"mounts\": [
		        {
		          \"source\": \".\",
		          \"target\": \".\",
		          \"flags\": [
		            \"MS_BIND\"
		          ]
		        },
		        {
		          \"source\": \".\",
		          \"type\": \"pivot-root\"
		        }
		      ]
		    }
		  },
		  \"process\": {
		    \"args\": [\"busybox\", \"echo\", \"hello\"]
		  }
		}' 2>actual &&
	grep -B1 'execvpe' actual >actual-exec &&
	cat <<-EOF >expected-exec &&
		execute: busybox echo hello
		execvpe: No such file or directory
	EOF
	test_cmp expected-exec actual-exec
"

test_expect_success BUSYBOX,ECHO,ID 'Test process.host' "
	ccon --config-string '{
		  \"version\": \"0.2.0\",
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
		    \"mount\": {
		      \"mounts\": [
		        {
		          \"source\": \".\",
		          \"target\": \".\",
		          \"flags\": [
		            \"MS_BIND\"
		          ]
		        },
		        {
		          \"source\": \".\",
		          \"type\": \"pivot-root\"
		        }
		      ]
		    }
		  },
		  \"process\": {
		    \"host\": true,
		    \"args\": [\"busybox\", \"echo\", \"hello\"]
		  }
		}' >actual &&
	echo 'hello' >expected &&
	test_cmp expected actual
"

test_done
