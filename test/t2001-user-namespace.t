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

test_description='Test user namespaces'

. ./sharness.sh

test_expect_success CAT,ID,SHELL 'Test user namespace creation' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"namespaces\": {
		    \"user\": {}
		  },
		  \"process\": {
		    \"args\": [\"sh\", \"-c\", \"id -u && id -g\"]
		  }
		}' >actual &&
	cat <<-EOF >expected &&
		$(cat /proc/sys/kernel/overflowuid)
		$(cat /proc/sys/kernel/overflowgid)
	EOF
	test_cmp expected actual
"

test_expect_success CAT,ID,SHELL 'Test user namespace ID mapping' "
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
		    }
		  },
		  \"process\": {
		    \"args\": [\"sh\", \"-c\", \"id -u && id -g\"]
		  }
		}' >actual &&
	cat <<-EOF >expected &&
		0
		0
	EOF
	test_cmp expected actual
"

test_expect_success CAT,ECHO,GREP,ID,!ROOT,SED 'Test unprivileged user must deny setgroups before mapping GIDs' "
	test_expect_code 1 ccon --verbose --config-string '{
		  \"version\": \"0.1.0\",
		  \"namespaces\": {
		    \"user\": {
		      \"gidMappings\": [
		        {
		          \"containerID\": 0,
		          \"hostID\": $(id -u),
		          \"size\": 1
		        }
		      ]
		    }
		  },
		  \"process\": {
		    \"args\": [\"echo\", \"hello\"]
		  }
		}' 2>actual &&
	sed 's|proc/[0-9][0-9]*/|proc/###/|g' actual >actual-no-pid &&
	grep gid_map actual-no-pid >actual-gid-map &&
	cat <<-EOF >expected &&
		write '0 $(id -u) 1' to /proc/###/gid_map
		failed to write '0 $(id -u) 1' to /proc/###/gid_map
	EOF
	test_cmp expected actual-gid-map
"

test_expect_success ECHO,ID,ROOT 'Test privileged user can call setgroups' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"namespaces\": {
		    \"user\": {
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
		          \"size\": 3
		        }
		      ]
		    }
		  },
		  \"process\": {
		    \"user\": {
		      \"additionalGids\": [1, 2]
		    },
		    \"args\": [\"id\", \"-G\"]
		  }
		}' >actual &&
	echo '0 1 2' >expected &&
	test_cmp expected actual
"

test_done
