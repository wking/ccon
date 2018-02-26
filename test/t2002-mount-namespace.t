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

test_description='Test mount namespaces'

. ./sharness.sh

test_expect_success READLINK 'Test mount namespace creation' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"namespaces\": {
		    \"user\": {},
		    \"mount\": {}
		  },
		  \"process\": {
		    \"args\": [\"readlink\", \"/proc/self/ns/mnt\"]
		  }
		}' >container &&
	readlink /proc/self/ns/mnt >host &&
	test_must_fail test_cmp host container
"

test_expect_success TOUCH 'Test mount namespace read-only mount' "
	test_expect_code 1 ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"namespaces\": {
		    \"user\": {},
		    \"mount\": {
		      \"mounts\": [
		        {
		          \"target\": \"/\",
		          \"flags\": [
		            \"MS_REMOUNT\",
		            \"MS_BIND\",
		            \"MS_RDONLY\"
		          ]
		        }
		      ]
		    }
		  },
		  \"process\": {
		    \"args\": [\"touch\", \"/mount-test\"]
		  }
		}' 2>actual &&
	echo \"touch: cannot touch '/mount-test': Read-only file system\" >expected &&
	test_cmp expected actual
"

test_expect_success BUSYBOX,ID 'Test mount namespace pivot root' "
	mkdir -p rootfs &&
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
		          \"source\": \"rootfs\",
		          \"target\": \"rootfs\",
		          \"flags\": [
		            \"MS_BIND\"
		          ]
		        },
		        {
		          \"source\": \"rootfs\",
		          \"type\": \"pivot-root\"
		        }
		      ]
		    }
		  },
		  \"process\": {
		    \"args\": [\"/bin/busybox\", \"ls\", \"-a\", \"/\"],
		    \"host\": true
		  }
		}' >actual &&
	cat <<-EOF >expected &&
		.
		..
	EOF
	test_cmp expected actual
"

test_expect_success BUSYBOX,ID 'Test mount namespace creates destination directories' "
	mkdir -p rootfs &&
	ccon --verbose --config-string '{
		  \"version\": \"0.4.0\",
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
		          \"target\": \"/tmp/\",
		          \"type\": \"tmpfs\"
		        },
		        {
		          \"target\": \"/tmp/foo/bar\",
		          \"type\": \"tmpfs\"
		        }
		      ]
		    }
		  },
		  \"process\": {
		    \"args\": [\"/bin/busybox\", \"ls\", \"/tmp/foo\"],
		    \"host\": true
		  }
		}' >actual &&
	cat <<-EOF >expected &&
		bar
	EOF
	test_cmp expected actual
"

test_done
