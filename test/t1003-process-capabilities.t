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

test_description='Test process capabilities'

. ./sharness.sh

command -v captest && test_set_prereq CAPTEST

test_expect_success CAPTEST 'Test process.capabilities unset' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"captest\", \"--text\"]
		  }
		}' >actual &&
	captest --text >expected &&
	test_cmp expected actual
"

test_expect_success CAPTEST 'Test process.capabilities empty array' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"capabilities\": [],
		    \"args\": [\"captest\", \"--text\"]
		  }
		}' >actual &&
	grep 'Current capabilities' actual >actual-capabilities &&
	echo 'Current capabilities: none' >expected &&
	test_cmp expected actual-capabilities
"

test_expect_success CAPTEST,CAT,ROOT 'Test privileged process.capabilities' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"capabilities\": [\"CAP_NET_BIND_SERVICE\", \"CAP_NET_RAW\"],
		    \"args\": [\"captest\", \"--text\"]
		  }
		}' >actual &&
	cat <<-EOF >expected &&
		Child User  credentials uid:0 euid:0 suid:0
		Child Group credentials gid:0 egid:0 sgid:0
		Child Effective: net_bind_service, net_raw
		Child Permitted: net_bind_service, net_raw
		Child Inheritable: net_bind_service, net_raw
		Child Bounding Set: net_bind_service, net_raw
		Child securebits flags: none
		User  credentials uid:0 euid:0 suid:0
		Group credentials gid:0 egid:0 sgid:0
		Effective: net_bind_service, net_raw
		Permitted: net_bind_service, net_raw
		Inheritable: net_bind_service, net_raw
		Bounding Set: net_bind_service, net_raw
		securebits flags: none
		Attempting direct access to shadow...SUCCESS
		Attempting to access shadow by child process...SUCCESS
	EOF
	test_cmp expected actual
"

test_expect_success CAPTEST,CAT,GREP,!ROOT 'Test unprivileged process.capabilities' "
	test_expect_code 1 ccon --verbose --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"capabilities\": [\"CAP_NET_BIND_SERVICE\", \"CAP_NET_RAW\"],
		    \"args\": [\"captest\", \"--text\"]
		  }
		}' 2>actual &&
	grep -B3 -A1 'apply specified capabilities' actual >actual-captest &&
	cat <<-EOF >expected-captest &&
		remove all capabilities from the scratch space
		restore CAP_NET_BIND_SERVICE capability to scratch space
		restore CAP_NET_RAW capability to scratch space
		apply specified capabilities to bounding and traditional sets
		failed to apply capabilities
	EOF
	test_cmp expected-captest actual-captest
"

test_expect_success CAPTEST,CAT,ROOT 'Test privileged hook capabilities' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"capabilities\": [\"CAP_NET_BIND_SERVICE\", \"CAP_NET_RAW\"],
		        \"args\": [\"captest\", \"--text\"]
		      }
		    ]
		  }
		}' >actual &&
	cat <<-EOF >expected &&
		Child User  credentials uid:0 euid:0 suid:0
		Child Group credentials gid:0 egid:0 sgid:0
		Child Effective: net_bind_service, net_raw
		Child Permitted: net_bind_service, net_raw
		Child Inheritable: net_bind_service, net_raw
		Child Bounding Set: net_bind_service, net_raw
		Child securebits flags: none
		User  credentials uid:0 euid:0 suid:0
		Group credentials gid:0 egid:0 sgid:0
		Effective: net_bind_service, net_raw
		Permitted: net_bind_service, net_raw
		Inheritable: net_bind_service, net_raw
		Bounding Set: net_bind_service, net_raw
		securebits flags: none
		Attempting direct access to shadow...SUCCESS
		Attempting to access shadow by child process...SUCCESS
	EOF
	test_cmp expected actual
"

test_done
