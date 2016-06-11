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

test_description='Test process user'

. ./sharness.sh

test_expect_success ID 'Test process.user.uid unset' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"id\", \"-u\"]
		  }
		}' >actual &&
	id -u >expected &&
	test_cmp expected actual
"

test_expect_success ID 'Test process.user.gid unset' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"id\", \"-g\"]
		  }
		}' >actual &&
	id -g >expected &&
	test_cmp expected actual
"

test_expect_success ID 'Test process.user.additionalGids unset' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"args\": [\"id\", \"-G\"]
		  }
		}' >actual &&
	id -G >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,ID,ROOT 'Test privileged process.user.uid' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"user\": {
		      \"uid\": 1
		    },
		    \"args\": [\"id\", \"-u\"]
		  }
		}' >actual &&
	echo '1' >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,ID,ROOT 'Test privileged process.user.gid' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"user\": {
		      \"gid\": 1
		    },
		    \"args\": [\"id\", \"-g\"]
		  }
		}' >actual &&
	echo '1' >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,ID,ROOT 'Test privileged process.user.additionalGids' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
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

test_expect_success ECHO,GREP,ID,!ROOT 'Test unprivileged process.user.uid' "
	test_expect_code 1 ccon --verbose --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"user\": {
		      \"uid\": 1
		    },
		    \"args\": [\"id\", \"-u\"]
		  }
		}' 2>actual &&
	grep -B1 'setuid' actual >actual-setuid &&
	echo 'set UID to 1' >expected-setuid &&
  echo 'setuid: Operation not permitted' >>expected-setuid &&
	test_cmp expected-setuid actual-setuid
"

test_expect_success ECHO,GREP,ID,!ROOT 'Test unprivileged process.user.gid' "
	test_expect_code 1 ccon --verbose --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"user\": {
		      \"gid\": 1
		    },
		    \"args\": [\"id\", \"-u\"]
		  }
		}' 2>actual &&
	grep -B1 'setgid' actual >actual-setgid &&
	echo 'set GID to 1' >expected-setgid &&
  echo 'setgid: Operation not permitted' >>expected-setgid &&
	test_cmp expected-setgid actual-setgid
"

test_expect_success ECHO,GREP,ID,!ROOT 'Test unprivileged process.user.additionalGids' "
	test_expect_code 1 ccon --verbose --config-string '{
		  \"version\": \"0.1.0\",
		  \"process\": {
		    \"user\": {
		      \"additionalGids\": [1, 2]
		    },
		    \"args\": [\"id\", \"-G\"]
		  }
		}' 2>actual &&
	grep -B1 'setgroups' actual >actual-setgroups &&
	echo 'set additional GIDs to [1, 2]' >expected-setgroups &&
  echo 'setgroups: Operation not permitted' >>expected-setgroups &&
	test_cmp expected-setgroups actual-setgroups
"

test_expect_success ECHO,ID,ROOT 'Test privileged hook user.uid' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"user\": {
		          \"uid\": 1
		        },
		        \"args\": [\"id\", \"-u\"]
		      }
		    ]
		  }
		}' >actual &&
	echo '1' >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,ID,ROOT 'Test privileged hook user.gid' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"user\": {
		          \"gid\": 1
		        },
		        \"args\": [\"id\", \"-g\"]
		      }
		    ]
		  }
		}' >actual &&
	echo '1' >expected &&
	test_cmp expected actual
"

test_expect_success ECHO,ID,ROOT 'Test privileged hook user.additionalGids' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {
		        \"user\": {
		          \"additionalGids\": [1, 2]
		        },
		        \"args\": [\"id\", \"-G\"]
		      }
		    ]
		  }
		}' >actual &&
	echo '0 1 2' >expected &&
	test_cmp expected actual
"

test_done
