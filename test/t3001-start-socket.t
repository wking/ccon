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

test_description='Test start socket'

. ./sharness.sh

test_expect_success BUSYBOX,TIMEOUT 'Test socket blocks without start' "
	test_expect_code 124 timeout 1 ccon --socket sock --config-string '{
		  \"version\": \"0.5.0\",
		  \"process\": {
		    \"args\": [\"busybox\", \"echo\", \"hello\"]
		  }
		}'
"

test_expect_success BUSYBOX,ECHO,GREP,INOTIFYWAIT,SLEEP,WAIT 'Test start with empty config' "
	mkdir -p sock &&
	> wait &&
	(
		inotifywait -e create sock 2>>wait &&
		ccon-cli --socket sock/sock --config-string ''
	) &
	while ! grep '^Watches established.$' wait
	do
		sleep 0
	done &&
	ccon --socket sock/sock --config-string '{
		  \"version\": \"0.5.0\",
		  \"process\": {
		    \"args\": [\"busybox\", \"echo\", \"hello\"]
		  }
		}' >actual &&
	wait &&
	echo 'hello' >expected &&
	test_cmp expected actual
"

test_expect_success BUSYBOX,ECHO,GREP,INOTIFYWAIT,SLEEP,WAIT 'Test start with process config' "
	mkdir -p sock &&
	> wait &&
	(
		inotifywait -e create sock 2>>wait &&
		ccon-cli --socket sock/sock --config-string '{
			  \"args\": [\"busybox\", \"echo\", \"goodbye\"]
			}'
	) &
	while ! grep '^Watches established.$' wait
	do
		sleep 0
	done &&
	ccon --socket sock/sock --config-string '{
		  \"version\": \"0.5.0\"
		}' >actual &&
	wait &&
	echo 'goodbye' >expected &&
	test_cmp expected actual
"

test_expect_success BUSYBOX,ECHO,GREP,ID,INOTIFYWAIT,SLEEP,WAIT 'Test start with process.host' "
	mkdir -p sock &&
	> wait &&
	(
		inotifywait -e create sock 2>>wait &&
		ccon-cli --socket sock/sock --config-string '{
		    \"host\": true,
			  \"args\": [\"busybox\", \"echo\", \"goodbye\"]
			}'
	) &
	while ! grep '^Watches established.$' wait
	do
		sleep 0
	done &&
	ccon --socket sock/sock --config-string '{
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
		  }
		}' >actual &&
	wait &&
	echo 'goodbye' >expected &&
	test_cmp expected actual
"

test_expect_success BUSYBOX,ECHO,GREP,INOTIFYWAIT,SLEEP,WAIT 'Test recover container process exit code' "
	mkdir -p sock &&
	> wait &&
	(
		inotifywait -e create sock 2>>wait &&
		ccon-cli --socket sock/sock --config-string '{
			  \"args\": [\"busybox\", \"sh\", \"-c\", \"exit 124\"]
			}'
	) &
	while ! grep '^Watches established.$' wait
	do
		sleep 0
	done &&
	test_expect_code 124 ccon --socket sock/sock --config-string '{
		  \"version\": \"0.5.0\"
		}' &&
	wait
"

test_done
