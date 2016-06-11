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

test_description='Test option parsing'

. ./sharness.sh

test_expect_success ECHO,HEAD 'Test --help' '
	ccon --help >actual &&
	head -n1 actual >actual-first-line &&
	echo "usage: ccon [OPTION]..." >expected &&
	test_cmp expected actual-first-line
'

test_expect_success ECHO 'Test --version' '
	ccon --version >actual &&
	echo "ccon 0.4.0" >expected &&
	test_cmp expected actual
'

test_expect_success CAT,ECHO 'Test --config' "
	cat <<-EOF >cfg.json &&
		{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {\"args\": [\"echo\", \"test\", \"--config\"]}
		    ]
		  }
		}
	EOF
	ccon --config cfg.json >actual 2>&1 &&
	echo 'test --config' >expected &&
	test_cmp expected actual
"

test_expect_success ECHO 'Test --config-string' "
	ccon --config-string '{
		  \"version\": \"0.1.0\",
		  \"hooks\": {
		    \"pre-start\": [
		      {\"args\": [\"echo\", \"test\", \"--config-string\"]}
		    ]
		  }
		}' >actual 2>&1 &&
	echo 'test --config-string' >expected &&
	test_cmp expected actual
"

test_expect_success CAT,SED 'Test --verbose' "
	ccon --verbose --config-string '{\"version\": \"0.1.0\"}' 2>actual &&
	sed 's/[0-9][0-9]*/###/g' actual >actual-no-PID &&
	cat <<-EOF >expected &&
		launched container process with PID ###
		process not defined, exiting
		container process ### exited with ###
	EOF
	test_cmp expected actual-no-PID
"

test_done
