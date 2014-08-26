#
# Feature testing shell scripting library
#
# Copyright 2014 Pedro A. Hortas (pah@ucodev.org)
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

test_lib()
{
	# test lib support
	echo 'int main(void) { return 0; }' > build/${1}.c && clang -o build/${1} build/${1}.c -l${1}

	if [ $? -eq 0 ]; then
		touch .l${1}
		echo -ne "-l${1} " >> .libs
	fi
}

