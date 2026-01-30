# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM compiler
RUN apt-get update && apt-get install -y make cmake autoconf pkg-config libtool
RUN git clone https://github.com/vstakhov/libucl

RUN cd libucl && git reset --hard 8a0294f9eaa4e70342e562cb92792bbe3df90e70

WORKDIR $SRC

COPY build.sh $SRC/
COPY ucl_add_string_fuzzer.options $SRC/ucl_add_string_fuzzer.options

RUN $SRC/build.sh

WORKDIR $OUT

ENV EXECUTABLE_NAME_BASE=ucl_add_string_fuzzer
