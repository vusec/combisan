FROM combisan

#fts flags
ENV UBSAN_FLAGS=""
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize-recover=address -stdlib=libc++ ${UBSAN_FLAGS}"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize-recover=address -stdlib=libc++ ${UBSAN_FLAGS}"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=guetzli_fuzzer

#copy relevant files
COPY build.sh $SRC

RUN apt install -y libpng-dev pkg-config

#msan stuff
ENV AFL_USE_ASAN=1

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
#COPY seeds/* in/
#COPY afl_5min.zip $OUT
#RUN unzip afl_5min.zip -d in/
COPY jpeg.dict .

ENV DOCKER_NAME=guetzli

#ENV DICT="-x jpeg.dict"

COPY ${EXECUTABLE_NAME_BASE}_afl $OUT

ENV COMBISAN_UNINSTRUMENTED=${EXECUTABLE_NAME_BASE}_afl
