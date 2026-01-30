FROM combisan

#fts flags
ENV UBSAN_FLAGS=""
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize-recover=address ${UBSAN_FLAGS}"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize-recover=address ${UBSAN_FLAGS}"



#dummy executable name
ENV EXECUTABLE_NAME_BASE=c-ares_fuzzer

#this specific project needs this, is it in common with all fts?
RUN apt install -y libtool

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

ENV DOCKER_NAME=c-ares

COPY ${EXECUTABLE_NAME_BASE}_afl $OUT

ENV COMBISAN_UNINSTRUMENTED=${EXECUTABLE_NAME_BASE}_afl
