FROM combisan

#fts flags
ENV UBSAN_FLAGS=""
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize-recover=address ${UBSAN_FLAGS}  -stdlib=libc++"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize-recover=address ${UBSAN_FLAGS}  -stdlib=libc++"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=re2_fuzzer

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

ENV AFL_USE_ASAN=1

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
RUN echo "{}" > in/in

COPY ${EXECUTABLE_NAME_BASE}_afl $OUT

ENV COMBISAN_UNINSTRUMENTED=${EXECUTABLE_NAME_BASE}_afl
