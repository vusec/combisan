FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=woff2_fuzzer

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

ENV AFL_USE_ASAN=1

#add UBSan
ENV CFLAGS="${CFLAGS} ${SANITIZER_FLAGS_undefined}"
ENV CXXFLAGS="${CXXFLAGS} ${SANITIZER_FLAGS_undefined}"

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT
RUN cp -r $SRC/seeds/* in/
