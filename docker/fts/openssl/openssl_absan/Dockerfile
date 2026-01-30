FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -ldl"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -ldl"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=openssl_fuzzer

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

ENV AFL_USE_ASAN=1

#add UBSan
#removing null and function as they produce a violation in every input
ENV SANITIZER_FLAGS_undefined "-fsanitize=array-bounds,bool,builtin,enum,integer-divide-by-zero,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,integer-divide-by-zero,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr"
ENV CFLAGS="${CFLAGS} ${SANITIZER_FLAGS_undefined}"
ENV CXXFLAGS="${CXXFLAGS} ${SANITIZER_FLAGS_undefined}"

#RUN apt install -y libgcrypt-dev

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
RUN echo "hi" > in/in
RUN mkdir $OUT/runtime/
COPY runtime/* $OUT/runtime/

ENV DOCKER_NAME=openssl
