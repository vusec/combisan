FROM combisan

#fts flags
ENV UBSAN_FLAGS="-fsanitize=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize-recover=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,returns-nonnull-attribute,shift,signed-integer-overflow,vla-bound,vptr"
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize-recover=address ${UBSAN_FLAGS}"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize-recover=address ${UBSAN_FLAGS}"
#dummy executable name
ENV EXECUTABLE_NAME_BASE=pcre2_fuzzer

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

RUN apt install -y libtool

ENV AFL_USE_ASAN=1

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
RUN echo "{}" > in/in
COPY pcre2_fuzzer.dict $OUT/

ENV DICT="-x pcre2_fuzzer.dict"

COPY ${EXECUTABLE_NAME_BASE}_afl $OUT

ENV COMBISAN_UNINSTRUMENTED=${EXECUTABLE_NAME_BASE}_afl

COPY crashes $OUT
