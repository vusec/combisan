FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=libxml2_fuzzer

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

RUN apt install -y libtool autoconf automake python-dev liblzma-dev pkg-config zlib1g-dev

ENV AFL_USE_ASAN=1

#add UBSan
#For this project, we disable "function" as it causes a false positive
ENV SANITIZER_FLAGS_undefined "-fsanitize=array-bounds,bool,builtin,enum,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr"
ENV CFLAGS="${CFLAGS} ${SANITIZER_FLAGS_undefined}"
ENV CXXFLAGS="${CXXFLAGS} ${SANITIZER_FLAGS_undefined}"

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
RUN echo "hi" > in/in
RUN cp /src/aflplusplus/dictionaries/xml.dict $OUT

ENV DICT="-x xml.dict"
