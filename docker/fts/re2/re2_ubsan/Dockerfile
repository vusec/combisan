FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=re2_fuzzer

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

#add UBSan
ENV CFLAGS="${CFLAGS} ${SANITIZER_FLAGS_undefined}"
ENV CXXFLAGS="${CXXFLAGS} ${SANITIZER_FLAGS_undefined}"

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
RUN echo "{}" > in/in
