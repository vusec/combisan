FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=woff2_fuzzer

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT
RUN cp -r $SRC/seeds/* in/
