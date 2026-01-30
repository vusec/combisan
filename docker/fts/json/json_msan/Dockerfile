FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=json_fuzzer

#copy relevant files
COPY build.sh $SRC

#msan stuff
ENV AFL_USE_MSAN=1
#ENV LD_LIBRARY_PATH=$MSAN_LIBS
RUN cp $MSAN_LIBS/* /usr/local/lib/x86_64-unknown-linux-gnu/
RUN cp $MSAN_LIBS/* /usr/lib/x86_64-linux-gnu/

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
COPY seeds/* in/

RUN cp $AFL/dictionaries/json.dict $OUT
ENV DICT="-x json.dict"

ENV DOCKER_NAME=json
