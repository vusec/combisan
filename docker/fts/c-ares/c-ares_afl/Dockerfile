FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only"

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
