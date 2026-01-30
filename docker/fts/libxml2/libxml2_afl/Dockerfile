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

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
RUN echo "hi" > in/in
RUN cp /src/aflplusplus/dictionaries/xml.dict $OUT

ENV DICT="-x xml.dict"
