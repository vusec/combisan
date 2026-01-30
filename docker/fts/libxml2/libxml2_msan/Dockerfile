FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=libxml2_fuzzer

#copy relevant files
COPY build.sh $SRC
COPY target.cc $SRC

RUN apt install -y libtool autoconf automake python-dev liblzma-dev pkg-config zlib1g-dev

ENV AFL_USE_MSAN=1
#ENV LD_LIBRARY_PATH=$MSAN_LIBS
RUN cp $MSAN_LIBS/* /usr/local/lib/x86_64-unknown-linux-gnu/
RUN cp $MSAN_LIBS/* /usr/lib/x86_64-linux-gnu/

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
RUN echo "hi" > in/in
RUN cp /src/aflplusplus/dictionaries/xml.dict $OUT

ENV DICT="-x xml.dict"
