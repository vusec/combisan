FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++ -pthread"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++ -pthread"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=guetzli_fuzzer

#copy relevant files
COPY build.sh $SRC

RUN apt install -y libpng-dev pkg-config

#build
RUN ./build.sh

#setup fuzzing dir
WORKDIR $OUT

#empty seed for this one
#COPY seeds/* in/
#COPY afl_5min.zip $OUT
#RUN unzip afl_5min.zip -d in/
COPY jpeg.dict .

#ENV DICT="-x jpeg.dict"
