FROM compiler

#fts flags
ENV CFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++"
ENV CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++"

#dummy executable name
ENV EXECUTABLE_NAME_BASE=guetzli_fuzzer

#copy relevant files
COPY build.sh $SRC

RUN apt install -y libpng-dev pkg-config

#add UBSan
ENV CFLAGS="${CFLAGS} ${SANITIZER_FLAGS_undefined}"
ENV CXXFLAGS="${CXXFLAGS} ${SANITIZER_FLAGS_undefined}"

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
