git clone https://github.com/PCRE2Project/pcre2.git pcre2
cd pcre2
git reset --hard 65457aa
./autogen.sh
CCLD="$CXX $CXXFLAGS" ./configure --disable-shared --enable-never-backslash-C --with-match-limit=1000 --with-match-limit-recursion=1000
make -j 8
set -x
$CXX $CXXFLAGS $SRC/target.cc -I ./src -Wl,--whole-archive ./.libs/*.a -Wl,-no-whole-archive $LIB_FUZZING_ENGINE -o $EXECUTABLE_NAME_BASE


cp ./$EXECUTABLE_NAME_BASE $OUT
