git clone https://github.com/google/guetzli.git
cd guetzli
git reset --hard 9afd0bbb7db0bd3a50226845f0f6c36f14933b6b
make guetzli_static -j 8
set -x
$CXX $CXXFLAGS -std=c++11 fuzz_target.cc -I . bin/Release/libguetzli_static.a $LIB_FUZZING_ENGINE -o $EXECUTABLE_NAME_BASE

cp ./$EXECUTABLE_NAME_BASE $OUT
