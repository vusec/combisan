git clone https://github.com/google/re2.git re2
cd re2
git reset --hard 499ef7eff7455ce9c9fae86111d4a77b6ac335de
sed -i 's/int RunningOnValgrind() {/int RunningOnValgrind() {  return true;/g' util/valgrind.cc
make clean
make -j 8 obj/libre2.a
set -x
$CXX $CXXFLAGS $SRC/target.cc -I ./ ./obj/libre2.a -lpthread $LIB_FUZZING_ENGINE -o $EXECUTABLE_NAME_BASE

cp ./$EXECUTABLE_NAME_BASE $OUT

