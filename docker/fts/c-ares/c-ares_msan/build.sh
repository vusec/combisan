git clone https://github.com/c-ares/c-ares.git c-ares
cd c-ares
git reset --hard 51fbb479f7948fca2ace3ff34a15ff27e796afdd
./buildconf
./configure --disable-shared
make -j $(nproc)
$CXX $CXXFLAGS $SRC/target.cc -I . .libs/libcares.a $LIB_FUZZING_ENGINE -o $EXECUTABLE_NAME_BASE

cp ./$EXECUTABLE_NAME_BASE $OUT
