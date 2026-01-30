git clone https://github.com/openssl/openssl.git openssl
cd openssl
git reset --hard OpenSSL_1_0_1f
CC="$CC $CFLAGS" ./config
CCLD="$CXX $CXXFLAGS" ./configure --disable-shared
make clean
make
$CXX $CXXFLAGS $SRC/target.cc -DCERT_PATH=\"$SRC/\"  ./libssl.a ./libcrypto.a $LIB_FUZZING_ENGINE -I ./include -o $EXECUTABLE_NAME_BASE

cp ./$EXECUTABLE_NAME_BASE $OUT
