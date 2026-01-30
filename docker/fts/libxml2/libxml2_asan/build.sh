
git clone https://gitlab.gnome.org/GNOME/libxml2.git libxml2
cd libxml2
git reset --hard v2.9.2
./autogen.sh 
CCLD="$CXX $CXXFLAGS" ./configure --disable-shared 
make -j 8
$CXX $CXXFLAGS -std=c++11 $SRC/target.cc -I include .libs/libxml2.a $LIB_FUZZING_ENGINE -lz -o $EXECUTABLE_NAME_BASE

cp ./$EXECUTABLE_NAME_BASE $OUT
