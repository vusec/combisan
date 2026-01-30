
git clone https://github.com/google/woff2.git SRC
cd SRC
git reset --hard 9476664fd6931ea6ec532c94b816d8fbbe3aed90
cd ../
git clone https://github.com/google/brotli.git BROTLI
cd BROTLI
git reset --hard 3a9032ba8733532a6cd6727970bade7f7c0e2f52
cd ../
git clone https://github.com/FontFaceKit/roboto.git seeds
cd seeds
git reset --hard 0e41bf923e2599d651084eece345701e55a8bfde
cd ../
rm -f *.o
for f in font.cc normalize.cc transform.cc woff2_common.cc woff2_dec.cc woff2_enc.cc glyph.cc table_tags.cc variable_length.cc woff2_out.cc; do
  $CXX $CXXFLAGS -std=c++11  -I BROTLI/dec -I BROTLI/enc -c SRC/src/$f &
done
for f in BROTLI/dec/*.c BROTLI/enc/*.cc; do
  $CXX $CXXFLAGS -c $f &
done
wait

set -x
$CXX $CXXFLAGS *.o $LIB_FUZZING_ENGINE $SRC/target.cc -I SRC/src -o $EXECUTABLE_NAME_BASE

cp ./$EXECUTABLE_NAME_BASE $OUT
