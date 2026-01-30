
git clone https://github.com/nlohmann/json.git json
cd json
git reset --hard b04543ecc58188a593f8729db38c2c87abd90dc3
make fuzzers -Ctest -j $(nproc)
$CXX $CXXFLAGS -stdlib=libc++ -I ./src test/src/fuzzer-parse_json.cpp $LIB_FUZZING_ENGINE -o $EXECUTABLE_NAME_BASE

cp ./$EXECUTABLE_NAME_BASE $OUT
