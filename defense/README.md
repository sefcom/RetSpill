## Build LLVM
```bash
mkdir build && cd build
cmake -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release  -G "Unix Makefiles" ../llvm
```