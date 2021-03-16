#!/bin/bash

if [ ! -d ./AFLplusplus ]; then
  git clone https://github.com/AFLplusplus/AFLplusplus.git
  cd AFLplusplus
  make
  cd ./unicorn_mode
  ./build_unicorn_support.sh
  cd ../../
fi
AFL_AUTORESUME=1 AFL_PATH="$(realpath ./AFLplusplus)" PATH="$AFL_PATH:$PATH" afl-fuzz -t 40 -i afl_inputs -o afl_outputs -U -- python3 ./airties5630_mips32.py @@
