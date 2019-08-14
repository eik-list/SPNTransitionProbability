# Transition probability for Substitution-Permutation Networks
Simple C/C++ code for experimenting with the transition probabilities of the
number of active bytes per column in AES-like ciphers. The Z-table is
essentially the distribution of the number of active bytes per column through
the MixColumns operation in AES.


## Dependencies
- A C++ compiler. Per default, `g++` is declared in the `Makefile`, but this 
  can be changed to `clang++` or any other at your own choice.

- Victor Shoup's NTL library:
  https://www.shoup.net/ntl/
  
- `make` for building.

- At Aug 2019, the build process was simplified to `cmake`. On current Linux
  distributions, `sudo apt install cmake` should install it.
  
- Unfortunately, I am a fan of tests. So the `gtest` extension for `cmake` is
  required to build with it. On current Linux distributions, `sudo apt-get
  install libgtest-dev` should install `gtest`. Moreover, it needs pthreads in
  any form on the system.

 

## Building
- If `make`, a C++ compiler, and the NTL library are installed, you can simply 
  type `make` in the command-line and the default target `transition_matrix` 
  will be built. 

- Typing `make transition_matrix` also builds the target `transition_matrix` 
  for you.

- If `cmake` with `gtest` is installed, typing `cmake .` should make all tests.


## Usage
- Executing `transition_matrix` computes the difference of the transition
  probabilities for the AES (p_{AES}) and that of a random permutation 
  (p_{rand}) and outputs p_{AES} - p_{rand}.

- There are various tests in the `tests` directory that can be built separately
  with `make <the_test_of_choice>:

  - `test_aes_column_transition_algorithm` executes various selected tests for
    the transition through round-reduced AES. Take a look into the
    `tests/test_aes_column_transition_algorithm.cc` file for what is tested and
    adapt to your needs.

  - `test_aes_byte_transition_algorithm` executest various selected tests for
    the transition through round-reduced AES, but traces individual active and
    inactive bytes through r-round AES.

  - `test_small_aes_byte_transition_algorithm` works similarly as
    `test_aes_byte_transition_algorithm` for Small-AES, a version with 4-bit
    S-boxes.

  - `test_all_aes_column_transitions` executes all single column input-output
    patterns through 2-8 rounds of the AES.

  - `test_all_aes_byte_transitions` executes all single active-byte
    input-output patterns through 2-8 rounds of the AES.

  - `test_all_small_aes_column_transitions` executes all single column
    input-output patterns through 2-8 rounds of Small-AES.

  - `test_all_small_aes_byte_transitions` executes all single active-byte
    input-output patterns through 2-8 rounds of Small-AES.

  - `test_byte_pattern_generator` just checks if a helper class that derives
    all active-byte patterns from a given active-bytes-in-columns-pattern works
    as expected.



## Author/Reference
Sondre Rønjom: A Short Note on a Weight Probability Distribution Related to
SPNs. IACR Cryptology ePrint Archive 2019: 750 (2019).
https://eprint.iacr.org/2019/750.pdf

