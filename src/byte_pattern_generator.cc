/**
 * Copyright 2019 anonymized
 */

#include "byte_pattern_generator.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>

// ------------------------------------------------------------------------

namespace utils {

    BytePatternGenerator::BytePatternGenerator() {
        createActiveBytePatterns();
    }

    void BytePatternGenerator::createActiveBytePatterns() {
        ACTIVE_BYTE_PATTERNS = {
            {{0, 0, 0, 0}},
            {{0, 0, 0, 1}, {0, 0, 1, 0}, {0, 1, 0, 0}, {1, 0, 0, 0}},
            {{0, 0, 1, 1}, {0, 1, 0, 1}, {0, 1, 1, 0}, {1, 0, 0, 1},
                {1, 0, 1, 0}, {1, 1, 0, 0}},
            {{0, 1, 1, 1}, {1, 0, 1, 1}, {1, 1, 0, 1}, {1, 1, 1, 0}},
            {{1, 1, 1, 1}}
        };
    }

    // ------------------------------------------------------------------------

    void BytePatternGenerator::initialize(const uint8_t columnPattern[4]) {
        for (size_t i = 0; i < 4; ++i) {
            _columnPattern[i] = columnPattern[i];
        }

        _current = 0;
        _numPatterns = getNumElements(_columnPattern);
        getNumSubPatterns(columnPattern, _numSubPatterns);
    }

    // ------------------------------------------------------------------------

    void
    BytePatternGenerator::getNumSubPatterns(const uint8_t columnPattern[4],
                                            uint8_t numSubPatterns[4]) const {
        for (size_t i = 0; i < 4; ++i) {
            numSubPatterns[i] = binomialCoefficients[columnPattern[i]];
        }
    }

    // ------------------------------------------------------------------------

    size_t
    BytePatternGenerator::getNumElements(const uint8_t columnPattern[4]) const {
        size_t result = 1;

        for (size_t i = 0; i < 4; ++i) {
            result *= binomialCoefficients[columnPattern[i]];
        }

        return result;
    }

    // ------------------------------------------------------------------------

    bool BytePatternGenerator::hasNext() const {
        return _current < _numPatterns;
    }

    // ------------------------------------------------------------------------

    void BytePatternGenerator::next(uint8_t bytePattern[4][4]) {
        if (!hasNext()) {
            return;
        }

        uint8_t columnIndices[4];

        patternIndexToBytePatternIndices(_current,
                                         _numSubPatterns,
                                         columnIndices);
        toActiveBytePattern(_columnPattern, columnIndices, bytePattern);

        _current++;
    }

    // ------------------------------------------------------------------------

    /**
     * @example Let activeColumnPattern = [1, 3, 0, 2] be a column-activity
     * pattern. Then, there are
     * binom(4, 1) = 4 options for Column 0,
     * binom(4, 3) = 4 options for Column 1,
     * binom(4, 0) = 1 option for Column 2, and
     * binom(4, 2) = 6 options for Column 3.
     * So, there are 4 * 4 * 1 * 6 = 96 possible patterns in total.
     * We expect moduli to be [4, 4, 1, 6] then.
     * Given some patternIndex in [0..95], e.g. 42, we want to have the corres-
     * ponding pattern.
     *
     * For each column, we simply order byte patterns for the column lexico-
     * graphically, e.g.,
     * - for 1 active byte, the order is [0001, 0010, 0100, 1000].
     * - for 2 active bytes, the order is [0011, 0101, 0110, 1001, 1010, 1100].
     * - for 3 active bytes, the order is [0111, 1011, 1101, 1110].
     *
     * 42 will produce columnIndices [1, 3, 0, 0], which means
     * - Column pattern 1 of 1 active byte for Column 0: 0010
     * - Column pattern 3 of 3 active bytes for Column 1: 1110
     * - Column pattern 0 of 0 active bytes for Column 2: 0000
     * - Column pattern 0 of 2 active bytes for Column 3: 0011.
     *
     * So, the output will be [0010, 1110, 0000, 0011].
     *
     * We map 42 to [1, 3, 0, 0] by:
     * - 42 mod 6 = 0 => 0-th pattern of Column 3
     *   (42 - 0) / 6 = 7
     * -  7 mod 1 = 0 => 0-th pattern of Column 2
     *   (7 - 0) / 1 = 7
     * -  7 mod 4 = 3 => 3-rd pattern of Column 1
     *   (7 - 3) / 4 = 1
     * -  1 mod 4 = 1 => 1-st pattern of Column 0
     *
     * @param patternIndex
     * @param numSubPatterns
     * @param columnIndices
     */
    void BytePatternGenerator::patternIndexToBytePatternIndices(
        const size_t patternIndex,  // 42
        const uint8_t numSubPatterns[4],  // [4, 4, 1, 6]
        uint8_t columnIndices[4]) const {  // [1, 3, 0, 2]
        size_t index = patternIndex;

        for (size_t i = 0; i < 4; ++i) {
            size_t remainder = index % numSubPatterns[3 - i];
            columnIndices[3 - i] = static_cast<uint8_t >(remainder);
            index = (index - remainder) / numSubPatterns[3 - i];
        }
    }

    // ------------------------------------------------------------------------

    void BytePatternGenerator::toActiveBytePattern(
        const uint8_t columnPattern[4],  // [1, 3, 0, 2]
        const uint8_t columnPatternIndices[4],  // [1, 3, 0, 0]
        uint8_t bytePattern[4][4]) const {  // [0010, 1101, 0000, 0011]
        for (size_t i = 0; i < 4; ++i) {
            // In order: 1, 3, 0, 2
            const uint8_t numActiveBytesInCol = columnPattern[i];
            // In order: 1, 3, 0, 0
            const uint8_t patternIndex = columnPatternIndices[i];

            for (size_t j = 0; j < 4; ++j) {
                bytePattern[i][j] =
                    ACTIVE_BYTE_PATTERNS[numActiveBytesInCol][patternIndex][j];
            }
        }
    }

    // ------------------------------------------------------------------------

    void BytePatternGenerator::reset() {
        _current = 0;
    }

}  // namespace utils
