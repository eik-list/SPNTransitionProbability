/**
 * Copyright 2019 anonymized
 */

#ifndef _BYTE_PATTERN_GENERATOR_H
#define _BYTE_PATTERN_GENERATOR_H

#include <stdint.h>
#include <stdlib.h>
#include <array>
#include <vector>

namespace utils {

    class BytePatternGenerator {
    public:

        BytePatternGenerator();

        /**
         * Resets the counter to 0 and stores the given column pattern.
         * @param columnPattern Array, where the i-th entry represents of the
         * number of active bytes in Column i.
         * @example [1, 3, 0, 2]
         */
        void initialize(const uint8_t columnPattern[4]);

        /**
         * Returns the number of active-byte patterns for the given column
         * pattern.
         * @param columnPattern Array, where the i-th entry represents of the
         * number of active bytes in Column i.
         * @example [1, 3, 0, 2] returns binom(4, 1) * binom(4, 3) *
         * binom(4, 0) * binom(4, 2) = 96.
         * @return
         */
        size_t getNumElements(const uint8_t columnPattern[4]) const;

        /**
         * Computes the column-wise number of active-byte patterns for the given
         * column pattern.
         * @param columnPattern Array, where the i-th entry represents of the
         * number of active bytes in Column i.
         * @param numSubPatterns
         * @example [1, 3, 0, 2] stores [binom(4, 1), binom(4, 3),
         * binom(4, 0), binom(4, 2)] = [4, 4, 1, 6] in numSubPatterns.
         */
        void getNumSubPatterns(const uint8_t columnPattern[4],
                               uint8_t numSubPatterns[4]) const;

        /**
         * @return True if there are more active-byte patterns to iterate
         * through, i.e., if the counter is 0 and initialize has been called.
         * False otherwise.
         */
        bool hasNext() const;

        /**
         * @param bytePattern If hasNext() is true, stores the next active-byte
         * pattern into bytePattern and increments the counter.
         * Does nothing otherwise.
         */
        void next(uint8_t bytePattern[4][4]);

        /**
         * Resets the counter to 0.
         */
        void reset();

    private:

        /**
         * Initializer for ACTIVE_BYTE_PATTERNS.
         */
        void createActiveBytePatterns();

        /**
         * Maps the index to the active-byte pattern index.
         * @param patternIndex
         * @param numSubPatterns
         * @param columnIndices
         * @example pattern index 42 and numSubPatterns of [4, 4, 1, 6]
         * yields [1, 3, 0, 0], which is stored in columnIndices.
         */
        void patternIndexToBytePatternIndices(size_t patternIndex,
                                              const uint8_t numSubPatterns[4],
                                              uint8_t columnIndices[4]) const;

        void toActiveBytePattern(const uint8_t columnPattern[4],
                                 const uint8_t columnPatternIndices[4],
                                 uint8_t bytePattern[4][4]) const;

        const uint8_t binomialCoefficients[5] = {1, 4, 6, 4, 1};
        uint8_t _columnPattern[4];
        size_t _numPatterns = 0;
        size_t _current = 0;
        uint8_t _numSubPatterns[4];

        std::vector<std::vector<std::array<uint8_t, 4> > > ACTIVE_BYTE_PATTERNS;

    };

}

#endif //_BYTE_PATTERN_GENERATOR_H
