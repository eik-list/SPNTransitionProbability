/**
 * Copyright 2019 anonymized
 */

#ifndef _COLUMN_PATTERN_GENERATOR_H
#define _COLUMN_PATTERN_GENERATOR_H

#include <stdint.h>
#include <stdlib.h>
#include <array>
#include <vector>

namespace utils {

    class ColumnPatternGenerator {
    public:

        ColumnPatternGenerator();

        /**
         * Resets the counter to 0 and stores the given column pattern.
         * @param columnPattern Array, where the i-th entry represents of the
         * number of active bytes in Column i.
         * @example [1, 3, 0, 2]
         */
        void initialize(const uint8_t columnPattern[4]);

        /**
         * Returns the number of active-column patterns for the given column
         * pattern.
         * @param columnPattern Array, where the i-th entry represents of the
         * number of active bytes in Column i.
         * @example [1, 3, 0, 2] returns (2 * 4 * 1 * 3) - 1 combinations
         * from the set product [0,1] x [0,1,2,3] x [0] x [0,1,2],
         * except [0,0,0,0].
         * @return
         */
        size_t getNumElements(const uint8_t columnPattern[4]) const;

        /**
         * @return True if there are more active-byte patterns to iterate
         * through, i.e., if the counter is 0 and initialize has been called.
         * False otherwise.
         */
        bool hasNext() const;

        /**
         * @param columnPattern If hasNext() is true, stores the next active-column
         * pattern into columnPattern and increments the counter.
         * Does nothing otherwise.
         */
        void next(uint8_t columnPattern[4]);

        /**
         * Resets the counter to 0.
         */
        void reset();

    private:
        const uint8_t binomialCoefficients[5] = {1, 4, 6, 4, 1};
        uint8_t _columnPattern[4];
        size_t _numPatterns = 0;
        size_t _current = 0;

    };

}

#endif //_COLUMN_PATTERN_GENERATOR_H
