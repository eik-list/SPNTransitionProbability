/**
 * Copyright 2019 anonymized
 */

#include "column_pattern_generator.h"

#include <cstdint>
#include <cstdlib>

#include <iostream>

// ------------------------------------------------------------------------

namespace utils {

    ColumnPatternGenerator::ColumnPatternGenerator() = default;

    // ------------------------------------------------------------------------

    void ColumnPatternGenerator::initialize(const uint8_t columnPattern[4]) {
        for (size_t i = 0; i < 4; ++i) {
            _columnPattern[i] = columnPattern[i];
        }

        _current = 0;
        _numPatterns = getNumElements(_columnPattern);
    }

    // ------------------------------------------------------------------------

    size_t
    ColumnPatternGenerator::getNumElements(
        const uint8_t columnPattern[4]) const {
        size_t result = 1;

        for (size_t i = 0; i < 4; ++i) {
            result *= binomialCoefficients[columnPattern[i]];
        }

        return result;
    }

    // ------------------------------------------------------------------------

    bool ColumnPatternGenerator::hasNext() const {
        return _current < _numPatterns;
    }

    // ------------------------------------------------------------------------

    void next(uint8_t columnPattern[4]) {
    }

    // ------------------------------------------------------------------------

    void reset() {
    }

}  // namespace utils
