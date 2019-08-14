/**
 * Copyright 2019 anonymized
 */

#include <iostream>

#include <gtest/gtest.h>

#include "byte_pattern_generator.h"

// ------------------------------------------------------------------------

static void assertArrayEquals(const uint8_t *expected,
                              const uint8_t *actual,
                              const size_t numElements) {
    for (size_t i = 0; i < numElements; ++i) {
        ASSERT_EQ(expected[i], actual[i]);
    }
}

// ------------------------------------------------------------------------

TEST(BytePatternGenerator, test_repetition) {
    const uint8_t columnPattern[4] = {1, 3, 0, 2};
    uint8_t bytePattern[4][4];

    utils::BytePatternGenerator generator;
    generator.initialize(columnPattern);

    size_t numRuns = 0;

    while (generator.hasNext()) {
        generator.next(bytePattern);
        numRuns++;
    }

    ASSERT_EQ(96, numRuns);
}

// ------------------------------------------------------------------------

TEST(BytePatternGenerator, test_1302) {
    const uint8_t columnPattern[4] = {1, 3, 0, 2};
    const uint8_t subPatterns[4] = {4, 4, 1, 6};

    utils::BytePatternGenerator generator;
    generator.initialize(columnPattern);

    uint8_t actualSubPatterns[4];
    generator.getNumSubPatterns(columnPattern,
                                actualSubPatterns);
    assertArrayEquals(subPatterns, actualSubPatterns, 4);
    ASSERT_TRUE(generator.hasNext());
    ASSERT_EQ(96, generator.getNumElements(columnPattern));
}

// ------------------------------------------------------------------------

TEST(BytePatternGenerator, test_all_active) {
    const uint8_t columnPattern[4] = {4, 4, 4, 4};
    uint8_t bytePattern[4][4];

    utils::BytePatternGenerator generator;
    generator.initialize(columnPattern);

    ASSERT_TRUE(generator.hasNext());
    ASSERT_EQ(1, generator.getNumElements(columnPattern));

    generator.next(bytePattern);
    ASSERT_FALSE(generator.hasNext());
}

// ------------------------------------------------------------------------

TEST(BytePatternGenerator, test_none_active) {
    const uint8_t columnPattern[4] = {0, 0, 0, 0};
    uint8_t bytePattern[4][4];

    utils::BytePatternGenerator generator;
    generator.initialize(columnPattern);

    ASSERT_TRUE(generator.hasNext());
    ASSERT_EQ(1, generator.getNumElements(columnPattern));

    generator.next(bytePattern);
    ASSERT_FALSE(generator.hasNext());
}

// ---------------------------------------------------------

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
