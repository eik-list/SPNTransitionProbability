/**
 * Copyright 2019 anonymized
 */

#include <iostream>
#include <sstream>

#include "aes_byte_transition_algorithm.h"

// ------------------------------------------------------------------------

static void setUp(AESByteTransitionAlgorithm &algorithm) {
    algorithm.readZTable("../data/z_table_aes.bin");
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(AESByteTransitionAlgorithm &algorithm) {

}

// ------------------------------------------------------------------------

static void buildOutputInterests(std::bitset<65536> &distribution) {
    for (size_t bytePatternAsInt = 1;
         bytePatternAsInt < 65536; ++bytePatternAsInt) {
        const bool isFirstByteInactive = (bytePatternAsInt & 1) == 0;
        distribution[bytePatternAsInt] = isFirstByteInactive;
    }
}

// ------------------------------------------------------------------------

static void
buildFirstZeroByteOutputInterests(std::bitset<65536> &distribution) {
    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < 65536; ++bytePatternAsInt) {
        const bool isFirstByteInactive = ((bytePatternAsInt & 0x8000) == 0);
        distribution[bytePatternAsInt] = isFirstByteInactive;
    }
}

// ------------------------------------------------------------------------

static void
buildAtLeastOneZeroColumnOutputInterests(std::bitset<65536> &distribution) {
    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < 65536; ++bytePatternAsInt) {
        const bool isColumn0Inactive = (bytePatternAsInt & 0xF000) == 0;
        const bool isColumn1Inactive = (bytePatternAsInt & 0x0F00) == 0;
        const bool isColumn2Inactive = (bytePatternAsInt & 0x00F0) == 0;
        const bool isColumn3Inactive = (bytePatternAsInt & 0x000F) == 0;
        distribution[bytePatternAsInt] =
            isColumn0Inactive || isColumn1Inactive || isColumn2Inactive ||
            isColumn3Inactive;
    }
}

// ------------------------------------------------------------------------

static void
buildFirstThreeZeroColumnOutputInterests(std::bitset<65536> &distribution) {
    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < 65536; ++bytePatternAsInt) {
        const bool isColumn0Inactive = (bytePatternAsInt & 0xF000) == 0;
        const bool isColumn1Inactive = (bytePatternAsInt & 0x0F00) == 0;
        const bool isColumn2Inactive = (bytePatternAsInt & 0x00F0) == 0;
        distribution[bytePatternAsInt] =
            isColumn0Inactive && isColumn1Inactive && isColumn2Inactive;
    }
}

// ------------------------------------------------------------------------

static void printProbabilities(const NTL::RR &probabilityForAES,
                               NTL::RR &probabilityForPRP) {
    probabilityForAES.SetOutputPrecision(100);
    probabilityForPRP.SetOutputPrecision(100);

    std::cout << "P_aes:" << std::endl;
    std::cout << probabilityForAES << std::endl;

    std::cout << "P_rand:" << std::endl;
    std::cout << probabilityForPRP << std::endl;

    std::cout << "Difference:" << std::endl;
    std::cout << probabilityForAES - probabilityForPRP << std::endl;
}

// ------------------------------------------------------------------------

static void testFourRoundSingleByteToSingleByteDistinguisher() {
    AESByteTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 4;
    std::bitset<65536> outputInterests;
    buildFirstZeroByteOutputInterests(outputInterests);

    NTL::vec_RR inputDistribution;
    inputDistribution.SetLength(65536);
    inputDistribution[0].SetPrecision(400);
    algorithm.buildFirstByteDistribution(inputDistribution);

    NTL::RR probabilityForAES;
    algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                             inputDistribution,
                                             outputInterests,
                                             NUM_ROUNDS);

    NTL::RR probabilityForPRP;
    algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                             outputInterests);

    printProbabilities(probabilityForAES, probabilityForPRP);

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testFiveRoundSingleByteDistinguisher() {
    AESByteTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    std::bitset<65536> outputInterests;
    buildOutputInterests(outputInterests);

    NTL::vec_RR inputDistribution;
    inputDistribution.SetLength(65536);
    inputDistribution[0].SetPrecision(400);
    algorithm.buildFirstByteDistribution(inputDistribution);

    NTL::RR probabilityForAES;
    algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                             inputDistribution,
                                             outputInterests,
                                             NUM_ROUNDS);

    NTL::RR probabilityForPRP;
    algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                             outputInterests);

    printProbabilities(probabilityForAES, probabilityForPRP);

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testFiveRoundSingleByteToColumnDistinguisher() {
    AESByteTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    std::bitset<65536> outputInterests;
    buildAtLeastOneZeroColumnOutputInterests(outputInterests);

    NTL::vec_RR inputDistribution;
    inputDistribution.SetLength(65536);
    inputDistribution[0].SetPrecision(400);
    algorithm.buildFirstByteDistribution(inputDistribution);

    NTL::RR probabilityForAES;
    algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                             inputDistribution,
                                             outputInterests,
                                             NUM_ROUNDS);

    NTL::RR probabilityForPRP;
    algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                             outputInterests);

    printProbabilities(probabilityForAES, probabilityForPRP);

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testFiveRoundSingleByteToThreeColumnsDistinguisher() {
    AESByteTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    std::bitset<65536> outputInterests;
    buildFirstThreeZeroColumnOutputInterests(outputInterests);

    NTL::vec_RR inputDistribution;
    inputDistribution.SetLength(65536);
    inputDistribution[0].SetPrecision(400);
    algorithm.buildFirstByteDistribution(inputDistribution);

    NTL::RR probabilityForAES;
    algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                             inputDistribution,
                                             outputInterests,
                                             NUM_ROUNDS);

    NTL::RR probabilityForPRP;
    algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                             outputInterests);

    printProbabilities(probabilityForAES, probabilityForPRP);
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

int main() {
    testFourRoundSingleByteToSingleByteDistinguisher();

    testFiveRoundSingleByteDistinguisher();
    testFiveRoundSingleByteToColumnDistinguisher();
    testFiveRoundSingleByteToThreeColumnsDistinguisher();
    return EXIT_SUCCESS;
}
