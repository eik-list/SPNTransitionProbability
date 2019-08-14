/**
 * Copyright 2019 anonymized
 */

#include <iostream>
#include <sstream>

#include "small_aes_byte_transition_algorithm.h"

// ------------------------------------------------------------------------

static void setUp(SmallAESByteTransitionAlgorithm &algorithm) {
    algorithm.readZTable("../data/z_table_small_aes.bin");
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(SmallAESByteTransitionAlgorithm &algorithm) {

}

// ------------------------------------------------------------------------

static void buildFirstByteZeroOutputInterests(std::bitset<65536> &distribution) {
    for (size_t bytePatternAsInt = 1;
         bytePatternAsInt < 65536; ++bytePatternAsInt) {
        const bool isFirstByteInactive = (bytePatternAsInt & 1) == 0;
        distribution[bytePatternAsInt] = isFirstByteInactive;
    }
}

// ------------------------------------------------------------------------

static void
buildAtLeastOneZeroColumnOutputInterests(std::bitset<65536> &distribution) {
    for (size_t bytePatternAsInt = 0x0000;
         bytePatternAsInt <= 0xFFFF; ++bytePatternAsInt) {
        const bool isColumn0Inactive = (bytePatternAsInt & 0xF000) == 0;
        const bool isColumn1Inactive = (bytePatternAsInt & 0x0F00) == 0;
        const bool isColumn2Inactive = (bytePatternAsInt & 0x00F0) == 0;
        const bool isColumn3Inactive = (bytePatternAsInt & 0x000F) == 0;
        distribution[bytePatternAsInt] = (isColumn0Inactive ||
            isColumn1Inactive ||
            isColumn2Inactive ||
            isColumn3Inactive);
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

static void
testFourRoundSingleByteDistinguisher() {
    SmallAESByteTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 4;
    std::bitset<65536> outputInterests;
    buildFirstByteZeroOutputInterests(outputInterests);

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

    NTL::RR distance = probabilityForAES - probabilityForPRP;
    distance.SetOutputPrecision(100);

    std::cout << NUM_ROUNDS << " "
              << "1000000000000000" << " "
              << "0***************" << " "
              << probabilityForAES << " "
              << probabilityForPRP << " "
              << distance
              << std::endl;

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testFiveRoundSingleByteDistinguisher() {
    SmallAESByteTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    std::bitset<65536> outputInterests;
    buildFirstByteZeroOutputInterests(outputInterests);

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

static void testFiveRoundSingleByteToDiagonalDistinguisher() {
    SmallAESByteTransitionAlgorithm algorithm;
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

int main() {
    testFourRoundSingleByteDistinguisher();
    testFiveRoundSingleByteDistinguisher();
    testFiveRoundSingleByteToDiagonalDistinguisher();
    return EXIT_SUCCESS;
}
