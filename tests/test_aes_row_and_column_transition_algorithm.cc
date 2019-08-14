/**
 * Copyright 2019 anonymized
 */

#include <iostream>

#include "aes_row_and_column_transition_algorithm.h"

// ------------------------------------------------------------------------

static bool assertEquals(const NTL::RR &expected,
                         const NTL::RR &actual) {

    if (expected != actual) {
        std::cerr << "Expected "
                  << expected
                  << " but was "
                  << actual
                  << std::endl;
    }

    return static_cast<bool>(expected == actual);
}

// ------------------------------------------------------------------------

static void setUp(AESRowAndColumnTransitionAlgorithm &algorithm) {
    algorithm.readZTable("../data/z_table_aes.bin");
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(AESRowAndColumnTransitionAlgorithm &algorithm) {

}

// ------------------------------------------------------------------------

static void buildOutputInterests(bool distribution[5][5][5][5][5][5][5][5]) {
    for (size_t column0 = 0; column0 < 5; column0++) {
        for (size_t column1 = 0; column1 < 5; column1++) {
            for (size_t column2 = 0; column2 < 5; column2++) {
                for (size_t column3 = 0; column3 < 5; column3++) {

                    for (size_t row0 = 0; row0 < 5; row0++) {
                        for (size_t row1 = 0; row1 < 5; row1++) {
                            for (size_t row2 = 0; row2 < 5; row2++) {
                                for (size_t row3 = 0;
                                     row3 < 5; row3++) {
                                    distribution[column0][column1][column2][column3][row0][row1][row2][row3] = (
                                        column0 == 0 || column1 == 0 ||
                                        column2 == 0 || column3 == 0);
                                }
                            }
                        }
                    }

                }
            }
        }
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

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 * This encodes the 5-round expectation distinguisher from
 * https://eprint.iacr.org/2018/182.
 */
static void testFiveRoundDiagonalDistinguisher() {
    AESRowAndColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5][5][5][5][5];
    buildOutputInterests(outputInterests);

    NTL::vec_RR inputDistribution;
    algorithm.buildFirstDiagonalDistribution(inputDistribution);

    NTL::RR probabilityForAES;
    algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                             inputDistribution,
                                             outputInterests,
                                             NUM_ROUNDS);

    NTL::RR probabilityForPRP;
    algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                             outputInterests);

    printProbabilities(probabilityForAES, probabilityForPRP);

    const NTL::RR expectedProbabilityForAES = NTL::to_RR(
        0.9313230244917459214672303626407816985994e-9);
    const NTL::RR expectedProbabilityForPRP = NTL::to_RR(
        0.9313225742902178639298357677289701794083e-9);
    assertEquals(expectedProbabilityForAES, probabilityForAES);
    assertEquals(expectedProbabilityForPRP, probabilityForPRP);

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

int main() {
    testFiveRoundDiagonalDistinguisher();
    return EXIT_SUCCESS;
}
