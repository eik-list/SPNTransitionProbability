/**
 * Copyright 2019 anonymized
 */

#include <iostream>
#include <sstream>

#include <gtest/gtest.h>

#include "aes_column_transition_algorithm.h"

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

static void setUp(AESColumnTransitionAlgorithm &algorithm) {
    algorithm.readZTable("../data/z_table_aes.bin");
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(AESColumnTransitionAlgorithm &algorithm) {

}

// ------------------------------------------------------------------------

static size_t
getNumZeroOutputColumns(const size_t v0,
                        const size_t v1,
                        const size_t v2,
                        const size_t v3) {
    size_t result = 0;

    if (v0 == 0) { result++; }
    if (v1 == 0) { result++; }
    if (v2 == 0) { result++; }
    if (v3 == 0) { result++; }

    return result;
}

// ------------------------------------------------------------------------

static void buildAllOutputInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = true;
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildAtLeastNZeroColumnOutputInterests(bool distribution[5][5][5][5],
                                       const size_t minNumZeroOutputColumns) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    const size_t numZeroOutputColumns = getNumZeroOutputColumns(
                        v0, v1, v2, v3);
                    distribution[v0][v1][v2][v3] =
                        (numZeroOutputColumns >= minNumZeroOutputColumns);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildAtLeastNZeroColumnOutputInterestsWithFirstColumnBytes(
    bool distribution[5][5][5][5],
    const size_t minNumZeroOutputColumns,
    const size_t numActiveInFirstColumn) {
    //
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    const size_t numZeroOutputColumns = getNumZeroOutputColumns(
                        v0, v1, v2, v3);
                    distribution[v0][v1][v2][v3] =
                        (numZeroOutputColumns >= minNumZeroOutputColumns)
                        && (v0 == numActiveInFirstColumn);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildAtLeastOneZeroColumnOutputInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 == 0 || v1 == 0 ||
                                                    v2 == 0 || v3 == 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void buildFixedColumnOutputInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 == 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyOneFixedColumnOutputInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 == 0)
                                                   && (v1 > 0)
                                                   && (v2 > 0)
                                                   && (v3 > 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyOneFixedNonZeroColumnOutputInterests(
    bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 > 0)
                                                   && (v1 == 0)
                                                   && (v2 == 0)
                                                   && (v3 == 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildTwoZeroOutputColumnInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = ((v0 == 0) && (v1 == 0))
                                                   ||
                                                   ((v0 == 0) && (v2 == 0))
                                                   ||
                                                   ((v0 == 0) && (v3 == 0))
                                                   ||
                                                   ((v1 == 0) && (v2 == 0))
                                                   ||
                                                   ((v1 == 0) && (v3 == 0))
                                                   ||
                                                   ((v2 == 0) && (v3 == 0));
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildTwoFixedZeroOutputColumnInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = ((v0 == 0) && (v1 == 0));
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyTwoFixedZeroOutputColumnInterests(
    bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 == 0)
                                                   && (v1 == 0)
                                                   && (v2 > 0)
                                                   && (v3 > 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyTwoFixedNonZeroOutputColumnInterests(
    bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 > 0)
                                                   && (v1 > 0)
                                                   && (v2 == 0)
                                                   && (v3 == 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildThreeZeroOutputColumnInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] =
                        ((v0 == 0) && (v1 == 0) && (v2 == 0))
                        || ((v0 == 0) && (v2 == 0) && (v3 == 0))
                        || ((v0 == 0) && (v1 == 0) && (v3 == 0))
                        || ((v1 == 0) && (v2 == 0) && (v3 == 0));
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildThreeFixedZeroOutputColumnInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] =
                        ((v0 == 0) && (v1 == 0) && (v2 == 0));
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyThreeFixedZeroOutputColumnInterests(
    bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 == 0)
                                                   && (v1 == 0)
                                                   && (v2 == 0)
                                                   && (v3 > 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyThreeFixedNonZeroOutputColumnInterests(
    bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 > 0)
                                                   && (v1 > 0)
                                                   && (v2 > 0)
                                                   && (v3 == 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyFourFixedNonZeroOutputColumnInterests(
    bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 > 0)
                                                   && (v1 > 0)
                                                   && (v2 > 0)
                                                   && (v3 > 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyNFirstNonZeroOutputColumnInterests(bool distribution[5][5][5][5],
                                               const size_t numFirstNonZeroOutputColumns) {
    if (numFirstNonZeroOutputColumns == 1) {
        buildExactlyOneFixedNonZeroColumnOutputInterests(distribution);
    } else if (numFirstNonZeroOutputColumns == 2) {
        buildExactlyTwoFixedNonZeroOutputColumnInterests(distribution);
    } else if (numFirstNonZeroOutputColumns == 3) {
        buildExactlyThreeFixedNonZeroOutputColumnInterests(distribution);
    } else if (numFirstNonZeroOutputColumns == 4) {
        buildExactlyFourFixedNonZeroOutputColumnInterests(distribution);
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyNFirstNonZeroOutputBytesInterests(bool distribution[5][5][5][5],
                                              const size_t numFirstNonZeroOutputColumns,
                                              const size_t numFirstNonZeroOutputBytes) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] =
                        (v0 == numFirstNonZeroOutputBytes)
                        && (v1 == 0)
                        && (v2 == 0)
                        && (v3 == 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
buildExactlyNZeroOutputColumnInterests(bool distribution[5][5][5][5],
                                       const size_t numDesiredZeroOutputColumns) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    const size_t numZeroOutputColumns = getNumZeroOutputColumns(
                        v0, v1, v2, v3);
                    distribution[v0][v1][v2][v3] =
                        (numZeroOutputColumns == numDesiredZeroOutputColumns);
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

    std::cout << "# P_aes:" << std::endl;
    std::cout << probabilityForAES << std::endl;

    std::cout << "# P_rand:" << std::endl;
    std::cout << probabilityForPRP << std::endl;

    std::cout << "# Difference:" << std::endl;
    std::cout << probabilityForAES - probabilityForPRP << std::endl;
}

// ------------------------------------------------------------------------

/**
 * uvec[1] = 1 (and every other entry uvec[i] = 0
 * encodes the 5-round distinguisher from
 * https://eprint.iacr.org/2019/622
 * that starts from a single active byte only.
 * It should produce a bias of 0.22466723256..e-15 = 2^(-51.981).
 */
static void testFiveRoundSingleByteDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildAtLeastOneZeroColumnOutputInterests(outputInterests);

    NTL::vec_RR inputDistribution;
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
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildThreeZeroOutputColumnInterests(outputInterests);

    NTL::vec_RR inputDistribution;
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

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 * This encodes the 5-round expectation distinguisher from
 * https://eprint.iacr.org/2018/182.
 */
static void testFiveRoundDiagonalDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildAtLeastOneZeroColumnOutputInterests(outputInterests);

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
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 */
static void testFiveRoundDiagonalToOneFixedZeroColumnDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildFixedColumnOutputInterests(outputInterests);

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
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 */
static void
testFiveRoundDiagonalToExactlyOneFixedZeroColumnDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildExactlyOneFixedColumnOutputInterests(outputInterests);

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

    std::cout << "5 rounds: first diagonal to M_{0}"
              << std::endl;

    printProbabilities(probabilityForAES, probabilityForPRP);
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 */
static void testFiveRoundDiagonalToTwoZeroColumnsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildTwoZeroOutputColumnInterests(outputInterests);

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
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 */
static void testFiveRoundDiagonalToTwoFixedZeroColumnsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildTwoFixedZeroOutputColumnInterests(outputInterests);

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
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 */
static void
testFiveRoundDiagonalToExactlyTwoFixedZeroColumnsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildExactlyTwoFixedZeroOutputColumnInterests(outputInterests);

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

    std::cout << "5 rounds: first diagonal to M_{0,1}"
              << std::endl;
    printProbabilities(probabilityForAES, probabilityForPRP);
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 */
static void testFiveRoundDiagonalToThreeZeroColumnsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildThreeZeroOutputColumnInterests(outputInterests);

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
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 */
static void testFiveRoundDiagonalToThreeFixedZeroColumnsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildThreeFixedZeroOutputColumnInterests(outputInterests);

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
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 */
static void
testFiveRoundDiagonalToExactlyThreeFixedZeroColumnsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildExactlyThreeFixedZeroOutputColumnInterests(outputInterests);

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

    std::cout << "5 rounds: first diagonal to M_{0,1,2}"
              << std::endl;
    printProbabilities(probabilityForAES, probabilityForPRP);
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

/**
 * uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
 * encodes a full diagonal input space.
 * This encodes the 6-round distinguisher from
 * https://eprint.iacr.org/2019/622.
 */
static void testSixRoundDiagonalDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 6;
    bool outputInterests[5][5][5][5];
    buildAtLeastOneZeroColumnOutputInterests(outputInterests);

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
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testSevenRoundDiagonalDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 7;
    bool outputInterests[5][5][5][5];
    buildAtLeastOneZeroColumnOutputInterests(outputInterests);

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

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testSevenRoundDiagonalToFixedColumnDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 7;
    bool outputInterests[5][5][5][5];
    buildFixedColumnOutputInterests(outputInterests);

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

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testSevenRoundTwoDiagonalsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 7;
    bool outputInterests[5][5][5][5];
    buildTwoZeroOutputColumnInterests(outputInterests);

    NTL::vec_RR inputDistribution;
    algorithm.buildFirstTwoDiagonalsDistribution(inputDistribution);

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

static void testSevenRoundOneToTwoDiagonalsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 7;
    bool outputInterests[5][5][5][5];
    buildTwoZeroOutputColumnInterests(outputInterests);

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

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testSevenRoundThreeDiagonalsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 7;
    bool outputInterests[5][5][5][5];
    buildAtLeastOneZeroColumnOutputInterests(outputInterests);

    NTL::vec_RR inputDistribution;
    algorithm.buildFirstThreeDiagonalsDistribution(inputDistribution);

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

/**
 * Maps a pattern of active bytes/columns to an int.
 * @example wpattern[2, 3, 1, 1] is mapped to
 * 2 * 5^0 + 3 * 5^1 + 1 * 5^2 + 1 * 5^3.
 * @param pattern Array of bytes/columns of a state.
 * @return
 */
static size_t computeIndex(const size_t pattern[4]) {
    size_t result = 0;

    for (size_t i = 0; i < 4; i++) {
        result += static_cast<size_t>(pow(5, i)) * pattern[i];
    }

    return result;
}

// ------------------------------------------------------------------------

static void printDistribution(const NTL::vec_RR &distribution) {
    std::cout << "# Distribution" << std::endl;
    distribution[0].SetOutputPrecision(100);

    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    const size_t pattern[4] = {v0, v1, v2, v3};
                    const size_t index = computeIndex(pattern);

//                    if (distribution[index] > 0) {
                        std::cout << v0
                                  << v1
                                  << v2
                                  << v3 << " "
                                  << distribution[index] << std::endl;
//                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void testSingleRoundColumnDistinguishers() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 1;
    bool outputInterests[5][5][5][5];

    std::cout << "#Rounds" << " "
              << "#Active input columns" << " "
              << "#>= Zero output columns" << std::endl;

    for (size_t numActiveInputColumns = 1;
         numActiveInputColumns <= 4;
         ++numActiveInputColumns) {
        //
        for (size_t minNumZeroOutputColumns = 1;
             minNumZeroOutputColumns <= 4;
             ++minNumZeroOutputColumns) {

            buildAtLeastNZeroColumnOutputInterests(outputInterests,
                                                   minNumZeroOutputColumns);

            NTL::vec_RR inputDistribution;
            algorithm.buildExactlyFirstNDiagonalsDistribution(inputDistribution,
                                                              numActiveInputColumns);

            NTL::RR probabilityForAES;
            algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                                     inputDistribution,
                                                     outputInterests,
                                                     NUM_ROUNDS);

            NTL::RR probabilityForPRP;
            algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                                     outputInterests);

            std::cout << NUM_ROUNDS << " "
                      << numActiveInputColumns << " "
                      << minNumZeroOutputColumns << std::endl;
            printProbabilities(probabilityForAES, probabilityForPRP);
        }
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testFiveRoundDiagonalToExactlyNZeroColumnsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    const size_t numActiveInputColumns = 1;

    std::cout << "#Rounds" << " "
              << "#Active input columns" << " "
              << "#Zero output columns" << std::endl;

    for (size_t numZeroOutputColumns = 0;
         numZeroOutputColumns <= 4;
         ++numZeroOutputColumns) {
        // TODO
        buildExactlyNZeroOutputColumnInterests(outputInterests,
                                               numZeroOutputColumns);

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

        std::cout << NUM_ROUNDS << " "
                  << numActiveInputColumns << " "
                  << numZeroOutputColumns << std::endl;
        printProbabilities(probabilityForAES, probabilityForPRP);
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testFiveRoundDiagonalToExactlyNFirstNonZeroColumnsDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    const size_t numActiveInputColumns = 1;

    std::cout << "#Rounds" << " "
              << "#Active input columns" << " "
              << "#Non-zero first output columns" << std::endl;

    for (size_t numFirstNonZeroOutputColumns = 1;
         numFirstNonZeroOutputColumns <= 4;
         ++numFirstNonZeroOutputColumns) {
        // TODO
        buildExactlyNFirstNonZeroOutputColumnInterests(outputInterests,
                                                       numFirstNonZeroOutputColumns);

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

        std::cout << NUM_ROUNDS << " "
                  << numActiveInputColumns << " "
                  << numFirstNonZeroOutputColumns << std::endl;
        printProbabilities(probabilityForAES, probabilityForPRP);
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testFiveRoundDiagonalToExactlyNFirstNonZeroBytesDistinguisher() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    const size_t numActiveInputColumns = 1;

    std::cout << "#Rounds "
              << "#Active input columns "
              << "#Non-zero first output columns "
              << "#Non-zero output bytes"
              << std::endl;

    for (size_t numFirstNonZeroOutputColumns = 1;
         numFirstNonZeroOutputColumns <= 4;
         ++numFirstNonZeroOutputColumns) {
        for (size_t numFirstNonZeroBytes = 1;
             numFirstNonZeroBytes <= 4; ++numFirstNonZeroBytes) {
            //
            buildExactlyNFirstNonZeroOutputBytesInterests(outputInterests,
                                                          numFirstNonZeroOutputColumns,
                                                          numFirstNonZeroBytes);

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

            std::cout << NUM_ROUNDS << " "
                      << numActiveInputColumns << " "
                      << numFirstNonZeroOutputColumns << " "
                      << numFirstNonZeroBytes
                      << std::endl;
            printProbabilities(probabilityForAES, probabilityForPRP);
        }
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testWriteMatrix() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    for (size_t numRounds = 1; numRounds <= 1; ++numRounds) {
        NTL::mat_RR matrix;
        matrix.SetDims(625, 625);
        matrix[0][0].SetPrecision(400);
        matrix[0][0].SetOutputPrecision(100);

        std::stringstream ss;
        ss << "matrix" << numRounds << ".txt";
        const std::string path = ss.str();

        algorithm.createMatrix(matrix, numRounds);
        algorithm.writeMatrix(path, matrix);
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void printIndividualRoundColumnDistributions() {
    AESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t MAX_NUM_ROUNDS = 6;
    bool outputInterests[5][5][5][5];
    buildAllOutputInterests(outputInterests);

    // ------------------------------------------------------------------------
    // Random distribution
    // ------------------------------------------------------------------------

    NTL::vec_RR outputDistribution;
    algorithm.computeOutputDistributionForPRP(outputDistribution);

    std::cout << "# v_rand" << std::endl;
    printDistribution(outputDistribution);

    std::cout << "#Rounds" << " "
              << "#Active input columns" << " "
              << "#>= Zero output columns" << std::endl;

    for (size_t numActiveInputColumns = 1;
         numActiveInputColumns <= 1;
         ++numActiveInputColumns) {
        // --------------------------------------------------------------------
        // v0 distribution
        // --------------------------------------------------------------------

        NTL::vec_RR inputDistribution;
        algorithm.buildExactlyFirstNDiagonalsDistribution(inputDistribution,
                                                          numActiveInputColumns);
        std::cout << "# v0" << std::endl;
        printDistribution(inputDistribution);

        for (size_t numRounds = 2; numRounds <= MAX_NUM_ROUNDS; ++numRounds) {
            // --------------------------------------------------------------------
            // vi
            // --------------------------------------------------------------------

            algorithm.computeOutputDistributionForAES(outputDistribution,
                                                      inputDistribution,
                                                      numRounds);

            std::cout << "# v" << (numRounds - 1) << std::endl;
            printDistribution(outputDistribution);
        }
    }

    tearDown(algorithm);
}
// ------------------------------------------------------------------------

int main() {
//    testFiveRoundSingleByteDistinguisher();
//    testFiveRoundSingleByteToThreeColumnsDistinguisher();
//    testFiveRoundDiagonalDistinguisher();
//    testFiveRoundDiagonalToTwoZeroColumnsDistinguisher();
//    testFiveRoundDiagonalToThreeZeroColumnsDistinguisher();
//
//    testFiveRoundDiagonalToOneFixedZeroColumnDistinguisher();
//    testFiveRoundDiagonalToTwoFixedZeroColumnsDistinguisher();
//    testFiveRoundDiagonalToThreeFixedZeroColumnsDistinguisher();
//
//    testFiveRoundDiagonalToExactlyOneFixedZeroColumnDistinguisher();
//    testFiveRoundDiagonalToExactlyTwoFixedZeroColumnsDistinguisher();
//    testFiveRoundDiagonalToExactlyThreeFixedZeroColumnsDistinguisher();
//
//    testSixRoundDiagonalDistinguisher();
//    testSevenRoundDiagonalDistinguisher();
//    testSevenRoundDiagonalToFixedColumnDistinguisher();
//    testSevenRoundOneToTwoDiagonalsDistinguisher();
//    testSevenRoundTwoDiagonalsDistinguisher();
//    testSevenRoundThreeDiagonalsDistinguisher();

//    testFiveRoundDiagonalToExactlyNFirstNonZeroColumnsDistinguisher();
//    testFiveRoundDiagonalToExactlyNFirstNonZeroBytesDistinguisher();
//    testSingleRoundColumnDistinguishers();
//    testWriteMatrix();
    printIndividualRoundColumnDistributions();
    return EXIT_SUCCESS;
}
