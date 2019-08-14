/**
 * Copyright 2019 anonymized
 */

#include <iostream>

#include "small_aes_column_transition_algorithm.h"


// ------------------------------------------------------------------------

static void setUp(SmallAESColumnTransitionAlgorithm &algorithm) {
    algorithm.readZTable("../data/z_table_small_aes.bin");
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(SmallAESColumnTransitionAlgorithm &algorithm) {

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

static void buildOutputByteInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 < 4);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void buildOutputByteInterests(bool distribution[5][5][5][5],
                                     const size_t numActiveBytes) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 == numActiveBytes);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void buildMaxNumOutputByteInterests(bool distribution[5][5][5][5],
                                           const size_t maxNumActiveBytes) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = (v0 <= maxNumActiveBytes);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void buildOutputColumnInterests(bool distribution[5][5][5][5]) {
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

static void testManyDiagonalToByteDistinguishers() {
    SmallAESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    bool outputInterests[5][5][5][5];
    buildOutputByteInterests(outputInterests);

    std::cout
        << "#Testing full diagonals to <4 active output bytes in first column"
        << std::endl;
    std::cout << "#Rounds #Diagonal Distance" << std::endl;

    for (size_t numActiveDiagonals = 1;
         numActiveDiagonals <= 3; ++numActiveDiagonals) {

        NTL::vec_RR inputDistribution;
        algorithm.buildFirstNDiagonalsDistribution(inputDistribution,
                                                   numActiveDiagonals);

        for (size_t numRounds = 2; numRounds <= 8; ++numRounds) {
            NTL::RR probabilityForAES;
            algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                                     inputDistribution,
                                                     outputInterests,
                                                     numRounds);

            NTL::RR probabilityForPRP;
            algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                                     outputInterests);

            NTL::RR distance = probabilityForAES - probabilityForPRP;
            distance.SetOutputPrecision(100);

            std::cout << numRounds << " "
                      << numActiveDiagonals << " "
                      << distance;

            if (distance < 0) {
                distance = -distance;
            }

            NTL::RR two;
            two = 2;
            NTL::RR logDistance = log(distance) / log(two);

            std::cout << " " << logDistance << std::endl;
        }

        std::cout << std::endl;
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testManyDiagonalToColumnDistinguishers() {
    SmallAESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    bool outputInterests[5][5][5][5];
    buildOutputColumnInterests(outputInterests);

    std::cout << "#Testing diagonals to zero-difference first column"
              << std::endl;
    std::cout << "#Rounds #Diagonals Distance" << std::endl;

    for (size_t numActiveDiagonals = 1;
         numActiveDiagonals <= 3; ++numActiveDiagonals) {

        NTL::vec_RR inputDistribution;
        algorithm.buildFirstNDiagonalsDistribution(inputDistribution,
                                                   numActiveDiagonals);

        for (size_t numRounds = 2; numRounds <= 8; ++numRounds) {
            NTL::RR probabilityForAES;
            algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                                     inputDistribution,
                                                     outputInterests,
                                                     numRounds);

            NTL::RR probabilityForPRP;
            algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                                     outputInterests);

            NTL::RR distance = probabilityForAES - probabilityForPRP;
            distance.SetOutputPrecision(100);

            std::cout << numRounds << " "
                      << numActiveDiagonals << " "
                      << distance;

            if (distance < 0) {
                distance = -distance;
            }

            NTL::RR two;
            two = 2;
            NTL::RR logDistance = log(distance) / log(two);

            std::cout << " " << logDistance << std::endl;
        }

        std::cout << std::endl;
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testManyPartialDiagonalToColumnDistinguishers() {
    SmallAESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    bool outputInterests[5][5][5][5];
    buildOutputColumnInterests(outputInterests);

    std::cout
        << "#Testing partial first diagonal to zero-difference first column"
        << std::endl;
    std::cout << "#Rounds #Input-bytes Distance" << std::endl;

    for (size_t numActiveBytes = 1;
         numActiveBytes <= 3; ++numActiveBytes) {

        NTL::vec_RR inputDistribution;
        algorithm.buildFirstNBytesDistribution(inputDistribution,
                                               numActiveBytes);

        for (size_t numRounds = 2; numRounds <= 8; ++numRounds) {
            NTL::RR probabilityForAES;
            algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                                     inputDistribution,
                                                     outputInterests,
                                                     numRounds);

            NTL::RR probabilityForPRP;
            algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                                     outputInterests);

            NTL::RR distance = probabilityForAES - probabilityForPRP;
            distance.SetOutputPrecision(100);

            std::cout << numRounds << " "
                      << numActiveBytes << " "
                      << distance;

            if (distance < 0) {
                distance = -distance;
            }

            NTL::RR two;
            two = 2;
            NTL::RR logDistance = log(distance) / log(two);

            std::cout << " " << logDistance << std::endl;
        }

        std::cout << std::endl;
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testManyPartialDiagonalToByteDistinguishers() {
    SmallAESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    std::cout
        << "#Testing partial first diagonal to <= output bytes in first column"
        << std::endl;
    std::cout << "#Rounds #Input-bytes #Output-bytes Distance" << std::endl;

    for (size_t numActiveInputBytes = 1;
         numActiveInputBytes <= 3; ++numActiveInputBytes) {

        NTL::vec_RR inputDistribution;
        algorithm.buildFirstNBytesDistribution(inputDistribution,
                                               numActiveInputBytes);

        for (size_t numRounds = 2; numRounds <= 8; ++numRounds) {

            for (size_t numActiveOutputBytes = 0;
                 numActiveOutputBytes <= 4; ++numActiveOutputBytes) {

                bool outputInterests[5][5][5][5];
                buildMaxNumOutputByteInterests(outputInterests, numActiveOutputBytes);

                NTL::RR probabilityForAES;
                algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                                         inputDistribution,
                                                         outputInterests,
                                                         numRounds);

                NTL::RR probabilityForPRP;
                algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                                         outputInterests);

                NTL::RR distance = probabilityForAES - probabilityForPRP;
                distance.SetOutputPrecision(100);

                std::cout << numRounds << " "
                          << numActiveInputBytes << " "
                          << numActiveOutputBytes << " "
                          << distance;

                if (distance == 0) {
                    std::cout << " -" << std::endl;
                    continue;
                }

                if (distance < 0) {
                    distance = -distance;
                }

                NTL::RR two;
                two = 2;
                NTL::RR logDistance = log(distance) / log(two);

                std::cout << " " << logDistance << std::endl;
            }

            std::cout << std::endl;
        }
    }

    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testFiveRoundSingleByteDistinguisher() {
    SmallAESColumnTransitionAlgorithm algorithm;
    setUp(algorithm);

    const size_t NUM_ROUNDS = 5;
    bool outputInterests[5][5][5][5];
    buildOutputColumnInterests(outputInterests);

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

int main() {
//    testManyDiagonalToColumnDistinguishers();
//    testManyDiagonalToByteDistinguishers();
//    testManyPartialDiagonalToColumnDistinguishers();
//    testManyPartialDiagonalToByteDistinguishers();
    testFiveRoundSingleByteDistinguisher();
    return EXIT_SUCCESS;
}
