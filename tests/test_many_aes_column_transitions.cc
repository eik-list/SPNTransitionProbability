/**
 * Copyright 2019 anonymized
 */

#include <iostream>
#include <string>

#include "aes_column_transition_algorithm.h"
#include "argparse.h"

// ------------------------------------------------------------------------

static const size_t PRECISION = 400;
static const size_t OUTPUT_PRECISION = 100;

// ------------------------------------------------------------------------

typedef struct {
    size_t maxNumRounds;
    size_t minNumRounds;
    std::string zTablePath;
} ExperimentContext;

// ------------------------------------------------------------------------

static void setUp(const std::string &zTablePath,
                  AESColumnTransitionAlgorithm &algorithm) {
    algorithm.readZTable(zTablePath);
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(AESColumnTransitionAlgorithm &algorithm) {

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

static void
buildAtLeastOneZeroColumnOutputInterests(bool distribution[5][5][5][5]) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    if ((v0 == 0) && (v1 == 0) && (v2 == 0) && (v3 == 0)) {
                        continue;
                    }

                    distribution[v0][v1][v2][v3] = (v0 == 0) || (v1 == 0) ||
                                                   (v2 == 0) || (v3 == 0);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static bool
hasExactlyNumActive(const size_t v0, const size_t v1, const size_t v2,
                    const size_t v3, const size_t numDesiredActive) {
    if (numDesiredActive == 0) {
        return (v0 == 0) && (v1 == 0) && (v2 == 0) && (v3 == 0);
    }

    if (numDesiredActive == 1) {
        return (v0 > 0) && (v1 == 0) && (v2 == 0) && (v3 == 0);
    }

    if (numDesiredActive == 2) {
        return (v0 > 0) && (v1 > 0) && (v2 == 0) && (v3 == 0);
    }

    if (numDesiredActive == 3) {
        return (v0 > 0) && (v1 > 0) && (v2 > 0) && (v3 == 0);
    }

    return (v0 > 0) && (v1 > 0) && (v2 > 0) && (v3 > 0);
}

// ------------------------------------------------------------------------

static
void buildMaxNumOutputColumnInterests(bool distribution[5][5][5][5],
                                      const size_t numActiveOutputColumns) {
    for (size_t v0 = 0; v0 < 5; v0++) {
        for (size_t v1 = 0; v1 < 5; v1++) {
            for (size_t v2 = 0; v2 < 5; v2++) {
                for (size_t v3 = 0; v3 < 5; v3++) {
                    distribution[v0][v1][v2][v3] = hasExactlyNumActive(
                        v0, v1, v2, v3, numActiveOutputColumns);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

static void
testManyDiagonalToByteDistinguishers(const ExperimentContext &context) {
    AESColumnTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);

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
            probabilityForAES.SetPrecision(PRECISION);
            probabilityForAES = 0;
            algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                                     inputDistribution,
                                                     outputInterests,
                                                     numRounds);

            NTL::RR probabilityForPRP;
            probabilityForPRP.SetPrecision(PRECISION);
            probabilityForPRP = 0;
            algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                                     outputInterests);

            NTL::RR distance = probabilityForAES - probabilityForPRP;
            distance.SetOutputPrecision(OUTPUT_PRECISION);

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

static void
testManyDiagonalToColumnDistinguishers(const ExperimentContext &context) {
    AESColumnTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);

    bool outputInterests[5][5][5][5];
    buildAtLeastOneZeroColumnOutputInterests(outputInterests);

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
            probabilityForAES.SetPrecision(PRECISION);
            probabilityForAES = 0;
            algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                                     inputDistribution,
                                                     outputInterests,
                                                     numRounds);

            NTL::RR probabilityForPRP;
            probabilityForPRP.SetPrecision(PRECISION);
            probabilityForPRP = 0;
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

static void testManyPartialDiagonalToColumnDistinguishers(
    const ExperimentContext &context) {
    AESColumnTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);

    bool outputInterests[5][5][5][5];
    buildAtLeastOneZeroColumnOutputInterests(outputInterests);

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

static void
testManyPartialDiagonalToByteDistinguishers(const ExperimentContext &context) {
    AESColumnTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);

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
                buildMaxNumOutputByteInterests(outputInterests,
                                               numActiveOutputBytes);

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

static void testDiagonalToOutputColumns(const ExperimentContext &context) {
    AESColumnTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);

    std::cout << "#Testing first diagonal to exactly n first output columns"
              << std::endl;
    std::cout << "#Rounds #Input Diagonals #Active Output Columns Distance"
              << std::endl;

    NTL::vec_RR inputDistribution;
    algorithm.buildFirstDiagonalDistribution(inputDistribution);

    const size_t numRounds = 5;
    const size_t numActiveInputColumns = 1;

    for (size_t numActiveOutputColumns = 1;
         numActiveOutputColumns <= 4; ++numActiveOutputColumns) {

        bool outputInterests[5][5][5][5];
        buildMaxNumOutputColumnInterests(outputInterests,
                                         numActiveOutputColumns);

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
                  << numActiveInputColumns << " "
                  << numActiveOutputColumns << " "
                  << probabilityForAES << " ";

        if (probabilityForAES == 0) {
            std::cout << " -" << std::endl;
            continue;
        }

        NTL::RR two;
        two = 2;
        NTL::RR logProbabilityForAES = log(probabilityForAES) / log(two);

        std::cout << " " << logProbabilityForAES << std::endl;
    }

    std::cout << std::endl;
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void testNDiagonalsToOutputColumns(const ExperimentContext &context) {
    AESColumnTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);

    std::cout << "#Testing first diagonal to exactly n first output columns"
              << std::endl;
    std::cout << "#Rounds #Input Diagonals #Active Output Columns Distance"
              << std::endl;

    const size_t numRounds = 1;
    const size_t numActiveOutputColumns = 3;

    for (size_t numActiveInputColumns = 1;
         numActiveInputColumns <= 4;
         ++numActiveInputColumns) {
        NTL::vec_RR inputDistribution;
        algorithm.buildFirstNDiagonalsDistribution(inputDistribution,
                                                   numActiveInputColumns);

        bool outputInterests[5][5][5][5];
        buildAtLeastOneZeroColumnOutputInterests(outputInterests);

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
                  << numActiveInputColumns << " "
                  << numActiveOutputColumns << " "
                  << probabilityForAES << " ";

        if (probabilityForAES == 0) {
            std::cout << " -" << std::endl;
            continue;
        }

        NTL::RR two;
        two = 2;
        NTL::RR logProbabilityForAES = log(probabilityForAES) / log(two);

        std::cout << " " << logProbabilityForAES << std::endl;
    }

    std::cout << std::endl;
    tearDown(algorithm);
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void
parse_args(ExperimentContext &context, int argc, const char **argv) {
    utils::ArgumentParser parser;
    parser.appName("Tests for the AES transitions.");
    parser.helpString("Tests for the AES transitions.");
    parser.useExceptions(true);
    parser.addArgument("-a", "--min_num_rounds", 1, false);
    parser.addArgument("-b", "--max_num_rounds", 1, false);
    parser.addArgument("-z", "--z_table_path", 1, false);

    try {
        parser.parse((size_t) argc, argv);
        context.minNumRounds = static_cast<size_t>(parser.retrieveAsLong("a"));
        context.maxNumRounds = static_cast<size_t>(parser.retrieveAsLong("b"));
        context.zTablePath = parser.retrieve<std::string>("z");
    } catch (...) {
        std::cerr << parser.usage().c_str() << std::endl;
        exit(EXIT_FAILURE);
    }
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(context, argc, argv);
//    testManyDiagonalToByteDistinguishers(context);
//    testManyDiagonalToColumnDistinguishers(context);
//    testManyPartialDiagonalToColumnDistinguishers(context);
//    testManyPartialDiagonalToByteDistinguishers(context);
    testDiagonalToOutputColumns(context);
    testNDiagonalsToOutputColumns(context);
    return EXIT_SUCCESS;
}
