/**
 * Copyright 2019 anonymized
 */

#include <iostream>
#include <string>

#include "small_aes_column_transition_algorithm.h"
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
                  SmallAESColumnTransitionAlgorithm &algorithm) {
    algorithm.readZTable(zTablePath);
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(SmallAESColumnTransitionAlgorithm &algorithm) {

}

// ------------------------------------------------------------------------

static void
toActiveColumnPattern(uint8_t columnPattern[4],
                      const size_t columnPatternAsInt) {
    size_t pattern = columnPatternAsInt;

    for (size_t i = 0; i < 4; i++) {
        const auto numActiveBytesInColumn = static_cast<uint8_t>(pattern % 5);
        columnPattern[i] = numActiveBytesInColumn;

        pattern -= numActiveBytesInColumn;
        pattern = pattern / 5;
    }
}

// ------------------------------------------------------------------------

static void buildSingleElementOutputInterests(bool outputInterests[5][5][5][5],
                                              const uint8_t outputColumnPattern[4]) {
    for (uint8_t v0 = 0; v0 < 5; ++v0) {
        for (uint8_t v1 = 0; v1 < 5; ++v1) {
            for (uint8_t v2 = 0; v2 < 5; ++v2) {
                for (uint8_t v3 = 0; v3 < 5; ++v3) {
                    outputInterests[v0][v1][v2][v3] = false;
                }
            }
        }
    }

    outputInterests[outputColumnPattern[0]][outputColumnPattern[1]][outputColumnPattern[2]][outputColumnPattern[3]] = true;
}

// ------------------------------------------------------------------------

static void
testAllSingleElementDistinguishers(const ExperimentContext &context) {
    SmallAESColumnTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);

    std::cout
        << "#Testing all distinguishers from a single input pattern to all "
        << "output patterns." << std::endl;
    std::cout << "#Rounds #Input #Output-bytes Distance" << std::endl;

    for (size_t numRounds = context.minNumRounds;
         numRounds <= context.maxNumRounds;
         ++numRounds) {
        NTL::mat_RR matrix;
        matrix.SetDims(625, 625);
        matrix[0][0].SetPrecision(PRECISION);

        algorithm.createMatrix(matrix, numRounds);

        for (size_t columnInputPatternAsInt = 1;
             columnInputPatternAsInt < 625; ++columnInputPatternAsInt) {

            NTL::vec_RR inputDistribution;
            algorithm.buildSingleElementDistribution(inputDistribution,
                                                     columnInputPatternAsInt);

            for (size_t columnOutputPatternAsInt = 1;
                 columnOutputPatternAsInt < 625; ++columnOutputPatternAsInt) {

                uint8_t outputColumnPattern[4];
                toActiveColumnPattern(outputColumnPattern,
                                      columnOutputPatternAsInt);

                bool outputInterests[5][5][5][5];
                buildSingleElementOutputInterests(outputInterests,
                                                  outputColumnPattern);

                NTL::RR probabilityForAES;
                probabilityForAES.SetPrecision(PRECISION);
                probabilityForAES = 0;
                algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                                         inputDistribution,
                                                         outputInterests,
                                                         matrix,
                                                         numRounds);

                NTL::RR probabilityForPRP;
                probabilityForPRP.SetPrecision(PRECISION);
                probabilityForPRP = 0;
                algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                                         outputInterests);

                NTL::RR distance = probabilityForAES - probabilityForPRP;
                distance.SetOutputPrecision(100);

                std::cout << numRounds << " "
                          << columnInputPatternAsInt << " "
                          << columnOutputPatternAsInt << " "
                          << probabilityForAES << " "
                          << probabilityForPRP << " "
                          << distance
                          << std::endl;
            }
        }
    }

    tearDown(algorithm);
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void
parse_args(ExperimentContext &context, int argc, const char **argv) {
    utils::ArgumentParser parser;
    parser.appName("Tests for the Small-AES transitions.");
    parser.helpString("Tests for the Small-AES transitions.");
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
    testAllSingleElementDistinguishers(context);
    return EXIT_SUCCESS;
}
