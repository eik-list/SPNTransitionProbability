/**
 * Copyright 2019 anonymized
 */

#include <iostream>
#include <string>

#include "small_aes_byte_transition_algorithm.h"
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
                  SmallAESByteTransitionAlgorithm &algorithm) {
    algorithm.readZTable(zTablePath);
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(SmallAESByteTransitionAlgorithm &algorithm) {

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

static void toActiveBytePattern(uint8_t bytePattern[4][4],
                                const int bytePatternAsInt) {
    for (int i = 0; i < 4; i++) {  // column
        for (int j = 0; j < 4; j++) {  // row
            bytePattern[j][i] = static_cast<uint8_t>(
                (bytePatternAsInt >> (4 * i + j)) & 1);
        }
    }
}

// ------------------------------------------------------------------------

static int computeIndexFromBytePattern(const uint8_t bytePattern[4][4]) {
    int result = 0;

    for (int i = 0; i < 4; i++) {  // column
        for (int j = 0; j < 4; j++) {  // row
            result |= (bytePattern[i][j] & 1) << (4 * i + j);
        }
    }

    return result;
}

// ------------------------------------------------------------------------

static void
buildSingleElementOutputInterests(std::bitset<65536> outputInterests,
                                  const uint8_t outputBytePattern[4][4]) {
    outputInterests.reset();
    const auto bytePatternAsInt = static_cast<size_t>(
        computeIndexFromBytePattern(outputBytePattern));
    outputInterests[bytePatternAsInt] = true;
}

// ------------------------------------------------------------------------

static void
testAllSingleElementDistinguishers(const ExperimentContext &context) {
    SmallAESByteTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);

    std::cout << "#Testing all distinguishers from a single input pattern to "
              << "all output patterns."
              << std::endl;
    std::cout << "#Rounds #Input #Output-bytes Distance"
              << std::endl;

    for (size_t numRounds = context.minNumRounds;
         numRounds <= context.maxNumRounds;
         ++numRounds) {
        NTL::mat_RR matrix;
        matrix.SetDims(625, 625);
        matrix[0][0].SetPrecision(PRECISION);

        algorithm.createMatrix(matrix, numRounds);

        for (size_t byteInputPatternAsInt = 1;
             byteInputPatternAsInt < 65536;
             ++byteInputPatternAsInt) {
            NTL::vec_RR inputDistribution;
            inputDistribution.SetLength(65536);
            inputDistribution[0].SetPrecision(400);
            algorithm.buildFirstByteDistribution(inputDistribution);

            algorithm.buildSingleElementDistribution(inputDistribution,
                                                     byteInputPatternAsInt);

            for (size_t byteOutputPatternAsInt = 1;
                 byteOutputPatternAsInt < 625; ++byteOutputPatternAsInt) {

                uint8_t outputBytePattern[4][4];
                toActiveBytePattern(outputBytePattern, byteOutputPatternAsInt);

                std::bitset<65536> outputInterests;
                buildSingleElementOutputInterests(outputInterests,
                                                  outputBytePattern);

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
                          << byteInputPatternAsInt << " "
                          << byteOutputPatternAsInt << " "
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
    testAllSingleElementDistinguishers(context);
    return EXIT_SUCCESS;
}
