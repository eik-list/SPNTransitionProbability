/**
 * Copyright 2019 anonymized
 */

#include <iostream>
#include <sstream>

#include "aes_byte_mixture_transition_algorithm.h"

#include "utils/argparse.h"
#include "dependency_strategy.h"
#include "min_weight_dependency_strategy.h"

// ------------------------------------------------------------------------

using utils::ArgumentParser;

// ------------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------------

static const size_t NUM_BYTE_PATTERNS = 65536;
static const size_t NUM_BITS_PRECISION = 400;
static const size_t NUM_BITS_OUTPUT_PRECISION = 100;

// ------------------------------------------------------------------------
// Types
// ------------------------------------------------------------------------

typedef struct {
    size_t bytePatternAsInt;
    size_t numRounds;
} ExperimentContext;
typedef std::bitset<NUM_BYTE_PATTERNS> PatternInterests;

// ------------------------------------------------------------------------
// Methods
// ------------------------------------------------------------------------

static void buildAllOutputInterests(PatternInterests &distribution) {
    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < NUM_BYTE_PATTERNS;
         ++bytePatternAsInt) {
        distribution[bytePatternAsInt] = true;
    }
}

// ------------------------------------------------------------------------

static void buildTwoColumnsOutputInterests(PatternInterests &distribution) {
    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < NUM_BYTE_PATTERNS;
         ++bytePatternAsInt) {
        distribution[bytePatternAsInt] = true;
    }
}

// ------------------------------------------------------------------------

static void prepareDistribution(NTL::vec_RR &distribution,
                                const size_t length,
                                const size_t precision) {
    distribution.SetLength(length);
    distribution[0].SetPrecision(precision);
}

// ------------------------------------------------------------------------

static void printProbabilities(const NTL::RR &probabilityForAES,
                               NTL::RR &probabilityForPRP) {
    probabilityForAES.SetOutputPrecision(NUM_BITS_OUTPUT_PRECISION);
    probabilityForPRP.SetOutputPrecision(NUM_BITS_OUTPUT_PRECISION);
    
    std::cout << "P_aes:" << std::endl;
    std::cout << probabilityForAES << std::endl;
    
    std::cout << "P_rand:" << std::endl;
    std::cout << probabilityForPRP << std::endl;
    
    std::cout << "Difference:" << std::endl;
    std::cout << probabilityForAES - probabilityForPRP << std::endl;
}

// ------------------------------------------------------------------------

static void printDistribution(const NTL::vec_RR &distribution) {
    const size_t length = distribution.length();
    
    for (size_t i = 0; i < length; ++i) {
        const auto &item = distribution[i];
        
        if (item <= 0.0) {
            continue;
        }
        
        std::cout << i << " " << item << std::endl;
    }
}

// ------------------------------------------------------------------------

static void setUp(AESByteMixtureTransitionAlgorithm &algorithm) {
    algorithm.readZTable("data/z_table_aes.bin");
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void tearDown(AESByteMixtureTransitionAlgorithm &algorithm) {
    (void) algorithm;
}

// ------------------------------------------------------------------------

static void runAlgorithm(ExperimentContext &context,
                         AESByteMixtureTransitionAlgorithm &algorithm) {
    PatternInterests outputInterests;
    buildAllOutputInterests(outputInterests);
    
    NTL::vec_RR inputDistribution;
    prepareDistribution(inputDistribution,
                        NUM_BYTE_PATTERNS,
                        NUM_BITS_PRECISION);
    algorithm.buildSingleElementDistribution(inputDistribution,
                                             context.bytePatternAsInt);
    printDistribution(inputDistribution);
    
    MinWeightDependencyStrategy dependencyStrategy;
    
    NTL::RR probabilityForAES;
    size_t numMixtureRounds = 0;
    algorithm.computeOutputProbabilityForAES(probabilityForAES,
                                             inputDistribution,
                                             outputInterests,
                                             context.bytePatternAsInt,
                                             context.numRounds,
                                             &dependencyStrategy,
                                             numMixtureRounds);
    
    std::cout << "# Mixture rounds: " << numMixtureRounds << std::endl;
    
    NTL::RR probabilityForPRP;
    algorithm.computeOutputProbabilityForPRP(probabilityForPRP,
                                             outputInterests);
    
    printProbabilities(probabilityForAES, probabilityForPRP);
}

// ------------------------------------------------------------------------

static void findMixtures(ExperimentContext &context) {
    AESByteMixtureTransitionAlgorithm algorithm;
    setUp(algorithm);
    runAlgorithm(context, algorithm);
    tearDown(algorithm);
}

// ------------------------------------------------------------------------

static void
parseArguments(ExperimentContext &context, int argc, const char **argv) {
    ArgumentParser parser;
    parser.appName("Tries to find mixture tuples for <r> rounds of the "
                   "AES, starting from input byte pattern <b>.");
    parser.addArgument("-b", "--byte_pattern", 1, false);
    parser.addArgument("-r", "--num_rounds", 1, false);
    
    try {
        parser.parse((size_t) argc, argv);
        context.bytePatternAsInt = parser.retrieveBitString("b");
        context.numRounds = parser.retrieveAsLong("r");
    } catch (...) {
        std::cerr << parser.usage().c_str() << std::endl;
        exit(EXIT_FAILURE);
    }
    
    printf("# Rounds %8zu\n", context.numRounds);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parseArguments(context, argc, argv);
    findMixtures(context);
    return EXIT_SUCCESS;
}
