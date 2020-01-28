/**
 * Copyright 2019 anonymized
 */

#include <iostream>
#include <string>
#include <tuple>

#include "aes_column_transition_algorithm.h"
#include "argparse.h"

// ------------------------------------------------------------------------

static const size_t PRECISION = 400;
static const size_t OUTPUT_PRECISION = 100;

// ------------------------------------------------------------------------

typedef struct {
    size_t maxNumToPrint;
    size_t maxNumRounds;
    size_t minNumRounds;
    std::string zTablePath;
} ExperimentContext;
//typedef std::tuple<NTL::RR, NTL::RR, NTL::RR, size_t, size_t> ProbabilityIndexTuple;

typedef struct {
    NTL::RR probabilityDistance;
    NTL::RR probabilityForAES;
    NTL::RR probabilityForPRP;
    size_t columnInputPatternAsInt = 0;
    size_t columnOutputPatternAsInt = 0;
} ProbabilityIndexTuple;

// ------------------------------------------------------------------------

static void setUp(const std::string &zTablePath,
                  AESColumnTransitionAlgorithm &algorithm) {
    algorithm.readZTable(zTablePath);
    algorithm.precomputeShiftRowsMatrix();
    algorithm.precomputeMixColumnsMatrix();
}

// ------------------------------------------------------------------------

static void
toActiveColumnPattern(uint8_t columnPattern[4],
                      const size_t columnPatternAsInt) {
    size_t pattern = columnPatternAsInt;
    
    for (size_t i = 0; i < 4; i++) {
        const auto numActiveBytesInColumn = pattern % 5;
        columnPattern[i] = numActiveBytesInColumn;
        
        pattern -= numActiveBytesInColumn;
        pattern = pattern / 5;
    }
}

// ------------------------------------------------------------------------

static void printPattern(const uint8_t pattern[4]) {
    for (size_t i = 0; i < 4; ++i) {
        std::cout << static_cast<unsigned>(pattern[i]);
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

static NTL::RR log2(const NTL::RR &probability) {
    if (probability == 0) {
        NTL::RR result;
        result = 0;
        return result;
    }
    
    NTL::RR two;
    two = 2;
    
    if (probability < 0) {
        return log(-probability) / log(two);
    }
    
    return log(probability) / log(two);
}

// ------------------------------------------------------------------------

static void printParametersAsPatterns(const size_t numRounds,
                                      const ProbabilityIndexTuple &tuple) {
    uint8_t columnInputPattern[4];
    uint8_t columnOutputPattern[4];
    toActiveColumnPattern(columnInputPattern, tuple.columnInputPatternAsInt);
    toActiveColumnPattern(columnOutputPattern, tuple.columnOutputPatternAsInt);
    
    std::cout << numRounds << " ";
    printPattern(columnInputPattern);
    std::cout << " ";
    printPattern(columnOutputPattern);
    
    std::cout << " " << log2(tuple.probabilityForAES)
              << " " << log2(tuple.probabilityForPRP)
              << " " << log2(tuple.probabilityDistance)
              << std::endl;
}

// ------------------------------------------------------------------------

static void printParameters(const size_t numRounds,
                            const ProbabilityIndexTuple &tuple) {
    std::cout << numRounds
              << " " << tuple.columnInputPatternAsInt
              << " " << tuple.columnOutputPatternAsInt
              << " " << tuple.probabilityForAES
              << " " << tuple.probabilityForPRP
              << " " << tuple.probabilityDistance
              << " " << log2(tuple.probabilityDistance)
              << std::endl;
}

// ------------------------------------------------------------------------

static void printVector(const std::vector<ProbabilityIndexTuple> &v,
                        const size_t maxNumToPrint,
                        const size_t numRounds) {
    size_t numToPrint = v.size();
    
    if (numToPrint > maxNumToPrint && maxNumToPrint > 0) {
        numToPrint = maxNumToPrint;
    }
    
    for (size_t i = 0; i < numToPrint; ++i) {
        if (maxNumToPrint == 0) {
            printParameters(numRounds, v[i]);
        } else {
            printParametersAsPatterns(numRounds, v[i]);
        }
    }
}

// ------------------------------------------------------------------------

static void findLargestProbabilityDistances(const NTL::mat_RR &aesMatrix,
                                            const NTL::vec_RR &prpVector,
                                            const size_t numRounds,
                                            const size_t maxNumToPrint) {
    std::vector<ProbabilityIndexTuple> distances;
    
    for (size_t columnInputPatternAsInt = 1;
         columnInputPatternAsInt < 625;
         ++columnInputPatternAsInt) {
        
        for (size_t columnOutputPatternAsInt = 1;
             columnOutputPatternAsInt < 625;
             ++columnOutputPatternAsInt) {
            ProbabilityIndexTuple item;
            item.probabilityForAES.SetPrecision(PRECISION);
            item.probabilityForPRP.SetPrecision(PRECISION);
            item.probabilityDistance.SetPrecision(PRECISION);
            
            item.probabilityForAES = aesMatrix[columnInputPatternAsInt][columnOutputPatternAsInt];
            item.probabilityForPRP = prpVector[columnOutputPatternAsInt];
            item.probabilityDistance =
                item.probabilityForAES - item.probabilityForPRP;
            item.columnInputPatternAsInt = columnInputPatternAsInt;
            item.columnOutputPatternAsInt = columnOutputPatternAsInt;
            
            distances.push_back(item);
        }
    }
    
    if (maxNumToPrint == 0) {
        printVector(distances, maxNumToPrint, numRounds);
        return;
    }
    
    std::sort(distances.begin(), distances.end(),
              [](ProbabilityIndexTuple const &t1,
                 ProbabilityIndexTuple const &t2) {
                  return t1.probabilityDistance < t2.probabilityDistance;
              });
    
    printVector(distances, maxNumToPrint, numRounds);
    
    std::sort(distances.begin(), distances.end(),
              [](ProbabilityIndexTuple const &t1,
                 ProbabilityIndexTuple const &t2) {
                  return t1.probabilityDistance > t2.probabilityDistance;
              });
    
    printVector(distances, maxNumToPrint, numRounds);
}

// ------------------------------------------------------------------------

static
void testAllSingleElementTrails(const ExperimentContext &context) {
    AESColumnTransitionAlgorithm algorithm;
    setUp(context.zTablePath, algorithm);
    
    std::cout << "#Testing all trails from a single input pattern to "
              << "all output patterns." << std::endl;
    std::cout << "#Rounds #Input #Output-bytes Distance" << std::endl;
    
    for (size_t numRounds = context.minNumRounds;
         numRounds <= context.maxNumRounds;
         ++numRounds) {
        NTL::mat_RR aesProbabilitiesMatrix;
        aesProbabilitiesMatrix.SetDims(625, 625);
        aesProbabilitiesMatrix[0][0].SetPrecision(PRECISION);
        
        algorithm.createMatrix(aesProbabilitiesMatrix, numRounds);
        
        NTL::vec_RR prpVector;
        prpVector.SetLength(625);
        prpVector[0].SetPrecision(PRECISION);
        
        algorithm.computeOutputDistributionForPRP(prpVector);
        findLargestProbabilityDistances(aesProbabilitiesMatrix,
                                        prpVector,
                                        numRounds,
                                        context.maxNumToPrint);
    }
}

// ------------------------------------------------------------------------

static void
testAllSingleElementDistinguishers(const ExperimentContext &context) {
    AESColumnTransitionAlgorithm algorithm;
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
                 columnOutputPatternAsInt <
                 625; ++columnOutputPatternAsInt) {
                
                uint8_t outputColumnPattern[4];
                toActiveColumnPattern(outputColumnPattern,
                                      columnOutputPatternAsInt);
                
                bool outputInterests[5][5][5][5];
                buildSingleElementOutputInterests(outputInterests,
                                                  outputColumnPattern);
                
                ProbabilityIndexTuple item;
                item.columnInputPatternAsInt = columnInputPatternAsInt;
                item.columnOutputPatternAsInt = columnOutputPatternAsInt;
                item.probabilityForAES.SetPrecision(PRECISION);
                item.probabilityForPRP.SetPrecision(PRECISION);
                item.probabilityDistance.SetPrecision(PRECISION);
                item.probabilityDistance.SetOutputPrecision(OUTPUT_PRECISION);
                
                item.probabilityForAES = 0;
                item.probabilityForPRP = 0;
                
                algorithm.computeOutputProbabilityForAES(item.probabilityForAES,
                                                         inputDistribution,
                                                         outputInterests,
                                                         matrix,
                                                         numRounds);
                
                algorithm.computeOutputProbabilityForPRP(item.probabilityForPRP,
                                                         outputInterests);
                
                item.probabilityDistance =
                    item.probabilityForAES - item.probabilityForPRP;
                printParameters(numRounds, item);
            }
        }
    }
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
    parser.addArgument("-p", "--print", 1, false);
    
    try {
        parser.parse((size_t) argc, argv);
        context.minNumRounds = static_cast<size_t>(parser.retrieveAsLong(
            "a"));
        context.maxNumRounds = static_cast<size_t>(parser.retrieveAsLong(
            "b"));
        context.zTablePath = parser.retrieve<std::string>("z");
        context.maxNumToPrint = static_cast<size_t>(parser.retrieveAsLong(
            "p"));
    } catch (...) {
        std::cerr << parser.usage().c_str() << std::endl;
        exit(EXIT_FAILURE);
    }
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(context, argc, argv);
//    testAllSingleElementDistinguishers(context);
    testAllSingleElementTrails(context);
    return EXIT_SUCCESS;
}
