/**
 * Copyright 2019 anonymized
 */

#include "aes_byte_mixture_transition_algorithm.h"
#include "dependency_strategy.h"

#include <cstdio>

#include <algorithm>
#include <bitset>
#include <fstream>
#include <vector>

#include "byte_pattern_generator.h"
#include "rijndael.h"

// ------------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------------

#define SC    ((BC - 4) >> 1)

static const uint8_t SHIFTS[3][4][2] = {
    {{0, 0},
        {1, 3},
        {2, 2},
        {3, 1}},
    
    {{0, 0},
        {1, 5},
        {2, 4},
        {3, 3}},
    
    {{0, 0},
        {1, 7},
        {3, 5},
        {4, 4}}
};

static NTL::RR BINOMIAL_COEFFICIENTS[5];
static NTL::RR Q16;
static NTL::RR Q24;
static NTL::RR Q32;
static NTL::RR Q64;
static NTL::RR Q96;
static NTL::RR Q128;
static NTL::RR POWERS_OF_255[5];

static const size_t NUM_BYTE_PATTERNS = 65536;
static const size_t NUM_COLUMN_PATTERNS = 625;
static const size_t NUM_BITS_PRECISION = 400;
static const size_t NUM_BITS_OUTPUT_PRECISION = 100;

// ------------------------------------------------------------------------

static void prepareMatrix(NTL::mat_RR &matrix,
                          const size_t dimension,
                          const size_t precision,
                          const size_t outputPrecision) {
    matrix.SetDims(dimension, dimension);
    matrix[0][0].SetPrecision(precision);
    matrix[0][0].SetOutputPrecision(outputPrecision);
}

// ------------------------------------------------------------------------

static void prepareDistribution(NTL::vec_RR &distribution,
                                const size_t length,
                                const size_t precision) {
    distribution.SetLength(length);
    distribution[0].SetPrecision(precision);
}

// ------------------------------------------------------------------------

static void prepareDistribution(NTL::vec_RR &distribution,
                                const size_t length,
                                const size_t precision,
                                const size_t outputPrecision) {
    distribution.SetLength(length);
    distribution[0].SetPrecision(precision);
    distribution[0].SetOutputPrecision(outputPrecision);
}

// ------------------------------------------------------------------------

static void printVector(const NTL::vec_RR &values) {
    auto numValues = static_cast<size_t >(values.length());
    
    for (size_t i = 0; i < numValues; ++i) {
        std::cout << values[i] << " ";
    }
    
    std::cout << std::endl;
}

// ------------------------------------------------------------------------

static void
printDependency(const size_t i, const AESColumnDependencyVector &item) {
    std::cout << i << " ";
    
    for (size_t j = 0; j < item.size(); ++j) {
        std::string columnDependencies = item[j].to_string();
        std::reverse(columnDependencies.begin(), columnDependencies.end());
        std::cout << "(" << columnDependencies << ") ";
    }
    
    std::cout << std::endl;
}

// ------------------------------------------------------------------------

static void
printPattern(const uint8_t bytePattern[NUM_AES_COLUMNS][NUM_AES_ROWS]) {
    for (size_t i = 0; i < NUM_AES_COLUMNS; ++i) {
        for (size_t j = 0; j < NUM_AES_ROWS; ++j) {
            printf("%d", bytePattern[j][i]);
        }
    }
    
    printf("\n");
}

// ------------------------------------------------------------------------

/**
 * Row 0 remains unchanged. The other three rows are rotated by 1, 2, 3
 * positions to the left.
 * @param a[4][4] Active-byte pattern of rows and columns
 * @param d
 * @param BC 4 = rows per column
 */
static void shiftRows(uint8_t a[4][MAXBC], const uint8_t d, const uint8_t BC) {
    uint8_t tmp[MAXBC];
    int i, j;
    
    for (i = 1; i < 4; i++) {
        for (j = 0; j < BC; j++) {
            tmp[j] = a[i][(j + SHIFTS[SC][i][d]) % BC];
        }
        
        for (j = 0; j < BC; j++) {
            a[i][j] = tmp[j];
        }
    }
}

// ------------------------------------------------------------------------

static size_t getColumnWeightFromInt(const uint8_t fourBits) {
    size_t result = 0;
    
    for (int i = 0; i < 4; ++i) {
        result += (fourBits >> i) & 1;
    }
    
    return result;
}

// ------------------------------------------------------------------------

/**
 * Returns the number of active cells in s[j][k], for j = 0..4.
 * @param bytePattern
 * @param column
 * @return
 */
static uint8_t
getNumActiveBytesInColumn(const uint8_t bytePattern[4][4], const int column) {
    uint8_t w = 0;
    
    for (size_t j = 0; j < 4; j++) {
        if (bytePattern[j][column] != 0) {
            w++;
        }
    }
    
    return w;
}

// ------------------------------------------------------------------------

static void
activeByteToActiveColumnPattern(const uint8_t activeBytePattern[4][4],
                                uint8_t activeColumnPattern[4]) {
    for (int i = 0; i < 4; i++) {  // getNumActiveBytesInColumn of i-th column
        activeColumnPattern[i] =
            getNumActiveBytesInColumn(activeBytePattern, i);
    }
}

// ------------------------------------------------------------------------

static void toActiveBytePattern(uint8_t bytePattern[4][4],
                                const int bytePatternAsInt) {
    for (int i = 0; i < NUM_AES_COLUMNS; i++) {  // column
        for (int j = 0; j < NUM_AES_ROWS; j++) {  // row
            bytePattern[j][i] = static_cast<uint8_t>(
                (bytePatternAsInt >> (4 * i + j)) & 1);
        }
    }
}

// ------------------------------------------------------------------------

static void
toActiveColumnPattern(uint8_t columnPattern[4], const int columnPatternAsInt) {
    int pattern = columnPatternAsInt;
    
    for (int i = 0; i < NUM_AES_COLUMNS; i++) {
        const int numActiveBytesInColumn = pattern % 5;
        columnPattern[i] = static_cast<uint8_t>(numActiveBytesInColumn);
        
        pattern -= numActiveBytesInColumn;
        pattern = pattern / 5;
    }
}

// ------------------------------------------------------------------------

static void
bytePatternIndexToActiveColumnPattern(uint8_t columnPattern[4],
                                      const size_t bytePatternIndex) {
    for (size_t i = 0; i < NUM_AES_COLUMNS; ++i) {
        const auto columnWeight =
            static_cast<uint8_t>((bytePatternIndex >> (NUM_AES_ROWS * i)) &
                                 0xF);
        columnPattern[i] = static_cast<uint8_t>(
            getColumnWeightFromInt(columnWeight));
    }
}

// ------------------------------------------------------------------------

static size_t getHammingWeight(const size_t value, const size_t numBits) {
    size_t weight = 0;
    
    for (uint8_t i = 0; i < numBits; ++i) {
        const size_t bit = (value >> i) & 1;
        if (bit != 0) {
            weight++;
        }
    }
    
    return weight;
}

// ------------------------------------------------------------------------

/**
 * @param S1 an active-byte pattern of an AES state.
 * @return The 16-bit value that corresponds to the state.
 */
static int computeIndexFromColumnPattern(const uint8_t columnPattern[4]) {
    int result = 0;
    
    for (int i = 0; i < 4; i++) {
        result += static_cast<int>(pow(5, i)) * columnPattern[i];
    }
    
    return result;
}

// ------------------------------------------------------------------------

/**
 * @param S1 an active-byte pattern of an AES state.
 * @return The 16-bit value that corresponds to the state.
 */
static int computeIndexFromBytePattern(const uint8_t bytePattern[4][4]) {
    int result = 0;
    
    for (int i = 0; i < NUM_AES_COLUMNS; i++) {  // column
        for (int j = 0; j < NUM_AES_ROWS; j++) {  // row
            result |= (bytePattern[i][j] & 1) << (4 * i + j);
        }
    }
    
    return result;
}

// ------------------------------------------------------------------------

static void
getWeightPattern(uint8_t weight_pattern0[4], uint8_t weight_pattern1[4],
                 const int p1) {
    uint8_t S1[4][4];
    toActiveBytePattern(S1, p1);
    
    for (int i = 0; i < 4; i++) {  // getNumActiveBytesInColumn of i-th column
        weight_pattern0[i] = getNumActiveBytesInColumn(S1, i);
    }
    
    shiftRows(S1, 0, 4);
    
    for (int i = 0; i < 4; i++) {
        weight_pattern1[i] = getNumActiveBytesInColumn(S1, i);
    }
}

// ------------------------------------------------------------------------

static void zeroize(NTL::vec_RR &input) {
    const auto numEntries = static_cast<size_t >(input.length());
    
    for (size_t i = 0; i < numEntries; ++i) {
        input[i] = 0;
    }
}

// ------------------------------------------------------------------------

static void initializeConstants() {
    Q16.SetPrecision(NUM_BITS_PRECISION);
    Q16 = 65536;
    
    Q24.SetPrecision(NUM_BITS_PRECISION);
    Q24 = 16777216;
    
    Q32.SetPrecision(NUM_BITS_PRECISION);
    Q32 = 4294967296;
    
    Q64.SetPrecision(NUM_BITS_PRECISION);
    Q64 = Q32 * Q32;
    
    Q96.SetPrecision(NUM_BITS_PRECISION);
    Q96 = Q64 * Q32;
    
    Q128.SetPrecision(NUM_BITS_PRECISION);
    Q128 = Q64 * Q64;
    
    // -----------------------------------------------------------------------
    // powersOf255[i] = 255^i
    // ------------------------------------------------------------------------
    
    POWERS_OF_255[0].SetPrecision(NUM_BITS_PRECISION);
    POWERS_OF_255[0] = 1;
    POWERS_OF_255[1] = 255;
    POWERS_OF_255[2] = 65025;
    POWERS_OF_255[3] = 16581375;
    POWERS_OF_255[4] = 4228250625;
    
    // ------------------------------------------------------------------------
    // Number of options with i active bytes.
    // BINOMIAL_COEFFICIENTS[i] = binom(4, i).
    // ------------------------------------------------------------------------
    
    BINOMIAL_COEFFICIENTS[0].SetPrecision(NUM_BITS_PRECISION);
    BINOMIAL_COEFFICIENTS[0] = 1;
    BINOMIAL_COEFFICIENTS[1] = 4;
    BINOMIAL_COEFFICIENTS[2] = 6;
    BINOMIAL_COEFFICIENTS[3] = 4;
    BINOMIAL_COEFFICIENTS[4] = 1;
}

// ------------------------------------------------------------------------

AESByteMixtureTransitionAlgorithm::AESByteMixtureTransitionAlgorithm() {
    initializeConstants();
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::buildFirstByteDistribution(
    NTL::vec_RR &distribution) const {
    distribution[1] = 1;
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::buildFirstDiagonalDistribution(
    NTL::vec_RR &distribution) const {
    
    for (size_t i = 1; i < NUM_BYTE_PATTERNS; ++i) {
        const bool otherDiagonalsInactive = (i & 0x7bde) == 0;
        distribution[i] = otherDiagonalsInactive;
    }
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::buildSingleElementDistribution(
    NTL::vec_RR &distribution,
    const size_t bytePatternAsInt) const {
    prepareDistribution(distribution,
                        NUM_BYTE_PATTERNS,
                        NUM_BITS_PRECISION,
                        NUM_BITS_OUTPUT_PRECISION);
    
    for (size_t i = 0; i < NUM_BYTE_PATTERNS; ++i) {
        distribution[i] = 0;
    }
    
    distribution[bytePatternAsInt] = 1;
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::buildSingleElementDistribution(
    NTL::vec_RR &distribution,
    const uint8_t bytePattern[NUM_AES_COLUMNS][NUM_AES_ROWS]) const {
    auto bytePatternAsInt = static_cast<const size_t >(
        computeIndexFromBytePattern(bytePattern));
    buildSingleElementDistribution(distribution, bytePatternAsInt);
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::precomputeShiftRowsMatrix() {
    // ------------------------------------------------------------------------
    // The transition probabilities for the SR layer is straight-forward.
    // Recall, T_SR is of dimension 625 x 625.
    // ------------------------------------------------------------------------
    
    TSRNormal.SetDims(NUM_COLUMN_PATTERNS, NUM_COLUMN_PATTERNS);
    TSRNormal[0][0].SetPrecision(NUM_BITS_PRECISION);
    
    for (size_t p1 = 0; p1 < NUM_BYTE_PATTERNS; p1++) {
        uint8_t weight_pattern0[4];
        uint8_t weight_pattern1[4];
        
        // ---------------------------------------------------------------------
        // This function is the main one here.
        // Given p1 = (...., ...., ...., ....)
        // ---------------------------------------------------------------------
        
        getWeightPattern(weight_pattern0, weight_pattern1, p1);
        
        const int I = computeIndexFromColumnPattern(weight_pattern0);
        const int J = computeIndexFromColumnPattern(weight_pattern1);
        
        NTL::RR M;
        M = 1;
        
        for (int i = 0; i < 4; i++) {
            M = M * BINOMIAL_COEFFICIENTS[weight_pattern0[i]];
        }
        
        TSRNormal[I][J] += 1 / M;
    }
    
    hasInitializedTSR = true;
}

// ------------------------------------------------------------------------

static void compressToColumnPattern(const NTL::vec_RR &bytePatternVector,
                                    NTL::vec_RR &columnPatternVector) {
    uint8_t bytePattern[4][4];
    uint8_t columnPattern[4];
    int columnPatternAsInt;
    
    zeroize(columnPatternVector);
    
    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < NUM_BYTE_PATTERNS;
         bytePatternAsInt++) {
        toActiveBytePattern(bytePattern, bytePatternAsInt);
        activeByteToActiveColumnPattern(bytePattern, columnPattern);
        
        columnPatternAsInt = computeIndexFromColumnPattern(columnPattern);
        columnPatternVector[columnPatternAsInt] +=
            bytePatternVector[bytePatternAsInt];
    }
}

// ------------------------------------------------------------------------

static void expandToBytePattern(const NTL::vec_RR &columnPatternVector,
                                NTL::vec_RR &bytePatternVector) {
    uint8_t bytePattern[4][4];
    uint8_t columnPattern[4];
    
    utils::BytePatternGenerator generator;
    
    for (size_t columnPatternAsInt = 0;
         columnPatternAsInt < NUM_COLUMN_PATTERNS;
         columnPatternAsInt++) {
        toActiveColumnPattern(columnPattern, columnPatternAsInt);
        generator.initialize(columnPattern);
        
        NTL::RR numBytePatterns;
        numBytePatterns.SetPrecision(NUM_BITS_PRECISION);
        numBytePatterns = generator.getNumElements(columnPattern);
        
        NTL::RR probabilityForBytePattern;
        probabilityForBytePattern.SetPrecision(NUM_BITS_PRECISION);
        probabilityForBytePattern =
            columnPatternVector[columnPatternAsInt] / numBytePatterns;
        
        while (generator.hasNext()) {
            generator.next(bytePattern);
            
            const auto bytePatternAsInt = static_cast<size_t >(
                computeIndexFromBytePattern(bytePattern));
            
            bytePatternVector[bytePatternAsInt] = probabilityForBytePattern;
        }
    }
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::precomputeMixColumnsMatrix() {
    // ------------------------------------------------------------------------
    // Compute a 625 x 625 transition matrix T_MC where indices are in base-5,
    // e.g. an integer 0<= I < 625 can be written as
    // I = i0 + i1 * 5 + i2 * 5^2 + i3 * 5^3, where (i0,i1,i2,i3) is s.t. there
    // are i_j active bytes in the j-th column with respect to the Super-Box
    // representation. This means, the first and last linear layers are omitted
    // so that we can work only with columns.
    //
    // T_MC is populated by going through all possible 625^2 combinations (I, J)
    // and simply computing
    // T_MC[i0+ i1 * 5 + i3 * 5^2 + i4 * 5^3][j0 + j1 * 5 + j3 * 5^2 + j4 * 5^3]
    //   = Pr[wt pattern (j0,j1,j2,h3) out | getNumActiveBytesInColumn pattern
    //     (i0,i1,i2,i3) in]
    //   = MDS-transition probabilities.
    // ------------------------------------------------------------------------
    
    hasInitializedTMC = false;
    
    if (!hasInitializedZTable) {
        std::cerr << "Z-Table has not been initialized." << std::endl;
    }
    
    TMC.SetDims(NUM_COLUMN_PATTERNS, NUM_COLUMN_PATTERNS);
    TMC[0][0].SetPrecision(NUM_BITS_PRECISION);
    
    for (uint8_t w1 = 0; w1 < 5; w1++) {
        for (uint8_t w2 = 0; w2 < 5; w2++) {
            for (uint8_t w3 = 0; w3 < 5; w3++) {
                for (uint8_t w4 = 0; w4 < 5; w4++) {
                    uint8_t weight_pattern0[4] = {w1, w2, w3, w4};
                    int I = computeIndexFromColumnPattern(weight_pattern0);
                    
                    for (uint8_t v1 = 0; v1 < 5; v1++) {
                        for (uint8_t v2 = 0; v2 < 5; v2++) {
                            for (uint8_t v3 = 0; v3 < 5; v3++) {
                                for (uint8_t v4 = 0; v4 < 5; v4++) {
                                    uint8_t weight_pattern1[4] = {v1, v2, v3,
                                                                  v4};
                                    int J = computeIndexFromColumnPattern(
                                        weight_pattern1);
                                    NTL::RR q;
                                    q = 1;
                                    
                                    // -----------------------------------------
                                    // Product of Z_Table[i][j] is the
                                    // transition probability for a single
                                    // application of MixColumns.
                                    // -----------------------------------------
                                    
                                    for (int i = 0; i < 4; i++) {
                                        q *= zTable[weight_pattern0[i]][weight_pattern1[i]];
                                    }
                                    
                                    TMC[I][J] = (BINOMIAL_COEFFICIENTS[v1]
                                                 * BINOMIAL_COEFFICIENTS[v2]
                                                 * BINOMIAL_COEFFICIENTS[v3]
                                                 * BINOMIAL_COEFFICIENTS[v4]) *
                                                q;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    hasInitializedTMC = true;
}

// ------------------------------------------------------------------------

static void readZTableFromPath(NTL::ZZ Z_ZZ[16][16], const std::string &path) {
    std::fstream inputFileStream;
    inputFileStream.open(path, std::fstream::in);
    
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            inputFileStream >> Z_ZZ[i][j];
        }
    }
    
    inputFileStream.close();
}

// ------------------------------------------------------------------------

static void convertZTableToRealValues(const NTL::ZZ Z_ZZ[16][16],
                                      NTL::RR Z[16][16]) {
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            conv(Z[i][j], Z_ZZ[i][j]);
        }
    }
}

// ------------------------------------------------------------------------

static void reduceZTable(NTL::mat_RR &Z_Table, const NTL::RR Z[16][16]) {
    Z_Table.SetDims(5, 5);
    Z_Table[0][0].SetPrecision(NUM_BITS_PRECISION);
    
    const size_t Qw[5] = {0, 1, 3, 7, 15};
    
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            Z_Table[i][j] = Z[Qw[i]][Qw[j]] / (POWERS_OF_255[i]);
        }
    }
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::readZTable(const std::string &path) {
    NTL::ZZ Z_ZZ[16][16];
    readZTableFromPath(Z_ZZ, path);
    
    NTL::RR Z[16][16];
    convertZTableToRealValues(Z_ZZ, Z);
    
    reduceZTable(zTable, Z);
    hasInitializedZTable = true;
}

// ------------------------------------------------------------------------

bool AESByteMixtureTransitionAlgorithm::haveMatricesBeenPrecomputed() const {
    if (!hasInitializedTSR) {
        std::cerr << "ShiftRows matrix has not been initialized. Aborting"
                  << std::endl;
    }
    
    if (!hasInitializedTMC) {
        std::cerr << "MixColumns matrix has not been initialized. Aborting."
                  << std::endl;
    }
    
    return hasInitializedTMC && hasInitializedTSR;
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::createMatrix(NTL::mat_RR &matrix,
                                                     const size_t numRounds) const {
    if (!haveMatricesBeenPrecomputed()) {
        return;
    }
    
    prepareMatrix(matrix, NUM_COLUMN_PATTERNS, NUM_BITS_PRECISION,
                  NUM_BITS_OUTPUT_PRECISION);
    
    if (numRounds == 0) {
        return;
    }
    
    matrix = TMC;
    
    if (numRounds == 1) {
        return;
    }
    
    for (size_t k = 0; k < numRounds - 2; ++k) {
        matrix = matrix * TSRNormal;
        matrix = matrix * TMC;
    }
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::applyMixColumns(
    NTL::vec_RR &bytePatternDistribution) const {
    
    NTL::vec_RR columnPatternDistribution;
    prepareDistribution(columnPatternDistribution, NUM_COLUMN_PATTERNS,
                        NUM_BITS_PRECISION,
                        NUM_BITS_OUTPUT_PRECISION);
    compressToColumnPattern(bytePatternDistribution, columnPatternDistribution);
    
    std::cout << "Columns before MC" << std::endl;
    printVector(columnPatternDistribution);
    
    columnPatternDistribution = columnPatternDistribution * TMC;
    
    std::cout << "Columns after MC" << std::endl;
    printVector(columnPatternDistribution);
    
    expandToBytePattern(columnPatternDistribution, bytePatternDistribution);
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::applyShiftRows(
    NTL::vec_RR &bytePatternDistribution) const {
    NTL::vec_RR result;
    prepareDistribution(result,
                        static_cast<const size_t>(bytePatternDistribution.length()),
                        NUM_BITS_PRECISION);
    
    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < NUM_BYTE_PATTERNS; bytePatternAsInt++) {
        const size_t mappedInt = TSR[bytePatternAsInt];
        result[mappedInt] = bytePatternDistribution[bytePatternAsInt];
    }
    
    bytePatternDistribution = result;
}

// ------------------------------------------------------------------------

static void prepareDependencies(const size_t bytePatternAsInt,
                                AESTransitionDependencyVector &dependencies) {
    uint8_t columnPattern[NUM_AES_COLUMNS];
    bytePatternIndexToActiveColumnPattern(columnPattern, bytePatternAsInt);
    
    const size_t columnPatternAsInt = computeIndexFromColumnPattern(
        columnPattern);
    
    for (uint8_t columnIndex = 0;
         columnIndex < NUM_AES_COLUMNS; ++columnIndex) {
        const auto shift = static_cast<size_t >(4 * columnIndex);
        size_t patternOfIthColumn = (bytePatternAsInt >> shift) & 0xF;
        patternOfIthColumn <<= shift;
        dependencies[columnPatternAsInt][columnIndex] = patternOfIthColumn;
        
        std::cout << columnPatternAsInt
                  << " " << static_cast<size_t >(columnIndex)
                  << std::endl;
    }
    
    printDependency(columnPatternAsInt, dependencies[columnPatternAsInt]);
}

// ------------------------------------------------------------------------

/**
 * Returns true if there exists a single non-zero difference in the dependencies
 * vector that does NOT dependent on ALL bytes that are active in the vector
 * startingBytePatternAsInt.
 * @param startingBytePatternAsInt
 * @param dependencies
 * @return
 */
bool hasMixtureEnded(const size_t startingBytePatternAsInt,
                     const AESTransitionDependencyVector &dependencies) {
    const size_t numElements = dependencies.size();
    const size_t numBitsSetAtStart = getHammingWeight(startingBytePatternAsInt,
                                                      NUM_AES_BYTES);
    
    // ------------------------------------------------------------------------
    // Start with difference corresponding to 1 to skip the trivial difference.
    // ------------------------------------------------------------------------
    
    for (size_t i = 1; i < numElements; ++i) {
        // --------------------------------------------------------------------
        // Each element is a vector of NUM_AES_COLUMNS dependencies, 1 for each
        // column.
        // --------------------------------------------------------------------
        bool hasMixtureEndedForCurrentPattern = false;
        
        size_t weight = getWeight(dependencies[i]);
        
        if (weight == 0) {
            continue;
        }
        
        for (size_t column = 0; column < NUM_AES_COLUMNS; ++column) {
            weight = dependencies[i][column].count();
            
            // ----------------------------------------------------------------
            // If there exists only one non-zero difference with full
            // dependencies, the mixture has ended.
            // ----------------------------------------------------------------
            
            if ((weight > 0) && (weight >= numBitsSetAtStart)) {
                hasMixtureEndedForCurrentPattern = true;
                break;
            }
        }
        
        // --------------------------------------------------------------------
        // If there exists only one non-zero difference for which the mixture
        // has not ended yet, then we can proceed with our mixing.
        // --------------------------------------------------------------------
        
        if (!hasMixtureEndedForCurrentPattern) {
            uint8_t bytePattern[NUM_AES_ROWS][NUM_AES_COLUMNS];
            toActiveBytePattern(bytePattern, startingBytePatternAsInt);
            
            return false;
        }
    }
    
    return true;
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::computeOutputProbabilityForAES(
    NTL::RR &probability,
    const NTL::vec_RR &inputDistribution,
    const std::bitset<NUM_BYTE_PATTERNS> &outputInterests,
    const size_t bytePatternAsInt,
    const size_t numRounds,
    const DependencyStrategy *strategy,
    size_t& numMixtureRounds) const {
    numMixtureRounds = 0;
    
    if (!haveMatricesBeenPrecomputed()) {
        return;
    }
    
    // ------------------------------------------------------------------------
    // Reset probability, and store the byte-pattern input distribution into the
    // column-pattern (= compressed) output distribution, even if nothing
    // is done.
    // ------------------------------------------------------------------------
    
    probability.SetPrecision(NUM_BITS_PRECISION);
    probability = 0;
    
    NTL::vec_RR outputDistribution;
    prepareDistribution(outputDistribution, NUM_COLUMN_PATTERNS,
                        NUM_BITS_PRECISION);
    
    compressToColumnPattern(inputDistribution, outputDistribution);
    
    if (numRounds == 0) {
        return;
    }
    
    // ------------------------------------------------------------------------
    // Prepare the dependencies of the starting difference.
    // ------------------------------------------------------------------------
    
    NTL::vec_RR tempDistribution;
    prepareDistribution(tempDistribution, NUM_COLUMN_PATTERNS,
                        NUM_BITS_PRECISION);
    tempDistribution = outputDistribution;
    
    AESTransitionDependencyVector dependencies(NUM_COLUMN_PATTERNS);
    prepareDependencies(bytePatternAsInt, dependencies);
    
    // ------------------------------------------------------------------------
    // Apply the MixColumns and ShiftRows updates for each round
    // ------------------------------------------------------------------------
    
    strategy->applyMixColumns(TMC,
                              tempDistribution,
                              dependencies,
                              outputDistribution);
    
    bool hasCurrentMixtureEnded = hasMixtureEnded(bytePatternAsInt,
                                                  dependencies);
    
    if (hasCurrentMixtureEnded) {
        numMixtureRounds = 0;
    }
    
    if (numRounds >= 2) {
        for (size_t k = 0; k < numRounds - 2; ++k) {
            strategy->applyShiftRows(TSRNormal,
                                     outputDistribution,
                                     dependencies,
                                     tempDistribution);
            
            if (!hasCurrentMixtureEnded) {
                numMixtureRounds = hasMixtureEnded(bytePatternAsInt,
                                                         dependencies);
                numMixtureRounds = k + 1;
            }
            
            strategy->applyMixColumns(TMC,
                                      tempDistribution,
                                      dependencies,
                                      outputDistribution);
            
            if (!hasCurrentMixtureEnded) {
                hasCurrentMixtureEnded = hasMixtureEnded(bytePatternAsInt,
                                                         dependencies);
                numMixtureRounds = k + 1;
            }
        }
    }
    
    NTL::vec_RR outputByteDistribution;
    prepareDistribution(outputByteDistribution,
                        NUM_BYTE_PATTERNS,
                        NUM_BITS_PRECISION,
                        NUM_BITS_OUTPUT_PRECISION);
    
    expandToBytePattern(outputDistribution, outputByteDistribution);
    
    for (size_t i = 1; i < NUM_BYTE_PATTERNS; ++i) {
        if (outputInterests[i]) {
            probability += outputByteDistribution[i];
        }
    }
}

// ------------------------------------------------------------------------

void AESByteMixtureTransitionAlgorithm::computeOutputProbabilityForPRP(
    NTL::RR &probability,
    const std::bitset<NUM_BYTE_PATTERNS> &outputInterests) const {
    probability.SetPrecision(NUM_BITS_PRECISION);
    
    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < NUM_BYTE_PATTERNS;
         ++bytePatternAsInt) {
        if (outputInterests[bytePatternAsInt]) {
            // Theoretically, we could use pow(255, numActiveBytes) / Q128
            // In practice, pow lacks precision
            uint8_t columnPattern[4];
            bytePatternIndexToActiveColumnPattern(columnPattern,
                                                  bytePatternAsInt);
            
            probability += POWERS_OF_255[columnPattern[0]] *
                           POWERS_OF_255[columnPattern[1]] *
                           POWERS_OF_255[columnPattern[2]] *
                           POWERS_OF_255[columnPattern[3]] /
                           (Q32 * Q32 * Q32 * Q32);
        }
    }
}

// ------------------------------------------------------------------------
