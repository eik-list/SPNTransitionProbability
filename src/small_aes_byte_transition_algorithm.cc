/**
 * Copyright 2019 anonymized
 */

#include "small_aes_byte_transition_algorithm.h"

#include <cstdio>

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
static const size_t PRECISION = 400;
static const size_t OUTPUT_PRECISION = 100;
static NTL::RR Q8;
static NTL::RR Q12;
static NTL::RR Q16;
static NTL::RR Q24;
static NTL::RR Q32;
static NTL::RR Q48;
static NTL::RR Q64;
static NTL::RR POWERS_OF_15[5];

// ------------------------------------------------------------------------

static void printVector(const NTL::vec_RR &values) {
    auto numValues = static_cast<size_t >(values.length());

    for (size_t i = 0; i < numValues; ++i) {
        std::cout << values[i] << " ";
    }

    std::cout << std::endl;
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

static size_t getHammingWeight(uint8_t bytePattern[4][4]) {
    size_t result = 0;

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            result += bytePattern[i][j] & 1;
        }
    }

    return result;
}

// ------------------------------------------------------------------------

static size_t getHammingWeightFromInt(const size_t bytePatternAsInt) {
    size_t result = 0;

    for (int i = 0; i < 16; ++i) {
        result += (bytePatternAsInt >> i) & 1;
    }

    return result;
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
    for (int i = 0; i < 4; i++) {  // column
        for (int j = 0; j < 4; j++) {  // row
            bytePattern[j][i] = static_cast<uint8_t>(
                (bytePatternAsInt >> (4 * i + j)) & 1);
        }
    }
}

// ------------------------------------------------------------------------

static void
toActiveColumnPattern(uint8_t columnPattern[4], const int columnPatternAsInt) {
    int pattern = columnPatternAsInt;

    for (int i = 0; i < 4; i++) {
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
    for (int i = 0; i < 4; ++i) {
        const auto columnWeight =
            static_cast<uint8_t>((bytePatternIndex >> (4 * i)) & 0xF);
        columnPattern[i] = static_cast<uint8_t>(
            getColumnWeightFromInt(columnWeight));
    }
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

    for (int i = 0; i < 4; i++) {  // column
        for (int j = 0; j < 4; j++) {  // row
            result |= (bytePattern[i][j] & 1) << (4 * i + j);
        }
    }

    return result;
}

// ------------------------------------------------------------------------

static void
getWeightPattern(uint8_t wpattern0[4], uint8_t wpattern1[4], const int p1) {
    uint8_t S1[4][4];
    toActiveBytePattern(S1, p1);

    for (int i = 0; i < 4; i++) {  // getNumActiveBytesInColumn of i-th column
        wpattern0[i] = getNumActiveBytesInColumn(S1, i);
    }

    shiftRows(S1, 0, 4);

    for (int i = 0; i < 4; i++) {
        wpattern1[i] = getNumActiveBytesInColumn(S1, i);
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
    Q8.SetPrecision(PRECISION);
    Q8 = 256;

    Q12.SetPrecision(PRECISION);
    Q12 = 4096;

    Q16.SetPrecision(PRECISION);
    Q16 = 65536;

    Q24.SetPrecision(PRECISION);
    Q24 = 16777216;

    Q32.SetPrecision(PRECISION);
    Q32 = 4294967296;

    Q48.SetPrecision(PRECISION);
    Q48 = Q16 * Q32;

    Q64.SetPrecision(PRECISION);
    Q64 = Q32 * Q32;

    // -----------------------------------------------------------------------
    // powersOf15[i] = 15^i
    // ------------------------------------------------------------------------

    POWERS_OF_15[0].SetPrecision(PRECISION);
    POWERS_OF_15[0] = 1;
    POWERS_OF_15[1] = 15;
    POWERS_OF_15[2] = 225;
    POWERS_OF_15[3] = 3375;
    POWERS_OF_15[4] = 50625;

    // ------------------------------------------------------------------------
    // Number of options with i active bytes.
    // BINOMIAL_COEFFICIENTS[i] = binom(4, i).
    // ------------------------------------------------------------------------

    BINOMIAL_COEFFICIENTS[0].SetPrecision(PRECISION);
    BINOMIAL_COEFFICIENTS[0] = 1;
    BINOMIAL_COEFFICIENTS[1] = 4;
    BINOMIAL_COEFFICIENTS[2] = 6;
    BINOMIAL_COEFFICIENTS[3] = 4;
    BINOMIAL_COEFFICIENTS[4] = 1;
}

// ------------------------------------------------------------------------

SmallAESByteTransitionAlgorithm::SmallAESByteTransitionAlgorithm() {
    initializeConstants();
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::buildFirstByteDistribution(
    NTL::vec_RR &distribution) const {
    distribution[1] = 1;
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::buildFirstDiagonalDistribution(
    NTL::vec_RR &distribution) const {

    for (size_t i = 1; i < 65536; ++i) {
        const bool otherDiagonalsInactive = (i & 0x7bde) == 0;
        distribution[i] = otherDiagonalsInactive;
    }
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::buildSingleElementDistribution(
    NTL::vec_RR &distribution,
    const size_t bytePatternAsInt) const {

    distribution.SetLength(65536);
    distribution[0].SetPrecision(PRECISION);
    distribution[0].SetOutputPrecision(OUTPUT_PRECISION);

    for (size_t i = 0; i < 65536; ++i) {
        distribution[i] = 0;
    }

    distribution[bytePatternAsInt] = 1;
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::buildSingleElementDistribution(
    NTL::vec_RR &distribution,
    const uint8_t bytePattern[4][4]) const {
    const size_t bytePatternAsInt = static_cast<size_t >(computeIndexFromBytePattern(
        bytePattern));
    buildSingleElementDistribution(distribution, bytePatternAsInt);
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::precomputeShiftRowsMatrix() {
    // ------------------------------------------------------------------------
    // The transition probabilities for the SR layer is straight-forward.
    // Recall, T_SR is of dimension 625 x 625.
    // ------------------------------------------------------------------------

    TSRNormal.SetDims(625, 625);
    TSRNormal[0][0].SetPrecision(PRECISION);

    for (int p1 = 0; p1 < 65536; p1++) {
        uint8_t wpattern0[4];
        uint8_t wpattern1[4];

        // ---------------------------------------------------------------------
        // This function is the main one here.
        // Given p1 = (...., ...., ...., ....)
        // ---------------------------------------------------------------------

        getWeightPattern(wpattern0, wpattern1, p1);

        const int I = computeIndexFromColumnPattern(wpattern0);
        const int J = computeIndexFromColumnPattern(wpattern1);

        NTL::RR M;
        M = 1;

        for (int i = 0; i < 4; i++) {
            M = M * BINOMIAL_COEFFICIENTS[wpattern0[i]];
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

    for (int bytePatternAsInt = 0;
         bytePatternAsInt < 65536;
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

    for (int columnPatternAsInt = 0;
         columnPatternAsInt < 625;
         columnPatternAsInt++) {
        toActiveColumnPattern(columnPattern, columnPatternAsInt);
        generator.initialize(columnPattern);

        NTL::RR numBytePatterns;
        numBytePatterns.SetPrecision(PRECISION);
        numBytePatterns = generator.getNumElements(columnPattern);

        NTL::RR probabilityForBytePattern;
        probabilityForBytePattern.SetPrecision(PRECISION);
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

void SmallAESByteTransitionAlgorithm::precomputeMixColumnsMatrix() {
    // ------------------------------------------------------------------------
    // Compute a 625 x 625 transition matrix T_MC where indices are in base-5,
    // e.g. an integer 0<= I < 625 can be written as
    // I = i0 + i1 * 5 + i2 * 5^2 + i3 * 5^3, where (i0,i1,i2,i3) is s.t. there
    // are i_j active bytes in the j'th column with respect to the Super-Box
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

    TMC.SetDims(625, 625);

    TMC[0][0].SetPrecision(PRECISION);

    for (uint8_t w1 = 0; w1 < 5; w1++) {
        for (uint8_t w2 = 0; w2 < 5; w2++) {
            for (uint8_t w3 = 0; w3 < 5; w3++) {
                for (uint8_t w4 = 0; w4 < 5; w4++) {
                    uint8_t wpattern0[4] = {w1, w2, w3, w4};
                    int I = computeIndexFromColumnPattern(wpattern0);

                    for (uint8_t v1 = 0; v1 < 5; v1++) {
                        for (uint8_t v2 = 0; v2 < 5; v2++) {
                            for (uint8_t v3 = 0; v3 < 5; v3++) {
                                for (uint8_t v4 = 0; v4 < 5; v4++) {
                                    uint8_t wpattern1[4] = {v1, v2, v3, v4};
                                    int J = computeIndexFromColumnPattern(
                                        wpattern1);
                                    NTL::RR q;
                                    q = 1;

                                    // -----------------------------------------
                                    // Product of Z_Table[i][j] is the
                                    // transition probability for a single
                                    // application of MixColumns.
                                    // -----------------------------------------

                                    for (int i = 0; i < 4; i++) {
                                        q *= zTable[wpattern0[i]][wpattern1[i]];
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
    Z_Table[0][0].SetPrecision(PRECISION);

    const size_t Qw[5] = {0, 1, 3, 7, 15};

    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            Z_Table[i][j] = Z[Qw[i]][Qw[j]] / (POWERS_OF_15[i]);
        }
    }
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::readZTable(const std::string &path) {
    NTL::ZZ Z_ZZ[16][16];
    readZTableFromPath(Z_ZZ, path);

    NTL::RR Z[16][16];
    convertZTableToRealValues(Z_ZZ, Z);

    reduceZTable(zTable, Z);
    hasInitializedZTable = true;
}

// ------------------------------------------------------------------------

bool SmallAESByteTransitionAlgorithm::haveMatricesBeenPrecomputed() const {
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

void SmallAESByteTransitionAlgorithm::createMatrix(NTL::mat_RR &matrix,
                                              const size_t numRounds) const {
    if (!haveMatricesBeenPrecomputed()) {
        return;
    }

    matrix.SetDims(625, 625);
    matrix[0][0].SetPrecision(PRECISION);
    matrix[0][0].SetOutputPrecision(OUTPUT_PRECISION);

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

void SmallAESByteTransitionAlgorithm::applyMixColumns(
    NTL::vec_RR &bytePatternDistribution) const {

    NTL::vec_RR columnPatternDistribution;
    columnPatternDistribution.SetLength(625);
    columnPatternDistribution[0].SetPrecision(PRECISION);
    columnPatternDistribution[0].SetOutputPrecision(100);
    compressToColumnPattern(bytePatternDistribution, columnPatternDistribution);

    std::cout << "Columns before MC" << std::endl;
    printVector(columnPatternDistribution);

    columnPatternDistribution = columnPatternDistribution * TMC;

    std::cout << "Columns after MC" << std::endl;
    printVector(columnPatternDistribution);

    expandToBytePattern(columnPatternDistribution, bytePatternDistribution);
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::applyShiftRows(
    NTL::vec_RR &bytePatternDistribution) const {
    NTL::vec_RR result;
    result.SetLength(bytePatternDistribution.length());
    result[0].SetPrecision(PRECISION);

    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < 65536; bytePatternAsInt++) {
        const size_t mappedInt = TSR[bytePatternAsInt];
        result[mappedInt] = bytePatternDistribution[bytePatternAsInt];
    }

    bytePatternDistribution = result;
}

// ------------------------------------------------------------------------

static void
printInterest(const size_t bytePatternAsInt, const NTL::RR &probability) {
    printf("%04zx: ", bytePatternAsInt);
    std::cout << probability << std::endl;
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::computeOutputProbabilityForAES(
    NTL::RR &probability,
    const NTL::vec_RR &inputDistribution,
    const std::bitset<65536> &outputInterests,
    const NTL::mat_RR &matrix,
    const size_t numRounds) const {
    if (!haveMatricesBeenPrecomputed()) {
        return;
    }

    NTL::vec_RR outputDistribution;
    outputDistribution.SetLength(625);
    outputDistribution[0].SetPrecision(PRECISION);

    probability.SetPrecision(PRECISION);
    probability = 0;

    if (numRounds == 0) {
        return;
    }

    compressToColumnPattern(inputDistribution, outputDistribution);
    outputDistribution = outputDistribution * matrix;

    NTL::vec_RR outputByteDistribution;
    outputByteDistribution.SetLength(65536);
    outputByteDistribution[0].SetPrecision(PRECISION);
    outputByteDistribution[0].SetOutputPrecision(OUTPUT_PRECISION);

    expandToBytePattern(outputDistribution, outputByteDistribution);

    for (size_t bytePatternAsInt = 1;
         bytePatternAsInt < 65536;
         ++bytePatternAsInt) {
        if (outputInterests[bytePatternAsInt]) {
            probability += outputByteDistribution[bytePatternAsInt];
        }
    }
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::computeOutputProbabilityForAES(
    NTL::RR &probability,
    const NTL::vec_RR &inputDistribution,
    const std::bitset<65536> &outputInterests,
    const size_t numRounds) const {
    if (!haveMatricesBeenPrecomputed()) {
        return;
    }

    probability.SetPrecision(PRECISION);
    probability = 0;

    NTL::vec_RR outputDistribution;
    outputDistribution.SetLength(625);
    outputDistribution[0].SetPrecision(PRECISION);

    compressToColumnPattern(inputDistribution, outputDistribution);

    if (numRounds == 0) {
        return;
    }

    outputDistribution = outputDistribution * TMC;

    if (numRounds >= 2) {
        for (size_t k = 0; k < numRounds - 2; ++k) {
            outputDistribution = outputDistribution * TSRNormal;
            outputDistribution = outputDistribution * TMC;
        }
    }

    NTL::vec_RR outputByteDistribution;
    outputByteDistribution.SetLength(65536);
    outputByteDistribution[0].SetPrecision(PRECISION);
    outputByteDistribution[0].SetOutputPrecision(OUTPUT_PRECISION);

    expandToBytePattern(outputDistribution, outputByteDistribution);

    for (size_t bytePatternAsInt = 1;
         bytePatternAsInt < 65536;
         ++bytePatternAsInt) {
        if (outputInterests[bytePatternAsInt]) {
            probability += outputByteDistribution[bytePatternAsInt];
        }
    }
}

// ------------------------------------------------------------------------

void SmallAESByteTransitionAlgorithm::computeOutputProbabilityForPRP(
    NTL::RR &probability,
    const std::bitset<65536> &outputInterests) const {
    probability.SetPrecision(PRECISION);

    for (size_t bytePatternAsInt = 0;
         bytePatternAsInt < 65536;
         ++bytePatternAsInt) {
        if (outputInterests[bytePatternAsInt]) {
            // Theoretically, we could use pow(255, numActiveBytes) / Q64
            // In practice, pow lacks precision
            uint8_t columnPattern[4];
            bytePatternIndexToActiveColumnPattern(columnPattern,
                                                  bytePatternAsInt);

            probability += POWERS_OF_15[columnPattern[0]] *
                           POWERS_OF_15[columnPattern[1]] *
                           POWERS_OF_15[columnPattern[2]] *
                           POWERS_OF_15[columnPattern[3]] /
                           (Q16 * Q16 * Q16 * Q16);
        }
    }
}

// ------------------------------------------------------------------------
