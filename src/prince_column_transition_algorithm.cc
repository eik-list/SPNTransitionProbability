/**
 * Copyright 2019 anonymized
 */

#include "prince_column_transition_algorithm.h"

#include <fstream>

#include "rijndael.h"
#include "byte_pattern_generator.h"

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
static NTL::RR Q16;
static NTL::RR Q24;
static NTL::RR Q32;
static NTL::RR Q64;
static NTL::RR Q96;
static NTL::RR Q128;
static NTL::RR POWERS_OF_255[5];

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
static void shiftRows(uint8_t a[4][MAXBC], uint8_t d, uint8_t BC) {
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

/**
 * Returns the number of active cells in s[j][k], for j = 0..4.
 * @param s
 * @param k
 * @return
 */
static int getNumActiveBytesInColumn(uint8_t s[4][4], int k) {
    int w = 0;

    for (int j = 0; j < 4; j++) {
        if (s[j][k] != 0) {
            w += 1;
        }
    }

    return w;
}

// ------------------------------------------------------------------------

static void toActiveBytePattern(uint8_t S1[4][4], const int p1) {
    for (int i = 0; i < 4; i++) {  // column
        for (int j = 0; j < 4; j++) {  // row
            S1[j][i] = static_cast<uint8_t>((p1 >> (4 * i + j)) & 1);
        }
    }
}

// ------------------------------------------------------------------------

/**
 *
 * @param wpattern0 Stores #active bytes for columns of p1
 * @param wpattern1 Stores #active bytes for columns of p1 after ShiftRows
 * @param p1 16-bit integer
 * @example p1 = [0011, 0001, 1100, 1001] =>
 * S1[column][row]
 *    1 1 0 1
 *    1 0 0 0
 *    0 0 1 0
 *    0 0 1 1
 */
static void
getWeightPattern(int wpattern0[4], int wpattern1[4], const int p1) {
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

/**
 * Maps a pattern of active bytes/columns to an int.
 * @example wpattern[2, 3, 1, 1] is mapped to
 * 2 * 5^0 + 3 * 5^1 + 1 * 5^2 + 1 * 5^3.
 * @param pattern Array of bytes/columns of a state.
 * @return
 */
static int computeIndex(const int pattern[4]) {
    int result = 0;

    for (int i = 0; i < 4; i++) {
        result += static_cast<int>(pow(5, i)) * pattern[i];
    }

    return result;
}

// ------------------------------------------------------------------------

/**
 * Maps a pattern of active bytes/columns to an int.
 * @example wpattern[2, 3, 1, 1] is mapped to
 * 2 * 5^0 + 3 * 5^1 + 1 * 5^2 + 1 * 5^3.
 * @param pattern Array of bytes/columns of a state.
 * @return
 */
static size_t computeIndex(const uint8_t pattern[4]) {
    size_t result = 0;

    for (size_t i = 0; i < 4; i++) {
        result += static_cast<size_t>(pow(5, i)) * pattern[i];
    }

    return result;
}

// ------------------------------------------------------------------------

static void initializeConstants() {
    Q16.SetPrecision(PRECISION);
    Q16 = 65536;

    Q24.SetPrecision(PRECISION);
    Q24 = 16777216;

    Q32.SetPrecision(PRECISION);
    Q32 = 4294967296;

    Q64.SetPrecision(PRECISION);
    Q64 = Q32 * Q32;

    Q96.SetPrecision(PRECISION);
    Q96 = Q64 * Q32;

    Q128.SetPrecision(PRECISION);
    Q128 = Q64 * Q64;

    // -----------------------------------------------------------------------
    // powersOf255[i] = 255^i
    // ------------------------------------------------------------------------

    POWERS_OF_255[0].SetPrecision(PRECISION);
    POWERS_OF_255[0] = 1;
    POWERS_OF_255[1] = 255;
    POWERS_OF_255[2] = 65025;
    POWERS_OF_255[3] = 16581375;
    POWERS_OF_255[4] = 4228250625;

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

PRINCEColumnTransitionAlgorithm::PRINCEColumnTransitionAlgorithm() {
    initializeConstants();
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildSingleElementDistribution(
    NTL::vec_RR &distribution,
    const size_t columnPatternAsInt) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);
    distribution[0].SetOutputPrecision(OUTPUT_PRECISION);

    for (size_t i = 0; i < 625; ++i) {
        distribution[i] = 0;
    }

    distribution[columnPatternAsInt] = 1;
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildSingleElementDistribution(
    NTL::vec_RR &distribution,
    const uint8_t columnPattern[4]) const {
    const size_t columnPatternAsInt = computeIndex(columnPattern);
    buildSingleElementDistribution(distribution, columnPatternAsInt);
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildUniformDifferencesDistribution(
    NTL::vec_RR &distribution,
    const uint8_t columnPattern[4]) const {
    const size_t index = computeIndex(columnPattern);

    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);
    distribution[0].SetOutputPrecision(OUTPUT_PRECISION);

    utils::BytePatternGenerator generator;
    generator.initialize(columnPattern);

    uint8_t bytePattern[4][4];

    while (generator.hasNext()) {
        generator.next(bytePattern);
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildFirstByteDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);
    distribution[0].SetOutputPrecision(OUTPUT_PRECISION);
    distribution[1] = 1;
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildFirstDiagonalDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    for (int i = 1; i < 5; i++) {
        distribution[i] =
            BINOMIAL_COEFFICIENTS[i] * POWERS_OF_255[i] / (Q32 - 1);
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildFirstTwoDiagonalsDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    for (int numActiveBytesInColumn0 = 0;
         numActiveBytesInColumn0 < 5; numActiveBytesInColumn0++) {
        for (int numActiveBytesInColumn1 = 0;
             numActiveBytesInColumn1 < 5; numActiveBytesInColumn1++) {
            if (numActiveBytesInColumn0 == 0 &&
                numActiveBytesInColumn1 == 0) {
                continue;
            }

            const int pattern[4] = {numActiveBytesInColumn0,
                                    numActiveBytesInColumn1,
                                    0, 0};
            const int index = computeIndex(pattern);
            distribution[index] =
                BINOMIAL_COEFFICIENTS[numActiveBytesInColumn0] *
                POWERS_OF_255[numActiveBytesInColumn0] *
                BINOMIAL_COEFFICIENTS[numActiveBytesInColumn1] *
                POWERS_OF_255[numActiveBytesInColumn1] /
                (Q64 - 1);
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildFirstThreeDiagonalsDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    for (int numActiveBytesInColumn0 = 0;
         numActiveBytesInColumn0 < 5; numActiveBytesInColumn0++) {
        for (int numActiveBytesInColumn1 = 0;
             numActiveBytesInColumn1 < 5; numActiveBytesInColumn1++) {
            for (int numActiveBytesInColumn2 = 0;
                 numActiveBytesInColumn2 < 5; numActiveBytesInColumn2++) {
                if (numActiveBytesInColumn0 == 0 &&
                    numActiveBytesInColumn1 == 0 &&
                    numActiveBytesInColumn2 == 0) {
                    continue;
                }

                const int pattern[4] = {numActiveBytesInColumn0,
                                        numActiveBytesInColumn1,
                                        numActiveBytesInColumn2, 0};
                const int index = computeIndex(pattern);
                distribution[index] =
                    BINOMIAL_COEFFICIENTS[numActiveBytesInColumn0] *
                    POWERS_OF_255[numActiveBytesInColumn0] *
                    BINOMIAL_COEFFICIENTS[numActiveBytesInColumn1] *
                    POWERS_OF_255[numActiveBytesInColumn1] *
                    BINOMIAL_COEFFICIENTS[numActiveBytesInColumn2] *
                    POWERS_OF_255[numActiveBytesInColumn2] /
                    (Q96 - 1);
            }
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildAllDiagonalsDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    for (int numActiveBytesInColumn0 = 0;
         numActiveBytesInColumn0 < 5; numActiveBytesInColumn0++) {
        for (int numActiveBytesInColumn1 = 0;
             numActiveBytesInColumn1 < 5; numActiveBytesInColumn1++) {
            for (int numActiveBytesInColumn2 = 0;
                 numActiveBytesInColumn2 < 5; numActiveBytesInColumn2++) {
                for (int numActiveBytesInColumn3 = 0;
                     numActiveBytesInColumn3 < 5; numActiveBytesInColumn3++) {
                    if (numActiveBytesInColumn0 == 0 &&
                        numActiveBytesInColumn1 == 0 &&
                        numActiveBytesInColumn2 == 0 &&
                        numActiveBytesInColumn3 == 0) {
                        continue;
                    }

                    const int pattern[4] = {numActiveBytesInColumn0,
                                            numActiveBytesInColumn1,
                                            numActiveBytesInColumn2,
                                            numActiveBytesInColumn3};
                    const int index = computeIndex(pattern);
                    distribution[index] =
                        BINOMIAL_COEFFICIENTS[numActiveBytesInColumn0] *
                        POWERS_OF_255[numActiveBytesInColumn0] *
                        BINOMIAL_COEFFICIENTS[numActiveBytesInColumn1] *
                        POWERS_OF_255[numActiveBytesInColumn1] *
                        BINOMIAL_COEFFICIENTS[numActiveBytesInColumn2] *
                        POWERS_OF_255[numActiveBytesInColumn2] *
                        BINOMIAL_COEFFICIENTS[numActiveBytesInColumn3] *
                        POWERS_OF_255[numActiveBytesInColumn3] /
                        (Q128 - 1);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildFirstNDiagonalsDistribution(
    NTL::vec_RR &distribution,
    const size_t numDiagonals) const {

    switch (numDiagonals) {
        case 0:
            return;
        case 1:
            buildFirstDiagonalDistribution(distribution);
            return;
        case 2:
            buildFirstTwoDiagonalsDistribution(distribution);
            return;
        case 3:
            buildFirstThreeDiagonalsDistribution(distribution);
            return;
        case 4:
            buildAllDiagonalsDistribution(distribution);
            return;
        default:
            return;
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildExactlyFirstTwoDiagonalsDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    for (int numActiveBytesInColumn0 = 1;
         numActiveBytesInColumn0 < 5; numActiveBytesInColumn0++) {
        for (int numActiveBytesInColumn1 = 1;
             numActiveBytesInColumn1 < 5; numActiveBytesInColumn1++) {
            const int pattern[4] = {numActiveBytesInColumn0,
                                    numActiveBytesInColumn1,
                                    0, 0};
            const int index = computeIndex(pattern);
            distribution[index] =
                BINOMIAL_COEFFICIENTS[numActiveBytesInColumn0] *
                POWERS_OF_255[numActiveBytesInColumn0] *
                BINOMIAL_COEFFICIENTS[numActiveBytesInColumn1] *
                POWERS_OF_255[numActiveBytesInColumn1] /
                ((Q32 - 1) * (Q32 - 1));
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildExactlyFirstThreeDiagonalsDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    for (int numActiveBytesInColumn0 = 1;
         numActiveBytesInColumn0 < 5; numActiveBytesInColumn0++) {
        for (int numActiveBytesInColumn1 = 1;
             numActiveBytesInColumn1 < 5; numActiveBytesInColumn1++) {
            for (int numActiveBytesInColumn2 = 1;
                 numActiveBytesInColumn2 < 5; numActiveBytesInColumn2++) {
                const int pattern[4] = {numActiveBytesInColumn0,
                                        numActiveBytesInColumn1,
                                        numActiveBytesInColumn2, 0};
                const int index = computeIndex(pattern);
                distribution[index] =
                    BINOMIAL_COEFFICIENTS[numActiveBytesInColumn0] *
                    POWERS_OF_255[numActiveBytesInColumn0] *
                    BINOMIAL_COEFFICIENTS[numActiveBytesInColumn1] *
                    POWERS_OF_255[numActiveBytesInColumn1] *
                    BINOMIAL_COEFFICIENTS[numActiveBytesInColumn2] *
                    POWERS_OF_255[numActiveBytesInColumn2] /
                    ((Q32 - 1) * (Q32 - 1) * (Q32 - 1));
            }
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildExactlyAllDiagonalsDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    for (int numActiveBytesInColumn0 = 1;
         numActiveBytesInColumn0 < 5; numActiveBytesInColumn0++) {
        for (int numActiveBytesInColumn1 = 1;
             numActiveBytesInColumn1 < 5; numActiveBytesInColumn1++) {
            for (int numActiveBytesInColumn2 = 1;
                 numActiveBytesInColumn2 < 5; numActiveBytesInColumn2++) {
                for (int numActiveBytesInColumn3 = 1;
                     numActiveBytesInColumn3 < 5; numActiveBytesInColumn3++) {
                    const int pattern[4] = {numActiveBytesInColumn0,
                                            numActiveBytesInColumn1,
                                            numActiveBytesInColumn2,
                                            numActiveBytesInColumn3};
                    const int index = computeIndex(pattern);
                    distribution[index] =
                        BINOMIAL_COEFFICIENTS[numActiveBytesInColumn0] *
                        POWERS_OF_255[numActiveBytesInColumn0] *
                        BINOMIAL_COEFFICIENTS[numActiveBytesInColumn1] *
                        POWERS_OF_255[numActiveBytesInColumn1] *
                        BINOMIAL_COEFFICIENTS[numActiveBytesInColumn2] *
                        POWERS_OF_255[numActiveBytesInColumn2] *
                        BINOMIAL_COEFFICIENTS[numActiveBytesInColumn3] *
                        POWERS_OF_255[numActiveBytesInColumn3] /
                        ((Q32 - 1) * (Q32 - 1) * (Q32 - 1) * (Q32 - 1));
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildExactlyFirstNDiagonalsDistribution(
    NTL::vec_RR &distribution,
    const size_t numDiagonals) const {

    switch (numDiagonals) {
        case 0:
            return;
        case 1:
            buildFirstDiagonalDistribution(distribution);
            return;
        case 2:
            buildExactlyFirstTwoDiagonalsDistribution(distribution);
            return;
        case 3:
            buildExactlyFirstThreeDiagonalsDistribution(distribution);
            return;
        case 4:
            buildExactlyAllDiagonalsDistribution(distribution);
            return;
        default:
            return;
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildFirstTwoBytesDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    NTL::RR binom[4];
    binom[0].SetPrecision(PRECISION);
    binom[0] = 1;
    binom[1] = 2;
    binom[2] = 1;

    for (int numActiveBytesInColumn0 = 1;
         numActiveBytesInColumn0 < 3; numActiveBytesInColumn0++) {
        const int pattern[4] = {numActiveBytesInColumn0, 0, 0, 0};
        const int index = computeIndex(pattern);
        distribution[index] =
            binom[numActiveBytesInColumn0] *
            POWERS_OF_255[numActiveBytesInColumn0] /
            (Q16 - 1);
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildFirstThreeBytesDistribution(
    NTL::vec_RR &distribution) const {
    distribution.SetLength(625);
    distribution[0].SetPrecision(PRECISION);

    NTL::RR binom[4];
    binom[0].SetPrecision(PRECISION);
    binom[0] = 1;
    binom[1] = 3;
    binom[2] = 3;
    binom[3] = 1;

    for (int numActiveBytesInColumn0 = 1;
         numActiveBytesInColumn0 < 4; numActiveBytesInColumn0++) {
        const int pattern[4] = {numActiveBytesInColumn0, 0, 0, 0};
        const int index = computeIndex(pattern);
        distribution[index] =
            binom[numActiveBytesInColumn0] *
            POWERS_OF_255[numActiveBytesInColumn0] /
            (Q24 - 1);
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::buildFirstNBytesDistribution(
    NTL::vec_RR &distribution,
    const size_t numBytes) const {

    switch (numBytes) {
        case 0:
            return;
        case 1:
            buildFirstByteDistribution(distribution);
            return;
        case 2:
            buildFirstTwoBytesDistribution(distribution);
            return;
        case 3:
            buildFirstThreeBytesDistribution(distribution);
            return;
        case 4:
            buildFirstDiagonalDistribution(distribution);
            return;
        default:
            return;
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::precomputeShiftRowsMatrix() {
    // ------------------------------------------------------------------------
    // The transition probabilities for the SR layer is straight-forward.
    // Recall, T_SR is of dimension 625 x 625.
    // ------------------------------------------------------------------------

    TSR.SetDims(625, 625);
    TSR[0][0].SetPrecision(PRECISION);

    for (int p1 = 0; p1 < 65536; p1++) {
        int wpattern0[4];
        int wpattern1[4];

        // ---------------------------------------------------------------------
        // This function is the main one here.
        // Given p1 = (...., ...., ...., ....)
        // ---------------------------------------------------------------------

        getWeightPattern(wpattern0, wpattern1, p1);

        const int I = computeIndex(wpattern0);
        const int J = computeIndex(wpattern1);

        NTL::RR M;
        M = 1;

        for (int i = 0; i < 4; i++) {
            M = M * BINOMIAL_COEFFICIENTS[wpattern0[i]];
        }

        TSR[I][J] += 1 / M;
    }

    hasInitializedTSR = true;
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::precomputeMixColumnsMatrix() {
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
        return;
    }

    TMC.SetDims(625, 625);

    TMC[0][0].SetPrecision(PRECISION);

    for (int w1 = 0; w1 < 5; w1++) {
        for (int w2 = 0; w2 < 5; w2++) {
            for (int w3 = 0; w3 < 5; w3++) {
                for (int w4 = 0; w4 < 5; w4++) {
                    int wpattern0[4] = {w1, w2, w3, w4};
                    int I = 0;

                    I = computeIndex(wpattern0);

                    for (int v1 = 0; v1 < 5; v1++) {
                        for (int v2 = 0; v2 < 5; v2++) {
                            for (int v3 = 0; v3 < 5; v3++) {
                                for (int v4 = 0; v4 < 5; v4++) {
                                    int wpattern1[4] = {v1, v2, v3, v4};
                                    int J = 0;
                                    J = computeIndex(wpattern1);
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

static bool readZTableFromPath(NTL::ZZ Z_ZZ[16][16], const std::string &path) {
    std::fstream inputFileStream;
    inputFileStream.open(path, std::fstream::in);

    if (inputFileStream.fail()) {
        inputFileStream.close();
        std::cerr << "File does not exist: " << path << std::endl;
        return false;
    }

    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            inputFileStream >> Z_ZZ[i][j];
        }
    }

    inputFileStream.close();
    return true;
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
            Z_Table[i][j] = Z[Qw[i]][Qw[j]] / (POWERS_OF_255[i]);
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::readZTable(const std::string &path) {
    NTL::ZZ Z_ZZ[16][16];
    hasInitializedZTable = false;

    if (!readZTableFromPath(Z_ZZ, path)) {
        return;
    }

    NTL::RR Z[16][16];
    convertZTableToRealValues(Z_ZZ, Z);

    reduceZTable(zTable, Z);
    hasInitializedZTable = true;
}

// ------------------------------------------------------------------------

bool PRINCEColumnTransitionAlgorithm::haveMatricesBeenPrecomputed() const {
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

void PRINCEColumnTransitionAlgorithm::createMatrix(NTL::mat_RR &matrix,
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

    if (numRounds == 1) {
        matrix = TSR;
        matrix = matrix * TMC;
        return;
    }

    matrix = TMC;

    for (size_t k = 0; k < numRounds - 2; ++k) {
        matrix = matrix * TSR;
        matrix = matrix * TMC;
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::writeMatrix(const std::string &path,
                                               const NTL::mat_RR &matrix)
const {
    std::fstream outputFileStream;
    outputFileStream.open(path, std::fstream::out);
    outputFileStream << "# First line = rows columns. Then one row per line, "
                     << "separated by a single space."
                     << std::endl;
    outputFileStream << "# "
                     << matrix.NumRows() << " "
                     << matrix.NumCols() << std::endl;

    for (int i = 0; i < 625; i++) {
        for (int j = 0; j < 625; j++) {
            outputFileStream << matrix[i][j] << ' ';
        }

        outputFileStream << std::endl;
    }

    outputFileStream.close();
}

// ------------------------------------------------------------------------

static void
printInterest(const int v0, const int v1, const int v2, const int v3,
              const NTL::RR &probability) {
    printf("%2d%2d%2d%2d: ", v0, v1, v2, v3);
    std::cout << probability << std::endl;
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::computeRealOutputDistribution(
    NTL::vec_RR &outputDistribution,
    const NTL::vec_RR &inputDistribution,
    const NTL::mat_RR &matrix) const {
    outputDistribution.SetLength(625);
    outputDistribution[0].SetPrecision(PRECISION);
    outputDistribution = inputDistribution * matrix;
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::computeRealOutputProbability(
    NTL::RR &probability,
    const NTL::vec_RR &inputDistribution,
    const bool outputInterests[5][5][5][5],
    const NTL::mat_RR &matrix,
    const size_t numRounds) const {

    probability.SetPrecision(PRECISION);
    probability = 0;

    if (numRounds == 0) {
        return;
    }

    NTL::vec_RR outputDistribution;
    computeRealOutputDistribution(outputDistribution, inputDistribution,
                                    matrix);

    for (int v0 = 0; v0 < 5; v0++) {
        for (int v1 = 0; v1 < 5; v1++) {
            for (int v2 = 0; v2 < 5; v2++) {
                for (int v3 = 0; v3 < 5; v3++) {
                    if (outputInterests[v0][v1][v2][v3]) {
                        const int indices[4] = {v0, v1, v2, v3};
                        const int index = computeIndex(indices);
                        probability += outputDistribution[index];
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::computeRealOutputDistribution(
    NTL::vec_RR &outputDistribution,
    const NTL::vec_RR &inputDistribution,
    const size_t numRounds) const {
    outputDistribution.SetLength(625);
    outputDistribution[0].SetPrecision(PRECISION);
    outputDistribution = inputDistribution;

    if (numRounds == 0) {
        return;
    }

    if (numRounds == 1) {
        outputDistribution = outputDistribution * TSR;
        outputDistribution = outputDistribution * TMC;
        return;
    }

    if (numRounds >= 2) {
        outputDistribution = outputDistribution * TMC;

        for (size_t k = 0; k < numRounds - 2; ++k) {
            outputDistribution = outputDistribution * TSR;
            outputDistribution = outputDistribution * TMC;
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::computeRealOutputProbability(
    NTL::RR &probability,
    const NTL::vec_RR &inputDistribution,
    const bool outputInterests[5][5][5][5],
    const size_t numRounds) const {

    if (!haveMatricesBeenPrecomputed()) {
        return;
    }

    probability = 0;
    probability.SetPrecision(PRECISION);

    NTL::vec_RR outputDistribution;
    computeRealOutputDistribution(outputDistribution,
                                    inputDistribution,
                                    numRounds);

    if (numRounds == 0) {
        return;
    }

    for (int v0 = 0; v0 < 5; v0++) {
        for (int v1 = 0; v1 < 5; v1++) {
            for (int v2 = 0; v2 < 5; v2++) {
                for (int v3 = 0; v3 < 5; v3++) {
                    if (outputInterests[v0][v1][v2][v3]) {
                        const int indices[4] = {v0, v1, v2, v3};
                        const int index = computeIndex(indices);
                        probability += outputDistribution[index];
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::computePRPOutputDistribution(
    NTL::vec_RR &outputDistribution) const {
    outputDistribution.SetLength(625);
    outputDistribution[0].SetPrecision(PRECISION);

    for (int v0 = 0; v0 < 5; v0++) {
        for (int v1 = 0; v1 < 5; v1++) {
            for (int v2 = 0; v2 < 5; v2++) {
                for (int v3 = 0; v3 < 5; v3++) {
                    const int pattern[4] = {v0, v1, v2, v3};
                    const int index = computeIndex(pattern);

                    outputDistribution[index] =
                        BINOMIAL_COEFFICIENTS[v0] * POWERS_OF_255[v0]
                        * BINOMIAL_COEFFICIENTS[v1] * POWERS_OF_255[v1]
                        * BINOMIAL_COEFFICIENTS[v2] * POWERS_OF_255[v2]
                        * BINOMIAL_COEFFICIENTS[v3] * POWERS_OF_255[v3]
                        / (Q32 * Q32 * Q32 * Q32);
                }
            }
        }
    }
}

// ------------------------------------------------------------------------

void PRINCEColumnTransitionAlgorithm::computePRPOutputProbability(
    NTL::RR &probability,
    const bool outputInterests[5][5][5][5]) const {

    probability.SetPrecision(PRECISION);
    probability = 0;

    for (int v0 = 0; v0 < 5; v0++) {
        for (int v1 = 0; v1 < 5; v1++) {
            for (int v2 = 0; v2 < 5; v2++) {
                for (int v3 = 0; v3 < 5; v3++) {
                    if (outputInterests[v0][v1][v2][v3]) {
                        probability +=
                            BINOMIAL_COEFFICIENTS[v0] * POWERS_OF_255[v0]
                            * BINOMIAL_COEFFICIENTS[v1] * POWERS_OF_255[v1]
                            * BINOMIAL_COEFFICIENTS[v2] * POWERS_OF_255[v2]
                            * BINOMIAL_COEFFICIENTS[v3] * POWERS_OF_255[v3]
                            / (Q32 * Q32 * Q32 * Q32);
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------------
