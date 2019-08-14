/**
 * Copyright 2019 S. Ronjom
 *
 * Parts taken from rijndael-alg-ref.c   v2.2   March 2002
 * Reference ANSI C code
 * authors: Paulo Barreto and Vincent Rijmen
 *
 * This code is placed in the public domain.
 * Do NOT use for any production purposes.
 */

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <chrono>
#include <fstream>
#include <set>
#include <unordered_set>
#include <iterator>
#include <list>
#include <map>

#include <NTL/ZZ.h>
#include <NTL/RR.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_RR.h>

#include "rijndael.h"
#include "boxes-ref.dat"

// ------------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------------

#define SC    ((BC - 4) >> 1)

NTL::RR BINOMIAL_COEFFICIENTS[5];
static int precision = 300;
NTL::RR Q32;
NTL::RR powersOf255[5];
NTL::mat_RR Q1;

static const uint8_t shifts[3][4][2] = {
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

// ------------------------------------------------------------------------
// Methods
// ------------------------------------------------------------------------

/**
 * Row 0 remains unchanged. The other three rows are rotated by 1, 2, 3
 * positions to the left.
 * @param a[4][4] Active-byte pattern of rows and columns
 * @param d
 * @param BC 4 = rows per column
 */
void shiftRows(uint8_t a[4][MAXBC], uint8_t d, uint8_t BC) {
    uint8_t tmp[MAXBC];
    int i, j;

    for (i = 1; i < 4; i++) {
        for (j = 0; j < BC; j++) {
            tmp[j] = a[i][(j + shifts[SC][i][d]) % BC];
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
int weight(uint8_t s[4][4], int k) {
    int w = 0;

    for (int j = 0; j < 4; j++) {
        if (s[j][k] != 0) {
            w += 1;
        }
    }

    return w;
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
void get_weight_pattern(int wpattern0[4], int wpattern1[4], int p1) {
    uint8_t S1[4][4];

    for (int i = 0; i < 4; i++) { // column
        for (int j = 0; j < 4; j++) { // row
            S1[j][i] = (p1 >> (4 * i + j)) & 1;
        }
    }

    for (int i = 0; i < 4; i++) { // getNumActiveBytesInColumn of i-th column
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
int computeIndex(const int *pattern) {
    int result = 0;

    for (int i = 0; i < 4; i++) {
        result += static_cast<int>(pow(5, i)) * pattern[i];
    }

    return result;
}

// ------------------------------------------------------------------------

/**
 * Computes transition probability matrices form MC and SR layers, and construct
 * an r-round transition probability matrix by multiplying these together
 * enough times.

 * Computing the weight transition probability (WTP) matrix for AES, which may
 * be viewed as a extended weight-distribution matrix for a (32,16) code over
 * GF(2^8).

 * An exchange set WTP is considered. It combines a single-round
 * exchange-transition probability with the wtp. Thus, let TX[I,J] denote the
 * probability of exchanging.
 *
 * @return
 */
int main() {
    Q32 = 4294967296;

    // ------------------------------------------------------------------------
    // Note: A sufficient level of precision is important. Insufficient
    // precision may be the root of potential errors.
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // Note: Setting the precision on the first element defines the precision
    // for all elements in a table.
    // ------------------------------------------------------------------------

    Q1.SetDims(625, 625);
    Q1[0][0].SetPrecision(precision);
    Q1[0][0].SetOutputPrecision(precision);

    // ------------------------------------------------------------------------
    // Q_w[i] = 2^i - 1
    // ------------------------------------------------------------------------

    int Qw[5] = {0, 1, 3, 7, 15};

    // ------------------------------------------------------------------------
    // T_SR = the transition matrix of ShiftRows
    // T_MC = the transition matrix of MixColumns
    // Stores transitions of {0..4}^4 -> {0..4}^4, which represent the number
    // of active bytes in the individual column.
    // ------------------------------------------------------------------------

    static NTL::mat_RR TSR; //[625][625];
    static NTL::mat_RR TMC; //[625][625];
    TSR.SetDims(625, 625);
    TMC.SetDims(625, 625);

    TSR[0][0].SetPrecision(precision);
    TSR[0][0].SetOutputPrecision(precision);

    TMC[0][0].SetPrecision(precision);
    TMC[0][0].SetOutputPrecision(precision);

    // Helper for high-precision multiplication with 1.
    NTL::RR one;
    one.SetPrecision(precision);
    one.SetOutputPrecision(precision);
    one = 1;

    // ------------------------------------------------------------------------
    // powersOf255[i] = 255^i
    // ------------------------------------------------------------------------

    powersOf255[0].SetPrecision(precision);
    powersOf255[0] = 1;
    powersOf255[1] = 255;
    powersOf255[2] = 65025;
    powersOf255[3] = 16581375;
    powersOf255[4] = 4228250625;

    // ------------------------------------------------------------------------
    // Number of options with i active bytes.
    // BINOMIAL_COEFFICIENTS[i] = binom(4, i).
    // ------------------------------------------------------------------------

    BINOMIAL_COEFFICIENTS[0].SetPrecision(precision);
    BINOMIAL_COEFFICIENTS[0] = 1;
    BINOMIAL_COEFFICIENTS[1] = 4;
    BINOMIAL_COEFFICIENTS[2] = 6;
    BINOMIAL_COEFFICIENTS[3] = 4;
    BINOMIAL_COEFFICIENTS[4] = 1;

    // ------------------------------------------------------------------------
    // Read the MDS getNumActiveBytesInColumn distribution from file.
    // ------------------------------------------------------------------------

    NTL::ZZ Z_ZZ[16][16];
    std::fstream inputFileStream;

    inputFileStream.open("z_table_aes.bin", std::fstream::in);

    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            inputFileStream >> Z_ZZ[i][j];
        }
    }

    inputFileStream.close();
    std::cout << std::endl;

//    NTL::ZZ Q;
//    Q = 0;

    // ------------------------------------------------------------------------
    // Convert the transition table to RR.
    // ------------------------------------------------------------------------

    NTL::RR Z[16][16];

    for (int i = 0; i < 16; i++) {
        NTL::RR res;
        res = 0;

        for (int j = 0; j < 16; j++) {
            conv(Z[i][j], Z_ZZ[i][j]);
        }
    }

    // ------------------------------------------------------------------------
    // Compute T_SR
    // Compute L_SR
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // The Z_Table is the transition probability matrix for the MixColumns
    // matrix. For i, j = 0..4, Z_Table[i][j] is initialized with
    // #Differences with i active column bytes ->
    // #Differences with j active column bytes
    // ------------------------------------------------------------------------

    NTL::mat_RR Z_Table;
    Z_Table.SetDims(5, 5);
    Z_Table[0][0].SetPrecision(precision);

    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            Z_Table[i][j] = Z[Qw[i]][Qw[j]] / (powersOf255[i]);
        }
    }

    std::cout << "Compute TSR" << std::endl;

    // ------------------------------------------------------------------------
    // The transition probabilities for the SR layer is straight-forward.
    // Recall, T_SR is of dimension 625 x 625.
    // ------------------------------------------------------------------------

    for (int p1 = 0; p1 < 65536; p1++) {
        int I = 0;
        int J = 0;
        int wpattern0[4];
        int wpattern1[4];

        // ---------------------------------------------------------------------
        // This function is the main one here.
        // Given p1 = (...., ...., ...., ....)
        // ---------------------------------------------------------------------

        get_column_and_row_weight_pattern(wpattern0, wpattern1, p1);

        I = computeIndex(wpattern0);
        J = computeIndex(wpattern1);

        NTL::RR M;
        M = 1;

        for (int i = 0; i < 4; i++) {
            M = M * BINOMIAL_COEFFICIENTS[wpattern0[i]];
        }

        TSR[I][J] += 1 / M;
    }

    std::cout << "Compute TMC" << std::endl;

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
    //   = Pr[wt pattern (j0,j1,j2,h3) out | getNumActiveBytesInColumn pattern (i0,i1,i2,i3) in]
    //   = MDS-transition probabilities.
    // ------------------------------------------------------------------------

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
                                        q *= Z_Table[wpattern0[i]][wpattern1[i]];
                                    }


                                    TMC[I][J] = (BINOMIAL_COEFFICIENTS[v1]
                                        * BINOMIAL_COEFFICIENTS[v2]
                                        * BINOMIAL_COEFFICIENTS[v3]
                                        * BINOMIAL_COEFFICIENTS[v4]) * q;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------------
    // Compute transition probability matrix Q1 formed by iterating TMC and TSR.
    // ------------------------------------------------------------------------

    std::cout
        << "Computing the matrix product (currently takes the most time...)."
        << std::endl
        << "This can take a few minutes on COTS computers."
        << std::endl;

    NTL::mat_RR Q2;
    Q2.SetDims(625, 625);
    Q2[0][0].SetOutputPrecision(precision);

    // ------------------------------------------------------------------------
    // Note that we start after (MC SR MC SR MC) = 4 rounds.
    // So, we need to start with SR.
    // ------------------------------------------------------------------------

//    Q2 = TSR * TMC;
//    Q1 = TMC * Q2 * Q2 * Q2;
//    Q1 = TMC * TSR * TMC * TSR * TMC * TSR * TMC;

    // ------------------------------------------------------------------------
    // Example:
    // Q1[4][r] is the probability that two plaintexts with difference in D_0
    // and 4 active bytes in D_0 result in a pair of ciphertexts with a
    // getNumActiveBytesInColumn-pattern encoded by r or (u_0, u_1, u_2, u_3), where
    // r = u_0 + u_1 * 5 + u_2 * 5^2 + u_3 * 5^3.
    // We restrict the sum below to all outputs where the first word has a
    // getNumActiveBytesInColumn of v4 = 0, which corresponds to the case that the difference
    // before the last round has a zero difference in column C_0, which means
    // that the ciphertext difference is in the mixed space M_{1,2,3}.
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // p_rand = The transition probability from u -> v for a random permutation.
    // p_aes = The transition probability from u -> v for the AES.
    // ------------------------------------------------------------------------

    NTL::RR prand;
    prand.SetPrecision(precision);
    prand = 0;

    NTL::RR paes;
    paes.SetPrecision(precision);
    paes = 0;

    // ------------------------------------------------------------------------
    // Our transition-probability vector.
    // ------------------------------------------------------------------------

    NTL::vec_RR uvec;
    uvec.SetLength(625);
    uvec[0].SetPrecision(precision);

    // ------------------------------------------------------------------------
    // uvec[i] = binom(4, i) * 255^i / (2^32 - 1) for i = 1..4
    // encodes a full diagonal input space.
    // This encodes the 5-round distinguisher from
    // https://eprint.iacr.org/2018/182.
    // ------------------------------------------------------------------------

    for (int i = 1; i < 5; i++) {
        uvec[i] = BINOMIAL_COEFFICIENTS[i] * powersOf255[i] / (Q32 - 1);
    }

    // ------------------------------------------------------------------------
    // uvec[1] = 1 (and every other entry uvec[i] = 0
    // encodes the 5-round distinguisher from
    // https://eprint.iacr.org/2019/622
    // that starts from a single active byte only.
    // It should produce a bias of 0.22466723256..e-15 = 2^(-51.981)
    // ------------------------------------------------------------------------

//    uvec[1] = one;

    // ------------------------------------------------------------------------
    // The important multiplication with Q1 maps the transition probabilities
    // of the previous input space to the outputs.
    //
    // Thereafter, uvec[i] = probability of output pattern i, encoded
    // as number in [0..624].
    // ------------------------------------------------------------------------

    NTL::vec_RR vvec;
    vvec.SetLength(625);
    vvec[0].SetPrecision(precision);

//    Q1 = TMC * TSR * TMC * TSR * TMC * TSR * TMC;
//    vvec = uvec * Q1;
    vvec = uvec * TMC;

    const int num_rounds = 4;

    for (int k = 0; k < num_rounds - 1; ++k) {
        vvec = vvec * TSR;
        vvec = vvec * TMC;
    }

    // ------------------------------------------------------------------------
    // v = (v0, v1, v2, v3) is the activity pattern of the columns of the
    // ciphertext difference.
    // We add all probabilities that have at least one zero column.
    // ------------------------------------------------------------------------

    for (int v0 = 0; v0 < 5; v0++) {
        for (int v1 = 0; v1 < 5; v1++) {
            for (int v2 = 0; v2 < 5; v2++) {
                for (int v3 = 0; v3 < 5; v3++) {
                    if (v0 == 0 || v1 == 0 || v2 == 0 || v3 == 0) {
                        prand += BINOMIAL_COEFFICIENTS[v0] * powersOf255[v0]
                            * BINOMIAL_COEFFICIENTS[v1] * powersOf255[v1]
                            * BINOMIAL_COEFFICIENTS[v2] * powersOf255[v2]
                            * BINOMIAL_COEFFICIENTS[v3] * powersOf255[v3]
                            / (Q32 * Q32 * Q32 * Q32);
                        paes += vvec[v0 + v1 * 5 + v2 * pow(5, 2) +
                                     v3 * pow(5, 3)];
                    }
                }
            }
        }
    }

    std::cout << "P_aes:" << std::endl;
    std::cout << paes << std::endl;

    std::cout << "P_rand:" << std::endl;
    std::cout << prand << std::endl;

    std::cout << "Difference:" << std::endl;
    std::cout << paes - prand << std::endl;

    return EXIT_SUCCESS;
}
