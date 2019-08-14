/**
 * Copyright 2019 anonymized
 */

#ifndef _AES_COLUMN_TRANSITION_ALGORITHM_H
#define _AES_COLUMN_TRANSITION_ALGORITHM_H

// ------------------------------------------------------------------------

#include <string>

#include <NTL/RR.h>
#include <NTL/ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_RR.h>

// ------------------------------------------------------------------------

class AESColumnTransitionAlgorithm {

public:

    AESColumnTransitionAlgorithm();

    void buildSingleElementDistribution(NTL::vec_RR &distribution,
                                        size_t columnPatternAsInt) const;

    void buildSingleElementDistribution(NTL::vec_RR &distribution,
                                        const uint8_t columnPattern[4]) const;

    void buildUniformDifferencesDistribution(NTL::vec_RR &distribution,
                                             const uint8_t columnPattern[4]) const;

    /**
     * Builds the active-byte difference distribution for the AES that
     * models a single active first byte.
     * @param distribution The vector for storing the distribution.
     */
    void buildFirstByteDistribution(NTL::vec_RR &distribution) const;

    /**
     * Builds the active-byte difference distribution for the AES that
     * models an active first diagonal.
     * @param distribution The vector for storing the distribution.
     */
    void buildFirstDiagonalDistribution(NTL::vec_RR &distribution) const;

    void buildFirstTwoDiagonalsDistribution(NTL::vec_RR &distribution) const;

    void buildFirstThreeDiagonalsDistribution(NTL::vec_RR &distribution) const;

    void buildAllDiagonalsDistribution(NTL::vec_RR &distribution) const;

    void buildFirstNDiagonalsDistribution(NTL::vec_RR &distribution,
                                          size_t numDiagonals) const;


    void
    buildExactlyFirstTwoDiagonalsDistribution(NTL::vec_RR &distribution) const;

    void buildExactlyFirstThreeDiagonalsDistribution(
        NTL::vec_RR &distribution) const;

    void buildExactlyAllDiagonalsDistribution(NTL::vec_RR &distribution) const;

    void buildExactlyFirstNDiagonalsDistribution(NTL::vec_RR &distribution,
                                                 size_t numDiagonals) const;


    void buildFirstTwoBytesDistribution(NTL::vec_RR &distribution) const;

    void buildFirstThreeBytesDistribution(NTL::vec_RR &distribution) const;

    void buildFirstNBytesDistribution(NTL::vec_RR &distribution,
                                      size_t numBytes) const;

    /**
     * Verifies if the shiftRows and MixColumns matrix have been precomputed.
     * This is necessary to derive the output probabilities later.
     * @return True if both matrices have been precomputed; false otherwise.
     */
    bool haveMatricesBeenPrecomputed() const;

    /**
     * Precomputes the 625x625-entries transition matrix through ShiftRows and
     * stores it internally.
     */
    void precomputeShiftRowsMatrix();

    /**
     * Precomputes the 625x625-entries transition matrix through MixColumns and
     * stores it internally.
     */
    void precomputeMixColumnsMatrix();

    /**
     * Reads a 16x16 matrix from a file, which the entry at Row i and Column j
     * represents the number of input differences with i active bytes
     * that are mapped to an output difference with j active bytes through
     * MixColumns.
     * @param path The file path
     */
    void readZTable(const std::string &path);

    /**
     * Creates the multiplied matrix of the given number of r rounds.
     * If r = 0, returns an identity matrix.
     * The first round needs only the MixColumns transition matrix T_MC.
     * For each further round, multiplies it with the ShiftRows transition
     * matrix T_SR and the MixColumns matrix T_MC.
     * (TMC * TSR)^{r - 2} * TMC.
     * @param matrix
     * @param numRounds
     */
    void createMatrix(NTL::mat_RR &matrix, size_t numRounds) const;

    /**
     * Writes matrix to a text file.
     * @param path Output path, must exist and must have permissions.
     * Otherwise, this method does nothing.
     * @param matrix The matrix to write.
     */
    void writeMatrix(const std::string &path,
                     const NTL::mat_RR &matrix) const;

    void computeOutputProbabilityForAES(NTL::RR &probability,
                                        const NTL::vec_RR &inputDistribution,
                                        const bool outputInterests[5][5][5][5],
                                        const NTL::mat_RR &matrix,
                                        size_t numRounds) const;

    /**
     * Given (1) an input distribution that denotes the fractions of differences
     * with how many active bytes if which columns, (2) a vector of output
     * interests that describes which truncated differentials are considered
     * at the output, and (3) the number of considered rounds, this function
     * computes the sum of probability of all input-output transitions.
     * Assumes an optimal S-box.
     *
     * The ShiftRows operation in the first row is neglected and so are the
     * ShiftRows and MixColumns operations in the last round since the adversary
     * can easily strip them off.
     *
     * So, regard the inputDistribution as active bytes in Columns,
     * *after* the first ShiftRows.
     * Similarly, regard the outputInterests as active bytes in Columns,
     * *before* the final ShiftRows and MixColumns.
     *
     * @param probability
     * @param inputDistribution
     * @param outputInterests vector v = [v_0, v_1, v_2, v_3], where each
     * v_i in {0, 1, 2, 3, 4} denotes the number of active bytes in Column i.
     * If v[v_0][v_1][v_2][v_3] = True, the probability for the transition
     * of inputDistribution -> v is added to the probability.
     * @param numRounds
     */
    void computeOutputProbabilityForAES(NTL::RR &probability,
                                        const NTL::vec_RR &inputDistribution,
                                        const bool outputInterests[5][5][5][5],
                                        size_t numRounds) const;

    /**
     * Computes the probability of the output patterns for a random permutation.
     * @param probability
     * @param outputInterests
     */
    void computeOutputProbabilityForPRP(NTL::RR &probability,
                                        const bool outputInterests[5][5][5][5])
    const;

private:

    NTL::mat_RR zTable;
    NTL::mat_RR TSR;
    NTL::mat_RR TMC;

    bool hasInitializedZTable = false;
    bool hasInitializedTSR = false;
    bool hasInitializedTMC = false;

};

// ------------------------------------------------------------------------

#endif // _AES_COLUMN_TRANSITION_ALGORITHM_H
