/**
 * Copyright 2019 anonymized
 */

#ifndef _AES_BYTE_MIXTURE_TRANSITION_ALGORITHM_H
#define _AES_BYTE_MIXTURE_TRANSITION_ALGORITHM_H

// ------------------------------------------------------------------------

#include <bitset>
#include <string>
#include <vector>

#include <NTL/RR.h>
#include <NTL/ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_RR.h>

#include "dependency_strategy.h"
#include "aes_dependency_vector.h"

// ------------------------------------------------------------------------

class AESByteMixtureTransitionAlgorithm {

public:
    
    AESByteMixtureTransitionAlgorithm();
    
    // ------------------------------------------------------------------------
    
    
    
    // ------------------------------------------------------------------------
    
    /**
     * Builds the active-byte difference distribution for the AES that
     * models a single active first byte.
     * @param distribution The vector for storing the distribution.
     */
    void buildFirstByteDistribution(NTL::vec_RR &distribution) const;
    
    // ------------------------------------------------------------------------
    
    void buildFirstDiagonalDistribution(NTL::vec_RR &distribution) const;
    
    // ------------------------------------------------------------------------
    
    void buildSingleElementDistribution(NTL::vec_RR &distribution,
                                        size_t bytePatternAsInt) const;
    
    // ------------------------------------------------------------------------
    
    void buildSingleElementDistribution(NTL::vec_RR &distribution,
                                        const uint8_t bytePattern[4][4]) const;
    
    // ------------------------------------------------------------------------
    
    /**
     * Verifies if the shiftRows and MixColumns matrix have been precomputed.
     * This is necessary to derive the output probabilities later.
     * @return True if both matrices have been precomputed; false otherwise.
     */
    bool haveMatricesBeenPrecomputed() const;
    
    // ------------------------------------------------------------------------
    
    /**
     * Precomputes the 625x625-entries transition matrix through ShiftRows and
     * stores it internally.
     */
    void precomputeShiftRowsMatrix();
    
    // ------------------------------------------------------------------------
    
    /**
     * Precomputes the 625x625-entries transition matrix through MixColumns and
     * stores it internally.
     */
    void precomputeMixColumnsMatrix();
    
    // ------------------------------------------------------------------------
    
    /**
     * Reads a 16x16 matrix from a file, which the entry at Row i and Column j
     * represents the number of input differences with i active bytes
     * that are mapped to an output difference with j active bytes through
     * MixColumns.
     * @param path The file path
     */
    void readZTable(const std::string &path);
    
    // ------------------------------------------------------------------------
    
    void createMatrix(NTL::mat_RR &matrix,
                      size_t numRounds) const;
    
    // ------------------------------------------------------------------------
    
    void applyMixColumns(NTL::vec_RR &outputDistribution) const;
    
    // ------------------------------------------------------------------------
    
    void applyShiftRows(NTL::vec_RR &outputDistribution) const;
    
    // ------------------------------------------------------------------------
    
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
                                        const std::bitset<65536> &outputInterests,
                                        size_t bytePatternAsInt,
                                        size_t numRounds,
                                        const DependencyStrategy *strategy,
                                        size_t& numMixtureRounds) const;
    
    // ------------------------------------------------------------------------
    
    /**
     * Computes the probability of the output patterns for a random permutation.
     * @param probability
     * @param outputInterests
     */
    void computeOutputProbabilityForPRP(
        NTL::RR &probability,
        const std::bitset<65536> &outputInterests) const;

private:
    
    NTL::mat_RR zTable;
    std::vector<size_t> TSR;
    NTL::mat_RR TSRNormal;
    NTL::mat_RR TMC;
    
    bool hasInitializedZTable = false;
    bool hasInitializedTSR = false;
    bool hasInitializedTMC = false;
    
};

// ------------------------------------------------------------------------

#endif // _AES_BYTE_MIXTURE_TRANSITION_ALGORITHM_H
