/**
 * Copyright 2019 anonymized
 */

#ifndef _AES_ROW_AND_COLUMN_TRANSITION_ALGORITHM_H
#define _AES_ROW_AND_COLUMN_TRANSITION_ALGORITHM_H

// ------------------------------------------------------------------------

#include <string>

#include <NTL/RR.h>
#include <NTL/ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_RR.h>

// ------------------------------------------------------------------------

class AESRowAndColumnTransitionAlgorithm {

public:

    AESRowAndColumnTransitionAlgorithm();

    void buildFirstByteDistribution(NTL::vec_RR &distribution) const;

    void buildFirstDiagonalDistribution(NTL::vec_RR &distribution) const;

    bool haveMatricesBeenPrecomputed() const;

    void precomputeShiftRowsMatrix();

    void precomputeMixColumnsMatrix();

    void readZTable(const std::string &path);

    void createMatrix(NTL::mat_RR &matrix, size_t numRounds) const;

    void writeMatrix(const std::string &path,
                     const NTL::mat_RR &matrix) const;

    void computeOutputProbabilityForAES(NTL::RR &probability,
                                        const NTL::vec_RR &inputDistribution,
                                        const bool outputInterests[5][5][5][5][5][5][5][5],
                                        size_t numRounds) const;

    void computeOutputProbabilityForPRP(NTL::RR &probability,
                                        const bool outputInterests[5][5][5][5][5][5][5][5])
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

#endif // _AES_ROW_AND_COLUMN_TRANSITION_ALGORITHM_H
