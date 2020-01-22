/**
 * Copyright 2019 anonymized
 */

#ifndef _MIN_WEIGHT_DEPENDENCY_STRATEGY_H
#define _MIN_WEIGHT_DEPENDENCY_STRATEGY_H

// ------------------------------------------------------------------------

#include <NTL/RR.h>
#include <NTL/ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_RR.h>

#include "aes_dependency_vector.h"
#include "dependency_strategy.h"

// ------------------------------------------------------------------------

class MinWeightDependencyStrategy : public DependencyStrategy {

public:
    
    virtual ~MinWeightDependencyStrategy() {}
    
    // ------------------------------------------------------------------------
    
    virtual void applyShiftRows(const NTL::mat_RR &matrix,
                                const NTL::vec_RR &inputDistribution,
                                AESTransitionDependencyVector &dependencies,
                                NTL::vec_RR &outputDistribution) const;
    
    // ------------------------------------------------------------------------
    
    virtual void applyMixColumns(const NTL::mat_RR &matrix,
                                 const NTL::vec_RR &inputDistribution,
                                 AESTransitionDependencyVector &dependencies,
                                 NTL::vec_RR &outputDistribution) const;
    
};

// ------------------------------------------------------------------------

#endif // _MIN_WEIGHT_DEPENDENCY_STRATEGY_H
