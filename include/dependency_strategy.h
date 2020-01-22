/**
 * Copyright 2019 anonymized
 */

#ifndef _DEPENDENCY_STRATEGY_H
#define _DEPENDENCY_STRATEGY_H

// ------------------------------------------------------------------------

#include <NTL/RR.h>
#include <NTL/ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_RR.h>

#include "aes_dependency_vector.h"

// ------------------------------------------------------------------------

class DependencyStrategy {

public:
    
    virtual ~DependencyStrategy() {}
    
    // ------------------------------------------------------------------------
    
    virtual void applyShiftRows(const NTL::mat_RR &matrix,
                                const NTL::vec_RR &inputDistribution,
                                AESTransitionDependencyVector &dependencies,
                                NTL::vec_RR &outputDistribution) const = 0;
    
    // ------------------------------------------------------------------------
    
    virtual void applyMixColumns(const NTL::mat_RR &matrix,
                                 const NTL::vec_RR &inputDistribution,
                                 AESTransitionDependencyVector &dependencies,
                                 NTL::vec_RR &outputDistribution) const = 0;
    
};

// ------------------------------------------------------------------------

#endif // _DEPENDENCY_STRATEGY_H
