/**
 * Copyright 2019 anonymized
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <stdlib.h>

#include <NTL/RR.h>

// ------------------------------------------------------------------------

namespace utils {

    NTL::RR log2(const NTL::RR& value, const size_t numPrecisionBits);

}

// ------------------------------------------------------------------------

#endif // _UTIL_H
