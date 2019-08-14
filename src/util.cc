/**
 * Copyright 2019 anonymized
 */

#include "util.h"

#include <stdlib.h>

#include <NTL/RR.h>

// ------------------------------------------------------------------------

namespace utils {

    NTL::RR log2(const NTL::RR& value) {
        return log(value) / log(2);
    }

    // ------------------------------------------------------------------------


}  // namespace utils
