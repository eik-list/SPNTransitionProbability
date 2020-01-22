#include "aes_dependency_vector.h"

#include <algorithm>
#include <iterator>

// ------------------------------------------------------------------------

const AESByteDependencies &getByteDependencies(
    const AESByteDependencyVector &dependencyVector,
    uint8_t byteIndex) {
    return dependencyVector[byteIndex];
}

// ------------------------------------------------------------------------

const AESByteDependencies &getColumnDependencies(
    const AESColumnDependencyVector &dependencyVector,
    uint8_t columnIndex) {
    return dependencyVector[columnIndex];
}

// ------------------------------------------------------------------------

size_t getWeight(const AESColumnDependencyVector &vector) {
    size_t hammingWeight = 0;
    
    for (const auto& element : vector) {
        hammingWeight += element.count();
    }
    
    return hammingWeight;
}

// ------------------------------------------------------------------------

static void sortVector(const uint8_t array[NUM_AES_COLUMNS],
                       uint8_t result[NUM_AES_COLUMNS],
                       uint8_t sortOrder[NUM_AES_COLUMNS]) {
    bool used[NUM_AES_COLUMNS];
    
    for (uint8_t i = 0; i < NUM_AES_COLUMNS; ++i) {
        used[i] = false;
    }
    
    for (uint8_t i = 0; i < NUM_AES_COLUMNS; ++i) {
        uint8_t minimum = std::numeric_limits<uint8_t>::max();
        uint8_t minimum_index = NUM_AES_COLUMNS + 1;
        
        for (uint8_t j = 0; j < NUM_AES_COLUMNS; ++j) {
            if (used[j]) {
                continue;
            }
            
            if (minimum < array[j]) {
                continue;
            }
            
            minimum = array[j];
            minimum_index = j;
        }
        
        used[minimum_index] = true;
        sortOrder[i] = minimum_index;
        result[i] = minimum;
    }
}

// ------------------------------------------------------------------------

/**
 * Example:
 * inputColumnPattern = [0, 1, 3, 3]
 * sortedOutputColumnPattern = [4, 2, 1, 0]
 * inputDependencyVector = [a, b, c, d]
 * outputDependencyVector = [b|c|d, c|d, c, c]
 *
 * @param inputColumnPattern
 * @param sortedOutputColumnPattern
 * @param dependencyVector
 * @param result
 */
static void applyTransition(const uint8_t inputColumnPattern[NUM_AES_COLUMNS],
                            uint8_t sortedOutputColumnPattern[NUM_AES_COLUMNS],
                            const AESColumnDependencyVector &dependencyVector,
                            AESColumnDependencyVector &result) {
    for (uint8_t i = 0; i < NUM_AES_COLUMNS; ++i) {
        uint8_t numActiveBytesInInputColumn = inputColumnPattern[i];
        
        for (uint8_t j = 0; j < NUM_AES_COLUMNS; ++j) {
            if (numActiveBytesInInputColumn == 0) {
                break;
            }
            
            const uint8_t numActiveBytesInOutputColumn =
                sortedOutputColumnPattern[j];
            
            if (numActiveBytesInOutputColumn == 0) {
                continue;
            }
            
            result[j] |= dependencyVector[i];
            sortedOutputColumnPattern[j]--;
            numActiveBytesInInputColumn--;
        }
    }
}

// ------------------------------------------------------------------------

static void sortInOldOrder(const uint8_t sortOrder[NUM_AES_COLUMNS],
                           const AESColumnDependencyVector &input,
                           AESColumnDependencyVector &output) {
    for (uint8_t i = 0; i < NUM_AES_COLUMNS; ++i) {
        const uint8_t index = sortOrder[i];
        output[index] = input[i];
    }
}

// ------------------------------------------------------------------------

void updateDependencies(const uint8_t inputColumnPattern[NUM_AES_COLUMNS],
                        const uint8_t outputColumnPattern[NUM_AES_COLUMNS],
                        AESColumnDependencyVector &dependencyVector) {
    uint8_t sortedOutputColumnPattern[NUM_AES_COLUMNS];
    uint8_t sortOrder[NUM_AES_COLUMNS];
    sortVector(outputColumnPattern, sortedOutputColumnPattern, sortOrder);
    
    AESColumnDependencyVector result;
    applyTransition(inputColumnPattern,
                    sortedOutputColumnPattern,
                    dependencyVector,
                    result);
    
    sortInOldOrder(sortedOutputColumnPattern, result, dependencyVector);
}

// ------------------------------------------------------------------------
