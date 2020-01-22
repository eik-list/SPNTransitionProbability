#ifndef _AES_DEPENDENCY_VECTOR_H
#define _AES_DEPENDENCY_VECTOR_H

// ------------------------------------------------------------------------

#include <array>
#include <bitset>
#include <vector>
#include <cstdint>

#include "rijndael.h"

// ------------------------------------------------------------------------

typedef std::bitset<NUM_AES_BYTES> AESByteDependencies;
typedef std::array<AESByteDependencies, NUM_AES_BYTES> AESByteDependencyVector;
typedef std::array<AESByteDependencies, NUM_AES_COLUMNS> AESColumnDependencyVector;
typedef std::vector<AESColumnDependencyVector> AESTransitionDependencyVector;

// ------------------------------------------------------------------------

/**
 * Returns the byte dependencies for the i-th byte, where 0 <= i < NUM_AES_BYTES.
 * @throw If byteIndex >= NUM_AES_BYTES.
 * @param dependencyVector
 * @param byteIndex
 * @return
 */
const AESByteDependencies &getByteDependencies(
    const AESByteDependencyVector &dependencyVector,
    uint8_t byteIndex);

// ------------------------------------------------------------------------

/**
 * Returns the byte dependencies for the i-th column, where 0 <= i < NUM_AES_COLUMNS.
 * @throw If byteIndex >= NUM_AES_COLUMNS.
 * @param dependencyVector
 * @param columnIndex i
 * @return
 */
const AESByteDependencies &getColumnDependencies(
    const AESColumnDependencyVector &dependencyVector,
    uint8_t columnIndex);

// ------------------------------------------------------------------------

void updateDependencies(const uint8_t inputColumnPattern[NUM_AES_COLUMNS],
                        const uint8_t outputColumnPattern[NUM_AES_COLUMNS],
                        AESColumnDependencyVector &dependencyVector);

// ------------------------------------------------------------------------

size_t getWeight(const AESColumnDependencyVector &vector);

// ------------------------------------------------------------------------

#endif //_AES_DEPENDENCY_VECTOR_H
