/**
 * Copyright 2019 anonymized
 */

#include "min_weight_dependency_strategy.h"
#include "../include/rijndael.h"

#include <algorithm>
#include <functional>
#include <numeric>

// ------------------------------------------------------------------------
// Types
// ------------------------------------------------------------------------

typedef std::function<void(const NTL::mat_RR &,
                           const NTL::vec_RR &,
                           const AESTransitionDependencyVector &,
                           const std::vector<size_t> &,
                           const size_t,
                           NTL::vec_RR &,
                           AESTransitionDependencyVector &)> UpdateDistributionCallback;

// ------------------------------------------------------------------------
// Utility functions
// ------------------------------------------------------------------------

static void
toActiveColumnPattern(uint8_t columnPattern[NUM_AES_COLUMNS],
                      const int columnPatternAsInt) {
    int pattern = columnPatternAsInt;
    
    for (int i = 0; i < 4; i++) {
        const int numActiveBytesInColumn = pattern % 5;
        columnPattern[i] = static_cast<uint8_t>(numActiveBytesInColumn);
        
        pattern -= numActiveBytesInColumn;
        pattern = pattern / 5;
    }
}

// ------------------------------------------------------------------------

//static void printDistribution(const NTL::vec_RR &distribution) {
//    const size_t length = distribution.length();
//    printf("  Distribution (%zu entries)\n", length);
//
//    for (size_t i = 0; i < length; ++i) {
//        const auto &item = distribution[i];
//
//        if (item <= 0.0) {
//            continue;
//        }
//
//        uint8_t columnPattern[NUM_AES_COLUMNS];
//        toActiveColumnPattern(columnPattern, i);
//
//        printf("%3zu (%hhu%hhu%hhu%hhu) ", i, columnPattern[0],
//               columnPattern[1], columnPattern[2], columnPattern[3]);
//        std::cout << item << std::endl;
//    }
//}

// ------------------------------------------------------------------------

//static void
//printDependency(const size_t i, const AESColumnDependencyVector &item) {
//    std::cout << i << " ";
//
//    for (size_t j = 0; j < item.size(); ++j) {
//        std::string columnDependencies = item[j].to_string();
//        std::reverse(columnDependencies.begin(), columnDependencies.end());
//        std::cout << "(" << columnDependencies << ") ";
//    }
//
//    std::cout << std::endl;
//}

// ------------------------------------------------------------------------

//static void printDependencies(const AESTransitionDependencyVector &v) {
//    const size_t length = v.size();
//    printf("  Dependencies (%zu)\n", length);
//
//    for (size_t i = 0; i < length; ++i) {
//        if (getWeight(v[i]) == 0) {
//            continue;
//        }
//
//        printDependency(i, v[i]);
//    }
//}

// ------------------------------------------------------------------------

//static void printColumnPattern(const uint8_t pattern[NUM_AES_COLUMNS]) {
//    printf("%hhu%hhu%hhu%hhu", pattern[0], pattern[1], pattern[2], pattern[3]);
//}

// ------------------------------------------------------------------------

/**
 * https://stackoverflow.com/questions/1577475/c-sorting-and-keeping-track-of-indexes
 * @tparam T
 * @param v
 * @return
 */
template<typename T>
std::vector<size_t> sortIndicesSimpleDescending(const std::vector<T> &v) {
    // ------------------------------------------------------------------------
    // Initialize original index locations
    // ------------------------------------------------------------------------
    std::vector<size_t> indices(v.size());
    std::iota(indices.begin(), indices.end(), 0);
    
    // ------------------------------------------------------------------------
    // Sort indexes based on comparing values in v using std::stable_sort
    // instead of std::sort to avoid unnecessary index re-orderings when v
    // contains equal elements.
    // ------------------------------------------------------------------------
    std::stable_sort(
        indices.begin(),
        indices.end(),
        [&v](size_t leftIndex, size_t rightIndex) {
            return v[leftIndex] > v[rightIndex];
        }
    );
    
    return indices;
}

/**
 * https://stackoverflow.com/questions/1577475/c-sorting-and-keeping-track-of-indexes
 * @tparam T
 * @param v
 * @return
 */
template<typename T>
std::vector<size_t> sortIndices(const std::vector<T> &v) {
    // ------------------------------------------------------------------------
    // Initialize original index locations
    // ------------------------------------------------------------------------
    std::vector<size_t> indices(v.size());
    std::iota(indices.begin(), indices.end(), 0);
    
    // ------------------------------------------------------------------------
    // Sort indexes based on comparing values in v using std::stable_sort
    // instead of std::sort to avoid unnecessary index re-orderings when v
    // contains equal elements.
    // ------------------------------------------------------------------------
    std::stable_sort(
        indices.begin(),
        indices.end(),
        [&v](size_t leftIndex, size_t rightIndex) {
            const size_t leftWeight = getWeight(v[leftIndex]);
            const size_t rightWeight = getWeight(v[rightIndex]);
            
            if (rightWeight == 0) {
                return true;
            }
            
            if (leftWeight == 0) {
                return false;
            }
            
            return (leftWeight < rightWeight);
        }
    );
    
    return indices;
}

// ------------------------------------------------------------------------

static void prepareDistribution(NTL::vec_RR &distribution,
                                const size_t length,
                                const size_t precision) {
    distribution.SetLength(length);
    distribution[0].SetPrecision(precision);
}

// ------------------------------------------------------------------------

/**
 * Sorts input into output and stores the indices into output.
 * The dimensions of output and indices are adapted automatically.
 * Example:
 * input = [5, 3, 7, 29, 0, 1, 15, 8], and
 * indices = [4, 5, 1, 0, 2, 7, 6, 3]
 * output will become [0, 1, 3, 5, 7, 8, 15, 29].
 *
 * Input locations must overlap with output locations.
 * Do NOT use the same array.
 * @param input
 * @param indices
 * @param output
 */
//static void sortVectorAccordingToIndices(const uint8_t input[],
//                                         const size_t num_elements,
//                                         const std::vector<size_t> &indices,
//                                         uint8_t output[]) {
//    for (size_t i = 0; i < num_elements; ++i) {
//        const size_t original_index = indices[i];
//        output[i] = input[original_index];
//    }
//}

// ------------------------------------------------------------------------

/**
 * Sorts input into output and stores the indices into output.
 * The dimensions of output and indices are adapted automatically.
 * Example:
 * input = [5, 3, 7, 29, 0, 1, 15, 8], and
 * indices = [4, 5, 1, 0, 2, 7, 6, 3]
 * output will become [0, 1, 3, 5, 7, 8, 15, 29].
 *
 * Input locations must overlap with output locations.
 * Do NOT use the same array.
 * @param input
 * @param indices
 * @param output
 */
static void sortVectorAccordingToIndices(const NTL::vec_RR &input,
                                         const std::vector<size_t> &indices,
                                         NTL::vec_RR &output) {
    const auto length = static_cast<size_t >(input.length());
    
    if (input.length() < 1) {
        return;
    }
    
    prepareDistribution(output, length, input[0].precision());
    
    for (size_t i = 0; i < length; ++i) {
        const size_t original_index = indices[i];
        output[i] = input[original_index];
    }
}

// ------------------------------------------------------------------------

/**
 * Sorts input into output and stores the indices into output.
 * The dimensions of output and indices are adapted automatically.
 * Example:
 * input = [5, 3, 7, 29, 0, 1, 15, 8], and
 * indices = [4, 5, 1, 0, 2, 7, 6, 3]
 * output will become [0, 1, 3, 5, 7, 8, 15, 29].
 *
 * Input locations must overlap with output locations.
 * Do NOT use the same array.
 * @param input
 * @param indices
 * @param output
 */
static void
sortVectorAccordingToIndices(const AESTransitionDependencyVector &input,
                             const std::vector<size_t> &indices,
                             AESTransitionDependencyVector &output) {
    const auto length = static_cast<size_t >(input.size());
    output.clear();
    output.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        const size_t original_index = indices[i];
        output.push_back(input[original_index]);
    }
}

// ------------------------------------------------------------------------
// Helper functions for the main logic
// ------------------------------------------------------------------------

/**
 * Updates the probabilities distribution.
 * For the transition algorithms, this was just y = M * x.
 * This is only non-static to allow its use as a callback.
 *
 * @param columnSortedMatrix M
 * @param sortedDistribution x
 * @param sortedDependencies
 * @param smallestNonZeroIndex
 * @param outputDistribution y
 * @param outputDependencies
 */
static void updateDistributionThroughMixColumns(
    const NTL::mat_RR &columnSortedMatrix,
    const NTL::vec_RR &sortedDistribution,
    const AESTransitionDependencyVector &sortedDependencies,
    const std::vector<size_t> &sortOrder,
    const size_t smallestNonZeroIndex,
    NTL::vec_RR &outputDistribution,
    AESTransitionDependencyVector &outputDependencies) {
    (void)sortOrder;
    auto numColumns = static_cast<size_t >(columnSortedMatrix.NumCols());
    const auto numRows = static_cast<size_t >(columnSortedMatrix.NumRows());
    AESColumnDependencyVector zeroDependencies;
    
    for (size_t row = 0; row < numRows; ++row) {
        // ----------------------------------------------------------------
        // If we find no transition to the pattern with integer representation
        // i, we will use a probability y[i] = 0.
        // ----------------------------------------------------------------
        
        outputDistribution[row] = 0;
        outputDependencies[row] = zeroDependencies;
        
        for (size_t column = smallestNonZeroIndex;
             column < numColumns;
             ++column) {
            // ----------------------------------------------------------------
            // Ignore i if M[*][i] * x[i] = 0
            // ----------------------------------------------------------------
            if (sortedDistribution[column] == 0) {
                continue;
            }
            
            if (columnSortedMatrix[row][column] == 0) {
                continue;
            }
            
            // ----------------------------------------------------------------
            // Simply set y[i] = M[*][i] * x[i] for the first i such that
            // y[i] != 0.
            // ----------------------------------------------------------------
            
            outputDistribution[row] = columnSortedMatrix[row][column]
                                      * sortedDistribution[column];
            
            // ----------------------------------------------------------------
            // Simple. Since we store only a single dependency vector per
            // column, we don't have to update anything. No merging of byte
            // dependencies, no zeroizing.
            // ----------------------------------------------------------------
            
            outputDependencies[row] = sortedDependencies[column];
            
            // ----------------------------------------------------------------
            // Break since we found the first transition.
            // ----------------------------------------------------------------
            
            break;
        }
    }
    
    AESColumnDependencyVector zero;
    outputDependencies[0] = zero;
}

// ------------------------------------------------------------------------

static void updateDependencyThroughShiftRows(
    const size_t inputColumnPatternAsInt,
    const size_t outputColumnPatternAsInt,
    const AESColumnDependencyVector &inputDependencies,
    AESColumnDependencyVector &outputDependencies) {
    // ------------------------------------------------------------------------
    // Store input and output patterns
    // ------------------------------------------------------------------------
    
    // Example: input = [4,3,3,3], output = [3,3,3,4]
    uint8_t inputColumnPattern[NUM_AES_COLUMNS];
    toActiveColumnPattern(inputColumnPattern, inputColumnPatternAsInt);
    
    uint8_t outputColumnPattern[NUM_AES_COLUMNS];
    toActiveColumnPattern(outputColumnPattern, outputColumnPatternAsInt);
    std::vector<uint8_t> outputColumnPatternVector(outputColumnPattern,
                                                   outputColumnPattern +
                                                   NUM_AES_COLUMNS);
    
    std::vector<size_t> outputIndices;
    AESColumnDependencyVector tempDependencies;
    
    // ------------------------------------------------------------------------
    // Move column-wise active input bytes to the output vector
    // ------------------------------------------------------------------------
    
    for (uint8_t inputColumn = 0;
         inputColumn < NUM_AES_COLUMNS; ++inputColumn) {
        uint8_t numActiveInputBytes = inputColumnPattern[inputColumn];
        
        if (numActiveInputBytes == 0) {
            continue;
        }
        
        // ------------------------------------------------------------------------
        // Sort output-column indices by descending #active bytes
        // [3,3,3,4] => [4,3,3,3], indices will be [3,0,1,2]
        // ------------------------------------------------------------------------
        
        outputIndices = sortIndicesSimpleDescending(outputColumnPatternVector);
        
        for (uint8_t j = 0; j < NUM_AES_COLUMNS; ++j) {
            // ------------------------------------------------------------------------
            // Use the index with next highest #free active output bytes
            // ------------------------------------------------------------------------
            const uint8_t outputColumn = outputIndices[j];
            uint8_t numActiveOutputBytes = outputColumnPatternVector[outputColumn];
    
            if (numActiveOutputBytes == 0) {
                continue;
            }
    
            if (numActiveInputBytes <= numActiveOutputBytes) { // 1 vs. 2
                outputColumnPatternVector[outputColumn]--;
                numActiveInputBytes--;
                tempDependencies[outputColumn] |= inputDependencies[inputColumn];
            } else if (numActiveInputBytes > numActiveOutputBytes) { // 2 vs. 1
                outputColumnPatternVector[outputColumn]--;
                numActiveInputBytes--;
                tempDependencies[outputColumn] |= inputDependencies[inputColumn];
            }
    
            if (numActiveInputBytes == 0) { // All passed
                break;
            }
        }
    }
    
    // ------------------------------------------------------------------------
    // Revert the sorting in the column vector
    // [1,2,2,1] had been sorted to [2,2,1,1] with indices [1,2,0,3].
    // We sort the dependencies [d_1,d_2,d_0,d_3] back to [d_0,d_1,d_2,d_3].
    // ------------------------------------------------------------------------
    
    for (uint8_t i = 0; i < NUM_AES_COLUMNS; ++i) {
        uint8_t originalIndex = outputIndices[i];
        outputDependencies[originalIndex] = tempDependencies[i];
    }
}

// ------------------------------------------------------------------------

/**
 * Updates the probabilities distribution.
 * For the transition algorithms, this was just y = M * x.
 * This is only non-static to allow its use as a callback.
 *
 * @param columnSortedMatrix M
 * @param sortedDistribution x
 * @param sortedDependencies
 * @param smallestNonZeroIndex
 * @param outputDistribution y
 * @param outputDependencies
 */
void updateDistributionThroughShiftRows(
    const NTL::mat_RR &columnSortedMatrix,
    const NTL::vec_RR &sortedDistribution,
    const AESTransitionDependencyVector &sortedDependencies,
    const std::vector<size_t> &sortOrder,
    const size_t smallestNonZeroIndex,
    NTL::vec_RR &outputDistribution,
    AESTransitionDependencyVector &outputDependencies) {
    auto numColumns = static_cast<size_t >(columnSortedMatrix.NumCols());
    const auto numRows = static_cast<size_t >(columnSortedMatrix.NumRows());
    AESColumnDependencyVector zeroDependencies;
    
    for (size_t row = 0; row < numRows; ++row) {
        // ----------------------------------------------------------------
        // If we find no transition to the pattern with integer representation
        // i, we will use a probability y[i] = 0.
        // ----------------------------------------------------------------
        
        outputDistribution[row] = 0;
        outputDependencies[row] = zeroDependencies;
        
        for (size_t column = smallestNonZeroIndex;
             column < numColumns;
             ++column) {
            // ----------------------------------------------------------------
            // Ignore i if M[*][i] * x[i] = 0
            // ----------------------------------------------------------------
            if (sortedDistribution[column] == 0) {
                continue;
            }
            
            if (columnSortedMatrix[row][column] == 0) {
                continue;
            }
            
            // ----------------------------------------------------------------
            // Simply set y[i] = M[*][i] * x[i] for the first i such that
            // y[i] != 0.
            // ----------------------------------------------------------------
            
            outputDistribution[row] = columnSortedMatrix[row][column]
                                      * sortedDistribution[column];
            
            uint8_t rowColumnPattern[NUM_AES_COLUMNS];
            toActiveColumnPattern(rowColumnPattern, row);
            
            // ----------------------------------------------------------------
            // Updates the dependencies
            // ----------------------------------------------------------------
            
            AESColumnDependencyVector dependency;
            const size_t oldColumn = sortOrder[column];
            updateDependencyThroughShiftRows(oldColumn,
                                             row,
                                             sortedDependencies[column],
                                             dependency);
            outputDependencies[row] = dependency;
            
            // ----------------------------------------------------------------
            // Break since we found the first transition
            // ----------------------------------------------------------------
            
            break;
        }
    }
    
    AESColumnDependencyVector zero;
    outputDependencies[0] = zero;
}

// ------------------------------------------------------------------------

/**
 * Returns the index of the leftmost (i.e. smallest) index M[i] and
 * vector[i] such that the i-th entry in any column of M is non-zero and
 * vector[i] is non-zero.
 * @param matrix
 * @param vector
 * @return A non-zero index i that is either the desired index OR
 * that is the length of the smallest of both matrix and vector,
 * indicating no such index could be found.
 */
static size_t findSmallestCommonNonZeroIndex(const NTL::mat_RR &matrix,
                                             const NTL::vec_RR &v) {
    const auto length = static_cast<size_t >(v.length());
    auto numColumns = static_cast<size_t >(matrix.NumCols());
    
    if (length < numColumns) {
        numColumns = length;
    }
    
    const auto numRows = static_cast<size_t >(matrix.NumRows());
    
    for (size_t column = 0; column < numColumns; ++column) {
        if (v[column] == 0) {
            continue;
        }
        
        for (size_t row = 0; row < numRows; ++row) {
            if (matrix[row][column] != 0) {
                return column;
            }
        }
    }
    
    return numColumns;
}

// ------------------------------------------------------------------------

/**
 * Sorts the columns of matrix according to the given indices.
 * The dimensions of output are adapted automatically.
 * Example:
 * input columns are = [c_0, c_1, c_2, c_3], indices = [3, 1, 2, 0].
 * Then, the output columns will be [c_3, c_1, c_2, c_0].
 *
 * @throws if the lengths of input and indices differ.
 * @param input
 * @param indices
 * @param output
 */
static void sortMatrixColumns(const NTL::mat_RR &input,
                              const std::vector<size_t> &indices,
                              NTL::mat_RR &output) {
    if (input.NumCols() < 1 || input.NumRows() < 1) {
        return;
    }
    
    const auto precision = static_cast<size_t >(input[0][0].precision());
    const auto outputPrecision = static_cast<size_t >(input[0][0].OutputPrecision());
    
    output.SetDims(input.NumRows(), input.NumCols());
    output[0][0].SetPrecision(precision);
    output[0][0].SetOutputPrecision(outputPrecision);
    
    const auto numColumns = static_cast<size_t >(input.NumCols());
    const auto numRows = static_cast<size_t >(input.NumRows());
    
    for (size_t column = 0; column < numColumns; ++column) {
        const size_t original_column = indices[column];
        
        for (size_t row = 0; row < numRows; ++row) {
            output[row][column] = input[row][original_column];
        }
    }
}

// ------------------------------------------------------------------------

/**
 * Sorts input into output and stores the indices into output.
 * The dimensions of output and indices are adapted automatically.
 * Example:
 * input = [5, 3, 7, 29, 0, 1, 15, 8].
 * output will become [0, 1, 3, 5, 7, 8, 15, 29]
 * indices will become [4, 5, 1, 0, 2, 7, 6, 3].
 * @param input
 * @param output
 * @param indices
 */
static void sortDependenciesByWeight(const AESTransitionDependencyVector &input,
                                     AESTransitionDependencyVector &output,
                                     std::vector<size_t> &indices) {
    indices = sortIndices(input);
    output.reserve(input.size());
    sortVectorAccordingToIndices(input, indices, output);
}

// ------------------------------------------------------------------------
// Main logic
// ------------------------------------------------------------------------

static void updateDistribution(
    const NTL::mat_RR &matrix,
    const NTL::vec_RR &inputDistribution,
    AESTransitionDependencyVector &dependencies,
    NTL::vec_RR &outputDistribution,
    const UpdateDistributionCallback& updateDistributionCallback) {
    // ------------------------------------------------------------------------
    // Sort the dependencies with ascending weight. This is a heuristic.
    // ------------------------------------------------------------------------
    
    AESTransitionDependencyVector sortedDependencies;
    std::vector<size_t> sortOrder;
    sortDependenciesByWeight(dependencies, sortedDependencies, sortOrder);
    
    // ------------------------------------------------------------------------
    // Sort the matrix columns and the inputDistribution rows in the
    // same order as the dependencies. This is for faster access later.
    // ------------------------------------------------------------------------
    
    NTL::vec_RR sortedDistribution;
    prepareDistribution(sortedDistribution,
                        inputDistribution.length(),
                        inputDistribution[0].precision());
    
    sortVectorAccordingToIndices(inputDistribution,
                                 sortOrder,
                                 sortedDistribution);
    NTL::mat_RR sortedMatrix;
    sortMatrixColumns(matrix, sortOrder, sortedMatrix);
    
    // ------------------------------------------------------------------------
    // Find the smallest non-zero index i of matrix and inputDistribution for
    // fast access, where M[*][i] * x[i] is non-zero.
    // So, we do not have to consider any indices j < i that will yield 0
    // anyways.
    // ------------------------------------------------------------------------
    
    const size_t smallestCommonNonzeroIndex = findSmallestCommonNonZeroIndex(
        sortedMatrix, sortedDistribution
    );
    
    // ------------------------------------------------------------------------
    // Apply MixColumns, i.e., we use the first transition with non-zero
    // probability with minimum-weight dependency.
    // ------------------------------------------------------------------------
    
    AESTransitionDependencyVector outputDependencies;
    outputDependencies = sortedDependencies;
    
    updateDistributionCallback(sortedMatrix,
                               sortedDistribution,
                               sortedDependencies,
                               sortOrder,
                               smallestCommonNonzeroIndex,
                               outputDistribution,
                               outputDependencies);
    
    dependencies = outputDependencies;
}

// ------------------------------------------------------------------------

/**
 * Updates the probabilities distribution.
 * For the transition algorithms, this was just y = M * x.
 * Here, we will
 *
 * @param matrix M
 * @param inputDistribution x
 * @param outputDistribution y
 */
void MinWeightDependencyStrategy::applyMixColumns(
    const NTL::mat_RR &matrix,
    const NTL::vec_RR &inputDistribution,
    AESTransitionDependencyVector &dependencies,
    NTL::vec_RR &outputDistribution) const {
    updateDistribution(matrix,
                       inputDistribution,
                       dependencies,
                       outputDistribution,
                       &updateDistributionThroughMixColumns);
}

// ------------------------------------------------------------------------

void MinWeightDependencyStrategy::applyShiftRows(
    const NTL::mat_RR &matrix,
    const NTL::vec_RR &inputDistribution,
    AESTransitionDependencyVector &dependencies,
    NTL::vec_RR &outputDistribution) const {
    updateDistribution(matrix,
                       inputDistribution,
                       dependencies,
                       outputDistribution,
                       &updateDistributionThroughShiftRows);
}
