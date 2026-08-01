/*==========================================================================
 * masm_preprocessor.h — MASM-to-NASM-style preprocessor interface
 *=========================================================================*/

#ifndef MASM_PREPROCESSOR_H
#define MASM_PREPROCESSOR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Preprocess a MASM source file, expanding macros and handling directives.
 *
 * @param input_file    Path to input MASM source file
 * @param output_file   Path to output preprocessed file
 * @param include_paths Array of include search paths (can be NULL)
 * @param path_count    Number of include paths
 * @return 0 on success, non-zero on error
 */
int masm_preprocess(const char *input_file, const char *output_file,
                    const char **include_paths, int path_count);

/**
 * Preprocess with default include paths.
 * Searches: current directory, d:/rawrxd/src/asm
 */
int masm_preprocess_default(const char *input_file, const char *output_file);

#ifdef __cplusplus
}
#endif

#endif /* MASM_PREPROCESSOR_H */
