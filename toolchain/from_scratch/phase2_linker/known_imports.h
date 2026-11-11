#ifndef KNOWN_IMPORTS_H
#define KNOWN_IMPORTS_H
#include <stdint.h>
#include <stddef.h>

/* Returns the DLL that exports `symbol`, or NULL when unknown. */
const char *known_import_dll(const char *symbol);

/* Number of entries in the table (for diagnostics). */
int known_import_count(void);

#endif
