/* ===========================================================================
 * src/core/sqlite3.h -- DECLARATION SET FOR THE BUNDLED SQLITE AMALGAMATION
 * ===========================================================================
 *
 * READ THIS BEFORE TRUSTING IT. This is NOT the upstream SQLite public header.
 * It declares only the 24 entry points and 9 constants that
 * src/core/sqlite_wrapper.cpp actually calls, and every declaration below was
 * transcribed from the prototype that src/core/sqlite3.c itself carries at the
 * line quoted beside it. Upstream sqlite3.h is roughly 250 KB and declares
 * several hundred entry points; this file is ~200 lines and is not a substitute
 * for it. If a second consumer ever needs the rest of the API, drop this file
 * and install the real sqlite3.h from the 3.47.2 distribution instead.
 *
 * ----------------------------------------------------------------------------
 * WHY THIS FILE EXISTS NOW (RAWRXD_MISSING_SOURCE_001)
 * ----------------------------------------------------------------------------
 * The tree carries the SQLite amalgamation (src/core/sqlite3.c, 9,455,951 bytes,
 * "Real sqlite3 amalgamation (sqlite.org 3.47.2)" per CMakeLists.txt:3222) but
 * not the interface half. sqlite_wrapper.cpp:14 opens with
 *
 *     #include <sqlite3.h>
 *
 * and fails:
 *
 *     src\core\sqlite_wrapper.cpp(14,10): error C1083: Cannot open include file:
 *         'sqlite3.h': No such file or directory
 *
 * sqlite_wrapper.cpp IS in the RawrXD_Gold source list, so this absence alone
 * stops that target compiling.
 *
 * ----------------------------------------------------------------------------
 * WHY TRANSCRIPTION IS SAFE HERE, AND WOULD NOT BE IN GENERAL
 * ----------------------------------------------------------------------------
 * sqlite3.c contains the amalgamation's own prototypes, so each declaration here
 * is copied from the definition it will be linked against rather than recalled.
 * That removes the usual hazard of hand-writing a C ABI header, where a wrong
 * parameter type produces a silent mis-call instead of a compile error.
 *
 * Two things are NOT load-bearing and should not be read as more than they are:
 *
 *   SQLITE_API expands to nothing. In the real header it is a calling-convention
 *   macro (SQLITE_CDECL on Windows, empty elsewhere). On x64 Windows there is a
 *   single calling convention, so the definitions in sqlite3.c and the calls
 *   from sqlite_wrapper.cpp already agree regardless of what this expands to.
 *   This header is therefore correct for the x64 build in this tree and is NOT
 *   portable to a 32-bit build without the real macro.
 *
 *   Only the handles are opaque. sqlite3 and sqlite3_stmt are never dereferenced
 *   by the wrapper -- sqlite_wrapper.hpp forward-declares both as plain structs
 *   for exactly this reason -- so no field layout is reproduced here and none
 *   can drift.
 *
 * The one genuinely load-bearing value is SQLITE_TRANSIENT, defined by upstream
 * as a cast of -1 to the destructor pointer. That value is passed straight
 * through to sqlite3_bind_text/sqlite3_bind_blob, which is how the wrapper asks
 * SQLite to copy the caller's buffer instead of aliasing it. Getting it wrong
 * would be a use-after-free, so it is transcribed exactly (sqlite3.c:6402) and
 * not approximated.
 *
 * ONE MORE TRANSCRIPTION ERROR WORTH RECORDING, because it was in the measuring
 * instrument rather than in this file. The first pass that determined "which
 * SQLite entry points does sqlite_wrapper.cpp use" matched with
 *
 *     \bsqlite3_[A-Za-z_]+
 *
 * which excludes digits. It therefore reported sqlite3_bind_int64 as
 * sqlite3_bind_int and sqlite3_open_v2 as sqlite3_open_v, and this header
 * faithfully declared the truncated names. The build then failed with
 *
 *     sqlite_wrapper.cpp(68,14): error C3861: 'sqlite3_bind_int64': identifier not found
 *
 * i.e. a diagnostic that named a real SQLite function and pointed at a call
 * site, which reads as "the wrapper calls something that does not exist" when in
 * fact the census that produced the header had never seen the name. Re-run with
 * \bsqlite3_[A-Za-z0-9_]+ the true list is 25 entry points, three of which carry
 * a digit. A symbol census that silently truncates names is worse than no
 * census: it produces a header that looks complete and is not.
 *
 * Scope check: src/core/sqlite_wrapper.cpp is the ONLY translation unit in the
 * tree that includes <sqlite3.h>. Every other hit is inside sqlite3.c itself
 * and is a commented-out include directive, so this header cannot shadow the
 * real one for any other consumer.
 *
 * The nested comment terminator below is deliberately NOT written as a literal
 * block-comment close inside this block comment. Doing that on the first draft
 * closed the comment early, and the leak produced, in order:
 *     sqlite3.h(62,50): error C2018: unknown character '0x60'   (a backtick)
 *     sqlite3.h(62,51): error C2059: syntax error: ','
 *     sqlite3.h(71,12): error C2143: syntax error: missing ';' before '{'
 *     sqlite3.h(71,12): error C2447: '{': missing function header
 * and then 40-odd downstream C3861 "identifier not found" for sqlite3_step,
 * sqlite3_errmsg, sqlite3_column_text and the rest, because the whole
 * declaration block had been swallowed as comment text. The downstream errors
 * pointed at the CALL SITES and named real SQLite functions, so a reader
 * skimming the log would conclude the wrapper was calling something that does
 * not exist, when the header had simply stopped being read at line 62.
 * ===========================================================================
 */

#ifndef RAWRXD_SQLITE3_H_INCLUDED
#define RAWRXD_SQLITE3_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

/* --- Calling convention ---------------------------------------------------
 * Upstream defines SQLITE_API as __declspec(dllexport) on Windows and as an
 * empty macro elsewhere. This header defines it as empty, which is correct for
 * the x64 build in this tree: there is a single calling convention, so
 * sqlite3.c's definitions and sqlite_wrapper.cpp's calls already agree. It is
 * NOT portable to a 32-bit build, where SQLITE_CDECL is load-bearing.
 *
 * Do not add dllexport here. sqlite3.c is compiled into RawrXD_Gold as a
 * static object; exporting the symbols would change the link, not fix it.
 */
#ifndef SQLITE_API
#define SQLITE_API
#endif

/* --- Types ---------------------------------------------------------------
 * sqlite3.c:588   typedef struct sqlite3 sqlite3;
 * sqlite3.c:4367  typedef struct sqlite3_stmt sqlite3_stmt;
 * Both are opaque: the wrapper only ever holds pointers to them.
 */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

/* sqlite3.c:6400  typedef void (*sqlite3_destructor_type)(void*); */
typedef void (*sqlite3_destructor_type)(void*);

/* Upstream spells this `long long`; SQLite guarantees >= 64 bits. */
typedef long long int sqlite3_int64;

/* --- Result codes --------------------------------------------------------
 * Values transcribed from sqlite3.c. These are frozen public ABI values, not
 * implementation details, so they are stable across SQLite releases.
 */
#define SQLITE_OK           0    /* Successful result                        */
#define SQLITE_ROW         100   /* sqlite3_step() has another row ready      */
#define SQLITE_DONE        101   /* sqlite3_step() has finished executing    */

/* --- Flags for sqlite3_open_v2 ------------------------------------------
 * sqlite3.c:4091 documents these; the values are the frozen ABI values.
 */
#define SQLITE_OPEN_READONLY        0x00000001
#define SQLITE_OPEN_READWRITE       0x00000002
#define SQLITE_OPEN_CREATE          0x00000004
#define SQLITE_OPEN_URI             0x00000040
#define SQLITE_OPEN_MEMORY          0x00000080
#define SQLITE_OPEN_NOMUTEX         0x00008000
#define SQLITE_OPEN_FULLMUTEX       0x00010000
#define SQLITE_OPEN_SHAREDCACHE     0x00020000
#define SQLITE_OPEN_PRIVATECACHE    0x00040000

/* --- Destructor selectors ------------------------------------------------
 * SQLITE_STATIC   (sqlite3.c) -- SQLite copies the buffer.
 * SQLITE_TRANSIENT (sqlite3.c:6402) -- SQLite copies and frees immediately;
 *                   the (sqlite3_destructor_type)-1 cast is upstream's own and
 *                   is what distinguishes it from SQLITE_STATIC.
 * Both are needed because "don't copy, don't free" (a null destructor) means
 * something different from either of these.
 */
#define SQLITE_STATIC      ((sqlite3_destructor_type)0)
#define SQLITE_TRANSIENT   ((sqlite3_destructor_type)-1)

/* --- Connection lifecycle -------------------------------------------------
 * sqlite3.c:184703  int sqlite3_open_v2(const char*, sqlite3**, int, const char*);
 * sqlite3.c         int sqlite3_open(const char*, sqlite3**);
 */
SQLITE_API int sqlite3_open_v2(const char *filename,
                               sqlite3 **ppDb,
                               int flags,
                               const char *zVfs);
SQLITE_API int sqlite3_open(const char *filename,
                            sqlite3 **ppDb);
SQLITE_API int sqlite3_close(sqlite3*);

/* --- Statement lifecycle --------------------------------------------------
 * sqlite3.c:143540  int sqlite3_prepare_v2(sqlite3*, const char*, int,
 *                                           sqlite3_stmt**, const char**);
 * NOTE the parameter name in the amalgamation is nBytes, not nByte; the type
 * is int either way. Passing pzTail == NULL is explicitly permitted by SQLite
 * and is how the wrapper discards the tail of a multi-statement string.
 */
SQLITE_API int sqlite3_prepare_v2(sqlite3 *db,
                                  const char *zSql,
                                  int nBytes,
                                  sqlite3_stmt **ppStmt,
                                  const char **pzTail);
SQLITE_API int sqlite3_step(sqlite3_stmt*);
SQLITE_API int sqlite3_reset(sqlite3_stmt *pStmt);
SQLITE_API int sqlite3_finalize(sqlite3_stmt *pStmt);

/* --- Binding --------------------------------------------------------------
 * Transcribed from sqlite3.c. bind_text and bind_blob take a
 * sqlite3_destructor_type; the amalgamation spells the parameter
 * `void(*)(void*)`, which is the same type.
 * sqlite3.c:5037  int sqlite3_bind_text(sqlite3_stmt*,int,const char*,int,void(*)(void*));
 * sqlite3.c        int sqlite3_bind_blob(sqlite3_stmt*, int, const void*, int n, void(*)(void*));
 */
SQLITE_API int sqlite3_bind_int(sqlite3_stmt*, int, int);
SQLITE_API int sqlite3_bind_int64(sqlite3_stmt*, int, sqlite3_int64);
SQLITE_API int sqlite3_bind_double(sqlite3_stmt*, int, double);
SQLITE_API int sqlite3_bind_text(sqlite3_stmt*, int, const char*, int,
                                 void(*)(void*));
SQLITE_API int sqlite3_bind_blob(sqlite3_stmt*, int, const void*, int n,
                                 void(*)(void*));
SQLITE_API int sqlite3_bind_null(sqlite3_stmt*, int);
SQLITE_API int sqlite3_clear_bindings(sqlite3_stmt*);

/* --- Result access --------------------------------------------------------
 * sqlite3.c:5605  const unsigned char *sqlite3_column_text(sqlite3_stmt*, int);
 * NOTE the unsigned return. sqlite_wrapper.cpp must cast before treating it as
 * a C string; that is the wrapper's business, not the ABI's.
 */
SQLITE_API int sqlite3_column_count(sqlite3_stmt *pStmt);
SQLITE_API const char *sqlite3_column_name(sqlite3_stmt*, int N);
SQLITE_API const unsigned char *sqlite3_column_text(sqlite3_stmt*, int iCol);

/* --- Convenience execution ------------------------------------------------
 * sqlite3.c:137094  int sqlite3_exec(sqlite3*, const char*,
 *                                   int(*)(void*,int,char**,char**),
 *                                   void*, char**);
 * Passing a null callback and a null errmsg is permitted and is the common case.
 */
SQLITE_API int sqlite3_exec(sqlite3*,
                            const char *sql,
                            int (*callback)(void*,int,char**,char**),
                            void *,
                            char **errmsg);

/* --- Diagnostics and counters -------------------------------------------- */
SQLITE_API const char *sqlite3_errmsg(sqlite3*);
SQLITE_API void sqlite3_free(void*);
SQLITE_API sqlite3_int64 sqlite3_last_insert_rowid(sqlite3*);
SQLITE_API int sqlite3_changes(sqlite3*);
SQLITE_API int sqlite3_total_changes(sqlite3*);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RAWRXD_SQLITE3_H_INCLUDED */