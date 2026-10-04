// Behavioural probe for the MC_* editor-core ABI.
// RAWRXD_MONACO_RETURN_CONVENTION_001: proves the gap buffer really inserts,
// deletes, reports length/lines and tokenizes -- and that the int-return
// convention matches the header (1 = success, 0 = failure).
#include "RawrXD_MonacoCore.h"

#include <cstdio>
#include <cstring>
#include <string>

static int g_fail = 0;
static int g_run  = 0;

static void check(bool cond, const char* what) {
    ++g_run;
    if (!cond) { ++g_fail; std::printf("FAIL: %s\n", what); }
}

int main() {
    // ---- 1. Init returns 1 on success (NOT 0) -----------------------------
    MC_GapBuffer gb;
    const int initRc = MC_GapBuffer_Init(&gb, 64);
    check(initRc == 1, "MC_GapBuffer_Init returns 1 on success");
    check(MC_GapBuffer_Length(&gb) == 0, "fresh buffer length is 0");
    check(MC_GapBuffer_LineCount(&gb) == 1, "fresh buffer has 1 line");

    // ---- 2. Insert returns 1 AND the bytes are really there ----------------
    const int insRc = MC_GapBuffer_Insert(&gb, 0, "hello", 5);
    check(insRc == 1, "MC_GapBuffer_Insert returns 1 on success");
    check(MC_GapBuffer_Length(&gb) == 5, "length is 5 after inserting 5 bytes");

    char line[128];
    check(MC_GapBuffer_GetLine(&gb, 0, line, sizeof(line)) == 5, "GetLine returns 5");
    check(std::strcmp(line, "hello") == 0, "GetLine content is 'hello'");

    // ---- 3. A successful insert must NOT be reported as failure ------------
    //       This is the exact inversion that was fixed.
    check(insRc != 0, "successful insert is non-zero for the '!= 0' caller test");

    // ---- 4. Failure paths must return 0 (was -1, which read as success) ----
    MC_GapBuffer bad{};
    check(MC_GapBuffer_Insert(&bad, 0, "x", 1) == 0,
          "insert into an uninitialised buffer returns 0 (failure)");
    check(MC_GapBuffer_Insert(&gb, 9999, "x", 1) == 0,
          "out-of-range insert returns 0 (failure)");

    // ---- 5. Mid-string insert at a non-zero offset --------------------------
    check(MC_GapBuffer_Insert(&gb, 5, " world", 6) == 1, "append ' world' succeeds");
    check(MC_GapBuffer_Length(&gb) == 11, "length is 11");
    MC_GapBuffer_GetLine(&gb, 0, line, sizeof(line));
    check(std::strcmp(line, "hello world") == 0, "content is 'hello world'");

    // ---- 6. Insert in the middle (gap actually moves) -----------------------
    check(MC_GapBuffer_Insert(&gb, 5, ",", 1) == 1, "mid insert succeeds");
    check(MC_GapBuffer_Length(&gb) == 12, "length is 12");
    MC_GapBuffer_GetLine(&gb, 0, line, sizeof(line));
    check(std::strcmp(line, "hello, world") == 0, "content is 'hello, world'");

    // ---- 7. Newlines produce real line counts -------------------------------
    check(MC_GapBuffer_Insert(&gb, 12, "\nsecond", 7) == 1, "newline insert succeeds");
    check(MC_GapBuffer_LineCount(&gb) == 2, "line count is 2");
    MC_GapBuffer_GetLine(&gb, 1, line, sizeof(line));
    check(std::strcmp(line, "second") == 0, "line 1 is 'second'");

    // ---- 8. Delete returns 1 and removes bytes ------------------------------
    // Buffer before this step is "hello, world\nsecond" (19 bytes).
    // Delete(pos=6, len=6) removes " world" (bytes 6..11), leaving
    // "hello," + "\nsecond" = 6 + 1 + 6 = 13 bytes, still 2 lines.
    const int delRc = MC_GapBuffer_Delete(&gb, 6, 6);
    check(delRc == 1, "MC_GapBuffer_Delete returns 1 on success");
    check(MC_GapBuffer_Length(&gb) == 13, "length is 13 after deleting 6 of 19");
    check(MC_GapBuffer_LineCount(&gb) == 2, "still 2 lines (no newline was deleted)");
    MC_GapBuffer_GetLine(&gb, 0, line, sizeof(line));
    check(std::strcmp(line, "hello,") == 0, "line 0 is 'hello,'");
    MC_GapBuffer_GetLine(&gb, 1, line, sizeof(line));
    check(std::strcmp(line, "second") == 0, "line 1 is still 'second'");

    // ---- 9. Deleting a newline must merge two lines -------------------------
    {
        MC_GapBuffer m;
        MC_GapBuffer_Init(&m, 64);
        MC_GapBuffer_Insert(&m, 0, "a\nb", 3);
        check(MC_GapBuffer_LineCount(&m) == 2, "2 lines after 'a\\nb'");
        check(MC_GapBuffer_Delete(&m, 1, 1) == 1, "delete the newline succeeds");
        check(MC_GapBuffer_LineCount(&m) == 1, "lines merged to 1");
        MC_GapBuffer_GetLine(&m, 0, line, sizeof(line));
        check(std::strcmp(line, "ab") == 0, "merged line is 'ab'");
        MC_GapBuffer_Destroy(&m);
    }

    // ---- 10. Growth past the initial capacity --------------------------------
    {
        const uint32_t before = MC_GapBuffer_Length(&gb);
        const std::string big(5000, 'x');
        check(MC_GapBuffer_Insert(&gb, before,
                                  big.data(), (uint32_t)big.size()) == 1,
              "insert larger than initial capacity succeeds (grows)");
        check(MC_GapBuffer_Length(&gb) == before + 5000, "length grew by exactly 5000");
    }

    // ---- 11. Delete failure path returns 0 ----------------------------------
    check(MC_GapBuffer_Delete(&gb, 999999, 1) == 0, "out-of-range delete returns 0");
    check(MC_GapBuffer_Delete(&gb, 0, 0) == 1, "zero-length delete is a no-op success");

    // ---- 12. Tokenizer produces real, correctly-typed tokens ---------------
    {
        const char* src = "int x = 42; // note";
        MC_Token toks[MC_MAX_TOKENS_PER_LINE];
        const uint32_t n = MC_TokenizeLine(src, (uint32_t)std::strlen(src),
                                           toks, MC_MAX_TOKENS_PER_LINE);
        check(n > 0, "tokenizer produced tokens");
        check(n < MC_MAX_TOKENS_PER_LINE, "token count within bounds");

        bool sawKeyword = false, sawNumber = false, sawComment = false;
        for (uint32_t i = 0; i < n; ++i) {
            if (toks[i].tokenType == (uint32_t)MC_TokenType::Keyword)  sawKeyword = true;
            if (toks[i].tokenType == (uint32_t)MC_TokenType::Number)   sawNumber  = true;
            if (toks[i].tokenType == (uint32_t)MC_TokenType::Comment)  sawComment = true;
        }
        check(sawKeyword, "'int' classified as Keyword");
        check(sawNumber,  "'42' classified as Number");
        check(sawComment, "'// note' classified as Comment");
        // Every token must lie inside the line.
        bool inBounds = true;
        for (uint32_t i = 0; i < n; ++i)
            if (toks[i].startCol + toks[i].length > std::strlen(src)) inBounds = false;
        check(inBounds, "all token spans are within the line");
    }

    MC_GapBuffer_Destroy(&gb);
    check(gb.pBuffer == nullptr, "Destroy clears the buffer pointer");

    std::printf("CHECKS=%d FAIL=%d\n", g_run, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}