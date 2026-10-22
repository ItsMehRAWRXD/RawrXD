// C02 - COFF object writer certification.
//
// The compiler's COFF writer must produce objects that the certified
// RawrXD native linker accepts and turns into a Windows-loadable
// executable. This is the first half of the E2E path:
//
//   RawrXD COFF writer -> rawrxd_link.exe -> Windows -> exit code
//
// No external compiler, assembler or linker participates.

#include "object/CoffWriter.h"

#include "rawrstd/sys.h"

using namespace rawr;
using rawrstd::String;

static int g_pass = 0;
static int g_fail = 0;

static void ok(const char* what) {
    rawrstd::write_stdout("  [PASS] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("\n", 1);
    ++g_pass;
}

static void bad(const char* what, const String& detail) {
    rawrstd::write_stdout("  [FAIL] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("  -- ", 4);
    rawrstd::write_stderr(detail.data(), detail.size());
    rawrstd::write_stderr("\n", 1);
    ++g_fail;
}

static void check(bool cond, const char* what) {
    if (cond) ok(what);
    else bad(what, String("condition false"));
}

// ---------------------------------------------------------------------------
// The test program.
//
//   entry:
//     sub  rsp, 0x28            ; 32 bytes of shadow space + alignment
//     mov  ecx, 42              ; uExitCode
//     call qword ptr [rip + d]  ; kernel32!ExitProcess
//     add  rsp, 0x28
//     ret
//
// The call uses the `__imp_` convention, so the relocation targets the
// import address table slot directly.
// ---------------------------------------------------------------------------
static const uint8 kCode[] = {
    0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 0x28
    0xB9, 0x2A, 0x00, 0x00, 0x00,       // mov  ecx, 42
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call qword ptr [rip + 0]
    0x48, 0x83, 0xC4, 0x28,             // add  rsp, 0x28
    0xC3                                // ret
};

static const uint32 kCallDispOffset = 11;   // the displacement field of the call

int main(int argc, char** argv) {
    const char* out_dir = (argc > 1) ? argv[1] : ".";

    rawrstd::write_stdout("C02 COFF object writer certification\n", 36);
    rawrstd::write_stdout("========================================\n", 40);

    String obj_path;
    obj_path << out_dir << "/c02_fixture.obj";

    // -----------------------------------------------------------------
    // Build the object
    // -----------------------------------------------------------------
    CoffWriter writer;

    int text = writer.add_section(".text",
                                  kScnCntCode | kScnMemExecute | kScnMemRead,
                                  16);
    writer.append_data(text, kCode, sizeof(kCode));

    // The import symbol is undefined, so the linker binds it to an IAT slot.
    int imp = writer.add_symbol(CoffSymbol::external("__imp_ExitProcess"));
    int entry = writer.add_symbol(
        CoffSymbol::external("entry", static_cast<int16>(text), 0, true));
    check(entry >= 0, "the entry symbol was added");

    writer.add_relocation(text, kCallDispOffset, static_cast<uint32>(imp),
                          CoffReloc::Rel32);

    // Tell the linker which library the import comes from.
    writer.add_directive("/DEFAULTLIB:kernel32.lib");

    check(writer.write(obj_path.data()), "object written");

    // -----------------------------------------------------------------
    // Structural checks on the serialized object
    // -----------------------------------------------------------------
    rawrstd::File f;
    check(f.open(obj_path.data(), rawrstd::FileMode::Read), "object can be reopened");
    rawrstd::Vector<uint8> bytes;
    if (f.is_open()) {
        char buf[4096];
        for (;;) {
            int64 got = f.read(buf, sizeof(buf));
            if (got <= 0) break;
            for (int64 i = 0; i < got; ++i) {
                bytes.push_back(static_cast<uint8>(buf[i]));
            }
        }
        f.close();
    }
    check(!bytes.empty(), "object is not empty");

    if (bytes.size() >= 20) {
        uint16 machine = static_cast<uint16>(bytes[0] | (bytes[1] << 8));
        uint16 num_sections = static_cast<uint16>(bytes[2] | (bytes[3] << 8));
        uint32 symtab = static_cast<uint32>(bytes[8] | (bytes[9] << 8) |
                                            (bytes[10] << 16) | (bytes[11] << 24));
        uint32 num_syms = static_cast<uint32>(bytes[12] | (bytes[13] << 8) |
                                              (bytes[14] << 16) | (bytes[15] << 24));

        check(machine == 0x8664, "machine is AMD64");
        check(num_sections == 2, "two sections (.drectve and .text)");
        check(symtab < bytes.size(), "symbol table offset is inside the file");
        check(num_syms == 3, "three symbols (file, import, entry)");

        // The .drectve section must carry the DEFAULTLIB directive.
        bool found_directive = false;
        for (size_type i = 0; i + 21 < bytes.size(); ++i) {
            if (bytes[i] == '/' && bytes[i + 1] == 'D' && bytes[i + 2] == 'E' &&
                bytes[i + 3] == 'F' && bytes[i + 4] == 'A' && bytes[i + 5] == 'U' &&
                bytes[i + 6] == 'L' && bytes[i + 7] == 'T') {
                found_directive = true;
                break;
            }
        }
        check(found_directive, "the /DEFAULTLIB directive is present");

        // The long symbol name must live in the string table.
        bool found_long_name = false;
        for (size_type i = 0; i + 6 < bytes.size(); ++i) {
            if (bytes[i] == '_' && bytes[i + 1] == '_' && bytes[i + 2] == 'i' &&
                bytes[i + 3] == 'm' && bytes[i + 4] == 'p' && bytes[i + 5] == '_') {
                found_long_name = true;
                break;
            }
        }
        if (!found_long_name) {
            String dump;
            dump << "object is " << bytes.size() << " bytes: ";
            for (size_type i = 0; i < bytes.size() && i < 256; ++i) {
                char c = static_cast<char>(bytes[i]);
                if (c >= ' ' && c < 127) dump << c;
                else dump << '.';
            }
            bad("the long symbol name is in the string table", dump);
        } else {
            ok("the long symbol name is in the string table");
        }
    } else {
        bad("object header", String("object is too small"));
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    rawrstd::write_stdout("----------------------------------------\n", 40);
    String summary;
    summary << "C02 result: " << g_pass << " passed, " << g_fail << " failed\n";
    rawrstd::write_stdout(summary.data(), summary.size());

    return g_fail == 0 ? 0 : 1;
}
