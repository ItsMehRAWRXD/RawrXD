// Probes a DLL's export table as the loader sees it: the mapped image.
#include <windows.h>
#include <stdio.h>

static unsigned char* g_base;

static unsigned char* map_rva(DWORD rva, DWORD* out_raw) {
    unsigned char* dos = g_base;
    DWORD peOff = *(DWORD*)(dos + 0x3C);
    unsigned char* nt = g_base + peOff;
    int nsec = *(unsigned short*)(nt + 6);
    unsigned char* opt = nt + 24;
    unsigned char* secTab = nt + 24 + *(unsigned short*)(nt + 20);
    for (int i = 0; i < nsec; ++i) {
        unsigned char* s = secTab + i * 40;
        DWORD va = *(DWORD*)(s + 12);
        DWORD vs = *(DWORD*)(s + 8);
        if (rva >= va && rva < va + vs) {
            if (out_raw) *out_raw = *(DWORD*)(s + 20);
            return g_base + rva;
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: probe_exports <dll> [name]\n");
        return 2;
    }
    const char* name = (argc > 2) ? argv[2] : "RawrxdAdd";

    HMODULE m = LoadLibraryA(argv[1]);
    printf("LoadLibrary('%s') = %p, error=%lu\n", argv[1], (void*)m, GetLastError());
    if (!m) return 1;
    g_base = (unsigned char*)m;

    FARPROC byName = GetProcAddress(m, name);
    printf("GetProcAddress('%s') = %p, error=%lu\n", name, (void*)byName, GetLastError());

    unsigned char* dos = g_base;
    DWORD peOff = *(DWORD*)(dos + 0x3C);
    unsigned char* nt = g_base + peOff;
    unsigned char* opt = nt + 24;

    // The data directories start at optional header offset 112, so the
    // export directory is the first DWORD pair.
    DWORD expRva = *(DWORD*)(opt + 112);
    DWORD expSize = *(DWORD*)(opt + 116);
    printf("export dir RVA=0x%08X size=0x%08X\n", expRva, expSize);

    unsigned char* d = map_rva(expRva, NULL);
    if (!d) {
        printf("the export directory RVA does not map to any section\n");
        printf("sections as the loader sees them:\n");
        {
            unsigned char* nt2 = g_base + *(DWORD*)(g_base + 0x3C);
            int nsec2 = *(unsigned short*)(nt2 + 6);
            unsigned short optSize2 = *(unsigned short*)(nt2 + 20);
            unsigned char* st2 = nt2 + 24 + optSize2;
            printf("  nsec=%d optSize=%d secTab=0x%X\n", nsec2, optSize2, (size_t)(st2 - g_base));
            for (int i = 0; i < nsec2; ++i) {
                unsigned char* s = st2 + i * 40;
                printf("  [%d] name='%.8s' VS=0x%08X VA=0x%08X RawSz=0x%08X RawPtr=0x%08X Chars=0x%08X\n",
                       i, s, *(DWORD*)(s + 8), *(DWORD*)(s + 12),
                       *(DWORD*)(s + 16), *(DWORD*)(s + 20), *(DWORD*)(s + 36));
            }
        }
        return 1;
    }
    printf("as the loader sees it:\n");
    printf("  Characteristics       = 0x%08X\n", *(DWORD*)(d + 0));
    printf("  TimeDateStamp         = 0x%08X\n", *(DWORD*)(d + 4));
    printf("  MajorVersion          = 0x%04X\n", *(unsigned short*)(d + 8));
    printf("  MinorVersion          = 0x%04X\n", *(unsigned short*)(d + 10));
    DWORD nameRva = *(DWORD*)(d + 12);
    printf("  Name                  = 0x%08X '%s'\n", nameRva, (char*)map_rva(nameRva, NULL));
    printf("  Base                  = %u\n", *(DWORD*)(d + 16));
    DWORD nFunc = *(DWORD*)(d + 20);
    DWORD nName = *(DWORD*)(d + 24);
    printf("  NumberOfFunctions     = %u\n", nFunc);
    printf("  NumberOfNames         = %u\n", nName);
    DWORD afRva = *(DWORD*)(d + 28);
    DWORD anRva = *(DWORD*)(d + 32);
    DWORD anoRva = *(DWORD*)(d + 36);
    printf("  AddressOfFunctions    = 0x%08X\n", afRva);
    printf("  AddressOfNames        = 0x%08X\n", anRva);
    printf("  AddressOfNameOrdinals = 0x%08X\n", anoRva);

    for (DWORD i = 0; i < nFunc && i < 8; ++i) {
        DWORD* tab = (DWORD*)map_rva(afRva, NULL);
        printf("    func[%u] rva=0x%08X\n", i, tab ? tab[i] : 0);
    }
    for (DWORD i = 0; i < nName && i < 8; ++i) {
        DWORD* tab = (DWORD*)map_rva(anRva, NULL);
        unsigned short* ord = (unsigned short*)map_rva(anoRva, NULL);
        if (!tab || !ord) break;
        printf("    name[%u] '%s' ordinal=%u\n", i,
               tab[i] ? (char*)map_rva(tab[i], NULL) : "?", ord[i]);
    }

    FreeLibrary(m);
    return 0;
}
