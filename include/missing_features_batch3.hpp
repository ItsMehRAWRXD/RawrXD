#pragma once
namespace rawrxd {
    struct IDEFeatures3 { void initialize(){} };
    struct IDEFeatures4 { void initialize(){} };
    struct IDEFeatures5 { void initialize(){} };
    struct IDEFeatures8 { void initialize(){} };
    struct IDEFeatures9 { void initialize(){} };

    namespace wal_gutter {
        inline int programmaticMutationDepth() { return 0; }
    }
}
