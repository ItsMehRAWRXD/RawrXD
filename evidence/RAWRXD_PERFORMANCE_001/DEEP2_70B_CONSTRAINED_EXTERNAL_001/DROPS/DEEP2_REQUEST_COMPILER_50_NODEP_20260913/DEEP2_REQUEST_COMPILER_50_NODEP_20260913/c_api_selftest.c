#include "d2_request_compiler_c.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    d2rc_plan_handle* h = d2rc_compile(
        "write graph; build graph; test graph; verify graph; commit graph; push graph"
    );
    assert(h != NULL);
    assert(d2rc_node_count(h) == 6);
    assert(d2rc_mechanism_count() == 50);
    assert(strlen(d2rc_mechanism_name(50)) > 0);
    assert(d2rc_ready_count(h) > 0);
    printf("DEEP2_REQUEST_COMPILER_C_ABI_SELFTEST=PASS\n");
    printf("C_ABI_NODES=%zu\n", d2rc_node_count(h));
    d2rc_free(h);
    return 0;
}
