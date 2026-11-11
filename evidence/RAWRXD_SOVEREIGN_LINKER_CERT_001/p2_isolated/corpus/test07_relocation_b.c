/* 07: data relocation — cross-TU ADDR/REL to global */
extern int global_counter;
int get_counter(void) { return global_counter; }
