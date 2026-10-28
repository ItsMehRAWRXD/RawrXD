/* 07: data relocation — global in this TU */
int global_counter = 100;
int get_counter(void);
int main(void) { return get_counter(); }
