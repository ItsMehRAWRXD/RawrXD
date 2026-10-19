#ifndef BS_PROCESS_H
#define BS_PROCESS_H
#include <stdint.h>
int bs_process_alive(uint32_t pid);
void bs_sleep_ms(uint32_t ms);
#endif
