// S1 SAST fixture: every finding below is intentional.
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void vulnerable(void) {
    char buf[16];
    strcpy(buf, "this string is definitely longer than sixteen bytes");   // SAST001
    strcat(buf, "more");                                                 // SAST002
    sprintf(buf, "%s", buf);                                             // SAST003
    gets(buf);                                                           // SAST004
    scanf("%s", buf);                                                    // SAST005
    system("echo hi");                                                   // SAST006
    char* p = (char*)malloc(32);
    free(p);
    p[0] = 'x';                                                          // SAST009 use-after-free
    char* q = (char*)malloc(atoi("999999"));                             // SAST010/SAST011
    (void)q;
    const char* password = "hunter2";                                    // SAST012
    (void)password;
}