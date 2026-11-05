#include "../~dev/rawrxd/src/core/cli_numeric_policy.h"
#include <stdio.h>
int main(void) {
    int passed=0; uint32_t u=77; float f=77;
#define TEST(label,expr) do {int ok=(expr);printf("%s=%s\n",label,ok?"PASS":"FAIL");passed+=ok;}while(0)
    TEST("01_token_one",rawrxd_parse_u32_range("1",1,65536,&u)&&u==1);
    TEST("02_token_max",rawrxd_parse_u32_range("65536",1,65536,&u)&&u==65536);
    TEST("03_token_zero",!rawrxd_parse_u32_range("0",1,65536,&u));
    TEST("04_token_negative",!rawrxd_parse_u32_range("-1",1,65536,&u));
    TEST("05_token_overflow",!rawrxd_parse_u32_range("999999999999999999999999",1,65536,&u));
    TEST("06_token_trailing",!rawrxd_parse_u32_range("2abc",1,65536,&u));
    TEST("07_token_missing",!rawrxd_parse_u32_range("",1,65536,&u));
    TEST("08_token_plus",!rawrxd_parse_u32_range("+2",1,65536,&u));
    TEST("09_token_overlimit",!rawrxd_parse_u32_range("65537",1,65536,&u));
    TEST("10_temp_zero",rawrxd_parse_f32_range("0",0,2,&f)&&f==0);
    TEST("11_temp_two",rawrxd_parse_f32_range("2",0,2,&f)&&f==2);
    TEST("12_temp_negative",!rawrxd_parse_f32_range("-0.1",0,2,&f));
    TEST("13_temp_nan",!rawrxd_parse_f32_range("nan",0,2,&f));
    TEST("14_temp_inf",!rawrxd_parse_f32_range("inf",0,2,&f));
    TEST("15_temp_trailing",!rawrxd_parse_f32_range("0.8bad",0,2,&f));
    TEST("16_top_p_zero",!rawrxd_parse_f32_range("0",0.000001,1,&f));
    TEST("17_top_p_one",rawrxd_parse_f32_range("1",0.000001,1,&f));
    TEST("18_top_k_over",!rawrxd_parse_u32_range("4097",1,4096,&u));
    TEST("19_null_output",!rawrxd_parse_u32_range("1",1,2,NULL));
    TEST("20_null_input",!rawrxd_parse_f32_range(NULL,0,2,&f));
    printf("CLI_NUMERIC_POLICY=%d/20\n",passed);
    return passed==20?0:1;
}
