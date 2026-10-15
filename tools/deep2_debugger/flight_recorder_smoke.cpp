#include "deep2_flight_recorder.hpp"
#include <cstdio>
int main(){
    rawrxd::debug::Recorder recorder;
    if(!recorder.start(L"deep2_flight.jsonl",100,50))return 2;
    {
        rawrxd::debug::Scope prefill(recorder,"prefill/layer_0");
        Sleep(150);
        prefill.progress(1);
        recorder.counter("gpu_dispatches",0);
    }
    recorder.stop();
    std::puts("FLIGHT_RECORDER_SMOKE_PASS");
    return 0;
}
