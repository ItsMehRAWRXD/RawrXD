import importlib.util, pathlib, subprocess, sys, tempfile
module_path=pathlib.Path('/mnt/data/patch_modelgenie_ir.py')
spec=importlib.util.spec_from_file_location('patch_modelgenie_ir',module_path)
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
source='''#include <algorithm>
    void Close()
static float FP16ToFloat(uint16_t h)
{
old f16
}
//=============================================================================
// Dequantizer for GGUF tensor types
        case ModelGenie::GGMLType::Q5_0:
        {
old q5
        }
        case ModelGenie::GGMLType::Q6_K:
        {
old q6
        }
        default:
            memset(out.data()
    const float* Get(uint32_t activationId) const
    const TensorView* Resolve(uint32_t romTensorId) const
    {
old resolve
    }
    // Get dequantized weight tensor (cached)
    GGUFROM romFile_;
    mutable std::unordered_map
static float* ResolveOutput(const GEN::OperationIR& op, ActivationArena& arena, const ROMResolver& romResolver) {
old resolver
}
//=============================================================================
// Primitive Dispatcher
            case Primitive::RmsNormFwd: {
old norm
            }
            case Primitive::LinearFwd: {
old lin
            }
            case Primitive::MatMulFwd: {
return false;
            }
            case Primitive::AttentionFwd: {
old attn
            }
            case Primitive::MlaDecompressFwd: {
old mla
            }
            case Primitive::RouterFwd: {
old router
            }
            case Primitive::TopKFwd: {
old topk
            }
            case Primitive::MoEExecuteFwd: {
old moe
            }
            case Primitive::ResidualAddFwd: {
old residual
            }
            case Primitive::LMHeadFwd: {
old lm
            }
            default:
                std::fprintf(stderr, "[IR] Unsupported primitive:
    // Linear forward pass (matrix-vector: output = input @ weight.T)
old linear
    // Attention forward pass
old attention
    // ResidualAdd forward pass
static void RMSNorm(float* out, const float* in, const float* w, int n, float eps)
{
old helper
}
static void Softmax(float* x, int n)
{
old softmax
}
static void MatMul(const float* A
old matmul
static void VecAdd(
        uint32_t opsSkipped = 0;
        // Capture logits from final LM Head output (activation 299 based on IR table)
    uint32_t SampleToken() const;
    std::vector<float> logits_;
    IRExecutor executor(ggufPath, 0);
    // Get actual dispatched/skipped counts from executor
old comment
    std::fprintf(stderr, "\\n=============================================================================\\n");
    std::fprintf(stderr, "IR_TABLE_AUTHORITY=1\\n");
    std::fprintf(stderr, "IR_OPS_VISITED=%u\\n", GEN::kExecutionOpCount);
            if (executed) {
                opsDispatched++;
'''
modified, changes=m.patch(source)
assert len(changes)==27, (len(changes),changes)
for expected in ('Q6_K block size','Q5_0 block size','return MoEExecuteFwd','IR_OPS_EXECUTED','IR_OPS_SKIPPED','IR_TABLE_AUTHORITY=%d','row-major on dim[0]'):
    assert expected in modified,expected
assert 'old attention' not in modified
assert 'old moe' not in modified
try:
    m.patch(modified)
    raise AssertionError('Second application must fail closed')
except m.PatchError:
    pass
with tempfile.TemporaryDirectory() as d:
    f=pathlib.Path(d)/'input.cpp';f.write_text(source)
    p=subprocess.run([sys.executable,str(module_path),'--source',str(f)],capture_output=True,text=True)
    assert p.returncode==0,p.stderr
    assert f.read_text()==source
print('PATCH_TEST=PASS')
print(f'TRANSFORMS={len(changes)}')
print('DRY_RUN_NO_WRITE=PASS')
print('SECOND_APPLICATION_FAIL_CLOSED=PASS')
print('BINARY_COMPILE_OR_TOKEN_PARITY=NOT_RUN')
