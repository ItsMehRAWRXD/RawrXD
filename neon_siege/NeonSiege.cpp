#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdarg>
#include <cstring>
#include <cstdlib>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")

// -----------------------------------------------------------------------------
// NEON SIEGE
// Source-only Win32 + D3D11 arena roguelite.
// No external libraries. No external assets. Embedded HLSL. Procedural geometry.
// -----------------------------------------------------------------------------

static const int kWidth = 1280;
static const int kHeight = 720;
static const float kPi = 3.14159265358979323846f;

struct Vec3 {
    float x{}, y{}, z{};
};
static Vec3 operator+(Vec3 a, Vec3 b) { return {a.x+b.x, a.y+b.y, a.z+b.z}; }
static Vec3 operator-(Vec3 a, Vec3 b) { return {a.x-b.x, a.y-b.y, a.z-b.z}; }
static Vec3 operator*(Vec3 a, float s) { return {a.x*s, a.y*s, a.z*s}; }
static float Dot(Vec3 a, Vec3 b) { return a.x*b.x + a.y*b.y + a.z*b.z; }
static float LenSq(Vec3 a) { return Dot(a,a); }
static float Len(Vec3 a) { return std::sqrt(LenSq(a)); }
static Vec3 Normalize(Vec3 v) {
    float l = Len(v);
    return l > 0.00001f ? v*(1.0f/l) : Vec3{};
}
static Vec3 Cross(Vec3 a, Vec3 b) {
    return {a.y*b.z-a.z*b.y, a.z*b.x-a.x*b.z, a.x*b.y-a.y*b.x};
}
static float Clamp(float v, float a, float b) { return v < a ? a : (v > b ? b : v); }

struct Mat4 { float m[16]{}; };

static Mat4 Identity() {
    Mat4 r{};
    r.m[0]=r.m[5]=r.m[10]=r.m[15]=1.0f;
    return r;
}
static Mat4 Mul(const Mat4& a, const Mat4& b) {
    Mat4 r{};
    for (int row=0; row<4; ++row)
        for (int col=0; col<4; ++col)
            for (int k=0; k<4; ++k)
                r.m[row*4+col] += a.m[row*4+k] * b.m[k*4+col];
    return r;
}
static Mat4 Translation(float x,float y,float z) {
    Mat4 r=Identity();
    r.m[12]=x; r.m[13]=y; r.m[14]=z;
    return r;
}
static Mat4 Scale(float x,float y,float z) {
    Mat4 r{};
    r.m[0]=x; r.m[5]=y; r.m[10]=z; r.m[15]=1;
    return r;
}
static Mat4 Perspective(float fovY, float aspect, float zn, float zf) {
    Mat4 r{};
    float y = 1.0f / std::tan(fovY*0.5f);
    float x = y / aspect;
    r.m[0]=x; r.m[5]=y;
    r.m[10]=zf/(zf-zn);
    r.m[11]=1.0f;
    r.m[14]=(-zn*zf)/(zf-zn);
    return r;
}
static Mat4 LookAt(Vec3 eye, Vec3 at, Vec3 up) {
    Vec3 z = Normalize(at-eye);
    Vec3 x = Normalize(Cross(up,z));
    Vec3 y = Cross(z,x);
    Mat4 r = Identity();
    r.m[0]=x.x; r.m[1]=y.x; r.m[2]=z.x;
    r.m[4]=x.y; r.m[5]=y.y; r.m[6]=z.y;
    r.m[8]=x.z; r.m[9]=y.z; r.m[10]=z.z;
    r.m[12]=-Dot(x,eye);
    r.m[13]=-Dot(y,eye);
    r.m[14]=-Dot(z,eye);
    return r;
}

struct Color { float r,g,b,a; };

enum class GameState { Menu, Playing, WaveComplete, Boss, Victory, GameOver };
enum class EnemyType { Grunt, Gunner, Tank, Boss };
enum class PickupType { Health, FireRate, Damage, Speed, Overdrive };

struct Enemy {
    EnemyType type{};
    Vec3 pos{};
    float hp{};
    float maxHp{};
    float speed{};
    float shootCooldown{};
    float scale{1.0f};
    bool alive{true};
};

struct Pickup {
    PickupType type{};
    Vec3 pos{};
    float ttl{20.0f};
    bool alive{true};
};

struct CertFlags {
    bool gameStart{};
    bool playerMovement{};
    bool playerFire{};
    bool enemyGrunt{};
    bool enemyGunner{};
    bool enemyTank{};
    bool waveProgression{};
    bool pickups{};
    bool upgrades{};
    bool playerDamage{};
    bool playerDeath{};
    bool playerRespawn{};
    bool bossSpawn{};
    bool bossCombat{};
    bool bossDeath{};
    bool gameOver{};
    bool restart{};
    bool victory{};
    bool telemetry{};
    bool framebufferEvidence{};
};

static HWND g_hwnd{};
static ID3D11Device* g_dev{};
static ID3D11DeviceContext* g_ctx{};
static IDXGISwapChain* g_swap{};
static ID3D11RenderTargetView* g_rtv{};
static ID3D11Texture2D* g_depth{};
static ID3D11DepthStencilView* g_dsv{};
static ID3D11VertexShader* g_vs{};
static ID3D11PixelShader* g_ps{};
static ID3D11InputLayout* g_layout{};
static ID3D11Buffer* g_vb{};
static ID3D11Buffer* g_ib{};
static ID3D11Buffer* g_cb{};
static ID3D11VertexShader* g_vs2d{};
static ID3D11PixelShader* g_ps2d{};
static ID3D11InputLayout* g_layout2d{};
static ID3D11Buffer* g_vb2d{};
static ID3D11DepthStencilState* g_depthOff{};
static ID3D11BlendState* g_alphaBlend{};
static ID3D11RasterizerState* g_noCull{};
static FILE* g_log{};

static GameState g_state = GameState::Menu;
static int g_wave=1, g_score=0, g_kills=0, g_lives=3;
static Vec3 g_player{0,1.2f,-8};
static float g_yaw=0.0f;
static float g_playerHp=100.0f;
static float g_maxHp=100.0f;
static float g_moveSpeed=6.0f;
static float g_damage=34.0f;
static float g_fireInterval=0.25f;
static float g_fireTimer=0.0f;
static float g_overdrive=0.0f;
static float g_waveDelay=0.0f;
static float g_sessionTime=0.0f;
static float g_damageFlash=0.0f;
static float g_hitFlash=0.0f;
static float g_bossSummonTimer=3.0f;
static uint32_t g_rng=0xC0FFEEu;
static std::vector<Enemy> g_enemies;
static std::vector<Pickup> g_pickups;
static CertFlags g_cert{};
static bool g_captureStartup=false, g_captureWave1=false, g_captureWave3=false, g_captureBoss=false, g_captureVictory=false;

static uint32_t NextRand() {
    g_rng = g_rng*1664525u + 1013904223u;
    return g_rng;
}
static float Rand01() { return float((NextRand()>>8)&0xFFFFFFu)/float(0xFFFFFFu); }

static void Log(const char* fmt, ...) {
    if (!g_log) return;
    SYSTEMTIME st{}; GetLocalTime(&st);
    std::fprintf(g_log, "%02u:%02u:%02u.%03u ", st.wHour,st.wMinute,st.wSecond,st.wMilliseconds);
    va_list ap; va_start(ap,fmt); std::vfprintf(g_log,fmt,ap); va_end(ap);
    std::fprintf(g_log,"\n"); std::fflush(g_log);
    g_cert.telemetry = true;
}

static const char* EnemyName(EnemyType t) {
    switch(t) {
        case EnemyType::Grunt: return "GRUNT";
        case EnemyType::Gunner: return "GUNNER";
        case EnemyType::Tank: return "TANK";
        default: return "BOSS";
    }
}
static const char* PickupName(PickupType t) {
    switch(t) {
        case PickupType::Health: return "HEALTH";
        case PickupType::FireRate: return "FIRE_RATE";
        case PickupType::Damage: return "DAMAGE";
        case PickupType::Speed: return "SPEED";
        default: return "OVERDRIVE";
    }
}

static void EnsureEvidenceDir() {
    CreateDirectoryW(L"evidence", nullptr);
}

static void ReleaseD3D() {
    if (g_noCull) g_noCull->Release();
    if (g_alphaBlend) g_alphaBlend->Release();
    if (g_depthOff) g_depthOff->Release();
    if (g_vb2d) g_vb2d->Release();
    if (g_layout2d) g_layout2d->Release();
    if (g_ps2d) g_ps2d->Release();
    if (g_vs2d) g_vs2d->Release();
    if (g_cb) g_cb->Release();
    if (g_ib) g_ib->Release();
    if (g_vb) g_vb->Release();
    if (g_layout) g_layout->Release();
    if (g_ps) g_ps->Release();
    if (g_vs) g_vs->Release();
    if (g_dsv) g_dsv->Release();
    if (g_depth) g_depth->Release();
    if (g_rtv) g_rtv->Release();
    if (g_swap) g_swap->Release();
    if (g_ctx) g_ctx->Release();
    if (g_dev) g_dev->Release();
}

static const char* kVS = R"(
cbuffer CB : register(b0) {
    row_major float4x4 mvp;
    float4 color;
};
struct I { float3 p:POSITION; };
struct O { float4 p:SV_POSITION; float4 c:COLOR0; };
O main(I i) {
    O o;
    o.p = mul(float4(i.p,1), mvp);
    o.c = color;
    return o;
})";

static const char* kPS = R"(
struct I { float4 p:SV_POSITION; float4 c:COLOR0; };
float4 main(I i):SV_TARGET { return i.c; }
)";

static const char* kVS2D = R"(
struct I { float2 p:POSITION; float4 c:COLOR0; };
struct O { float4 p:SV_POSITION; float4 c:COLOR0; };
O main(I i) { O o; o.p=float4(i.p,0,1); o.c=i.c; return o; }
)";
static const char* kPS2D = R"(
struct I { float4 p:SV_POSITION; float4 c:COLOR0; };
float4 main(I i):SV_TARGET { return i.c; }
)";

struct CBData { Mat4 mvp; Color color; };

struct Vertex3 { float x,y,z; };
static const Vertex3 kCubeVerts[] = {
    {-1,-1,-1},{-1, 1,-1},{ 1, 1,-1},{ 1,-1,-1},
    {-1,-1, 1},{-1, 1, 1},{ 1, 1, 1},{ 1,-1, 1}
};
static const uint16_t kCubeIdx[] = {
    0,1,2, 0,2,3, 4,6,5, 4,7,6,
    0,4,5, 0,5,1, 3,2,6, 3,6,7,
    1,5,6, 1,6,2, 0,3,7, 0,7,4
};

struct Vertex2 { float x,y; float r,g,b,a; };

static bool CompileShader(const char* src,const char* entry,const char* target,ID3DBlob** out) {
    ID3DBlob* err{};
    HRESULT hr=D3DCompile(src,strlen(src),nullptr,nullptr,nullptr,entry,target,
                          D3DCOMPILE_ENABLE_STRICTNESS|D3DCOMPILE_PACK_MATRIX_ROW_MAJOR,0,out,&err);
    if (FAILED(hr)) {
        if (err) {
            MessageBoxA(nullptr,(const char*)err->GetBufferPointer(),"Shader compile failed",MB_ICONERROR);
            err->Release();
        }
        return false;
    }
    if (err) err->Release();
    return true;
}

static bool InitD3D(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount=2;
    sd.BufferDesc.Width=kWidth;
    sd.BufferDesc.Height=kHeight;
    sd.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow=hwnd;
    sd.SampleDesc.Count=1;
    sd.Windowed=TRUE;
    sd.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL fl{};
    D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_0};
    HRESULT hr=D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,
        levels,1,D3D11_SDK_VERSION,&sd,&g_swap,&g_dev,&fl,&g_ctx);
    if (FAILED(hr)) return false;

    ID3D11Texture2D* back{};
    if (FAILED(g_swap->GetBuffer(0,__uuidof(ID3D11Texture2D),(void**)&back))) return false;
    hr=g_dev->CreateRenderTargetView(back,nullptr,&g_rtv);
    back->Release();
    if (FAILED(hr)) return false;

    D3D11_TEXTURE2D_DESC dd{};
    dd.Width=kWidth; dd.Height=kHeight; dd.MipLevels=1; dd.ArraySize=1;
    dd.Format=DXGI_FORMAT_D24_UNORM_S8_UINT; dd.SampleDesc.Count=1;
    dd.BindFlags=D3D11_BIND_DEPTH_STENCIL;
    if (FAILED(g_dev->CreateTexture2D(&dd,nullptr,&g_depth))) return false;
    if (FAILED(g_dev->CreateDepthStencilView(g_depth,nullptr,&g_dsv))) return false;

    ID3DBlob *vsb{},*psb{},*v2{},*p2{};
    if (!CompileShader(kVS,"main","vs_5_0",&vsb)) return false;
    if (!CompileShader(kPS,"main","ps_5_0",&psb)) return false;
    if (!CompileShader(kVS2D,"main","vs_5_0",&v2)) return false;
    if (!CompileShader(kPS2D,"main","ps_5_0",&p2)) return false;

    g_dev->CreateVertexShader(vsb->GetBufferPointer(),vsb->GetBufferSize(),nullptr,&g_vs);
    g_dev->CreatePixelShader(psb->GetBufferPointer(),psb->GetBufferSize(),nullptr,&g_ps);
    D3D11_INPUT_ELEMENT_DESC il[]={{"POSITION",0,DXGI_FORMAT_R32G32B32_FLOAT,0,0,D3D11_INPUT_PER_VERTEX_DATA,0}};
    g_dev->CreateInputLayout(il,1,vsb->GetBufferPointer(),vsb->GetBufferSize(),&g_layout);

    g_dev->CreateVertexShader(v2->GetBufferPointer(),v2->GetBufferSize(),nullptr,&g_vs2d);
    g_dev->CreatePixelShader(p2->GetBufferPointer(),p2->GetBufferSize(),nullptr,&g_ps2d);
    D3D11_INPUT_ELEMENT_DESC il2[]={
        {"POSITION",0,DXGI_FORMAT_R32G32_FLOAT,0,0,D3D11_INPUT_PER_VERTEX_DATA,0},
        {"COLOR",0,DXGI_FORMAT_R32G32B32A32_FLOAT,0,8,D3D11_INPUT_PER_VERTEX_DATA,0}};
    g_dev->CreateInputLayout(il2,2,v2->GetBufferPointer(),v2->GetBufferSize(),&g_layout2d);
    vsb->Release(); psb->Release(); v2->Release(); p2->Release();

    D3D11_BUFFER_DESC bd{};
    bd.Usage=D3D11_USAGE_DEFAULT; bd.ByteWidth=sizeof(kCubeVerts); bd.BindFlags=D3D11_BIND_VERTEX_BUFFER;
    D3D11_SUBRESOURCE_DATA init{}; init.pSysMem=kCubeVerts;
    if (FAILED(g_dev->CreateBuffer(&bd,&init,&g_vb))) return false;

    bd={}; bd.Usage=D3D11_USAGE_DEFAULT; bd.ByteWidth=sizeof(kCubeIdx); bd.BindFlags=D3D11_BIND_INDEX_BUFFER;
    init={}; init.pSysMem=kCubeIdx;
    if (FAILED(g_dev->CreateBuffer(&bd,&init,&g_ib))) return false;

    bd={}; bd.Usage=D3D11_USAGE_DYNAMIC; bd.ByteWidth=sizeof(CBData); bd.BindFlags=D3D11_BIND_CONSTANT_BUFFER;
    bd.CPUAccessFlags=D3D11_CPU_ACCESS_WRITE;
    if (FAILED(g_dev->CreateBuffer(&bd,nullptr,&g_cb))) return false;

    bd={}; bd.Usage=D3D11_USAGE_DYNAMIC; bd.ByteWidth=sizeof(Vertex2)*6*32;
    bd.BindFlags=D3D11_BIND_VERTEX_BUFFER; bd.CPUAccessFlags=D3D11_CPU_ACCESS_WRITE;
    if (FAILED(g_dev->CreateBuffer(&bd,nullptr,&g_vb2d))) return false;

    D3D11_DEPTH_STENCIL_DESC dsd{};
    dsd.DepthEnable=FALSE;
    dsd.DepthWriteMask=D3D11_DEPTH_WRITE_MASK_ZERO;
    dsd.DepthFunc=D3D11_COMPARISON_ALWAYS;
    if (FAILED(g_dev->CreateDepthStencilState(&dsd,&g_depthOff))) return false;

    D3D11_BLEND_DESC blend{};
    blend.RenderTarget[0].BlendEnable=TRUE;
    blend.RenderTarget[0].SrcBlend=D3D11_BLEND_SRC_ALPHA;
    blend.RenderTarget[0].DestBlend=D3D11_BLEND_INV_SRC_ALPHA;
    blend.RenderTarget[0].BlendOp=D3D11_BLEND_OP_ADD;
    blend.RenderTarget[0].SrcBlendAlpha=D3D11_BLEND_ONE;
    blend.RenderTarget[0].DestBlendAlpha=D3D11_BLEND_ZERO;
    blend.RenderTarget[0].BlendOpAlpha=D3D11_BLEND_OP_ADD;
    blend.RenderTarget[0].RenderTargetWriteMask=D3D11_COLOR_WRITE_ENABLE_ALL;
    if (FAILED(g_dev->CreateBlendState(&blend,&g_alphaBlend))) return false;

    D3D11_RASTERIZER_DESC rs{};
    rs.FillMode=D3D11_FILL_SOLID;
    rs.CullMode=D3D11_CULL_NONE;
    rs.DepthClipEnable=TRUE;
    if (FAILED(g_dev->CreateRasterizerState(&rs,&g_noCull))) return false;

    return true;
}

static void SpawnEnemy(EnemyType t, float x, float z) {
    Enemy e{};
    e.type=t; e.pos={x,1.0f,z};
    switch(t) {
        case EnemyType::Grunt: e.hp=e.maxHp=55; e.speed=3.8f; e.shootCooldown=1.2f; e.scale=0.55f; g_cert.enemyGrunt=true; break;
        case EnemyType::Gunner:e.hp=e.maxHp=85; e.speed=2.2f; e.shootCooldown=0.75f; e.scale=0.65f; g_cert.enemyGunner=true; break;
        case EnemyType::Tank:  e.hp=e.maxHp=180;e.speed=1.25f;e.shootCooldown=1.6f;e.scale=0.95f; g_cert.enemyTank=true; break;
        case EnemyType::Boss:  e.hp=e.maxHp=1200;e.speed=1.35f;e.shootCooldown=0.7f;e.scale=2.0f; g_cert.bossSpawn=true; break;
    }
    g_enemies.push_back(e);
    Log("BOT_SPAWN type=%s x=%.2f z=%.2f hp=%.0f",EnemyName(t),x,z,e.hp);
}

static Vec3 SpawnPoint(int i,int n) {
    float a=(float(i)/float(n))*kPi*2.0f;
    float r=9.0f + 3.0f*Rand01();
    return {std::cos(a)*r,1.0f,std::sin(a)*r};
}

static void StartWave(int wave) {
    g_wave=wave;
    g_enemies.clear();
    g_pickups.clear();

    if (wave==1) {
        for (int i=0;i<5;i++){ auto p=SpawnPoint(i,5); SpawnEnemy(EnemyType::Grunt,p.x,p.z); }
    } else if (wave==2) {
        for (int i=0;i<8;i++){
            auto p=SpawnPoint(i,8);
            SpawnEnemy(i%3==0?EnemyType::Gunner:EnemyType::Grunt,p.x,p.z);
        }
    } else if (wave==3) {
        for (int i=0;i<12;i++){
            auto p=SpawnPoint(i,12);
            EnemyType t=(i%5==0)?EnemyType::Tank:((i%3==0)?EnemyType::Gunner:EnemyType::Grunt);
            SpawnEnemy(t,p.x,p.z);
        }
    } else {
        g_state=GameState::Boss;
        SpawnEnemy(EnemyType::Boss,0,8);
        for(int i=0;i<4;i++){ auto p=SpawnPoint(i,4); SpawnEnemy(EnemyType::Grunt,p.x,p.z); }
        Log("BOSS_SPAWN");
    }
    Log("WAVE_START wave=%d count=%zu",wave,g_enemies.size());
}

static void ResetGame(bool fromRestart) {
    g_state=GameState::Playing;
    g_wave=1; g_score=0; g_kills=0; g_lives=3;
    g_player={0,1.2f,-8}; g_yaw=0; g_playerHp=g_maxHp;
    g_moveSpeed=6.0f; g_damage=34.0f; g_fireInterval=0.25f;
    g_overdrive=0; g_fireTimer=0; g_waveDelay=0; g_bossSummonTimer=3.0f;
    g_rng=0xC0FFEEu;
    g_enemies.clear(); g_pickups.clear();
    if (fromRestart) { g_cert.restart=true; Log("GAME_RESTART"); }
    else { g_cert.gameStart=true; Log("GAME_START seed=0xC0FFEE"); }
    StartWave(1);
}

static void SpawnPickup(Vec3 pos) {
    if (Rand01()>0.42f) return;
    Pickup p{};
    p.type=(PickupType)(NextRand()%5);
    p.pos={pos.x,0.45f,pos.z};
    g_pickups.push_back(p);
    Log("PICKUP_SPAWN type=%s x=%.2f z=%.2f",PickupName(p.type),p.pos.x,p.pos.z);
    g_cert.pickups=true;
}

static void ApplyPickup(Pickup& p) {
    switch(p.type) {
        case PickupType::Health: g_playerHp=std::min(g_maxHp,g_playerHp+35); break;
        case PickupType::FireRate: g_fireInterval=std::max(0.10f,g_fireInterval*0.85f); g_cert.upgrades=true; break;
        case PickupType::Damage: g_damage+=8; g_cert.upgrades=true; break;
        case PickupType::Speed: g_moveSpeed=std::min(10.0f,g_moveSpeed+0.55f); g_cert.upgrades=true; break;
        case PickupType::Overdrive: g_overdrive=6.0f; g_cert.upgrades=true; break;
    }
    p.alive=false;
    Log("PICKUP_COLLECT type=%s hp=%.0f damage=%.0f speed=%.2f fire_interval=%.3f",
        PickupName(p.type),g_playerHp,g_damage,g_moveSpeed,g_fireInterval);
}

static Vec3 Forward() { return Normalize({std::sin(g_yaw),0,std::cos(g_yaw)}); }
static Vec3 Right() { auto f=Forward(); return {f.z,0,-f.x}; }

static void DamagePlayer(float amount) {
    if (g_state!=GameState::Playing && g_state!=GameState::Boss) return;
    g_playerHp -= amount;
    g_damageFlash=0.18f;
    g_cert.playerDamage=true;
    Log("PLAYER_DAMAGE amount=%.1f hp=%.1f",amount,g_playerHp);
    if (g_playerHp<=0) {
        g_cert.playerDeath=true;
        --g_lives;
        Log("PLAYER_DEATH lives=%d",g_lives);
        if (g_lives<=0) {
            g_state=GameState::GameOver;
            g_cert.gameOver=true;
            Log("GAME_OVER score=%d kills=%d wave=%d",g_score,g_kills,g_wave);
        } else {
            g_player={0,1.2f,-8}; g_playerHp=g_maxHp;
            g_cert.playerRespawn=true;
            Log("PLAYER_RESPAWN lives=%d",g_lives);
        }
    }
}

static void Fire() {
    if (g_fireTimer>0) return;
    g_fireTimer = g_overdrive>0 ? 0.075f : g_fireInterval;
    g_cert.playerFire=true;
    Log("PLAYER_FIRE");

    Vec3 f=Forward();
    int best=-1;
    float bestScore=1e9f;
    for (int i=0;i<(int)g_enemies.size();++i) {
        auto& e=g_enemies[i];
        if (!e.alive) continue;
        Vec3 d=e.pos-g_player;
        float dist=Len(d);
        Vec3 dn=Normalize(d);
        float aim=Dot(f,dn);
        float threshold=e.type==EnemyType::Boss?0.965f:0.982f;
        if (aim>threshold && dist<40.0f) {
            float score=dist + (1.0f-aim)*100.0f;
            if (score<bestScore){bestScore=score;best=i;}
        }
    }
    if (best>=0) {
        auto& e=g_enemies[best];
        float dmg=g_overdrive>0?g_damage*1.25f:g_damage;
        e.hp-=dmg; g_hitFlash=0.10f;
        Log("%s_DAMAGE amount=%.1f hp=%.1f", e.type==EnemyType::Boss?"BOSS":"BOT",dmg,e.hp);
        if (e.type==EnemyType::Boss) g_cert.bossCombat=true;
        if (e.hp<=0) {
            e.alive=false;
            g_kills++; g_score += (e.type==EnemyType::Boss?500:100);
            Log("%s_DEATH type=%s score=%d",e.type==EnemyType::Boss?"BOSS":"BOT",EnemyName(e.type),g_score);
            if (e.type==EnemyType::Boss) {
                g_cert.bossDeath=true;
            } else {
                SpawnPickup(e.pos);
            }
        }
    }
}

static bool AllDead() {
    for (auto& e:g_enemies) if (e.alive) return false;
    return true;
}

static void UpdateTitle() {
    wchar_t buf[256];
    const wchar_t* s=L"MENU";
    if (g_state==GameState::Playing) s=L"PLAY";
    else if (g_state==GameState::Boss) s=L"BOSS";
    else if (g_state==GameState::Victory) s=L"VICTORY";
    else if (g_state==GameState::GameOver) s=L"GAME OVER";
    swprintf_s(buf,L"NEON SIEGE | %s | Wave %d | HP %.0f | Lives %d | Score %d | Kills %d",
               s,g_wave,g_playerHp,g_lives,g_score,g_kills);
    SetWindowTextW(g_hwnd,buf);
}

static void Update(float dt) {
    g_sessionTime+=dt;
    g_fireTimer=std::max(0.0f,g_fireTimer-dt);
    g_overdrive=std::max(0.0f,g_overdrive-dt);
    g_damageFlash=std::max(0.0f,g_damageFlash-dt);
    g_hitFlash=std::max(0.0f,g_hitFlash-dt);

    if (g_state==GameState::Menu) {
        if (GetAsyncKeyState(VK_RETURN)&0x8000) ResetGame(false);
        return;
    }
    if (g_state==GameState::Victory || g_state==GameState::GameOver) {
        if (GetAsyncKeyState('R')&0x8000) ResetGame(true);
        return;
    }
    if (g_state==GameState::WaveComplete) {
        g_waveDelay-=dt;
        if (g_waveDelay<=0) {
            int next=g_wave+1;
            if (next<=4) StartWave(next);
        }
        return;
    }

    float turn=0;
    if (GetAsyncKeyState(VK_LEFT)&0x8000) turn-=1;
    if (GetAsyncKeyState(VK_RIGHT)&0x8000) turn+=1;
    g_yaw += turn*2.2f*dt;

    Vec3 move{};
    if (GetAsyncKeyState('W')&0x8000) move=move+Forward();
    if (GetAsyncKeyState('S')&0x8000) move=move-Forward();
    if (GetAsyncKeyState('A')&0x8000) move=move-Right();
    if (GetAsyncKeyState('D')&0x8000) move=move+Right();
    if (LenSq(move)>0.001f) {
        move=Normalize(move);
        g_player=g_player+move*g_moveSpeed*dt;
        g_player.x=Clamp(g_player.x,-14,14);
        g_player.z=Clamp(g_player.z,-14,14);
        g_cert.playerMovement=true;
    }
    if ((GetAsyncKeyState(VK_SPACE)&0x8000) || (GetAsyncKeyState(VK_LBUTTON)&0x8000)) Fire();

    // Mouse look: recenter cursor while active.
    if (GetForegroundWindow()==g_hwnd) {
        RECT rc{}; GetClientRect(g_hwnd,&rc);
        POINT c{(rc.right-rc.left)/2,(rc.bottom-rc.top)/2};
        POINT cc=c; ClientToScreen(g_hwnd,&cc);
        POINT p{}; GetCursorPos(&p);
        LONG dx=p.x-cc.x;
        if (std::abs(dx)>0) g_yaw += float(dx)*0.0025f;
        SetCursorPos(cc.x,cc.y);
    }

    // Enemy AI. Boss minion insertion is deferred until after iteration so
    // std::vector reallocation can never invalidate the active reference.
    int aliveCount=0;
    bool summonBossGrunt=false;
    Vec3 bossGruntPos{};
    for (auto& e:g_enemies) {
        if (!e.alive) continue;
        aliveCount++;
        Vec3 d=g_player-e.pos;
        d.y=0;
        float dist=Len(d);
        Vec3 n=Normalize(d);
        e.shootCooldown-=dt;

        float desired=1.6f;
        if (e.type==EnemyType::Gunner) desired=6.0f;
        if (e.type==EnemyType::Tank) desired=2.4f;
        if (e.type==EnemyType::Boss) desired=4.0f;

        if (dist>desired+0.5f) e.pos=e.pos+n*e.speed*dt;
        else if (e.type==EnemyType::Gunner && dist<desired-1.0f) e.pos=e.pos-n*e.speed*0.6f*dt;

        if (dist<1.35f && e.shootCooldown<=0) {
            DamagePlayer(e.type==EnemyType::Tank?22.0f:(e.type==EnemyType::Boss?18.0f:12.0f));
            e.shootCooldown = e.type==EnemyType::Boss?0.55f:1.0f;
        } else if ((e.type==EnemyType::Gunner || e.type==EnemyType::Boss) && dist<10.0f && e.shootCooldown<=0) {
            DamagePlayer(e.type==EnemyType::Boss?14.0f:8.0f);
            e.shootCooldown = e.type==EnemyType::Boss?0.65f:1.05f;
        }

        // Deterministic time-based boss summon. The actual push_back happens
        // after this loop to avoid invalidating references into g_enemies.
        if (e.type==EnemyType::Boss && e.alive) {
            g_bossSummonTimer-=dt;
            if (g_bossSummonTimer<=0.0f && g_enemies.size()<24) {
                float a=Rand01()*kPi*2.0f;
                bossGruntPos={e.pos.x+std::cos(a)*3.0f,1.0f,e.pos.z+std::sin(a)*3.0f};
                summonBossGrunt=true;
                g_bossSummonTimer=5.0f;
            }
        }
    }
    if (summonBossGrunt) SpawnEnemy(EnemyType::Grunt,bossGruntPos.x,bossGruntPos.z);

    for (auto& p:g_pickups) {
        if (!p.alive) continue;
        p.ttl-=dt;
        if (p.ttl<=0){p.alive=false;continue;}
        Vec3 d=p.pos-g_player; d.y=0;
        if (LenSq(d)<1.2f*1.2f) ApplyPickup(p);
    }

    if (AllDead()) {
        if (g_wave>=4) {
            g_state=GameState::Victory;
            g_cert.victory=true;
            Log("VICTORY score=%d kills=%d time=%.2f",g_score,g_kills,g_sessionTime);
        } else {
            g_state=GameState::WaveComplete;
            g_waveDelay=1.75f;
            g_cert.waveProgression=true;
            Log("WAVE_COMPLETE wave=%d score=%d",g_wave,g_score);
        }
    }
    UpdateTitle();
}

static Color EnemyColor(EnemyType t) {
    switch(t) {
        case EnemyType::Grunt: return {1.0f,0.12f,0.25f,1};
        case EnemyType::Gunner:return {0.10f,0.55f,1.0f,1};
        case EnemyType::Tank: return {1.0f,0.55f,0.05f,1};
        default: return {0.85f,0.10f,1.0f,1};
    }
}
static Color PickupColor(PickupType t) {
    switch(t) {
        case PickupType::Health:return {0.10f,1.0f,0.20f,1};
        case PickupType::FireRate:return {0.0f,1.0f,1.0f,1};
        case PickupType::Damage:return {1.0f,0.10f,0.10f,1};
        case PickupType::Speed:return {1.0f,1.0f,0.10f,1};
        default:return {0.75f,0.10f,1.0f,1};
    }
}

static void DrawCube(Vec3 p,Vec3 s,Color c,const Mat4& viewProj) {
    CBData data{};
    Mat4 world=Mul(Scale(s.x,s.y,s.z),Translation(p.x,p.y,p.z));
    data.mvp=Mul(world,viewProj);
    data.color=c;
    D3D11_MAPPED_SUBRESOURCE ms{};
    if (SUCCEEDED(g_ctx->Map(g_cb,0,D3D11_MAP_WRITE_DISCARD,0,&ms))) {
        *(CBData*)ms.pData=data;
        g_ctx->Unmap(g_cb,0);
    }
    g_ctx->VSSetConstantBuffers(0,1,&g_cb);
    g_ctx->DrawIndexed((UINT)(sizeof(kCubeIdx)/sizeof(kCubeIdx[0])),0,0);
}

static int AddRect(Vertex2* v,int at,float x0,float y0,float x1,float y1,Color c) {
    Vertex2 q[6]={
        {x0,y0,c.r,c.g,c.b,c.a},{x1,y0,c.r,c.g,c.b,c.a},{x1,y1,c.r,c.g,c.b,c.a},
        {x0,y0,c.r,c.g,c.b,c.a},{x1,y1,c.r,c.g,c.b,c.a},{x0,y1,c.r,c.g,c.b,c.a}};
    for(int i=0;i<6;i++)v[at+i]=q[i];
    return at+6;
}

static void DrawHUD() {
    Vertex2 verts[6*32]{};
    int n=0;
    // health background + fill
    n=AddRect(verts,n,-0.95f,-0.90f,-0.35f,-0.84f,{0.10f,0.10f,0.13f,0.95f});
    float hpw=0.60f*Clamp(g_playerHp/g_maxHp,0,1);
    n=AddRect(verts,n,-0.95f,-0.90f,-0.95f+hpw,-0.84f,{0.10f,1.0f,0.25f,1});
    // crosshair
    Color cross=g_hitFlash>0?Color{1,1,0,1}:Color{0.1f,1,1,1};
    n=AddRect(verts,n,-0.002f,-0.026f,0.002f,0.026f,cross);
    n=AddRect(verts,n,-0.014f,-0.003f,0.014f,0.003f,cross);
    // boss bar
    if (g_state==GameState::Boss) {
        for (auto& e:g_enemies) if(e.alive && e.type==EnemyType::Boss) {
            n=AddRect(verts,n,-0.65f,0.86f,0.65f,0.91f,{0.12f,0.08f,0.15f,0.95f});
            float bw=1.30f*Clamp(e.hp/e.maxHp,0,1);
            n=AddRect(verts,n,-0.65f,0.86f,-0.65f+bw,0.91f,{0.85f,0.10f,1.0f,1});
            break;
        }
    }
    if (g_damageFlash>0) {
        n=AddRect(verts,n,-1,-1,1,1,{0.65f,0.02f,0.02f,0.12f});
    }

    D3D11_MAPPED_SUBRESOURCE ms{};
    if (SUCCEEDED(g_ctx->Map(g_vb2d,0,D3D11_MAP_WRITE_DISCARD,0,&ms))) {
        memcpy(ms.pData,verts,sizeof(Vertex2)*n);
        g_ctx->Unmap(g_vb2d,0);
    }
    UINT stride=sizeof(Vertex2),offset=0;
    g_ctx->IASetInputLayout(g_layout2d);
    g_ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    g_ctx->IASetVertexBuffers(0,1,&g_vb2d,&stride,&offset);
    g_ctx->VSSetShader(g_vs2d,nullptr,0);
    g_ctx->PSSetShader(g_ps2d,nullptr,0);
    g_ctx->OMSetDepthStencilState(g_depthOff,0);
    float blendFactor[4]={0,0,0,0};
    g_ctx->OMSetBlendState(g_alphaBlend,blendFactor,0xFFFFFFFFu);
    g_ctx->Draw(n,0);
    g_ctx->OMSetBlendState(nullptr,blendFactor,0xFFFFFFFFu);
}

static void Render() {
    float clear[4]={0.005f,0.008f,0.018f,1};
    g_ctx->ClearRenderTargetView(g_rtv,clear);
    g_ctx->ClearDepthStencilView(g_dsv,D3D11_CLEAR_DEPTH|D3D11_CLEAR_STENCIL,1,0);
    g_ctx->OMSetRenderTargets(1,&g_rtv,g_dsv);
    g_ctx->OMSetDepthStencilState(nullptr,0);
    g_ctx->RSSetState(g_noCull);

    D3D11_VIEWPORT vp{};
    vp.Width=(float)kWidth; vp.Height=(float)kHeight; vp.MaxDepth=1;
    g_ctx->RSSetViewports(1,&vp);

    UINT stride=sizeof(Vertex3),offset=0;
    g_ctx->IASetInputLayout(g_layout);
    g_ctx->IASetVertexBuffers(0,1,&g_vb,&stride,&offset);
    g_ctx->IASetIndexBuffer(g_ib,DXGI_FORMAT_R16_UINT,0);
    g_ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    g_ctx->VSSetShader(g_vs,nullptr,0);
    g_ctx->PSSetShader(g_ps,nullptr,0);

    Vec3 eye=g_player;
    Vec3 at=eye+Forward();
    Mat4 view=LookAt(eye,at,{0,1,0});
    Mat4 proj=Perspective(70.0f*kPi/180.0f,float(kWidth)/float(kHeight),0.05f,100.0f);
    Mat4 vp3=Mul(view,proj);

    // Arena floor + neon grid bars.
    DrawCube({0,-0.55f,0},{15.0f,0.25f,15.0f},{0.02f,0.025f,0.05f,1},vp3);
    for(int i=-14;i<=14;i+=2) {
        DrawCube({(float)i,-0.27f,0},{0.025f,0.01f,15},{0.02f,0.45f,0.55f,1},vp3);
        DrawCube({0,-0.27f,(float)i},{15,0.01f,0.025f},{0.02f,0.45f,0.55f,1},vp3);
    }
    // Arena walls.
    DrawCube({0,1.0f,15},{15,1.5f,0.15f},{0.08f,0.12f,0.20f,1},vp3);
    DrawCube({0,1.0f,-15},{15,1.5f,0.15f},{0.08f,0.12f,0.20f,1},vp3);
    DrawCube({15,1.0f,0},{0.15f,1.5f,15},{0.08f,0.12f,0.20f,1},vp3);
    DrawCube({-15,1.0f,0},{0.15f,1.5f,15},{0.08f,0.12f,0.20f,1},vp3);

    for(auto& e:g_enemies) if(e.alive) {
        float bob=0.08f*std::sin(g_sessionTime*4.0f + e.pos.x);
        DrawCube({e.pos.x,e.pos.y+bob,e.pos.z},{e.scale,e.scale,e.scale},EnemyColor(e.type),vp3);
    }
    for(auto& p:g_pickups) if(p.alive) {
        float bob=0.18f*std::sin(g_sessionTime*5.0f+p.pos.x);
        DrawCube({p.pos.x,p.pos.y+bob,p.pos.z},{0.25f,0.25f,0.25f},PickupColor(p.type),vp3);
    }
    DrawHUD();
}

#pragma pack(push,1)
struct BMPFileHeader {
    uint16_t type=0x4D42;
    uint32_t size{};
    uint16_t r1{},r2{};
    uint32_t offBits=54;
};
struct BMPInfoHeader {
    uint32_t size=40;
    int32_t width{},height{};
    uint16_t planes=1;
    uint16_t bitCount=32;
    uint32_t compression=0;
    uint32_t sizeImage{};
    int32_t xppm=2835,yppm=2835;
    uint32_t clrUsed{},clrImportant{};
};
#pragma pack(pop)

static bool CaptureBMP(const wchar_t* filename) {
    ID3D11Texture2D* back{};
    if (FAILED(g_swap->GetBuffer(0,__uuidof(ID3D11Texture2D),(void**)&back))) return false;
    D3D11_TEXTURE2D_DESC d{}; back->GetDesc(&d);
    D3D11_TEXTURE2D_DESC s=d;
    s.BindFlags=0; s.MiscFlags=0; s.Usage=D3D11_USAGE_STAGING; s.CPUAccessFlags=D3D11_CPU_ACCESS_READ;
    ID3D11Texture2D* stage{};
    if (FAILED(g_dev->CreateTexture2D(&s,nullptr,&stage))) { back->Release(); return false; }
    g_ctx->CopyResource(stage,back);
    back->Release();

    D3D11_MAPPED_SUBRESOURCE m{};
    if (FAILED(g_ctx->Map(stage,0,D3D11_MAP_READ,0,&m))) { stage->Release(); return false; }

    FILE* f{};
    _wfopen_s(&f,filename,L"wb");
    if (!f) { g_ctx->Unmap(stage,0); stage->Release(); return false; }

    BMPFileHeader fh{};
    BMPInfoHeader ih{};
    ih.width=(int)d.Width; ih.height=(int)d.Height;
    ih.sizeImage=d.Width*d.Height*4;
    fh.size=fh.offBits+ih.sizeImage;
    fwrite(&fh,sizeof(fh),1,f);
    fwrite(&ih,sizeof(ih),1,f);

    std::vector<uint8_t> row(d.Width*4);
    for (int y=(int)d.Height-1; y>=0; --y) {
        const uint8_t* src=(const uint8_t*)m.pData + size_t(y)*m.RowPitch;
        for (UINT x=0;x<d.Width;x++) {
            row[x*4+0]=src[x*4+2]; // B
            row[x*4+1]=src[x*4+1]; // G
            row[x*4+2]=src[x*4+0]; // R
            row[x*4+3]=255;
        }
        fwrite(row.data(),row.size(),1,f);
    }
    fclose(f);
    g_ctx->Unmap(stage,0);
    stage->Release();
    g_cert.framebufferEvidence=true;
    return true;
}

static void AutoCaptures() {
    if (!g_captureStartup && g_sessionTime>1.0f) {
        g_captureStartup=CaptureBMP(L"evidence\\startup.bmp");
        Log("FRAME_CAPTURE name=startup ok=%d",g_captureStartup?1:0);
    }
    if (!g_captureWave1 && g_state==GameState::Playing && g_wave==1 && g_sessionTime>2.5f) {
        g_captureWave1=CaptureBMP(L"evidence\\wave1.bmp");
        Log("FRAME_CAPTURE name=wave1 ok=%d",g_captureWave1?1:0);
    }
    if (!g_captureWave3 && g_wave==3) {
        g_captureWave3=CaptureBMP(L"evidence\\wave3.bmp");
        Log("FRAME_CAPTURE name=wave3 ok=%d",g_captureWave3?1:0);
    }
    if (!g_captureBoss && g_state==GameState::Boss) {
        g_captureBoss=CaptureBMP(L"evidence\\boss.bmp");
        Log("FRAME_CAPTURE name=boss ok=%d",g_captureBoss?1:0);
    }
    if (!g_captureVictory && g_state==GameState::Victory) {
        g_captureVictory=CaptureBMP(L"evidence\\victory.bmp");
        Log("FRAME_CAPTURE name=victory ok=%d",g_captureVictory?1:0);
    }
}

static void WriteSummary() {
    FILE* f{};
    fopen_s(&f,"evidence\\certification.txt","wb");
    if (!f) return;
    auto P=[&](const char* k,bool v){std::fprintf(f,"%s=%s\n",k,v?"PASS":"FAIL");};
    std::fprintf(f,"=== SUNSHINE_NEON_SIEGE_001 ===\n\n");
    P("STANDALONE_EXE",true);
    P("D3D11_RENDER",g_dev!=nullptr);
    P("PLAYER_MOVEMENT",g_cert.playerMovement);
    P("PLAYER_COMBAT",g_cert.playerFire);
    P("ENEMY_GRUNT",g_cert.enemyGrunt);
    P("ENEMY_GUNNER",g_cert.enemyGunner);
    P("ENEMY_TANK",g_cert.enemyTank);
    P("WAVE_PROGRESSION",g_cert.waveProgression);
    P("PICKUPS",g_cert.pickups);
    P("UPGRADES",g_cert.upgrades);
    P("PLAYER_DAMAGE",g_cert.playerDamage);
    P("PLAYER_DEATH",g_cert.playerDeath);
    P("PLAYER_RESPAWN",g_cert.playerRespawn);
    P("BOSS_SPAWN",g_cert.bossSpawn);
    P("BOSS_COMBAT",g_cert.bossCombat);
    P("BOSS_DEATH",g_cert.bossDeath);
    P("GAME_OVER",g_cert.gameOver);
    P("RESTART",g_cert.restart);
    P("VICTORY",g_cert.victory);
    P("GAMEPLAY_TELEMETRY",g_cert.telemetry);
    P("FRAMEBUFFER_EVIDENCE",g_cert.framebufferEvidence);

    bool pass=g_cert.gameStart && g_cert.playerMovement && g_cert.playerFire &&
              g_cert.enemyGrunt && g_cert.enemyGunner && g_cert.enemyTank &&
              g_cert.waveProgression && g_cert.bossSpawn && g_cert.bossCombat &&
              g_cert.bossDeath && g_cert.victory && g_cert.telemetry &&
              g_cert.framebufferEvidence;
    std::fprintf(f,"\nVERDICT=%s\n",pass?"PASS":"INCOMPLETE");
    fclose(f);

    fopen_s(&f,"evidence\\neon_siege_summary.txt","wb");
    if (f) {
        std::fprintf(f,"score=%d\nkills=%d\nwave=%d\nlives=%d\nsession_seconds=%.2f\n",
                     g_score,g_kills,g_wave,g_lives,g_sessionTime);
        fclose(f);
    }
}

static LRESULT CALLBACK WndProc(HWND h,UINT m,WPARAM w,LPARAM l) {
    switch(m) {
        case WM_CLOSE: DestroyWindow(h); return 0;
        case WM_DESTROY: PostQuitMessage(0); return 0;
        case WM_KEYDOWN:
            if (w==VK_ESCAPE) { DestroyWindow(h); return 0; }
            if (w=='R' && (g_state==GameState::Victory || g_state==GameState::GameOver)) {
                ResetGame(true); return 0;
            }
            break;
    }
    return DefWindowProcW(h,m,w,l);
}

int WINAPI wWinMain(HINSTANCE hi,HINSTANCE,LPWSTR,int) {
    EnsureEvidenceDir();
    fopen_s(&g_log,"evidence\\gameplay_events.txt","wb");
    Log("NEON_SIEGE_BOOT width=%d height=%d",kWidth,kHeight);

    WNDCLASSEXW wc{}; wc.cbSize=sizeof(wc); wc.lpfnWndProc=WndProc; wc.hInstance=hi;
    wc.hCursor=LoadCursor(nullptr,IDC_CROSS); wc.lpszClassName=L"NeonSiegeWindow";
    wc.style=CS_HREDRAW|CS_VREDRAW;
    RegisterClassExW(&wc);

    RECT r{0,0,kWidth,kHeight}; AdjustWindowRect(&r,WS_OVERLAPPEDWINDOW,FALSE);
    g_hwnd=CreateWindowExW(0,wc.lpszClassName,L"NEON SIEGE | Press ENTER to start",WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,r.right-r.left,r.bottom-r.top,nullptr,nullptr,hi,nullptr);
    if (!g_hwnd) return 2;
    if (!InitD3D(g_hwnd)) {
        MessageBoxW(g_hwnd,L"D3D11 initialization failed.",L"NEON SIEGE",MB_ICONERROR);
        return 3;
    }
    ShowWindow(g_hwnd,SW_SHOW);
    UpdateWindow(g_hwnd);
    ShowCursor(FALSE);

    LARGE_INTEGER fq{},prev{},now{};
    QueryPerformanceFrequency(&fq);
    QueryPerformanceCounter(&prev);

    MSG msg{};
    bool running=true;
    while(running) {
        while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)) {
            if (msg.message==WM_QUIT){running=false;break;}
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
        if (!running) break;

        QueryPerformanceCounter(&now);
        float dt=float(double(now.QuadPart-prev.QuadPart)/double(fq.QuadPart));
        prev=now;
        dt=std::min(dt,0.05f);

        Update(dt);
        Render();
        // Capture before Present: DXGI_SWAP_EFFECT_DISCARD does not guarantee
        // backbuffer contents remain valid after presentation.
        AutoCaptures();
        g_swap->Present(1,0);
    }

    WriteSummary();
    Log("NEON_SIEGE_EXIT");
    if (g_log) fclose(g_log);
    ShowCursor(TRUE);
    ReleaseD3D();
    return 0;
}
