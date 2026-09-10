// rawr_native_http_adapter.cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "rawr_native_e2e_abi.h"
#include "runtime_gguf_disk_resolve.h"

extern "C" uint32_t RawrNative_RegisterRuntimeModelSrc(
    const char* model_name, const RawrNativeProfileInfo* info,
    const char* source);

/* G3_IDE_MODEL_PROFILE_ADMISSION_001: no name seed table.
 * Admission is GGUF header KV via runtime_gguf_meta / disk register. */
static void seed_default_runtime_models(void) {
    static volatile LONG once = 0;
    (void)InterlockedCompareExchange(&once, 1, 0);
}

struct RouteDef {
    const char* path;
    uint32_t method_mask;
    volatile LONG attached_mask;
};

static RouteDef g_routes[] = {
    {"/api/agents", RN_HTTP_GET, 0},
    {"/api/agents/explain", RN_HTTP_GET, 0},
    {"/api/agents/explain/stats", RN_HTTP_GET, 0},
    {"/api/agents/history", RN_HTTP_GET, 0},
    {"/api/agents/replay", RN_HTTP_POST, 0},
    {"/api/agents/status", RN_HTTP_GET, 0},
    {"/api/backends", RN_HTTP_GET, 0},
    {"/api/backends/status", RN_HTTP_GET, 0},
    {"/api/backends/use", RN_HTTP_POST, 0},
    {"/api/chain", RN_HTTP_POST, 0},
    {"/api/chat", RN_HTTP_POST, 0},
    {"/api/cli", RN_HTTP_POST, 0},
    {"/api/extensions", RN_HTTP_GET, 0},
    {"/api/extensions/activate", RN_HTTP_POST, 0},
    {"/api/extensions/deactivate", RN_HTTP_POST, 0},
    {"/api/extensions/disable", RN_HTTP_POST, 0},
    {"/api/extensions/enable", RN_HTTP_POST, 0},
    {"/api/extensions/export", RN_HTTP_GET, 0},
    {"/api/extensions/host/kill", RN_HTTP_POST, 0},
    {"/api/extensions/host/logs", RN_HTTP_GET, 0},
    {"/api/extensions/host/restart", RN_HTTP_POST, 0},
    {"/api/extensions/host/status", RN_HTTP_GET, 0},
    {"/api/extensions/import", RN_HTTP_POST, 0},
    {"/api/extensions/install", RN_HTTP_POST, 0},
    {"/api/extensions/load-vsix", RN_HTTP_POST, 0},
    {"/api/extensions/marketplace/*", RN_HTTP_ANY, 0},
    {"/api/extensions/marketplace/search", RN_HTTP_POST, 0},
    {"/api/extensions/scan", RN_HTTP_POST, 0},
    {"/api/extensions/uninstall", RN_HTTP_POST, 0},
    {"/api/failures", RN_HTTP_GET, 0},
    {"/api/generate", RN_HTTP_POST, 0},
    {"/api/hotpatch/*", RN_HTTP_ANY, 0},
    {"/api/hotpatch/apply", RN_HTTP_POST, 0},
    {"/api/hotpatch/revert", RN_HTTP_POST, 0},
    {"/api/hotpatch/status", RN_HTTP_GET, 0},
    {"/api/hotpatch/toggle", RN_HTTP_POST, 0},
    {"/api/policies", RN_HTTP_GET, 0},
    {"/api/policies/apply", RN_HTTP_POST, 0},
    {"/api/policies/export", RN_HTTP_GET, 0},
    {"/api/policies/heuristics", RN_HTTP_GET, 0},
    {"/api/policies/import", RN_HTTP_POST, 0},
    {"/api/policies/reject", RN_HTTP_POST, 0},
    {"/api/policies/stats", RN_HTTP_GET, 0},
    {"/api/policies/suggestions", RN_HTTP_GET, 0},
    {"/api/read-file", RN_HTTP_POST, 0},
    {"/api/status", RN_HTTP_GET, 0},
    {"/api/subagent", RN_HTTP_POST, 0},
    {"/api/swarm", RN_HTTP_POST, 0},
    {"/api/tags", RN_HTTP_GET, 0},
    {"/api/tool", RN_HTTP_POST, 0},
    {"/ask", RN_HTTP_POST, 0},
    {"/complete", RN_HTTP_POST, 0},
    {"/complete/stream", RN_HTTP_POST, 0},
    {"/gui", RN_HTTP_GET, 0},
    {"/health", RN_HTTP_GET, 0},
    {"/metrics", RN_HTTP_GET, 0},
    {"/models", RN_HTTP_GET, 0},
    {"/status", RN_HTTP_GET, 0},
    {"/v1/chat/completions", RN_HTTP_POST, 0},
    {"/v1/models", RN_HTTP_GET, 0}
};
static const uint32_t g_route_count =
    (uint32_t)(sizeof(g_routes)/sizeof(g_routes[0]));

struct RuntimeModelSlot {
    volatile LONG active;
    char name[256];
    char source[32];
    RawrNativeProfileInfo info;
};
static RuntimeModelSlot g_runtime_models[32]{};

extern "C" uint32_t RawrNative_RegisterRuntimeModelSrc(
    const char* model_name,const RawrNativeProfileInfo* info,
    const char* source)
{
    if (!model_name || !*model_name || !info) return 1;
    const char* src =
        (source && *source) ? source : "model_metadata";
    for (uint32_t i=0;i<32;++i) {
        if (g_runtime_models[i].active &&
            strcmp(g_runtime_models[i].name,model_name)==0) {
            g_runtime_models[i].info=*info;
            strncpy_s(g_runtime_models[i].source,
                      sizeof(g_runtime_models[i].source),
                      src,_TRUNCATE);
            return 0;
        }
    }
    for (uint32_t i=0;i<32;++i) {
        if (InterlockedCompareExchange(
                &g_runtime_models[i].active,1,0)==0) {
            strncpy_s(g_runtime_models[i].name,
                      sizeof(g_runtime_models[i].name),
                      model_name,_TRUNCATE);
            strncpy_s(g_runtime_models[i].source,
                      sizeof(g_runtime_models[i].source),
                      src,_TRUNCATE);
            g_runtime_models[i].info=*info;
            return 0;
        }
    }
    return 2;
}

extern "C" uint32_t RawrNative_RegisterRuntimeModel(
    const char* model_name,const RawrNativeProfileInfo* info)
{
    return RawrNative_RegisterRuntimeModelSrc(
        model_name, info, "model_metadata");
}

extern "C" uint32_t RawrNative_UnregisterRuntimeModel(const char* model_name)
{
    if (!model_name) return 1;
    for (uint32_t i=0;i<32;++i) {
        if (g_runtime_models[i].active &&
            strcmp(g_runtime_models[i].name,model_name)==0) {
            InterlockedExchange(&g_runtime_models[i].active,0);
            g_runtime_models[i].name[0]=0;
            return 0;
        }
    }
    return 2;
}

static int find_runtime_model(
    const char* model_name,RawrNativeProfileInfo* out,
    char* src_out,size_t src_cap)
{
    if (!model_name || !out) return 0;
    for (uint32_t i=0;i<32;++i) {
        if (g_runtime_models[i].active &&
            strcmp(g_runtime_models[i].name,model_name)==0) {
            *out=g_runtime_models[i].info;
            if (src_out && src_cap)
                strncpy_s(src_out,src_cap,
                          g_runtime_models[i].source[0]
                              ? g_runtime_models[i].source
                              : "model_metadata",
                          _TRUNCATE);
            return 1;
        }
    }
    return 0;
}

static uint32_t runtime_model_count()
{
    uint32_t n=0;
    for (uint32_t i=0;i<32;++i) if (g_runtime_models[i].active) ++n;
    return n;
}

static int streq(const char* a,const char* b) {
    return a && b && strcmp(a,b)==0;
}
static int starts(const char* a,const char* p) {
    return a && p && strncmp(a,p,strlen(p))==0;
}
static int route_match(const char* pattern,const char* path) {
    if (!pattern || !path) return 0;
    const char* star=strchr(pattern,'*');
    if (!star) return strcmp(pattern,path)==0;
    return strncmp(pattern,path,(size_t)(star-pattern))==0;
}
static int json_find_key(const char* body,const char* key,const char** value) {
    if (!body || !key || !value) return 0;
    char needle[96];
    _snprintf_s(needle,sizeof(needle),_TRUNCATE,"\"%s\"",key);
    const char* p=strstr(body,needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p==' '||*p=='\t'||*p=='\r'||*p=='\n') ++p;
    if (*p!=':') return 0;
    ++p;
    while (*p==' '||*p=='\t'||*p=='\r'||*p=='\n') ++p;
    *value=p;
    return 1;
}
static uint32_t json_u32(const char* body,const char* key,uint32_t defv) {
    const char* p=nullptr;
    if (!json_find_key(body,key,&p)) return defv;
    return (uint32_t)strtoul(p,nullptr,10);
}
static int json_bool(const char* body,const char* key,int defv) {
    const char* p=nullptr;
    if (!json_find_key(body,key,&p)) return defv;
    if (strncmp(p,"true",4)==0) return 1;
    if (strncmp(p,"false",5)==0) return 0;
    return defv;
}
static int json_string(const char* body,const char* key,char* out,size_t cap) {
    const char* p=nullptr;
    if (!out || cap<2 || !json_find_key(body,key,&p) || *p!='"') return 0;
    ++p;
    size_t n=0;
    while (*p && *p!='"' && n+1<cap) {
        if (*p=='\\' && p[1]) {
            ++p;
            switch (*p) {
                case 'n': out[n++]='\n'; break;
                case 'r': out[n++]='\r'; break;
                case 't': out[n++]='\t'; break;
                default: out[n++]=*p; break;
            }
            ++p;
            continue;
        }
        out[n++]=*p++;
    }
    out[n]=0;
    return *p=='"';
}
static void parse_custom_csv(const char* body,uint64_t mask[4]) {
    char csv[1024]{};
    if (!json_string(body,"hop_custom_csv",csv,sizeof(csv))) return;
    char* p=csv;
    while (*p) {
        while (*p==' '||*p=='\t'||*p==',') ++p;
        if (!*p) break;
        char* end=nullptr;
        unsigned long v=strtoul(p,&end,10);
        if (end==p) break;
        if (v<256) mask[v>>6] |= (1ull << (v&63));
        p=end;
    }
}
static int write_json(
    char* out,uint32_t cap,uint32_t* hs,uint32_t status,const char* fmt,...)
{
    if (hs) *hs=status;
    if (!out || cap==0) return 0;
    va_list ap;
    va_start(ap,fmt);
    int n=_vsnprintf_s(out,cap,_TRUNCATE,fmt,ap);
    va_end(ap);
    return n>=0;
}

extern "C" void RawrNative_RegisterRouteAttachment(
    const char* path,uint32_t method_mask)
{
    if (!path) return;
    for (uint32_t i=0;i<g_route_count;++i) {
        if (route_match(g_routes[i].path,path) ||
            route_match(path,g_routes[i].path)) {
            InterlockedOr(&g_routes[i].attached_mask,(LONG)method_mask);
        }
    }
}

static RouteDef* find_route(const char* path) {
    for (uint32_t i=0;i<g_route_count;++i)
        if (route_match(g_routes[i].path,path)) return &g_routes[i];
    return nullptr;
}

static int write_routes(char* out,uint32_t cap,uint32_t* hs) {
    uint32_t pos=0;
    int n=_snprintf_s(out+pos,cap-pos,_TRUNCATE,
        "{\"ok\":true,\"route_count\":%u,\"routes\":[",g_route_count);
    if (n<0) return 0;
    pos+=(uint32_t)n;
    for (uint32_t i=0;i<g_route_count && pos+128<cap;++i) {
        const char* method =
            g_routes[i].method_mask==RN_HTTP_GET ? "GET" :
            g_routes[i].method_mask==RN_HTTP_POST ? "POST" : "ANY";
        n=_snprintf_s(out+pos,cap-pos,_TRUNCATE,
            "%s{\"path\":\"%s\",\"method\":\"%s\",\"attached\":%s}",
            i?",":"",g_routes[i].path,method,
            g_routes[i].attached_mask?"true":"false");
        if (n<0) return 0;
        pos+=(uint32_t)n;
    }
    n=_snprintf_s(out+pos,cap-pos,_TRUNCATE,"%s","]}");
    if (n<0) return 0;
    if (hs) *hs=200;
    return 1;
}

static int write_receipt(
    uint64_t id,char* out,uint32_t cap,uint32_t* hs)
{
    RawrNativeReceipt r{};
    if (!id || RawrNative_ReceiptGet(id,&r)!=0) {
        return write_json(out,cap,hs,404,
            "{\"ok\":false,\"error\":\"receipt_not_found\",\"request_id\":%llu}",
            (unsigned long long)id);
    }
    return write_json(out,cap,hs,200,
        "{\"ok\":true,\"request_id\":%llu,\"profile_id\":%u,"
        "\"requested_flags\":%u,\"prepared_flags\":%u,"
        "\"engine_applied_flags\":%u,\"backend_id\":%u,"
        "\"engine_status\":%d,\"generated_tokens\":%llu,"
        "\"qpc_begin\":%llu,\"qpc_engine_enter\":%llu,"
        "\"qpc_first_token\":%llu,\"qpc_end\":%llu}",
        (unsigned long long)r.request_id,r.profile_id,
        r.requested_flags,r.prepared_flags,r.engine_applied_flags,
        r.backend_id,r.engine_status,
        (unsigned long long)r.generated_tokens,
        (unsigned long long)r.qpc_begin,
        (unsigned long long)r.qpc_engine_enter,
        (unsigned long long)r.qpc_first_token,
        (unsigned long long)r.qpc_end);
}

extern "C" int RawrNative_HandleHttp(
    const char* method,const char* path,const char* body,
    char* out,uint32_t cap,uint32_t* hs)
{
    if (!method || !path || !out || cap==0) return 0;
    seed_default_runtime_models();

    if (streq(method,"GET") && streq(path,"/api/native/capabilities")) {
        const uint64_t caps=RawrNative_ModelBridgeCapabilities();
        return write_json(out,cap,hs,200,
            "{\"ok\":true,\"native_bridge\":true,"
            "\"model_bridge_caps\":%llu,\"safe_decode\":true,"
            "\"tensor_hop\":true,\"execution_receipts\":true,"
            "\"route_registry\":true,\"route_count\":%u,"
            "\"runtime_model_count\":%u}",
            (unsigned long long)caps,g_route_count,runtime_model_count());
    }

    if (streq(method,"GET") && streq(path,"/api/native/routes"))
        return write_routes(out,cap,hs);

    if (streq(method,"POST") && streq(path,"/api/native/route/probe")) {
        char route[256]{};
        if (!json_string(body,"path",route,sizeof(route)))
            return write_json(out,cap,hs,400,
                "{\"ok\":false,\"error\":\"missing_path\"}");
        RouteDef* r=find_route(route);
        if (!r)
            return write_json(out,cap,hs,404,
                "{\"ok\":false,\"path\":\"%s\",\"declared\":false,"
                "\"attached\":false}",route);
        const char* rm =
            r->method_mask==RN_HTTP_GET ? "GET" :
            r->method_mask==RN_HTTP_POST ? "POST" : "ANY";
        return write_json(out,cap,hs,200,
            "{\"ok\":true,\"path\":\"%s\",\"declared\":true,"
            "\"method\":\"%s\",\"attached\":%s}",
            r->path,rm,r->attached_mask?"true":"false");
    }

    if (streq(method,"GET") && streq(path,"/api/native/model-bridge/status")) {
        const uint64_t caps=RawrNative_ModelBridgeCapabilities();
        return write_json(out,cap,hs,200,
            "{\"ok\":true,\"capabilities\":%llu}",
            (unsigned long long)caps);
    }

    if (streq(method,"GET") && streq(path,"/api/native/safe-decode/status"))
        return write_json(out,cap,hs,200,
            "{\"ok\":true,\"authority\":\"x64_masm\","
            "\"phase\":\"request_normalization\","
            "\"execution_proof\":\"receipt_required\"}");

    if (streq(method,"GET") && streq(path,"/api/native/tensor-hop/status"))
        return write_json(out,cap,hs,200,
            "{\"ok\":true,\"authority\":\"x64_masm\","
            "\"strategies\":[\"auto\",\"even\",\"front\",\"back\",\"custom\"],"
            "\"auto_requires_engine_planner\":true,"
            "\"execution_proof\":\"receipt_required\"}");

    if (streq(method,"POST") && streq(path,"/api/native/runtime/register")) {
        char model[256]{};
        char gguf_path[1024]{};
        if (!json_string(body,"model",model,sizeof(model)))
            return write_json(out,cap,hs,400,
                "{\"ok\":false,\"error\":\"missing_model\"}");
        if (!json_string(body,"path",gguf_path,sizeof(gguf_path)))
            (void)json_string(body,"model_path",gguf_path,sizeof(gguf_path));
        RawrNativeProfileInfo profile{};
        uint32_t rc = 1;
        if (gguf_path[0])
            rc = RawrNative_RegisterRuntimeGgufPathEx(
                model, gguf_path, &profile);
        if (rc == 3)
            return write_json(out,cap,hs,422,
                "{\"ok\":false,\"error\":\"model_metadata_unsupported\","
                "\"model\":\"%s\"}", model);
        if (rc != 0)
            rc = RawrNative_TryRegisterRuntimeGgufFromDisk(model, &profile);
        if (rc == 3)
            return write_json(out,cap,hs,422,
                "{\"ok\":false,\"error\":\"model_metadata_unsupported\","
                "\"model\":\"%s\"}", model);
        if (rc != 0)
            return write_json(out,cap,hs,404,
                "{\"ok\":false,\"error\":\"model_profile_not_found\","
                "\"model\":\"%s\"}", model);
        return write_json(out,cap,hs,200,
            "{\"ok\":true,\"model\":\"%s\",\"profile_id\":%u,"
            "\"profile_source\":\"model_metadata\","
            "\"num_layers\":%u,\"context_max\":%u,\"ram_mb\":%u}",
            model, profile.profile_id, profile.num_layers,
            profile.context_max, profile.ram_mb);
    }

    if (streq(method,"POST") && streq(path,"/api/native/generation/prepare")) {
        char model[256]{};
        char gguf_path[1024]{};
        char profile_source[32] = "model_bridge";
        if (!json_string(body,"model",model,sizeof(model)))
            return write_json(out,cap,hs,400,
                "{\"ok\":false,\"error\":\"missing_model\"}");
        if (!json_string(body,"path",gguf_path,sizeof(gguf_path)))
            (void)json_string(body,"model_path",gguf_path,sizeof(gguf_path));

        RawrNativeProfileInfo profile{};
        int runtime_profile=find_runtime_model(
            model,&profile,profile_source,sizeof(profile_source));
        if (!runtime_profile && gguf_path[0]) {
            uint32_t rc = RawrNative_RegisterRuntimeGgufPathEx(
                model, gguf_path, &profile);
            if (rc == 3)
                return write_json(out,cap,hs,422,
                    "{\"ok\":false,\"error\":\"model_metadata_unsupported\","
                    "\"model\":\"%s\"}", model);
            if (rc == 0) {
                runtime_profile=1;
                strncpy_s(profile_source,sizeof(profile_source),
                          "model_metadata",_TRUNCATE);
            }
        }
        if (!runtime_profile &&
            RawrNative_ModelBridgeResolveProfile(model,&profile)!=0) {
            uint32_t rc = RawrNative_TryRegisterRuntimeGgufFromDisk(
                model,&profile);
            if (rc == 3)
                return write_json(out,cap,hs,422,
                    "{\"ok\":false,\"error\":\"model_metadata_unsupported\","
                    "\"model\":\"%s\"}", model);
            if (rc == 0) {
                runtime_profile=1;
                strncpy_s(profile_source,sizeof(profile_source),
                          "model_metadata",_TRUNCATE);
            } else {
                return write_json(out,cap,hs,404,
                    "{\"ok\":false,\"error\":\"model_profile_not_found\","
                    "\"model\":\"%s\","
                    "\"detail\":\"GGUF not found under F:/G:/D:/C:/"
                    "OllamaModels or exe\\\\models; place file or call "
                    "/api/native/runtime/register with path, or "
                    "RawrNative_RegisterRuntimeGgufPath / "
                    "RawrNative_RegisterRuntimeModel\"}",model);
            }
        }
        if (!runtime_profile)
            strncpy_s(profile_source,sizeof(profile_source),
                      "model_bridge",_TRUNCATE);

        RawrNativePolicyRequest q{};
        q.context=json_u32(body,"context",8192);
        q.max_tokens=json_u32(body,"max_tokens",512);
        q.temperature_milli=json_u32(body,"temperature_milli",700);
        q.top_p_milli=json_u32(body,"top_p_milli",900);
        q.top_k=json_u32(body,"top_k",40);
        q.stream=(uint32_t)json_bool(body,"stream",1);

        q.safe_enabled=(uint32_t)json_bool(body,"safe_enabled",1);
        q.safe_context=json_u32(body,"safe_context",3072);
        q.safe_max_tokens=json_u32(body,"safe_max_tokens",128);
        q.safe_temperature_milli=
            json_u32(body,"safe_temperature_milli",300);
        q.safe_top_p_milli=json_u32(body,"safe_top_p_milli",900);
        q.safe_top_k=json_u32(body,"safe_top_k",40);

        q.hop_enabled=(uint32_t)json_bool(body,"hop_enabled",0);
        q.hop_strategy=json_u32(body,"hop_strategy",RN_HOP_AUTO);
        q.hop_skip_permille=json_u32(body,"hop_skip_permille",250);
        q.hop_keep_first=json_u32(body,"hop_keep_first",2);
        q.hop_keep_last=json_u32(body,"hop_keep_last",2);
        parse_custom_csv(body,q.hop_custom_mask);

        RawrNativePolicy policy{};
        if (RawrNative_NormalizePolicy(&profile,&q,&policy)!=0)
            return write_json(out,cap,hs,400,
                "{\"ok\":false,\"error\":\"policy_invalid\"}");

        uint32_t requested_flags=0;
        if (q.safe_enabled) requested_flags|=RN_POLICY_SAFE_PREPARED;
        if (q.hop_enabled) requested_flags|=RN_POLICY_HOP_PREPARED;

        const uint64_t id=RawrNative_ReceiptBegin(
            profile.profile_id,requested_flags,policy.flags);

        return write_json(out,cap,hs,200,
            "{\"ok\":true,\"request_id\":%llu,\"model\":\"%s\","
            "\"profile_source\":\"%s\","
            "\"profile_id\":%u,\"engine_mode\":%u,\"num_layers\":%u,"
            "\"policy\":{\"context\":%u,\"max_tokens\":%u,"
            "\"temperature_milli\":%u,\"top_p_milli\":%u,\"top_k\":%u,"
            "\"stream\":%s,\"flags\":%u,\"safe_prepared\":%s,"
            "\"hop_prepared\":%s,\"hop_needs_engine\":%s,"
            "\"hop_skip_count\":%u}}",
            (unsigned long long)id,model,profile_source,
            profile.profile_id,profile.engine_mode,profile.num_layers,
            policy.context,policy.max_tokens,policy.temperature_milli,
            policy.top_p_milli,policy.top_k,
            policy.stream?"true":"false",policy.flags,
            (policy.flags&RN_POLICY_SAFE_PREPARED)?"true":"false",
            (policy.flags&RN_POLICY_HOP_PREPARED)?"true":"false",
            (policy.flags&RN_POLICY_HOP_NEEDS_ENGINE)?"true":"false",
            policy.hop_skip_count);
    }

    if (streq(method,"GET") && starts(path,"/api/native/receipt/")) {
        const char* tail=path+strlen("/api/native/receipt/");
        uint64_t id = streq(tail,"latest")
            ? RawrNative_ReceiptLatestId()
            : _strtoui64(tail,nullptr,10);
        return write_receipt(id,out,cap,hs);
    }

    return 0;
}
