/*
At the top of complete_server.cpp / tool_server.cpp request dispatch:

    char nativeJson[65536];
    uint32_t nativeStatus = 0;
    if (RawrNative_HandleHttp(method.c_str(), path.c_str(), body.c_str(),
                             nativeJson, sizeof(nativeJson), &nativeStatus)) {
        sendJson(nativeStatus, nativeJson);
        return;
    }

Beside EACH real route registration:

    RawrNative_RegisterRouteAttachment("/api/chat", RN_HTTP_POST);
    RawrNative_RegisterRouteAttachment("/api/status", RN_HTTP_GET);

Do not bulk-mark routes. Engine Explorer treats ATTACHED as a runtime witness.
*/
