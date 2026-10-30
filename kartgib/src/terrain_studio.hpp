#pragma once

struct StudioBrush {
    int mode = 0;
    float radius = 8.0f;
    float strength = 6.0f;
    float falloff = 2.0f;
};

bool studioCreate(const char* name);
void studioResetProps();
const char* studioName();
void studioGenerateSmooth();
void studioSetBrush(int mode, float radius, float strength, float falloff);
const StudioBrush& studioBrush();
void studioBrushEnable(bool on);
bool studioBrushOn();
void studioBegin();
int studioStamp(float x, float z);
void studioEnd();
int studioStroke(float x, float z);
bool terrainUndo();
bool terrainRedo();
bool studioSave(const char* path);
bool studioLoad(const char* path);
float studioHeight(float x, float z);
int studioSelect(int id);
int studioSelected();
bool studioTransform(int id, float x, float y, float z, float yaw, float scale);
bool studioObject(int id, float& x, float& y, float& z, float& yaw, float& scale);
void studioPlay(bool on);
bool studioPlaying();
bool studioAsk(const char* text);
int studioDirtyVerts();
int studioResolution();
float studioHash();
float* studioHeights();
inline int gStudioClock = 1;
inline int gHeightSeq = 0;
inline int gXformSeq = 0;
bool studioUndoXform();
void studioCamera(float view[16], float proj[16], int width, int height);
bool studioProject(const float view[16], const float proj[16], float x, float y, float z,
    int width, int height, int& px, int& py);
int studioStampScreen(const float view[16], const float proj[16], int width, int height, int mx, int my);
int studioStrokeScreen(const float view[16], const float proj[16], int width, int height, int mx, int my);
class Win32Window;
void studioPointer(Win32Window& window, const float view[16], const float proj[16], int x, int y, bool clicked, bool released);
