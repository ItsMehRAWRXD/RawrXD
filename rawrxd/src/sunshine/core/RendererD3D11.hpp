#pragma once

#include <d3d11.h>
#include <stdint.h>
#include "math.hpp"
#include "WindowWin32.hpp"

namespace Sunshine {

class Renderer {
public:
    bool initialize(Window* window);
    void shutdown();
    void resize(int width, int height);
    void beginFrame(float r, float g, float b);
    void endFrame();
    void present();

    ID3D11Device* getDevice() const { return m_device; }
    ID3D11DeviceContext* getContext() const { return m_context; }
    ID3D11RenderTargetView* getRenderTargetView() const { return m_rtv; }
    ID3D11DepthStencilView* getDepthStencilView() const { return m_dsv; }
    ID3D11DepthStencilState* getDepthStencilState() const { return m_depthStencilState; }

    struct Shader {
        ID3D11VertexShader* vs = nullptr;
        ID3D11PixelShader* ps = nullptr;
        ID3D11InputLayout* layout = nullptr;
        ID3DBlob* vsBlob = nullptr;
    };

    bool compileShader(const char* vsCode, const char* psCode, const D3D11_INPUT_ELEMENT_DESC* layout, uint32_t layoutCount, Shader* out);
    void releaseShader(Shader* shader);

    bool createVertexBuffer(const void* data, uint32_t size, uint32_t stride, ID3D11Buffer** out);
    bool createIndexBuffer(const void* data, uint32_t size, DXGI_FORMAT format, ID3D11Buffer** out);

    void setShader(const Shader* shader);
    void setVertexBuffer(ID3D11Buffer* vb, uint32_t stride);
    void setIndexBuffer(ID3D11Buffer* ib, DXGI_FORMAT format);
    void setConstantBuffer(uint32_t slot, ID3D11Buffer* cb);
    void drawIndexed(uint32_t count);
    void draw(uint32_t count);
    void setPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY topology);
    void setDepthStencilState(ID3D11DepthStencilState* state);
    void setRasterizerState(ID3D11RasterizerState* state);

    ID3D11Buffer* createConstantBuffer(uint32_t size);

private:
    Window* m_window = nullptr;
    ID3D11Device* m_device = nullptr;
    ID3D11DeviceContext* m_context = nullptr;
    IDXGISwapChain* m_swapChain = nullptr;
    ID3D11RenderTargetView* m_rtv = nullptr;
    ID3D11DepthStencilView* m_dsv = nullptr;
    ID3D11Texture2D* m_depthStencil = nullptr;
    ID3D11RasterizerState* m_rasterizer = nullptr;
    ID3D11DepthStencilState* m_depthStencilState = nullptr;
};

} // namespace Sunshine
