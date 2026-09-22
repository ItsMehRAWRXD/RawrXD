#include "RendererD3D11.hpp"
#include <d3dcompiler.h>
#include <string>

namespace Sunshine {

bool Renderer::initialize(Window* window) {
    m_window = window;
    int width = window->getWidth();
    int height = window->getHeight();

    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 1;
    sd.BufferDesc.Width = width;
    sd.BufferDesc.Height = height;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = window->getHandle();
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createFlags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
#ifdef _DEBUG
    createFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL featureLevel;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createFlags,
        nullptr, 0, D3D11_SDK_VERSION,
        &sd, &m_swapChain, &m_device, &featureLevel, &m_context);
    if (FAILED(hr)) return false;

    ID3D11Texture2D* backBuffer = nullptr;
    m_swapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&backBuffer);
    if (!backBuffer) return false;
    m_device->CreateRenderTargetView(backBuffer, nullptr, &m_rtv);
    backBuffer->Release();
    if (!m_rtv) return false;

    D3D11_TEXTURE2D_DESC dsd = {};
    dsd.Width = width;
    dsd.Height = height;
    dsd.MipLevels = 1;
    dsd.ArraySize = 1;
    dsd.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;
    dsd.SampleDesc.Count = 1;
    dsd.Usage = D3D11_USAGE_DEFAULT;
    dsd.BindFlags = D3D11_BIND_DEPTH_STENCIL;
    m_device->CreateTexture2D(&dsd, nullptr, &m_depthStencil);
    if (m_depthStencil) {
        m_device->CreateDepthStencilView(m_depthStencil, nullptr, &m_dsv);
    }

    D3D11_RASTERIZER_DESC rd = {};
    rd.FillMode = D3D11_FILL_SOLID;
    rd.CullMode = D3D11_CULL_BACK;
    rd.FrontCounterClockwise = FALSE;
    rd.DepthClipEnable = TRUE;
    m_device->CreateRasterizerState(&rd, &m_rasterizer);

    D3D11_DEPTH_STENCIL_DESC dssd = {};
    dssd.DepthEnable = TRUE;
    dssd.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
    dssd.DepthFunc = D3D11_COMPARISON_LESS;
    m_device->CreateDepthStencilState(&dssd, &m_depthStencilState);

    m_context->RSSetState(m_rasterizer);
    m_context->OMSetDepthStencilState(m_depthStencilState, 0);
    m_context->OMSetRenderTargets(1, &m_rtv, m_dsv);

    D3D11_VIEWPORT vp = {};
    vp.Width = (float)width;
    vp.Height = (float)height;
    vp.MinDepth = 0.0f;
    vp.MaxDepth = 1.0f;
    vp.TopLeftX = 0.0f;
    vp.TopLeftY = 0.0f;
    m_context->RSSetViewports(1, &vp);

    return true;
}

void Renderer::shutdown() {
    if (m_depthStencilState) { m_depthStencilState->Release(); m_depthStencilState = nullptr; }
    if (m_rasterizer) { m_rasterizer->Release(); m_rasterizer = nullptr; }
    if (m_dsv) { m_dsv->Release(); m_dsv = nullptr; }
    if (m_depthStencil) { m_depthStencil->Release(); m_depthStencil = nullptr; }
    if (m_rtv) { m_rtv->Release(); m_rtv = nullptr; }
    if (m_swapChain) { m_swapChain->Release(); m_swapChain = nullptr; }
    if (m_context) { m_context->Release(); m_context = nullptr; }
    if (m_device) { m_device->Release(); m_device = nullptr; }
    m_window = nullptr;
}

void Renderer::resize(int width, int height) {
    if (!m_swapChain || !m_device) return;
    m_context->OMSetRenderTargets(0, nullptr, nullptr);
    if (m_rtv) { m_rtv->Release(); m_rtv = nullptr; }
    if (m_dsv) { m_dsv->Release(); m_dsv = nullptr; }
    if (m_depthStencil) { m_depthStencil->Release(); m_depthStencil = nullptr; }

    m_swapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);

    ID3D11Texture2D* backBuffer = nullptr;
    m_swapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&backBuffer);
    if (backBuffer) {
        m_device->CreateRenderTargetView(backBuffer, nullptr, &m_rtv);
        backBuffer->Release();
    }

    D3D11_TEXTURE2D_DESC dsd = {};
    dsd.Width = width;
    dsd.Height = height;
    dsd.MipLevels = 1;
    dsd.ArraySize = 1;
    dsd.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;
    dsd.SampleDesc.Count = 1;
    dsd.Usage = D3D11_USAGE_DEFAULT;
    dsd.BindFlags = D3D11_BIND_DEPTH_STENCIL;
    m_device->CreateTexture2D(&dsd, nullptr, &m_depthStencil);
    if (m_depthStencil) {
        m_device->CreateDepthStencilView(m_depthStencil, nullptr, &m_dsv);
    }

    m_context->OMSetRenderTargets(1, &m_rtv, m_dsv);
    D3D11_VIEWPORT vp = {};
    vp.Width = (float)width;
    vp.Height = (float)height;
    vp.MinDepth = 0.0f;
    vp.MaxDepth = 1.0f;
    vp.TopLeftX = 0.0f;
    vp.TopLeftY = 0.0f;
    m_context->RSSetViewports(1, &vp);
}

void Renderer::beginFrame(float r, float g, float b) {
    float color[4] = {r, g, b, 1.0f};
    m_context->ClearRenderTargetView(m_rtv, color);
    if (m_dsv) m_context->ClearDepthStencilView(m_dsv, D3D11_CLEAR_DEPTH | D3D11_CLEAR_STENCIL, 1.0f, 0);
}

void Renderer::endFrame() {
}

void Renderer::present() {
    m_swapChain->Present(1, 0);
}

bool Renderer::compileShader(const char* vsCode, const char* psCode, const D3D11_INPUT_ELEMENT_DESC* layout, uint32_t layoutCount, Shader* out) {
    ID3DBlob* vsErrors = nullptr;
    ID3DBlob* psErrors = nullptr;
    HRESULT hr;
    hr = D3DCompile(vsCode, strlen(vsCode), nullptr, nullptr, nullptr, "main", "vs_4_0", 0, 0, &out->vsBlob, &vsErrors);
    if (FAILED(hr)) {
        if (vsErrors) vsErrors->Release();
        return false;
    }
    ID3DBlob* psBlob = nullptr;
    hr = D3DCompile(psCode, strlen(psCode), nullptr, nullptr, nullptr, "main", "ps_4_0", 0, 0, &psBlob, &psErrors);
    if (FAILED(hr)) {
        if (psBlob) psBlob->Release();
        if (psErrors) psErrors->Release();
        return false;
    }

    m_device->CreateVertexShader(out->vsBlob->GetBufferPointer(), out->vsBlob->GetBufferSize(), nullptr, &out->vs);
    m_device->CreatePixelShader(psBlob->GetBufferPointer(), psBlob->GetBufferSize(), nullptr, &out->ps);
    m_device->CreateInputLayout(layout, layoutCount, out->vsBlob->GetBufferPointer(), out->vsBlob->GetBufferSize(), &out->layout);
    psBlob->Release();
    return out->vs && out->ps && out->layout;
}

void Renderer::releaseShader(Shader* shader) {
    if (shader->vs) { shader->vs->Release(); shader->vs = nullptr; }
    if (shader->ps) { shader->ps->Release(); shader->ps = nullptr; }
    if (shader->layout) { shader->layout->Release(); shader->layout = nullptr; }
    if (shader->vsBlob) { shader->vsBlob->Release(); shader->vsBlob = nullptr; }
}

bool Renderer::createVertexBuffer(const void* data, uint32_t size, uint32_t stride, ID3D11Buffer** out) {
    D3D11_BUFFER_DESC bd = {};
    bd.Usage = D3D11_USAGE_DEFAULT;
    bd.ByteWidth = size;
    bd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    D3D11_SUBRESOURCE_DATA init = {};
    init.pSysMem = data;
    HRESULT hr = m_device->CreateBuffer(&bd, &init, out);
    return SUCCEEDED(hr);
}

bool Renderer::createIndexBuffer(const void* data, uint32_t size, DXGI_FORMAT format, ID3D11Buffer** out) {
    (void)format;
    D3D11_BUFFER_DESC bd = {};
    bd.Usage = D3D11_USAGE_DEFAULT;
    bd.ByteWidth = size;
    bd.BindFlags = D3D11_BIND_INDEX_BUFFER;
    D3D11_SUBRESOURCE_DATA init = {};
    init.pSysMem = data;
    HRESULT hr = m_device->CreateBuffer(&bd, &init, out);
    return SUCCEEDED(hr);
}

void Renderer::setShader(const Shader* shader) {
    m_context->VSSetShader(shader->vs, nullptr, 0);
    m_context->PSSetShader(shader->ps, nullptr, 0);
    m_context->IASetInputLayout(shader->layout);
}

void Renderer::setVertexBuffer(ID3D11Buffer* vb, uint32_t stride) {
    UINT offset = 0;
    m_context->IASetVertexBuffers(0, 1, &vb, &stride, &offset);
}

void Renderer::setIndexBuffer(ID3D11Buffer* ib, DXGI_FORMAT format) {
    m_context->IASetIndexBuffer(ib, format, 0);
}

void Renderer::setConstantBuffer(uint32_t slot, ID3D11Buffer* cb) {
    m_context->VSSetConstantBuffers(slot, 1, &cb);
}

void Renderer::drawIndexed(uint32_t count) {
    m_context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    m_context->DrawIndexed(count, 0, 0);
}

void Renderer::draw(uint32_t count) {
    m_context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    m_context->Draw(count, 0);
}

ID3D11Buffer* Renderer::createConstantBuffer(uint32_t size) {
    D3D11_BUFFER_DESC bd = {};
    bd.Usage = D3D11_USAGE_DEFAULT;
    bd.ByteWidth = size;
    bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    ID3D11Buffer* cb = nullptr;
    m_device->CreateBuffer(&bd, nullptr, &cb);
    return cb;
}

} // namespace Sunshine
