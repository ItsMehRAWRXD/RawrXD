<<<<<<< HEAD
#ifndef MULTIMODAL_ENGINE_H
#define MULTIMODAL_ENGINE_H

// C++20, no Qt. Image → base64 prompt; callback replaces signal.

#include <string>
#include <vector>
#include <functional>

class MultiModalEngine
{
public:
    using VisionPromptReadyFn = std::function<void(const std::string& base64, const std::string& mime)>;

    MultiModalEngine() = default;

    void setOnVisionPromptReady(VisionPromptReadyFn f) { m_onVisionPromptReady = std::move(f); }

    /** imageData: RGBA or RGB bytes; width, height, bytesPerPixel. */
    void processImage(const uint8_t* imageData, int width, int height, int bytesPerPixel = 4);
    void processImage(const std::string& filePath);

private:
    VisionPromptReadyFn m_onVisionPromptReady;
};

#endif // MULTIMODAL_ENGINE_H
=======
#ifndef MULTIMODAL_ENGINE_H
#define MULTIMODAL_ENGINE_H

#include <QObject>
#include <QImage>
#include <QString>

class MultiModalEngine : public QObject
{
    Q_OBJECT

public:
    explicit MultiModalEngine(QObject *parent = nullptr);

    // Accepts QImage or file path → base-64 PNG/JPG
    // Auto-detects MIME, resizes > 1024 px longest edge (bicubic)
    // Emits visionPromptReady(QString base64, QString mime)
    void processImage(const QImage &image);
    void processImage(const QString &filePath);

signals:
    void visionPromptReady(const QString &base64, const QString &mime);
};

#endif // MULTIMODAL_ENGINE_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
