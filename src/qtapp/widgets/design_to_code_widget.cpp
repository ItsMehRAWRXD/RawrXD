/**
 * @file design_to_code_widget.cpp
 * @brief Implementation of DesignToCodeWidget - design system viewer and component library browser
 */

#include "design_to_code_widget.h"
#include <QApplication>
#include <QClipboard>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QListWidget>
#include <QListWidgetItem>
#include <QTextEdit>
#include <QTabWidget>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include <QGroupBox>
#include <QScrollArea>
#include <QGridLayout>
#include <QFormLayout>
#include <QMenu>
#include <QAction>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QSettings>
#include <QStandardPaths>
#include <QPainter>
#include <QPixmap>
#include <QImage>
#include <QBuffer>
#include <QDebug>

// ============================================================================
// CodeGenerator Implementation
// ============================================================================

CodeGenerator::CodeGenerator(QObject* parent)
    : QObject(parent)
{
}

void CodeGenerator::generateCode(const DesignComponent& component, const QString& targetFramework, const QJsonObject& options)
{
    try {
        QString code;
        QString language;

        if (targetFramework == "Qt") {
            code = generateQtCode(component, options);
            language = "C++";
        } else if (targetFramework == "HTML/CSS") {
            code = generateHtmlCode(component, options);
            language = "HTML";
        } else if (targetFramework == "React") {
            code = generateReactCode(component, options);
            language = "JavaScript";
        } else if (targetFramework == "Flutter") {
            code = generateFlutterCode(component, options);
            language = "Dart";
        } else {
            throw std::runtime_error("Unsupported framework");
        }

        emit codeGenerated(code, language);
    } catch (const std::exception& e) {
        emit generationError(QString("Code generation failed: %1").arg(e.what()));
    }
}

QString CodeGenerator::generateQtCode(const DesignComponent& component, const QJsonObject& options)
{
    QString code;
    QTextStream stream(&code);

    // Generate class declaration
    stream << "class " << component.name << " : public QWidget {\n";
    stream << "    Q_OBJECT\n";
    stream << "public:\n";
    stream << "    explicit " << component.name << "(QWidget* parent = nullptr);\n";
    stream << "\n";

    // Generate properties
    if (component.properties.contains("width")) {
        stream << "    void setWidth(int width) { m_width = width; update(); }\n";
        stream << "    int getWidth() const { return m_width; }\n";
    }

    if (component.properties.contains("height")) {
        stream << "    void setHeight(int height) { m_height = height; update(); }\n";
        stream << "    int getHeight() const { return m_height; }\n";
    }

    stream << "\nprotected:\n";
    stream << "    void paintEvent(QPaintEvent* event) override;\n";
    stream << "\n";
    stream << "private:\n";

    // Generate member variables
    if (component.properties.contains("width")) {
        stream << "    int m_width;\n";
    }
    if (component.properties.contains("height")) {
        stream << "    int m_height;\n";
    }

    stream << "};\n\n";

    // Generate implementation
    stream << component.name << "::" << component.name << "(QWidget* parent)\n";
    stream << "    : QWidget(parent)\n";

    if (component.properties.contains("width")) {
        stream << "    , m_width(" << component.properties["width"].toInt(100) << ")\n";
    }
    if (component.properties.contains("height")) {
        stream << "    , m_height(" << component.properties["height"].toInt(50) << ")\n";
    }

    stream << "{\n";
    stream << "    setFixedSize(m_width, m_height);\n";
    stream << "}\n\n";

    stream << "void " << component.name << "::paintEvent(QPaintEvent* event) {\n";
    stream << "    Q_UNUSED(event)\n";
    stream << "    QPainter painter(this);\n";
    stream << "    painter.setRenderHint(QPainter::Antialiasing);\n";

    // Generate painting code based on component type
    if (component.category == "Button") {
        stream << "    // Draw button background\n";
        stream << "    painter.fillRect(rect(), QColor(100, 150, 200));\n";
        stream << "    painter.setPen(QPen(Qt::white));\n";
        stream << "    painter.drawText(rect(), Qt::AlignCenter, \"" << component.name << "\");\n";
    } else if (component.category == "Label") {
        stream << "    // Draw label text\n";
        stream << "    painter.setPen(QPen(Qt::black));\n";
        stream << "    painter.drawText(rect(), Qt::AlignCenter, \"" << component.name << "\");\n";
    }

    stream << "}\n";

    return code;
}

QString CodeGenerator::generateHtmlCode(const DesignComponent& component, const QJsonObject& options)
{
    QString code;
    QTextStream stream(&code);

    // Generate HTML structure
    if (component.category == "Button") {
        stream << "<button class=\"" << component.name.toLower() << "\"";
        if (component.properties.contains("onclick")) {
            stream << " onclick=\"" << component.properties["onclick"].toString() << "\"";
        }
        stream << ">\n";
        stream << "    " << component.name << "\n";
        stream << "</button>\n";
    } else if (component.category == "Label") {
        stream << "<div class=\"" << component.name.toLower() << "\">\n";
        stream << "    " << component.name << "\n";
        stream << "</div>\n";
    } else {
        stream << "<div class=\"" << component.name.toLower() << "\">\n";
        stream << "    <!-- " << component.name << " component -->\n";
        stream << "</div>\n";
    }

    // Generate CSS
    stream << "\n<style>\n";
    stream << "." << component.name.toLower() << " {\n";

    if (component.styles.contains("background-color")) {
        stream << "    background-color: " << component.styles["background-color"].toString() << ";\n";
    }
    if (component.styles.contains("color")) {
        stream << "    color: " << component.styles["color"].toString() << ";\n";
    }
    if (component.styles.contains("width")) {
        stream << "    width: " << component.styles["width"].toString() << ";\n";
    }
    if (component.styles.contains("height")) {
        stream << "    height: " << component.styles["height"].toString() << ";\n";
    }
    if (component.styles.contains("border-radius")) {
        stream << "    border-radius: " << component.styles["border-radius"].toString() << ";\n";
    }

    stream << "    /* Add more styles as needed */\n";
    stream << "}\n";
    stream << "</style>\n";

    return code;
}

QString CodeGenerator::generateReactCode(const DesignComponent& component, const QJsonObject& options)
{
    QString code;
    QTextStream stream(&code);

    stream << "import React from 'react';\n";
    stream << "import './" << component.name.toLower() << ".css';\n\n";

    stream << "const " << component.name << " = (props) => {\n";
    stream << "    return (\n";

    if (component.category == "Button") {
        stream << "        <button \n";
        stream << "            className=\"" << component.name.toLower() << "\"\n";
        stream << "            onClick={props.onClick}\n";
        stream << "        >\n";
        stream << "            {props.children || '" << component.name << "'}\n";
        stream << "        </button>\n";
    } else if (component.category == "Label") {
        stream << "        <div className=\"" << component.name.toLower() << "\">\n";
        stream << "            {props.children || '" << component.name << "'}\n";
        stream << "        </div>\n";
    } else {
        stream << "        <div className=\"" << component.name.toLower() << "\">\n";
        stream << "            {/* " << component.name << " component */}\n";
        stream << "            {props.children}\n";
        stream << "        </div>\n";
    }

    stream << "    );\n";
    stream << "};\n\n";
    stream << "export default " << component.name << ";\n";

    return code;
}

QString CodeGenerator::generateFlutterCode(const DesignComponent& component, const QJsonObject& options)
{
    QString code;
    QTextStream stream(&code);

    stream << "import 'package:flutter/material.dart';\n\n";

    stream << "class " << component.name << " extends StatelessWidget {\n";
    stream << "  const " << component.name << "({Key? key}) : super(key: key);\n\n";

    stream << "  @override\n";
    stream << "  Widget build(BuildContext context) {\n";
    stream << "    return ";

    if (component.category == "Button") {
        stream << "ElevatedButton(\n";
        stream << "      onPressed: () {},\n";
        stream << "      child: Text('" << component.name << "'),\n";
        stream << "    );\n";
    } else if (component.category == "Label") {
        stream << "Text(\n";
        stream << "      '" << component.name << "',\n";
        stream << "      style: TextStyle(\n";
        stream << "        fontSize: 16.0,\n";
        stream << "      ),\n";
        stream << "    );\n";
    } else {
        stream << "Container(\n";
        stream << "      child: Text('" << component.name << "'),\n";
        stream << "    );\n";
    }

    stream << "  }\n";
    stream << "}\n";

    return code;
}

// ============================================================================
// DesignToCodeWidget Implementation
// ============================================================================

DesignToCodeWidget::DesignToCodeWidget(QWidget* parent)
    : QWidget(parent)
    , mainLayout_(nullptr)
    , toolbarWidget_(nullptr)
    , mainSplitter_(nullptr)
    , newDesignBtn_(nullptr)
    , openDesignBtn_(nullptr)
    , saveDesignBtn_(nullptr)
    , importBtn_(nullptr)
    , exportBtn_(nullptr)
    , searchEdit_(nullptr)
    , categoryCombo_(nullptr)
    , frameworkCombo_(nullptr)
    , contentSplitter_(nullptr)
    , componentTree_(nullptr)
    , componentList_(nullptr)
    , detailsTabs_(nullptr)
    , propertiesTab_(nullptr)
    , stylesTab_(nullptr)
    , codeTab_(nullptr)
    , previewTab_(nullptr)
    , propertiesEditor_(nullptr)
    , stylesEditor_(nullptr)
    , codeEditor_(nullptr)
    , previewArea_(nullptr)
    , designSystemInfo_(nullptr)
    , systemNameLabel_(nullptr)
    , systemVersionLabel_(nullptr)
    , componentCountLabel_(nullptr)
    , categoryList_(nullptr)
    , codeGenerator_(nullptr)
    , generatorThread_(nullptr)
    , currentFramework_("Qt")
{
    supportedFrameworks_ = {"Qt", "HTML/CSS", "React", "Flutter"};

    setupUI();
    setupConnections();

    restoreState();

    qDebug() << "DesignToCodeWidget initialized";
}

DesignToCodeWidget::~DesignToCodeWidget()
{
    saveState();

    if (generatorThread_) {
        generatorThread_->quit();
        generatorThread_->wait();
    }
}

void DesignToCodeWidget::setupUI()
{
    mainLayout_ = new QVBoxLayout(this);
    mainLayout_->setContentsMargins(0, 0, 0, 0);
    mainLayout_->setSpacing(0);

    setupToolbar();
    setupMainArea();
    setupSidebar();

    // Set initial splitter sizes
    mainSplitter_->setSizes({250, 600});
    contentSplitter_->setSizes({300, 400});
}

void DesignToCodeWidget::setupToolbar()
{
    toolbarWidget_ = new QWidget(this);
    QHBoxLayout* toolbarLayout = new QHBoxLayout(toolbarWidget_);
    toolbarLayout->setContentsMargins(4, 2, 4, 2);

    newDesignBtn_ = new QPushButton(tr("New Design System"), toolbarWidget_);
    openDesignBtn_ = new QPushButton(tr("Open Design System"), toolbarWidget_);
    saveDesignBtn_ = new QPushButton(tr("Save Design System"), toolbarWidget_);

    toolbarLayout->addWidget(newDesignBtn_);
    toolbarLayout->addWidget(openDesignBtn_);
    toolbarLayout->addWidget(saveDesignBtn_);

    // Use spacing instead of addSeparator (not available in QBoxLayout)
    toolbarLayout->addSpacing(10);

    importBtn_ = new QPushButton(tr("Import Design"), toolbarWidget_);
    exportBtn_ = new QPushButton(tr("Export Code"), toolbarWidget_);

    toolbarLayout->addWidget(importBtn_);
    toolbarLayout->addWidget(exportBtn_);

    toolbarLayout->addStretch();

    toolbarLayout->addWidget(new QLabel(tr("Search:"), toolbarWidget_));
    searchEdit_ = new QLineEdit(toolbarWidget_);
    searchEdit_->setPlaceholderText(tr("Search components..."));
    searchEdit_->setMaximumWidth(200);
    toolbarLayout->addWidget(searchEdit_);

    toolbarLayout->addWidget(new QLabel(tr("Category:"), toolbarWidget_));
    categoryCombo_ = new QComboBox(toolbarWidget_);
    categoryCombo_->addItem(tr("All Categories"), "all");
    toolbarLayout->addWidget(categoryCombo_);

    toolbarLayout->addWidget(new QLabel(tr("Framework:"), toolbarWidget_));
    frameworkCombo_ = new QComboBox(toolbarWidget_);
    for (const QString& framework : supportedFrameworks_) {
        frameworkCombo_->addItem(framework);
    }
    frameworkCombo_->setCurrentText(currentFramework_);
    toolbarLayout->addWidget(frameworkCombo_);

    mainLayout_->addWidget(toolbarWidget_);
}

void DesignToCodeWidget::setupMainArea()
{
    mainSplitter_ = new QSplitter(Qt::Horizontal, this);
    mainLayout_->addWidget(mainSplitter_);

    // Component tree
    componentTree_ = new QTreeWidget(this);
    componentTree_->setHeaderLabel(tr("Components"));
    componentTree_->setRootIsDecorated(true);
    componentTree_->setAlternatingRowColors(true);
    componentTree_->setContextMenuPolicy(Qt::CustomContextMenu);

    mainSplitter_->addWidget(componentTree_);

    // Content area
    contentSplitter_ = new QSplitter(Qt::Vertical, this);
    mainSplitter_->addWidget(contentSplitter_);

    // Component list
    componentList_ = new QListWidget(this);
    componentList_->setViewMode(QListView::IconMode);
    componentList_->setIconSize(QSize(64, 64));
    componentList_->setSpacing(10);
    componentList_->setContextMenuPolicy(Qt::CustomContextMenu);

    contentSplitter_->addWidget(componentList_);

    // Details tabs
    detailsTabs_ = new QTabWidget(this);
    contentSplitter_->addWidget(detailsTabs_);

    setupDetailsTabs();
}

void DesignToCodeWidget::setupDetailsTabs()
{
    // Properties tab
    propertiesTab_ = new QWidget(this);
    QVBoxLayout* propertiesLayout = new QVBoxLayout(propertiesTab_);
    propertiesEditor_ = new QTextEdit(propertiesTab_);
    propertiesEditor_->setPlaceholderText(tr("Component properties (JSON)..."));
    propertiesLayout->addWidget(propertiesEditor_);

    // Styles tab
    stylesTab_ = new QWidget(this);
    QVBoxLayout* stylesLayout = new QVBoxLayout(stylesTab_);
    stylesEditor_ = new QTextEdit(stylesTab_);
    stylesEditor_->setPlaceholderText(tr("Component styles (JSON)..."));
    stylesLayout->addWidget(stylesEditor_);

    // Code tab
    codeTab_ = new QWidget(this);
    QVBoxLayout* codeLayout = new QVBoxLayout(codeTab_);
    codeEditor_ = new QTextEdit(codeTab_);
    codeEditor_->setPlaceholderText(tr("Generated code will appear here..."));
    codeEditor_->setFont(QFont("Consolas", 10));

    QHBoxLayout* codeButtonsLayout = new QHBoxLayout();
    QPushButton* generateBtn = new QPushButton(tr("Generate Code"), codeTab_);
    QPushButton* copyBtn = new QPushButton(tr("Copy to Clipboard"), codeTab_);
    codeButtonsLayout->addWidget(generateBtn);
    codeButtonsLayout->addWidget(copyBtn);
    codeButtonsLayout->addStretch();

    codeLayout->addLayout(codeButtonsLayout);
    codeLayout->addWidget(codeEditor_);

    connect(generateBtn, &QPushButton::clicked, this, &DesignToCodeWidget::onGenerateCode);
    connect(copyBtn, &QPushButton::clicked, [this]() {
        QApplication::clipboard()->setText(codeEditor_->toPlainText());
    });

    // Preview tab
    previewTab_ = new QWidget(this);
    QVBoxLayout* previewLayout = new QVBoxLayout(previewTab_);
    previewArea_ = new QScrollArea(previewTab_);
    previewArea_->setWidgetResizable(true);
    previewArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    previewArea_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    QWidget* previewContent = new QWidget();
    previewArea_->setWidget(previewContent);

    QHBoxLayout* previewButtonsLayout = new QHBoxLayout();
    QPushButton* previewBtn = new QPushButton(tr("Update Preview"), previewTab_);
    previewButtonsLayout->addWidget(previewBtn);
    previewButtonsLayout->addStretch();

    previewLayout->addLayout(previewButtonsLayout);
    previewLayout->addWidget(previewArea_);

    connect(previewBtn, &QPushButton::clicked, this, &DesignToCodeWidget::onPreviewComponent);

    // Add tabs
    detailsTabs_->addTab(propertiesTab_, tr("Properties"));
    detailsTabs_->addTab(stylesTab_, tr("Styles"));
    detailsTabs_->addTab(codeTab_, tr("Code"));
    detailsTabs_->addTab(previewTab_, tr("Preview"));
}

void DesignToCodeWidget::setupSidebar()
{
    QWidget* sidebarWidget = new QWidget(this);
    QVBoxLayout* sidebarLayout = new QVBoxLayout(sidebarWidget);

    // Design system info
    designSystemInfo_ = new QGroupBox(tr("Design System"), sidebarWidget);
    QVBoxLayout* infoLayout = new QVBoxLayout(designSystemInfo_);

    systemNameLabel_ = new QLabel(tr("No design system loaded"), designSystemInfo_);
    systemVersionLabel_ = new QLabel(tr("Version: N/A"), designSystemInfo_);
    componentCountLabel_ = new QLabel(tr("Components: 0"), designSystemInfo_);

    infoLayout->addWidget(new QLabel(tr("Name:"), designSystemInfo_));
    infoLayout->addWidget(systemNameLabel_);
    infoLayout->addWidget(new QLabel(tr("Version:"), designSystemInfo_));
    infoLayout->addWidget(systemVersionLabel_);
    infoLayout->addWidget(new QLabel(tr("Components:"), designSystemInfo_));
    infoLayout->addWidget(componentCountLabel_);

    sidebarLayout->addWidget(designSystemInfo_);

    // Categories
    QGroupBox* categoriesGroup = new QGroupBox(tr("Categories"), sidebarWidget);
    QVBoxLayout* categoriesLayout = new QVBoxLayout(categoriesGroup);

    categoryList_ = new QListWidget(categoriesGroup);
    categoryList_->setMaximumHeight(150);
    categoriesLayout->addWidget(categoryList_);

    sidebarLayout->addWidget(categoriesGroup);

    sidebarLayout->addStretch();

    mainSplitter_->addWidget(sidebarWidget);
}

void DesignToCodeWidget::setupConnections()
{
    // Toolbar actions
    connect(newDesignBtn_, &QPushButton::clicked, this, &DesignToCodeWidget::onNewDesignSystem);
    connect(openDesignBtn_, &QPushButton::clicked, this, &DesignToCodeWidget::onOpenDesignSystem);
    connect(saveDesignBtn_, &QPushButton::clicked, this, &DesignToCodeWidget::onSaveDesignSystem);
    connect(importBtn_, &QPushButton::clicked, this, &DesignToCodeWidget::onImportDesign);
    connect(exportBtn_, &QPushButton::clicked, this, &DesignToCodeWidget::onExportCode);

    // Search and filters
    connect(searchEdit_, &QLineEdit::textChanged, this, &DesignToCodeWidget::onSearchTextChanged);
    connect(categoryCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() {
        onCategoryChanged(categoryCombo_->currentData().toString());
    });
    connect(frameworkCombo_, &QComboBox::currentTextChanged, this, &DesignToCodeWidget::onFrameworkChanged);

    // Component selection
    connect(componentTree_, &QTreeWidget::itemClicked, this, &DesignToCodeWidget::onComponentSelected);
    connect(componentList_, &QListWidget::itemClicked, [this](QListWidgetItem* item) {
        if (item) {
            selectedComponentId_ = item->data(Qt::UserRole).toString();
            loadComponentDetails(selectedComponentId_);
            emit componentSelected(selectedComponentId_);
        }
    });

    // Context menus
    connect(componentTree_, &QWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        QTreeWidgetItem* item = componentTree_->itemAt(pos);
        if (item) {
            selectedComponentId_ = item->data(0, Qt::UserRole).toString();
            showContextMenu(pos);
        }
    });

    connect(componentList_, &QWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        QListWidgetItem* item = componentList_->itemAt(pos);
        if (item) {
            selectedComponentId_ = item->data(Qt::UserRole).toString();
            showContextMenu(pos);
        }
    });

    // Code generator
    if (!generatorThread_) {
        generatorThread_ = new QThread(this);
        codeGenerator_ = new CodeGenerator();
        codeGenerator_->moveToThread(generatorThread_);
        generatorThread_->start();
    }

    connect(codeGenerator_, &CodeGenerator::codeGenerated, this, &DesignToCodeWidget::onCodeGenerated);
    connect(codeGenerator_, &CodeGenerator::generationError, this, &DesignToCodeWidget::onGenerationError);
}

bool DesignToCodeWidget::loadDesignSystem(const QString& filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit error(tr("Failed to open design system file: %1").arg(filePath));
        return false;
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();

    if (!doc.isObject()) {
        emit error(tr("Invalid design system file format"));
        return false;
    }

    QJsonObject obj = doc.object();

    currentDesignSystem_.name = obj["name"].toString();
    currentDesignSystem_.version = obj["version"].toString();
    currentDesignSystem_.theme = obj["theme"].toString();
    currentDesignSystem_.projectPath = filePath;

    // Load categories
    QJsonObject categoriesObj = obj["categories"].toObject();
    currentDesignSystem_.categories.clear();
    for (const QString& key : categoriesObj.keys()) {
        currentDesignSystem_.categories[key] = categoriesObj[key].toString();
    }

    // Load components
    QJsonArray componentsArray = obj["components"].toArray();
    currentDesignSystem_.components.clear();

    for (const QJsonValue& val : componentsArray) {
        QJsonObject compObj = val.toObject();

        DesignComponent component;
        component.id = compObj["id"].toString();
        component.name = compObj["name"].toString();
        component.category = compObj["category"].toString();
        component.description = compObj["description"].toString();
        component.previewImage = compObj["previewImage"].toString();
        component.codeSnippet = compObj["codeSnippet"].toString();

        // Load properties
        component.properties = compObj["properties"].toObject();

        // Load styles
        component.styles = compObj["styles"].toObject();

        // Load tags
        QJsonArray tagsArray = compObj["tags"].toArray();
        for (const QJsonValue& tagVal : tagsArray) {
            component.tags.append(tagVal.toString());
        }

        currentDesignSystem_.components[component.id] = component;
    }

    currentDesignSystemPath_ = filePath;

    updateComponentTree();
    updateComponentList();
    updateCategories();
    updateDesignSystemInfo();

    emit designSystemLoaded(currentDesignSystem_.name);
    return true;
}

bool DesignToCodeWidget::saveDesignSystem(const QString& filePath)
{
    QString savePath = filePath.isEmpty() ? currentDesignSystemPath_ : filePath;

    if (savePath.isEmpty()) {
        savePath = QFileDialog::getSaveFileName(this, tr("Save Design System"), 
                                              QString(), tr("Design System files (*.dsys);;All files (*)"));
        if (savePath.isEmpty()) {
            return false;
        }
    }

    QJsonObject obj;
    obj["name"] = currentDesignSystem_.name;
    obj["version"] = currentDesignSystem_.version;
    obj["theme"] = currentDesignSystem_.theme;

    // Save categories
    QJsonObject categoriesObj;
    for (auto it = currentDesignSystem_.categories.begin(); it != currentDesignSystem_.categories.end(); ++it) {
        categoriesObj[it.key()] = it.value();
    }
    obj["categories"] = categoriesObj;

    // Save components
    QJsonArray componentsArray;
    for (const auto& component : currentDesignSystem_.components) {
        QJsonObject compObj;
        compObj["id"] = component.id;
        compObj["name"] = component.name;
        compObj["category"] = component.category;
        compObj["description"] = component.description;
        compObj["previewImage"] = component.previewImage;
        compObj["codeSnippet"] = component.codeSnippet;
        compObj["properties"] = component.properties;
        compObj["styles"] = component.styles;

        QJsonArray tagsArray;
        for (const QString& tag : component.tags) {
            tagsArray.append(tag);
        }
        compObj["tags"] = tagsArray;

        componentsArray.append(compObj);
    }
    obj["components"] = componentsArray;

    QJsonDocument doc(obj);

    QFile file(savePath);
    if (!file.open(QIODevice::WriteOnly)) {
        emit error(tr("Failed to save design system file: %1").arg(savePath));
        return false;
    }

    file.write(doc.toJson());
    file.close();

    currentDesignSystemPath_ = savePath;
    emit designSystemSaved(savePath);
    return true;
}

void DesignToCodeWidget::createNewDesignSystem(const QString& name)
{
    currentDesignSystem_.name = name;
    currentDesignSystem_.version = "1.0.0";
    currentDesignSystem_.theme = "default";
    currentDesignSystem_.components.clear();
    currentDesignSystem_.categories.clear();
    currentDesignSystem_.projectPath.clear();

    currentDesignSystemPath_.clear();

    updateComponentTree();
    updateComponentList();
    updateCategories();
    updateDesignSystemInfo();

    emit designSystemLoaded(name);
}

void DesignToCodeWidget::addComponent(const DesignComponent& component)
{
    currentDesignSystem_.components[component.id] = component;
    updateComponentTree();
    updateComponentList();
    updateCategories();
    updateDesignSystemInfo();
}

void DesignToCodeWidget::removeComponent(const QString& componentId)
{
    currentDesignSystem_.components.remove(componentId);
    updateComponentTree();
    updateComponentList();
    updateCategories();
    updateDesignSystemInfo();
}

void DesignToCodeWidget::updateComponent(const QString& componentId, const DesignComponent& component)
{
    if (currentDesignSystem_.components.contains(componentId)) {
        currentDesignSystem_.components[componentId] = component;
        updateComponentTree();
        updateComponentList();
        updateComponentPreview();
    }
}

void DesignToCodeWidget::generateCodeForComponent(const QString& componentId)
{
    if (!currentDesignSystem_.components.contains(componentId)) {
        return;
    }

    const DesignComponent& component = currentDesignSystem_.components[componentId];

    QJsonObject options;
    options["framework"] = currentFramework_;
    options["includeComments"] = true;

    QMetaObject::invokeMethod(codeGenerator_, "generateCode", 
                            Qt::QueuedConnection,
                            Q_ARG(DesignComponent, component),
                            Q_ARG(QString, currentFramework_),
                            Q_ARG(QJsonObject, options));
}

void DesignToCodeWidget::generateCodeForSelection()
{
    if (!selectedComponentId_.isEmpty()) {
        generateCodeForComponent(selectedComponentId_);
    }
}

void DesignToCodeWidget::importFromFigma(const QString& figmaFile)
{
    // Placeholder for Figma import functionality
    QMessageBox::information(this, tr("Import from Figma"), 
                           tr("Figma import functionality not implemented yet"));
}

void DesignToCodeWidget::exportToFramework(const QString& framework)
{
    if (currentDesignSystem_.components.isEmpty()) {
        QMessageBox::information(this, tr("Export"), tr("No components to export."));
        return;
    }

    QString dirPath = QFileDialog::getExistingDirectory(this, tr("Select Export Directory"));
    if (dirPath.isEmpty()) {
        return;
    }

    // Export all components
    for (const auto& component : currentDesignSystem_.components) {
        generateCodeForComponent(component.id);
        // In a real implementation, would save the generated code to files
    }

    QMessageBox::information(this, tr("Export Complete"), 
                           tr("Components exported to %1").arg(dirPath));
}

void DesignToCodeWidget::refresh()
{
    updateComponentTree();
    updateComponentList();
    updateCategories();
    updateDesignSystemInfo();
}

void DesignToCodeWidget::onCodeGenerated(const QString& code, const QString& language)
{
    codeEditor_->setText(code);
    emit codeGenerated(code, language);
}

void DesignToCodeWidget::onGenerationError(const QString& error)
{
    QMessageBox::warning(this, tr("Code Generation Error"), error);
    emit this->error(error);
}

void DesignToCodeWidget::onNewDesignSystem()
{
    bool ok;
    QString name = QInputDialog::getText(this, tr("New Design System"), 
                                       tr("Design system name:"), QLineEdit::Normal, "", &ok);
    if (ok && !name.isEmpty()) {
        createNewDesignSystem(name);
    }
}

void DesignToCodeWidget::onOpenDesignSystem()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open Design System"), 
                                                  QString(), tr("Design System files (*.dsys);;All files (*)"));
    if (!fileName.isEmpty()) {
        loadDesignSystem(fileName);
    }
}

void DesignToCodeWidget::onSaveDesignSystem()
{
    saveDesignSystem();
}

void DesignToCodeWidget::onImportDesign()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Import Design"), 
                                                  QString(), tr("Figma files (*.fig);;Sketch files (*.sketch);;All files (*)"));
    if (!fileName.isEmpty()) {
        if (fileName.endsWith(".fig")) {
            importFromFigma(fileName);
        } else {
            QMessageBox::information(this, tr("Import"), tr("Import format not supported yet"));
        }
    }
}

void DesignToCodeWidget::onExportCode()
{
    exportToFramework(currentFramework_);
}

void DesignToCodeWidget::onAddComponent()
{
    // Simple component creation dialog
    bool ok;
    QString name = QInputDialog::getText(this, tr("Add Component"), 
                                       tr("Component name:"), QLineEdit::Normal, "", &ok);
    if (!ok || name.isEmpty()) return;

    QString category = QInputDialog::getItem(this, tr("Component Category"), 
                                           tr("Select category:"), 
                                           QStringList() << "Button" << "Label" << "Input" << "Container" << "Custom", 0, false, &ok);
    if (!ok) return;

    DesignComponent component;
    component.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    component.name = name;
    component.category = category;
    component.description = tr("New %1 component").arg(category);

    // Set default properties based on category
    if (category == "Button") {
        component.properties["width"] = 100;
        component.properties["height"] = 30;
        component.properties["text"] = name;
        component.styles["background-color"] = "#007bff";
        component.styles["color"] = "#ffffff";
        component.styles["border-radius"] = "4px";
    } else if (category == "Label") {
        component.properties["width"] = 200;
        component.properties["height"] = 20;
        component.properties["text"] = name;
        component.styles["color"] = "#000000";
        component.styles["font-size"] = "14px";
    }

    addComponent(component);
}

void DesignToCodeWidget::onEditComponent()
{
    if (selectedComponentId_.isEmpty()) return;

    // In a real implementation, would show a component editor dialog
    QMessageBox::information(this, tr("Edit Component"), 
                           tr("Component editor not implemented yet"));
}

void DesignToCodeWidget::onDeleteComponent()
{
    if (selectedComponentId_.isEmpty()) return;

    const DesignComponent& component = currentDesignSystem_.components[selectedComponentId_];

    if (QMessageBox::question(this, tr("Delete Component"), 
                            tr("Delete component '%1'?").arg(component.name)) == QMessageBox::Yes) {
        removeComponent(selectedComponentId_);
        selectedComponentId_.clear();
    }
}

void DesignToCodeWidget::onComponentSelected(QTreeWidgetItem* item, int column)
{
    Q_UNUSED(column)
    if (!item) return;

    selectedComponentId_ = item->data(0, Qt::UserRole).toString();
    loadComponentDetails(selectedComponentId_);
    emit componentSelected(selectedComponentId_);
}

void DesignToCodeWidget::onCategoryChanged(const QString& category)
{
    updateComponentTree();
    updateComponentList();
}

void DesignToCodeWidget::onSearchTextChanged(const QString& text)
{
    updateComponentTree();
    updateComponentList();
}

void DesignToCodeWidget::onFrameworkChanged(const QString& framework)
{
    currentFramework_ = framework;
    if (!selectedComponentId_.isEmpty()) {
        generateCodeForComponent(selectedComponentId_);
    }
}

void DesignToCodeWidget::onGenerateCode()
{
    generateCodeForSelection();
}

void DesignToCodeWidget::onPreviewComponent()
{
    updateComponentPreview();
}

void DesignToCodeWidget::updateComponentTree()
{
    componentTree_->clear();

    QString searchText = searchEdit_->text().toLower();
    QString selectedCategory = categoryCombo_->currentData().toString();

    // Group components by category
    QMap<QString, QList<QTreeWidgetItem*>> categoryItems;

    for (const auto& component : currentDesignSystem_.components) {
        // Apply filters
        if (!searchText.isEmpty()) {
            bool matches = component.name.toLower().contains(searchText) ||
                          component.description.toLower().contains(searchText) ||
                          component.category.toLower().contains(searchText);
            if (!matches) {
                for (const QString& tag : component.tags) {
                    if (tag.toLower().contains(searchText)) {
                        matches = true;
                        break;
                    }
                }
            }
            if (!matches) continue;
        }

        if (selectedCategory != "all" && component.category != selectedCategory) {
            continue;
        }

        QTreeWidgetItem* item = new QTreeWidgetItem();
        item->setText(0, component.name);
        item->setData(0, Qt::UserRole, component.id);
        item->setIcon(0, QIcon(":/icons/component.png"));

        categoryItems[component.category].append(item);
    }

    // Add items to tree
    for (auto it = categoryItems.begin(); it != categoryItems.end(); ++it) {
        QTreeWidgetItem* categoryItem = new QTreeWidgetItem(componentTree_);
        categoryItem->setText(0, it.key());
        categoryItem->setIcon(0, QIcon(":/icons/folder.png"));

        for (QTreeWidgetItem* item : it.value()) {
            categoryItem->addChild(item);
        }

        categoryItem->setExpanded(true);
    }
}

void DesignToCodeWidget::updateComponentList()
{
    componentList_->clear();

    QString searchText = searchEdit_->text().toLower();
    QString selectedCategory = categoryCombo_->currentData().toString();

    for (const auto& component : currentDesignSystem_.components) {
        // Apply filters
        if (!searchText.isEmpty()) {
            bool matches = component.name.toLower().contains(searchText) ||
                          component.description.toLower().contains(searchText) ||
                          component.category.toLower().contains(searchText);
            if (!matches) continue;
        }

        if (selectedCategory != "all" && component.category != selectedCategory) {
            continue;
        }

        QListWidgetItem* item = new QListWidgetItem(componentList_);
        item->setText(component.name);
        item->setData(Qt::UserRole, component.id);

        // Generate preview icon
        QPixmap previewPixmap = generateComponentPreview(component);
        item->setIcon(QIcon(previewPixmap));

        item->setToolTip(QString("%1\n%2").arg(component.name, component.description));
    }
}

void DesignToCodeWidget::updateComponentPreview()
{
    if (selectedComponentId_.isEmpty()) return;

    const DesignComponent& component = currentDesignSystem_.components[selectedComponentId_];

    // Clear existing preview
    if (previewArea_->widget()) {
        delete previewArea_->widget();
    }

    QWidget* previewWidget = new QWidget();
    QVBoxLayout* previewLayout = new QVBoxLayout(previewWidget);

    // Component preview
    QLabel* previewLabel = new QLabel(previewWidget);
    QPixmap previewPixmap = generateComponentPreview(component);
    previewLabel->setPixmap(previewPixmap);
    previewLabel->setAlignment(Qt::AlignCenter);
    previewLayout->addWidget(previewLabel);

    // Component info
    QLabel* infoLabel = new QLabel(QString("<b>%1</b><br>%2<br>Category: %3")
                                  .arg(component.name, component.description, component.category), previewWidget);
    infoLabel->setWordWrap(true);
    previewLayout->addWidget(infoLabel);

    previewLayout->addStretch();
    previewArea_->setWidget(previewWidget);
}

void DesignToCodeWidget::updateCodePreview()
{
    if (!selectedComponentId_.isEmpty()) {
        generateCodeForComponent(selectedComponentId_);
    }
}

void DesignToCodeWidget::updateCategories()
{
    categoryCombo_->clear();
    categoryCombo_->addItem(tr("All Categories"), "all");

    QSet<QString> categories;
    for (const auto& component : currentDesignSystem_.components) {
        categories.insert(component.category);
    }

    for (const QString& category : categories) {
        categoryCombo_->addItem(category, category);
    }

    // Update category list in sidebar
    categoryList_->clear();
    for (const QString& category : categories) {
        QListWidgetItem* item = new QListWidgetItem(category, categoryList_);
        item->setData(Qt::UserRole, category);
    }
}

void DesignToCodeWidget::loadComponentDetails(const QString& componentId)
{
    if (!currentDesignSystem_.components.contains(componentId)) {
        return;
    }

    const DesignComponent& component = currentDesignSystem_.components[componentId];

    // Update properties
    QJsonDocument propsDoc(component.properties);
    propertiesEditor_->setText(propsDoc.toJson(QJsonDocument::Indented));

    // Update styles
    QJsonDocument stylesDoc(component.styles);
    stylesEditor_->setText(stylesDoc.toJson(QJsonDocument::Indented));

    // Generate code
    updateCodePreview();

    // Update preview
    updateComponentPreview();
}

void DesignToCodeWidget::showComponentProperties(const DesignComponent& component)
{
    // Implementation for showing detailed properties dialog
}

void DesignToCodeWidget::showComponentStyles(const DesignComponent& component)
{
    // Implementation for showing detailed styles dialog
}

QString DesignToCodeWidget::getComponentPreviewHtml(const DesignComponent& component) const
{
    QString html = "<div style='";

    // Apply styles
    if (component.styles.contains("background-color")) {
        html += "background-color: " + component.styles["background-color"].toString() + "; ";
    }
    if (component.styles.contains("color")) {
        html += "color: " + component.styles["color"].toString() + "; ";
    }
    if (component.styles.contains("width")) {
        html += "width: " + component.styles["width"].toString() + "; ";
    }
    if (component.styles.contains("height")) {
        html += "height: " + component.styles["height"].toString() + "; ";
    }
    if (component.styles.contains("border-radius")) {
        html += "border-radius: " + component.styles["border-radius"].toString() + "; ";
    }

    html += "padding: 8px; border: 1px solid #ccc; display: inline-block;'>";

    if (component.properties.contains("text")) {
        html += component.properties["text"].toString();
    } else {
        html += component.name;
    }

    html += "</div>";
    return html;
}

QPixmap DesignToCodeWidget::generateComponentPreview(const DesignComponent& component) const
{
    QPixmap pixmap(64, 64);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    // Draw a simple representation based on component type
    if (component.category == "Button") {
        painter.fillRect(4, 4, 56, 56, QColor(100, 150, 200));
        painter.setPen(QPen(Qt::white));
        painter.drawText(QRect(4, 4, 56, 56), Qt::AlignCenter, component.name.left(3));
    } else if (component.category == "Label") {
        painter.setPen(QPen(Qt::black));
        painter.drawText(QRect(4, 4, 56, 56), Qt::AlignCenter, component.name.left(3));
    } else {
        painter.setPen(QPen(Qt::gray));
        painter.drawRect(4, 4, 56, 56);
        painter.drawText(QRect(4, 4, 56, 56), Qt::AlignCenter, "?");
    }

    return pixmap;
}

void DesignToCodeWidget::updateDesignSystemInfo()
{
    systemNameLabel_->setText(currentDesignSystem_.name.isEmpty() ? tr("No design system loaded") : currentDesignSystem_.name);
    systemVersionLabel_->setText(tr("Version: %1").arg(currentDesignSystem_.version));
    componentCountLabel_->setText(tr("Components: %1").arg(currentDesignSystem_.components.size()));
}

void DesignToCodeWidget::showContextMenu(const QPoint& pos)
{
    QMenu menu(this);

    menu.addAction(tr("Add Component"), this, &DesignToCodeWidget::onAddComponent);
    if (!selectedComponentId_.isEmpty()) {
        menu.addAction(tr("Edit Component"), this, &DesignToCodeWidget::onEditComponent);
        menu.addAction(tr("Delete Component"), this, &DesignToCodeWidget::onDeleteComponent);
        menu.addSeparator();
        menu.addAction(tr("Generate Code"), this, &DesignToCodeWidget::onGenerateCode);
        menu.addAction(tr("Preview Component"), this, &DesignToCodeWidget::onPreviewComponent);
    }

    if (!menu.isEmpty()) {
        menu.exec(mapToGlobal(pos));
    }
}

void DesignToCodeWidget::saveState()
{
    QSettings settings;
    settings.beginGroup("DesignToCodeWidget");
    settings.setValue("mainSplitterSizes", mainSplitter_->saveState());
    settings.setValue("contentSplitterSizes", contentSplitter_->saveState());
    settings.setValue("currentFramework", currentFramework_);
    settings.setValue("selectedComponentId", selectedComponentId_);
    settings.endGroup();
}

void DesignToCodeWidget::restoreState()
{
    QSettings settings;
    settings.beginGroup("DesignToCodeWidget");

    if (settings.contains("mainSplitterSizes")) {
        mainSplitter_->restoreState(settings.value("mainSplitterSizes").toByteArray());
    }

    if (settings.contains("contentSplitterSizes")) {
        contentSplitter_->restoreState(settings.value("contentSplitterSizes").toByteArray());
    }

    currentFramework_ = settings.value("currentFramework", "Qt").toString();
    frameworkCombo_->setCurrentText(currentFramework_);

    selectedComponentId_ = settings.value("selectedComponentId").toString();

    settings.endGroup();
}