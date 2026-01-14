/**
 * @file icon_font_widget.cpp
 * @brief Full Icon Font Browser Widget implementation for RawrXD IDE
 * @author RawrXD Team
 */

#include "icon_font_widget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QTabWidget>
#include <QSplitter>
#include <QApplication>
#include <QClipboard>
#include <QFontDatabase>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QPainter>

IconFontWidget::IconFontWidget(QWidget* parent)
    : QWidget(parent)
    , m_settings(new QSettings("RawrXD", "IDE", this))
{
    setupUI();
    connectSignals();
    loadBuiltinFonts();
    loadRecentIcons();
    loadFavorites();
    populateIconList();
}

IconFontWidget::~IconFontWidget() {
    saveRecentIcons();
    saveFavorites();
}

void IconFontWidget::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(4, 4, 4, 4);
    mainLayout->setSpacing(4);
    
    setupToolbar();
    mainLayout->addWidget(m_toolbar);
    
    QSplitter* splitter = new QSplitter(Qt::Horizontal, this);
    
    // Icon grid
    QWidget* gridWidget = new QWidget(this);
    QVBoxLayout* gridLayout = new QVBoxLayout(gridWidget);
    gridLayout->setContentsMargins(0, 0, 0, 0);
    
    setupIconGrid();
    gridLayout->addWidget(m_iconList);
    
    splitter->addWidget(gridWidget);
    
    // Right panel: Preview + Recent/Favorites
    QWidget* rightPanel = new QWidget(this);
    QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    
    setupPreview();
    
    // Preview group
    QGroupBox* previewGroup = new QGroupBox("Preview", rightPanel);
    QVBoxLayout* previewLayout = new QVBoxLayout(previewGroup);
    previewLayout->addWidget(m_previewLabel, 0, Qt::AlignCenter);
    previewLayout->addWidget(m_iconNameLabel);
    previewLayout->addWidget(m_unicodeLabel);
    previewLayout->addWidget(m_categoriesLabel);
    
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(m_copyBtn);
    buttonLayout->addWidget(m_insertBtn);
    buttonLayout->addWidget(m_favoriteBtn);
    previewLayout->addLayout(buttonLayout);
    
    rightLayout->addWidget(previewGroup);
    
    // Tabs for recent and favorites
    QTabWidget* tabWidget = new QTabWidget(rightPanel);
    
    m_recentList = new QListWidget(this);
    m_recentList->setViewMode(QListView::IconMode);
    m_recentList->setIconSize(QSize(24, 24));
    m_recentList->setSpacing(4);
    m_recentList->setStyleSheet("QListWidget { background-color: #252526; }");
    tabWidget->addTab(m_recentList, "Recent");
    
    m_favoritesList = new QListWidget(this);
    m_favoritesList->setViewMode(QListView::IconMode);
    m_favoritesList->setIconSize(QSize(24, 24));
    m_favoritesList->setSpacing(4);
    m_favoritesList->setStyleSheet("QListWidget { background-color: #252526; }");
    tabWidget->addTab(m_favoritesList, "Favorites");
    
    rightLayout->addWidget(tabWidget);
    
    splitter->addWidget(rightPanel);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);
    
    mainLayout->addWidget(splitter);
}

void IconFontWidget::setupToolbar() {
    m_toolbar = new QToolBar("Icon Toolbar", this);
    
    // Search
    m_searchEdit = new QLineEdit(this);
    m_searchEdit->setPlaceholderText("Search icons...");
    m_searchEdit->setMinimumWidth(150);
    m_toolbar->addWidget(m_searchEdit);
    
    m_toolbar->addSeparator();
    
    // Font set selector
    m_fontSetCombo = new QComboBox(this);
    m_fontSetCombo->setMinimumWidth(150);
    m_toolbar->addWidget(new QLabel(" Font: ", this));
    m_toolbar->addWidget(m_fontSetCombo);
    
    // Category selector
    m_categoryCombo = new QComboBox(this);
    m_categoryCombo->setMinimumWidth(120);
    m_toolbar->addWidget(new QLabel(" Category: ", this));
    m_toolbar->addWidget(m_categoryCombo);
    
    m_toolbar->addSeparator();
    
    // Size
    m_sizeSpin = new QSpinBox(this);
    m_sizeSpin->setRange(12, 128);
    m_sizeSpin->setValue(24);
    m_sizeSpin->setSuffix("px");
    m_toolbar->addWidget(new QLabel(" Size: ", this));
    m_toolbar->addWidget(m_sizeSpin);
    
    // Output format
    m_outputFormatCombo = new QComboBox(this);
    m_outputFormatCombo->addItem("CSS Class", CssClass);
    m_outputFormatCombo->addItem("Unicode", Unicode);
    m_outputFormatCombo->addItem("HTML Entity", HtmlEntity);
    m_outputFormatCombo->addItem("HTML Tag", HtmlTag);
    m_outputFormatCombo->addItem("Qt Unicode", QtUnicode);
    m_toolbar->addWidget(new QLabel(" Format: ", this));
    m_toolbar->addWidget(m_outputFormatCombo);
}

void IconFontWidget::setupIconGrid() {
    m_iconList = new QListWidget(this);
    m_iconList->setViewMode(QListView::IconMode);
    m_iconList->setIconSize(QSize(32, 32));
    m_iconList->setSpacing(8);
    m_iconList->setResizeMode(QListView::Adjust);
    m_iconList->setUniformItemSizes(true);
    m_iconList->setStyleSheet(
        "QListWidget { background-color: #1e1e1e; color: #d4d4d4; }"
        "QListWidget::item { padding: 8px; border-radius: 4px; }"
        "QListWidget::item:selected { background-color: #264f78; }"
        "QListWidget::item:hover { background-color: #2d2d2d; }");
}

void IconFontWidget::setupPreview() {
    m_previewLabel = new QLabel(this);
    m_previewLabel->setMinimumSize(100, 100);
    m_previewLabel->setAlignment(Qt::AlignCenter);
    m_previewLabel->setStyleSheet(
        "QLabel { background-color: #2d2d2d; border: 1px solid #444; border-radius: 8px; }");
    
    m_iconNameLabel = new QLabel("No icon selected", this);
    m_iconNameLabel->setStyleSheet("QLabel { font-weight: bold; color: #d4d4d4; }");
    
    m_unicodeLabel = new QLabel("", this);
    m_unicodeLabel->setStyleSheet("QLabel { color: #808080; font-family: Consolas; }");
    
    m_categoriesLabel = new QLabel("", this);
    m_categoriesLabel->setStyleSheet("QLabel { color: #569cd6; }");
    m_categoriesLabel->setWordWrap(true);
    
    m_copyBtn = new QPushButton("📋 Copy", this);
    m_copyBtn->setToolTip("Copy icon code to clipboard");
    
    m_insertBtn = new QPushButton("➕ Insert", this);
    m_insertBtn->setToolTip("Insert icon at cursor");
    
    m_favoriteBtn = new QPushButton("⭐ Favorite", this);
    m_favoriteBtn->setToolTip("Add to favorites");
}

void IconFontWidget::connectSignals() {
    connect(m_searchEdit, &QLineEdit::textChanged, this, &IconFontWidget::onSearchTextChanged);
    connect(m_fontSetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &IconFontWidget::onFontSetChanged);
    connect(m_categoryCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &IconFontWidget::onCategoryChanged);
    connect(m_sizeSpin, QOverload<int>::of(&QSpinBox::valueChanged), 
            this, &IconFontWidget::onSizeChanged);
    connect(m_outputFormatCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &IconFontWidget::onOutputFormatChanged);
    
    connect(m_iconList, &QListWidget::itemClicked, this, &IconFontWidget::onIconClicked);
    connect(m_iconList, &QListWidget::itemDoubleClicked, this, &IconFontWidget::onIconDoubleClicked);
    
    connect(m_copyBtn, &QPushButton::clicked, this, &IconFontWidget::copySelectedIcon);
    connect(m_insertBtn, &QPushButton::clicked, this, &IconFontWidget::insertSelectedIcon);
    connect(m_favoriteBtn, &QPushButton::clicked, this, &IconFontWidget::addToFavorites);
    
    connect(m_recentList, &QListWidget::itemClicked, this, &IconFontWidget::onIconClicked);
    connect(m_favoritesList, &QListWidget::itemClicked, this, &IconFontWidget::onIconClicked);
}

void IconFontWidget::loadBuiltinFonts() {
    loadFontAwesome();
    loadMaterialIcons();
    
    // Update combo
    m_fontSetCombo->clear();
    for (const IconFontSet& set : m_fontSets) {
        m_fontSetCombo->addItem(set.name);
    }
}

void IconFontWidget::loadFontAwesome() {
    IconFontSet faSet;
    faSet.name = "Font Awesome 5";
    faSet.fontFamily = "Font Awesome 5 Free";
    faSet.prefix = "fa";
    
    // Common Font Awesome icons (subset - full implementation would load from JSON)
    QVector<QPair<QString, QString>> faIcons = {
        {"home", "f015"}, {"user", "f007"}, {"search", "f002"}, {"cog", "f013"},
        {"check", "f00c"}, {"times", "f00d"}, {"plus", "f067"}, {"minus", "f068"},
        {"star", "f005"}, {"heart", "f004"}, {"envelope", "f0e0"}, {"phone", "f095"},
        {"edit", "f044"}, {"trash", "f1f8"}, {"save", "f0c7"}, {"folder", "f07b"},
        {"file", "f15b"}, {"copy", "f0c5"}, {"paste", "f0ea"}, {"cut", "f0c4"},
        {"undo", "f0e2"}, {"redo", "f01e"}, {"refresh", "f021"}, {"download", "f019"},
        {"upload", "f093"}, {"cloud", "f0c2"}, {"lock", "f023"}, {"unlock", "f09c"},
        {"key", "f084"}, {"bell", "f0f3"}, {"calendar", "f073"}, {"clock", "f017"},
        {"map", "f279"}, {"globe", "f0ac"}, {"link", "f0c1"}, {"unlink", "f127"},
        {"code", "f121"}, {"terminal", "f120"}, {"database", "f1c0"}, {"server", "f233"},
        {"bug", "f188"}, {"wrench", "f0ad"}, {"hammer", "f6e3"}, {"tools", "f7d9"},
        {"rocket", "f135"}, {"fire", "f06d"}, {"bolt", "f0e7"}, {"sun", "f185"},
        {"moon", "f186"}, {"cloud-sun", "f6c4"}, {"snowflake", "f2dc"}, {"umbrella", "f0e9"},
        {"coffee", "f0f4"}, {"music", "f001"}, {"video", "f03d"}, {"image", "f03e"},
        {"camera", "f030"}, {"microphone", "f130"}, {"headphones", "f025"}, {"play", "f04b"},
        {"pause", "f04c"}, {"stop", "f04d"}, {"forward", "f04e"}, {"backward", "f04a"},
        {"bookmark", "f02e"}, {"tag", "f02b"}, {"tags", "f02c"}, {"flag", "f024"},
        {"comment", "f075"}, {"comments", "f086"}, {"share", "f064"}, {"share-alt", "f1e0"},
        {"thumbs-up", "f164"}, {"thumbs-down", "f165"}, {"smile", "f118"}, {"frown", "f119"},
        {"github", "f09b"}, {"gitlab", "f296"}, {"bitbucket", "f171"}, {"git", "f1d3"},
        {"npm", "f3d4"}, {"python", "f3e2"}, {"js", "f3b8"}, {"html5", "f13b"},
        {"css3", "f13c"}, {"react", "f41b"}, {"angular", "f420"}, {"vuejs", "f41f"},
        {"docker", "f395"}, {"linux", "f17c"}, {"windows", "f17a"}, {"apple", "f179"},
        {"android", "f17b"}, {"chrome", "f268"}, {"firefox", "f269"}, {"edge", "f282"},
    };
    
    for (const auto& icon : faIcons) {
        IconInfo info;
        info.name = icon.first;
        info.unicode = icon.second;
        info.fontFamily = faSet.fontFamily;
        info.categories = {"general"};
        faSet.icons.append(info);
    }
    
    m_fontSets.append(faSet);
}

void IconFontWidget::loadMaterialIcons() {
    IconFontSet mdSet;
    mdSet.name = "Material Design Icons";
    mdSet.fontFamily = "Material Icons";
    mdSet.prefix = "mdi";
    
    // Common Material icons (subset)
    QVector<QPair<QString, QString>> mdIcons = {
        {"home", "e88a"}, {"person", "e7fd"}, {"search", "e8b6"}, {"settings", "e8b8"},
        {"check", "e5ca"}, {"close", "e5cd"}, {"add", "e145"}, {"remove", "e15b"},
        {"star", "e838"}, {"favorite", "e87d"}, {"email", "e0be"}, {"phone", "e0cd"},
        {"edit", "e3c9"}, {"delete", "e872"}, {"save", "e161"}, {"folder", "e2c7"},
        {"description", "e873"}, {"content_copy", "e14d"}, {"content_paste", "e14f"}, {"content_cut", "e14e"},
        {"undo", "e166"}, {"redo", "e15a"}, {"refresh", "e5d5"}, {"file_download", "e2c4"},
        {"file_upload", "e2c6"}, {"cloud", "e2bd"}, {"lock", "e897"}, {"lock_open", "e898"},
        {"vpn_key", "e0da"}, {"notifications", "e7f4"}, {"event", "e878"}, {"schedule", "e8b5"},
        {"place", "e55f"}, {"public", "e80b"}, {"link", "e157"}, {"link_off", "e16f"},
        {"code", "e86f"}, {"terminal", "eb8e"}, {"storage", "e1db"}, {"dns", "e875"},
        {"bug_report", "e868"}, {"build", "e869"}, {"handyman", "f10b"}, {"construction", "ea3c"},
        {"rocket_launch", "eb9b"}, {"local_fire_department", "ef55"}, {"bolt", "ea0b"}, {"light_mode", "e518"},
        {"dark_mode", "e51c"}, {"wb_sunny", "e430"}, {"nights_stay", "ea46"}, {"ac_unit", "eb3b"},
        {"local_cafe", "e541"}, {"music_note", "e405"}, {"videocam", "e04b"}, {"photo", "e410"},
        {"photo_camera", "e412"}, {"mic", "e029"}, {"headset", "e310"}, {"play_arrow", "e037"},
        {"pause", "e034"}, {"stop", "e047"}, {"skip_next", "e044"}, {"skip_previous", "e045"},
        {"bookmark", "e866"}, {"label", "e892"}, {"loyalty", "e89a"}, {"flag", "e153"},
        {"chat", "e0b7"}, {"forum", "e0bf"}, {"share", "e80d"}, {"thumb_up", "e8dc"},
        {"thumb_down", "e8db"}, {"sentiment_satisfied", "e813"}, {"sentiment_dissatisfied", "e811"},
    };
    
    for (const auto& icon : mdIcons) {
        IconInfo info;
        info.name = icon.first;
        info.unicode = icon.second;
        info.fontFamily = mdSet.fontFamily;
        info.categories = {"general"};
        mdSet.icons.append(info);
    }
    
    m_fontSets.append(mdSet);
}

void IconFontWidget::loadIconFontSet(const IconFontSet& fontSet) {
    m_fontSets.append(fontSet);
    m_fontSetCombo->addItem(fontSet.name);
}

void IconFontWidget::loadCustomFont(const QString& fontPath, const QString& jsonPath) {
    // Load font file
    int fontId = QFontDatabase::addApplicationFont(fontPath);
    if (fontId == -1) {
        return;
    }
    
    QString fontFamily = QFontDatabase::applicationFontFamilies(fontId).first();
    
    // Load icon metadata from JSON
    QFile jsonFile(jsonPath);
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        return;
    }
    
    QJsonDocument doc = QJsonDocument::fromJson(jsonFile.readAll());
    QJsonObject root = doc.object();
    
    IconFontSet fontSet;
    fontSet.name = root["name"].toString(fontFamily);
    fontSet.fontFamily = fontFamily;
    fontSet.prefix = root["prefix"].toString();
    
    QJsonArray icons = root["icons"].toArray();
    for (const QJsonValue& iconVal : icons) {
        QJsonObject iconObj = iconVal.toObject();
        IconInfo info;
        info.name = iconObj["name"].toString();
        info.unicode = iconObj["unicode"].toString();
        info.fontFamily = fontFamily;
        
        QJsonArray categories = iconObj["categories"].toArray();
        for (const QJsonValue& cat : categories) {
            info.categories.append(cat.toString());
        }
        
        QJsonArray aliases = iconObj["aliases"].toArray();
        for (const QJsonValue& alias : aliases) {
            info.aliases.append(alias.toString());
        }
        
        fontSet.icons.append(info);
    }
    
    loadIconFontSet(fontSet);
}

void IconFontWidget::populateIconList() {
    m_iconList->clear();
    
    if (m_fontSets.isEmpty() || m_currentFontSetIndex >= m_fontSets.size()) {
        return;
    }
    
    const IconFontSet& fontSet = m_fontSets[m_currentFontSetIndex];
    m_filteredIcons.clear();
    
    for (const IconInfo& icon : fontSet.icons) {
        // Apply search filter
        if (!m_searchText.isEmpty()) {
            bool matches = icon.name.contains(m_searchText, Qt::CaseInsensitive);
            if (!matches) {
                for (const QString& alias : icon.aliases) {
                    if (alias.contains(m_searchText, Qt::CaseInsensitive)) {
                        matches = true;
                        break;
                    }
                }
            }
            if (!matches) continue;
        }
        
        // Apply category filter
        if (!m_currentCategory.isEmpty() && m_currentCategory != "All") {
            if (!icon.categories.contains(m_currentCategory, Qt::CaseInsensitive)) {
                continue;
            }
        }
        
        m_filteredIcons.append(icon);
        
        // Create list item
        QListWidgetItem* item = new QListWidgetItem();
        item->setText(icon.name);
        item->setData(Qt::UserRole, icon.name);
        item->setData(Qt::UserRole + 1, icon.unicode);
        item->setToolTip(QString("%1\nUnicode: %2").arg(icon.name, icon.unicode));
        
        // Create icon
        QPixmap pixmap(32, 32);
        pixmap.fill(Qt::transparent);
        QPainter painter(&pixmap);
        
        QFont iconFont(fontSet.fontFamily, 20);
        painter.setFont(iconFont);
        painter.setPen(QColor("#d4d4d4"));
        
        bool ok;
        ushort unicodeVal = icon.unicode.toUShort(&ok, 16);
        if (ok) {
            painter.drawText(pixmap.rect(), Qt::AlignCenter, QChar(unicodeVal));
        }
        
        item->setIcon(QIcon(pixmap));
        m_iconList->addItem(item);
    }
    
    populateCategories();
}

void IconFontWidget::populateCategories() {
    QString currentCat = m_categoryCombo->currentText();
    m_categoryCombo->clear();
    m_categoryCombo->addItem("All");
    
    if (m_fontSets.isEmpty() || m_currentFontSetIndex >= m_fontSets.size()) {
        return;
    }
    
    QSet<QString> categories;
    const IconFontSet& fontSet = m_fontSets[m_currentFontSetIndex];
    
    for (const IconInfo& icon : fontSet.icons) {
        for (const QString& cat : icon.categories) {
            categories.insert(cat);
        }
    }
    
    QStringList sortedCats = categories.values();
    sortedCats.sort();
    m_categoryCombo->addItems(sortedCats);
    
    int idx = m_categoryCombo->findText(currentCat);
    if (idx >= 0) {
        m_categoryCombo->setCurrentIndex(idx);
    }
}

void IconFontWidget::filterIcons() {
    populateIconList();
}

void IconFontWidget::updatePreview(const IconInfo& icon) {
    m_selectedIcon = icon;
    
    // Update preview label with large icon
    QPixmap pixmap(100, 100);
    pixmap.fill(QColor("#2d2d2d"));
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    
    const IconFontSet& fontSet = m_fontSets[m_currentFontSetIndex];
    QFont iconFont(fontSet.fontFamily, 48);
    painter.setFont(iconFont);
    painter.setPen(QColor("#d4d4d4"));
    
    bool ok;
    ushort unicodeVal = icon.unicode.toUShort(&ok, 16);
    if (ok) {
        painter.drawText(pixmap.rect(), Qt::AlignCenter, QChar(unicodeVal));
    }
    
    m_previewLabel->setPixmap(pixmap);
    
    // Update info labels
    m_iconNameLabel->setText(icon.name);
    m_unicodeLabel->setText(QString("Unicode: \\u%1").arg(icon.unicode.toUpper()));
    m_categoriesLabel->setText(icon.categories.isEmpty() ? "" : 
        QString("Categories: %1").arg(icon.categories.join(", ")));
    
    emit iconSelected(icon.name, icon.unicode);
}

QString IconFontWidget::formatIcon(const IconInfo& icon, OutputFormat format) const {
    if (m_fontSets.isEmpty() || m_currentFontSetIndex >= m_fontSets.size()) {
        return QString();
    }
    
    const IconFontSet& fontSet = m_fontSets[m_currentFontSetIndex];
    
    switch (format) {
        case Unicode:
            return QString("\\u%1").arg(icon.unicode.toUpper());
            
        case HtmlEntity:
            return QString("&#x%1;").arg(icon.unicode);
            
        case CssClass:
            return QString("%1 %1-%2").arg(fontSet.prefix, icon.name);
            
        case HtmlTag:
            return QString("<i class=\"%1 %1-%2\"></i>").arg(fontSet.prefix, icon.name);
            
        case QtUnicode:
            return QString("QChar(0x%1)").arg(icon.unicode);
            
        case SvgPath:
            // Would require SVG data to be available
            return QString();
            
        default:
            return icon.name;
    }
}

QString IconFontWidget::getSelectedIconCode() const {
    if (m_selectedIcon.name.isEmpty()) {
        return QString();
    }
    return formatIcon(m_selectedIcon, m_outputFormat);
}

QString IconFontWidget::getSelectedIconName() const {
    return m_selectedIcon.name;
}

// Slots
void IconFontWidget::onSearchTextChanged(const QString& text) {
    m_searchText = text;
    filterIcons();
}

void IconFontWidget::onCategoryChanged(int index) {
    m_currentCategory = m_categoryCombo->itemText(index);
    filterIcons();
}

void IconFontWidget::onFontSetChanged(int index) {
    m_currentFontSetIndex = index;
    populateIconList();
}

void IconFontWidget::onIconClicked(QListWidgetItem* item) {
    QString name = item->data(Qt::UserRole).toString();
    QString unicode = item->data(Qt::UserRole + 1).toString();
    
    // Find the icon info
    for (const IconInfo& icon : m_filteredIcons) {
        if (icon.name == name) {
            updatePreview(icon);
            break;
        }
    }
}

void IconFontWidget::onIconDoubleClicked(QListWidgetItem* item) {
    QString name = item->data(Qt::UserRole).toString();
    
    for (const IconInfo& icon : m_filteredIcons) {
        if (icon.name == name) {
            QString code = formatIcon(icon, m_outputFormat);
            emit iconDoubleClicked(code);
            
            // Add to recent
            if (!m_recentIcons.contains(name)) {
                m_recentIcons.prepend(name);
                if (m_recentIcons.size() > 20) {
                    m_recentIcons.removeLast();
                }
            }
            break;
        }
    }
}

void IconFontWidget::onSizeChanged(int size) {
    m_iconSize = size;
    m_iconList->setIconSize(QSize(size, size));
}

void IconFontWidget::onOutputFormatChanged(int index) {
    m_outputFormat = static_cast<OutputFormat>(m_outputFormatCombo->itemData(index).toInt());
}

void IconFontWidget::copySelectedIcon() {
    QString code = getSelectedIconCode();
    if (!code.isEmpty()) {
        QApplication::clipboard()->setText(code);
        emit iconCopied(code);
    }
}

void IconFontWidget::insertSelectedIcon() {
    QString code = getSelectedIconCode();
    if (!code.isEmpty()) {
        emit iconDoubleClicked(code);
    }
}

void IconFontWidget::addToFavorites() {
    if (m_selectedIcon.name.isEmpty()) return;
    
    if (!m_favoriteIcons.contains(m_selectedIcon.name)) {
        m_favoriteIcons.append(m_selectedIcon.name);
        
        // Update favorites list
        QListWidgetItem* item = new QListWidgetItem();
        item->setText(m_selectedIcon.name);
        item->setData(Qt::UserRole, m_selectedIcon.name);
        item->setData(Qt::UserRole + 1, m_selectedIcon.unicode);
        
        QPixmap pixmap(24, 24);
        pixmap.fill(Qt::transparent);
        QPainter painter(&pixmap);
        
        const IconFontSet& fontSet = m_fontSets[m_currentFontSetIndex];
        QFont iconFont(fontSet.fontFamily, 16);
        painter.setFont(iconFont);
        painter.setPen(QColor("#d4d4d4"));
        
        bool ok;
        ushort unicodeVal = m_selectedIcon.unicode.toUShort(&ok, 16);
        if (ok) {
            painter.drawText(pixmap.rect(), Qt::AlignCenter, QChar(unicodeVal));
        }
        
        item->setIcon(QIcon(pixmap));
        m_favoritesList->addItem(item);
    }
}

void IconFontWidget::refreshIconList() {
    populateIconList();
}

void IconFontWidget::setSearchText(const QString& text) {
    m_searchEdit->setText(text);
}

void IconFontWidget::setCategory(const QString& category) {
    int idx = m_categoryCombo->findText(category);
    if (idx >= 0) {
        m_categoryCombo->setCurrentIndex(idx);
    }
}

void IconFontWidget::setOutputFormat(OutputFormat format) {
    m_outputFormat = format;
    int idx = m_outputFormatCombo->findData(format);
    if (idx >= 0) {
        m_outputFormatCombo->setCurrentIndex(idx);
    }
}

void IconFontWidget::saveRecentIcons() {
    m_settings->setValue("IconFont/Recent", m_recentIcons);
}

void IconFontWidget::loadRecentIcons() {
    m_recentIcons = m_settings->value("IconFont/Recent").toStringList();
}

void IconFontWidget::saveFavorites() {
    m_settings->setValue("IconFont/Favorites", m_favoriteIcons);
}

void IconFontWidget::loadFavorites() {
    m_favoriteIcons = m_settings->value("IconFont/Favorites").toStringList();
}
