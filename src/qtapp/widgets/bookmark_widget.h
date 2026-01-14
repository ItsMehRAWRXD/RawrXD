/**
 * @file bookmark_widget.h
 * @brief Header for BookmarkWidget - Code bookmarks
 */

#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QListWidget>

class BookmarkWidget : public QWidget {
    Q_OBJECT
    
public:
    explicit BookmarkWidget(QWidget* parent = nullptr);
    ~BookmarkWidget();
    
private slots:
    void onAddBookmark();
    void onRemoveBookmark();
    void onGoToBookmark();
    
private:
    void setupUI();
    
    QVBoxLayout* mMainLayout;
    QLineEdit* mBookmarkInput;
    QPushButton* mAddButton;
    QPushButton* mRemoveButton;
    QPushButton* mGoToButton;
    QListWidget* mBookmarkList;
};

