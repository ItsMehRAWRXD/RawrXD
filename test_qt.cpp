#include <QApplication>
#include <QLabel>
#include <QDebug>

int main(int argc, char *argv[])
{
    qDebug() << "Testing Qt application...";
    QApplication app(argc, argv);
    QLabel label("Hello Qt!");
    label.show();
    qDebug() << "Qt application created successfully";
    return app.exec();
}