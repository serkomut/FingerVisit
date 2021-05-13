#ifndef SERIALPORTLIBRARY_H
#define SERIALPORTLIBRARY_H
#include <QtSerialPort/QSerialPort>
#include <QtSerialPort/QSerialPortInfo>
#include <qdebug.h>
#include <QStringList>
#include <qbytearray.h>

class serialportlibrary : public QObject
{
    Q_OBJECT
public:
    serialportlibrary();
    QSerialPort *SerialPort;

    QString PortName;
    qint32 BaudRate;

    void ScanPort(QStringList *_portnames);
    bool OpenPort(QString _portname, qint32 _baud);
    void ClosePort();
    void Write(const QByteArray _data);
    QByteArray ReadData();

};


#endif // SERIALPORTLIBRARY_H
