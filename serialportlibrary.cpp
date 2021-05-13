#include "serialportlibrary.h"

serialportlibrary::serialportlibrary()
{
    SerialPort = new QSerialPort;

}
void serialportlibrary::ScanPort(QStringList *_portnames)
{
    Q_FOREACH(QSerialPortInfo _spinfo, QSerialPortInfo::availablePorts())
    {
        *_portnames<<_spinfo.portName();
    }
}
bool serialportlibrary::OpenPort(const QString _portname,qint32 _baud)
{
    PortName="/dev/"+_portname;
    BaudRate=_baud;
    SerialPort->setPortName(PortName);
    SerialPort->setBaudRate(BaudRate);
    SerialPort->setDataBits(QSerialPort::Data8);
    SerialPort->setParity(QSerialPort::NoParity);
    SerialPort->setStopBits(QSerialPort::OneStop);
    SerialPort->setFlowControl(QSerialPort::NoFlowControl);
    if (SerialPort->open(QIODevice::ReadWrite))
    {
        return true;
    }
    else
    {
        return false;
    }
}
void serialportlibrary::ClosePort()
{
    if(SerialPort->isOpen())
        SerialPort->close();
}
void serialportlibrary::Write(const QByteArray _data)
{
    SerialPort->write(_data);
}
QByteArray serialportlibrary::ReadData()
{
    return SerialPort->readAll();
}
