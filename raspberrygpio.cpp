#include "raspberrygpio.h"

RaspberryGPIO::RaspberryGPIO()
{

}
bool RaspberryGPIO::setup(uint8_t _pin, direction _dir, edge _edge)
{
    pin=_pin;
    ValuePath="/sys/class/gpio/gpio";
    ValuePath.append(QString::number(_pin)).append("/value");
    qDebug()<<ValuePath;
    QString command="/bin/sh -c \"echo  ";
    command.append(QString::number( _pin)).append("  > /sys/class/gpio/export\"");
    QProcess::execute(command);
    command="/bin/sh -c \"echo  ";
    switch (_dir)
    {
        case in:
        {
            command.append("in").append(" > /sys/class/gpio/gpio").append(QString::number(_pin)).append("/direction\"");
            break;
        }
        case out:
        {
            command.append("out").append(" > /sys/class/gpio/gpio").append(QString::number(_pin)).append("/direction\"");
            break;
        }
    }
    QProcess::execute(command);
    command="/bin/sh -c \"echo  ";
    switch (_edge)
    {
        case rising:
        {
            command.append("rising").append(" > /sys/class/gpio/gpio").append(QString::number(_pin)).append("/edge\"");
            break;
        }
        case falling:
        {
            command.append("falling").append(" > /sys/class/gpio/gpio").append(QString::number(_pin)).append("/edge\"");
            break;
        }
        case both:
        {
            command.append("both").append(" > /sys/class/gpio/gpio").append(QString::number(_pin)).append("/edge\"");
            break;
        }
    }
    QProcess::execute(command);
}
bool RaspberryGPIO::close(uint8_t _pin)
{

        QString command="/bin/sh -c \"echo  ";
        command.append(QString::number( _pin)).append("  > /sys/class/gpio/unexport\"");
        QProcess::execute(command);
        return true;
}

bool RaspberryGPIO::isExists(uint8_t _pin)
{
    QString Path="/sys/class/gpio/gpio";
    Path.append(QString::number(_pin));
    if (QFile::exists(Path))
    {
        return true;
    }
    return false;
}
