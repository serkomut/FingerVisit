#ifndef RASPBERRYGPIO_H
#define RASPBERRYGPIO_H

#include <QProcess>
#include <QDebug>
#include <QFile>
enum direction
{
    in,
    out
};
enum edge
{
    falling,
    rising,
    both
};
class RaspberryGPIO
{
public:
    RaspberryGPIO();
    bool setup(uint8_t _pin, direction _dir, edge _edge);
    bool close(uint8_t _pin);
    bool isExists(uint8_t _pin);
    uint8_t pin;
    QString ValuePath;
};

#endif // RASPBERRYGPIO_H
