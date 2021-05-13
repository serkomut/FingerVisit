#ifndef DATABASCONFIGLIBRARY_H
#define DATABASCONFIGLIBRARY_H
#include <QtSql/QSql>
#include <QtSql/QSqlDatabase>
#include <QDebug>
#include <QSqlQuery>
#include <QSqlRecord>
typedef struct
{
    qint32 rowID;
    QString ConfigName;
    QString PortName;      //must be sure being same in fingerprintlibrary.h
    uint8_t IRQPin;
    uint32_t Password;
}Fingerprint_Values_DB;
typedef struct {
    uint16_t status_reg;
    uint16_t system_id;
    uint16_t capacity;
    uint16_t security_level;  //must be sure being same in fingerprintlibrarydefines.h
    uint32_t device_addr;
    uint16_t packet_len;
    uint16_t baud_rate;
} FPM_System_Params_DB;

class databasconfiglibrary
{
public:
    databasconfiglibrary();
    QSqlDatabase configDB;
    Fingerprint_Values_DB FPvalues;
    FPM_System_Params_DB FPParams;
    bool connectDB(const QString _DBname);
    bool readFingerConfigsFromDB(QString _configName);
};

#endif // DATABASCONFIGLIBRARY_H
