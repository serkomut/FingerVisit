#include "databasconfiglibrary.h"
databasconfiglibrary::databasconfiglibrary()
{
    configDB = QSqlDatabase::addDatabase("QSQLITE");
}
bool databasconfiglibrary::connectDB(const QString _DBname)
{
    configDB.setDatabaseName(_DBname);
    if(!configDB.open())
    {
        qDebug()<<"DB not connected!";
        return false;
    }
    else
    {
        qDebug()<<"DB connected!";
        return true;
    }
}
bool databasconfiglibrary::readFingerConfigsFromDB(QString _ConfigName)
{
    QSqlQuery query;
    query.prepare("SELECT * FROM FingerPrintConfig WHERE ConfigName = (:ConfigName)");
    query.bindValue(":ConfigName",_ConfigName);
    if (query.exec())
    {
       if (query.next())
       {
           bool ok;
           FPvalues.rowID = query.value("rowID").toString().toInt();
           FPvalues.ConfigName = query.value("ConfigName").toString();
           FPvalues.PortName = query.value("PortName").toString();
           FPParams.baud_rate = query.value("BaudRate").toString().toUInt() &0xffff;
           FPvalues.Password = query.value("Password").toString().toUInt(&ok,16);
           FPParams.device_addr = query.value("Address").toString().toUInt(&ok,16);
           FPParams.packet_len = query.value("PacketLength").toString().toUInt(&ok,16)&0xffff;
           FPParams.capacity = query.value("Capacity").toString().toUInt(&ok,16)&0xffff;
           FPParams.security_level = query.value("SecurityLevel").toString().toUInt(&ok,16)&0xffff;
           FPvalues.IRQPin = query.value("IRQPin").toString().toUInt() & 0xff;
           FPParams.system_id = query.value("SysID").toString().toUInt(&ok,16)&0xffff;
       }
    }
}
