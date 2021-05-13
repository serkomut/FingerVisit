#ifndef FINGERPRINTLIBRARY_H
#define FINGERPRINTLIBRARY_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fingerprintlibrarydefines.h>
#include <qdebug.h>
#include <serialportlibrary.h>
#include <QFileSystemWatcher>
#include <raspberrygpio.h>
#include <QObject>
#include <qthread.h>
#include <QPixmap>
#include <QImage>
#include <QTimer>
class fingerprintlibrary : public QObject
{
    Q_OBJECT
public:
    fingerprintlibrary();
    serialportlibrary *SerialPort;
    QFileSystemWatcher *FingerDetect;
    RaspberryGPIO *FingerDetectPin;
    QTimer *timer;
    uint32_t address;
    uint32_t password;
    QByteArray IncomingBuffer;
    bool manual_settings;
    FPM_System_Params *sys_params;
    uint16_t freeIndexCount;
    bool watchfirst;
    QByteArray image_buffer;
    bool enddata;
    bool fpmstate;
    bool TimeOutValue;

    bool begin(uint32_t pwd, uint32_t addr, uint8_t _pin, qint32 _baud, FPM_System_Params * params=nullptr);
    bool verifyPassword(uint32_t _pwd);
    bool writePacket(uint8_t packettype, QByteArray *packet, uint16_t len);
    int16_t read_ack_get_response(uint8_t * rc);
    int16_t getReply(QByteArray *replyBuf, uint16_t buflen, uint8_t * pktid);
    int16_t readParams(FPM_System_Params * user_params=nullptr);
    bool handshake(void);
    int16_t getImage(void);
    int16_t image2Tz(uint8_t slot);
    int16_t searchDatabase(uint16_t * finger_id, uint16_t * score, uint8_t slot);
    int32_t SearchDBTask();
    int32_t EnrollTask();
    bool get_free_id(uint16_t *fid);
    int16_t getFreeIndex(uint8_t page, uint16_t *id);
    int16_t enroll_finger(uint16_t fid);
    int16_t led_ctl(ledstate _led);
    int16_t createModel(void);
    int16_t storeModel(uint16_t id, uint8_t slot);
    bool get_template_count(uint16_t * count);
    int16_t getTemplateCount(uint16_t * template_cnt);
    int deleteFingerprint(uint16_t fid);
    int16_t deleteModel(uint16_t id, uint16_t how_many = 1);
    bool empty_database(void);
    int16_t emptyDatabase(void);
    bool stream_image(void);
    bool change_baud_rate(uint8_t value);
    int16_t setParam(uint8_t param, uint8_t value);
    bool set_packet_len_128(void);
    int16_t downImage(void);
    bool readRaw(bool * read_complete, uint16_t * read_len ) ;
    QImage PrepareBitmap();
    bool set_pwd(uint32_t pwd);
    int16_t setPassword(uint32_t pwd);
public slots:
    void   FingerDetectSlot(QString);
    void TimeoutSlot();
};

#endif // FINGERPRINTLIBRARY_H
