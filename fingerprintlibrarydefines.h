#ifndef FINGERPRINTLIBRARYDEFINES_H
#define FINGERPRINTLIBRARYDEFINES_H
#include <stdint.h>
#include <stddef.h>
#include <QString>

/* R551 is different in a few ways (no high-speed search, off-by-one template indices)
   uncomment this line if you have one of those */
//#define FPM_R551_MODULE

/* Set the debug level
   0: Disabled
   1: Errors only
   2: Everything
 */

#define IMAGE_SZ                    36864UL
#define FPM_DEBUG_LEVEL             1
#define FPM_FINGER_WAIT_TIMER       5000
#define FPM_FINGER_REMOVE_WAIT_TIMER 5000

// confirmation codes
#define FPM_OK                      0x00
#define FPM_HANDSHAKE_OK            0x55
#define FPM_PACKETRECIEVEERR        0x01
#define FPM_NOFINGER                0x02
#define FPM_IMAGEFAIL               0x03
#define FPM_IMAGEMESS               0x06
#define FPM_FEATUREFAIL             0x07
#define FPM_NOMATCH                 0x08
#define FPM_NOTFOUND                0x09
#define FPM_ENROLLMISMATCH          0x0A
#define FPM_BADLOCATION             0x0B
#define FPM_DBREADFAIL              0x0C
#define FPM_UPLOADFEATUREFAIL       0x0D
#define FPM_PACKETRESPONSEFAIL      0x0E
#define FPM_UPLOADFAIL              0x0F
#define FPM_DELETEFAIL              0x10
#define FPM_DBCLEARFAIL             0x11
#define FPM_PASSFAIL                0x13
#define FPM_INVALIDIMAGE            0x15
#define FPM_FLASHERR                0x18
#define FPM_INVALIDREG              0x1A
#define FPM_ADDRCODE                0x20
#define FPM_PASSVERIFY              0x21

// signature and packet ids
#define FPM_STARTCODE             0xEF01

#define FPM_COMMANDPACKET           0x01
#define FPM_DATAPACKET              0x02
#define FPM_ACKPACKET               0x07
#define FPM_ENDDATAPACKET           0x08

// commands
#define FPM_GETIMAGE                0x01
#define FPM_IMAGE2TZ                0x02
#define FPM_REGMODEL                0x05
#define FPM_STORE                   0x06
#define FPM_LOAD                    0x07
#define FPM_UPCHAR                  0x08
#define FPM_DOWNCHAR                0x09
#define FPM_IMGUPLOAD               0x0A
#define FPM_IMGDOWNLOAD             0x0B
#define FPM_DELETE                  0x0C
#define FPM_EMPTYDATABASE           0x0D
#define FPM_SETSYSPARAM             0x0E
#define FPM_READSYSPARAM            0x0F
#define FPM_VERIFYPASSWORD          0x13
#define FPM_SEARCH                  0x04
#define FPM_HISPEEDSEARCH           0x1B
#define FPM_TEMPLATECOUNT           0x1D
#define FPM_READTEMPLATEINDEX       0x1F
#define FPM_PAIRMATCH               0x03
#define FPM_SETPASSWORD             0x12
#define FPM_SETADDRESS              0x15
#define FPM_STANDBY                 0x33
#define FPM_HANDSHAKE               0x53

#define FPM_LEDON                   0x50
#define FPM_LEDOFF                  0x51
#define FPM_LED_CONTROL             0x35
#define FPM_GETIMAGE_NOLIGHT        0x52
#define FPM_GETRANDOM               0x14

/* returned whenever we time out while reading */
#define FPM_TIMEOUT                 -1
/* returned whenever we get an unexpected PID or length */
#define FPM_READ_ERROR              -2
/* returned whenever there's no free ID */
#define FPM_NOFREEINDEX             0xffff

#define FPM_MAX_PACKET_LEN          256
#define FPM_PKT_OVERHEAD_LEN        12

/* 32 is max packet length for ACKed commands, +1 for confirmation code */
#define FPM_BUFFER_SZ               (32 + 1)

/* default timeout is 2 seconds */
#define FPM_DEFAULT_TIMEOUT         2000
#define FPM_TEMPLATES_PER_PAGE      256

#define FPM_DEFAULT_PASSWORD        0x00000000
#define FPM_DEFAULT_ADDRESS         0xFFFFFFFF
#define FPM_DEFAULT_FD_PIN          23

#endif // FINGERPRINTLIBRARYDEFINES_H
/* use these constants when setting system
 * parameters with the setParam() method */
enum {
    FPM_SETPARAM_BAUD_RATE = 4,
    FPM_SETPARAM_SECURITY_LEVEL,
    FPM_SETPARAM_PACKET_LEN
};

/* possible values for system parameters that can be set with setParam() */

/* baud rates */
enum {
    FPM_BAUD_9600 = 1,
    FPM_BAUD_19200,
    FPM_BAUD_28800,
    FPM_BAUD_38400,
    FPM_BAUD_48000,
    FPM_BAUD_57600,
    FPM_BAUD_67200,
    FPM_BAUD_76800,
    FPM_BAUD_86400,
    FPM_BAUD_96000,
    FPM_BAUD_105600,
    FPM_BAUD_115200
};

/* security levels */
enum {
    FPM_FRR_1 = 1,
    FPM_FRR_2,
    FPM_FRR_3,
    FPM_FRR_4,
    FPM_FRR_5
};

/* packet lengths */
enum {
    FPM_PLEN_32,
    FPM_PLEN_64,
    FPM_PLEN_128,
    FPM_PLEN_256,
    FPM_PLEN_NONE = 0xff
};

/* possible output containers for template/image data read from the module */
enum {
    FPM_OUTPUT_TO_STREAM,
    FPM_OUTPUT_TO_BUFFER
};

typedef struct
{
    qint32 rowID;
    QString ConfigName;
    QString PortName;      //must be sure being same in databaseconfiglibrary.h
    uint8_t IRQPin;
    uint32_t Password;
}Fingerprint_Values;

typedef struct {
    uint16_t status_reg;
    uint16_t system_id;
    uint16_t capacity;
    uint16_t security_level;   //must be sure being same in databaseconfiglibrary.h
    uint32_t device_addr;
    uint16_t packet_len;
    uint16_t baud_rate;
} FPM_System_Params;

/* Default parameters to be used with R308 (and similar)

   status_reg: 0x0000,
   system_id: 0x0000,
   capacity: <Your-module-capacity>,
   security_level: FPM_FRR_5,
   device_addr: 0xFFFFFFFF,
   packet_len: FPM_PLEN_128,
   baud_rate: FPM_BAUD_57600

 */
typedef enum {
    FPM_STATE_READ_HEADER1,
    FPM_STATE_READ_HEADER2,
    FPM_STATE_READ_ADDRESS1,
    FPM_STATE_READ_ADDRESS2,
    FPM_STATE_READ_ADDRESS3,
    FPM_STATE_READ_ADDRESS4,
    FPM_STATE_READ_PID,
    FPM_STATE_READ_LENGTH1,
    FPM_STATE_READ_LENGTH2,
    FPM_STATE_READ_CONTENTS,
    FPM_STATE_READ_CHECKSUM1,
    FPM_STATE_READ_CHECKSUM2,
    FPM_STATE_ERROR,
    FPM_STATE_FINISH
} FPM_State;
enum ledstate
{
    on,
    off
};
