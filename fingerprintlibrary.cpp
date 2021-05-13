#include "fingerprintlibrary.h"

fingerprintlibrary::fingerprintlibrary()
{
    SerialPort = new serialportlibrary;
    sys_params = new FPM_System_Params;
    FingerDetectPin = new RaspberryGPIO;
    timer = new QTimer(this);
    TimeOutValue=false;
    connect(timer, SIGNAL(timeout()), this, SLOT(TimeoutSlot()));
    //timer->start(10000);

}
bool fingerprintlibrary::begin(uint32_t pwd, uint32_t addr, uint8_t _pin, qint32 _baud, FPM_System_Params * params)
{
    qDebug()<<_baud<<"aaaaaa";
    fpmstate=false;
    watchfirst=true;//for irq
    if(SerialPort->OpenPort("ttyUSB0",_baud))
    {
        qDebug()<<"PORT OPENED!";
    }
    else
    {
        qDebug()<<"PORT CAN'T OPENED!";
    }
    address = addr;
    password=pwd;
    if(!verifyPassword(password))
    {
        SerialPort->ClosePort();
        qDebug()<<"WRONG PASSWORD!";
        return false;
    }
    qDebug()<<"PASSWORD CORRECTED!";
    if (readParams(params) != FPM_OK)
    {
        SerialPort->ClosePort();
        qDebug()<<"PARAMETERS CAN'T READED";
        return false;
    }
//    if(FingerDetectPin->isExists(_pin))
//    {
//        FingerDetectPin->close(_pin);
//    }
//    FingerDetectPin->setup(_pin,in,falling);
//    FingerDetect->addPath(FingerDetectPin->ValuePath);
//    if(FingerDetectPin->isExists(_pin))
//    {
//    //connect(FingerDetect, SIGNAL (fileChanged(QString)),this, SLOT(FingerDetectSlot(QString)));
//    }
    qDebug()<<"status_reg"<<QString::number(params->status_reg,16);
    qDebug()<<"system_id"<<QString::number(params->system_id,16);
    qDebug()<<"capacity"<<QString::number(params->capacity,16);
    qDebug()<<"security_level"<<QString::number(params->security_level,16);
    qDebug()<<"packet_len"<<QString::number(params->packet_len,16);
    qDebug()<<"baud_rate"<<QString::number(params->baud_rate,16);
    qDebug()<<"device_addr"<<QString::number(params->device_addr,16);

    uint16_t fid;
    get_free_id(&fid);
    get_template_count(&fid);
    fpmstate=true;
    return true;
}
bool fingerprintlibrary::verifyPassword(uint32_t _pwd)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_VERIFYPASSWORD);
    SendDataContent.append((_pwd >> 24) & 0xff);
    SendDataContent.append((_pwd >> 16) & 0xff);
    SendDataContent.append((_pwd >> 8) & 0xff);
    SendDataContent.append(_pwd & 0xff);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 5);
    uint8_t confirm_code = 0;
    int16_t len = read_ack_get_response(&confirm_code);
    if (len < 0 || confirm_code != FPM_OK)
    {
        return false;
    }
    return true;
}
bool fingerprintlibrary::writePacket(uint8_t packettype, QByteArray * packet, uint16_t len)
{
    QByteArray SendData;
    len+=2;
    SendData.clear();
    SendData.append((FPM_STARTCODE>>8)& 0xff);
    SendData.append(FPM_STARTCODE & 0xff);
    SendData.append((address >> 24) & 0xff);
    SendData.append((address >> 16) & 0xff);
    SendData.append((address >> 8) & 0xff);
    SendData.append(address & 0xff);
    SendData.append(packettype);
    SendData.append((len>>8)& 0xff);
    SendData.append(len & 0xff);
    uint16_t sum = ((len>>8)& 0xff) + (len&0xFF) + packettype;
    for (uint8_t i=0; i< len-2; i++)
    {
        SendData.append(packet->at(i));
        sum += packet->at(i);
    }
    SendData.append((sum>>8)& 0xff);
    SendData.append(sum & 0xff);
    //qDebug()<<SendData.toHex(' ');
    SerialPort->Write(SendData);
    return true;
}
int16_t fingerprintlibrary::read_ack_get_response(uint8_t * rc)
{
    uint8_t pktid = 0;
    int16_t len = getReply(&IncomingBuffer, FPM_BUFFER_SZ, &pktid);
    if (len < 0)
    {
        return len;
    }
    if (pktid != FPM_ACKPACKET)
    {
        return FPM_READ_ERROR;
    }
    *rc=IncomingBuffer.at(9);
    return --len;
}
int16_t fingerprintlibrary::getReply(QByteArray * replyBuf, uint16_t buflen, uint8_t * pktid)
{
    FPM_State state = FPM_STATE_READ_HEADER1;
    IncomingBuffer.clear();
    uint16_t header = 0;
    uint8_t pid = 0;
    uint16_t length = 0;
    uint16_t chksum = 0;
    uint16_t remn = 0;
    uint32_t addr=0;
    char buffer;
    uint16_t to_check;
    while ((state!=FPM_STATE_ERROR)&&(state!=FPM_STATE_FINISH))
    {
        switch (state)
        {
            case FPM_STATE_READ_HEADER1:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    state = FPM_STATE_READ_HEADER2;
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        state = FPM_STATE_READ_HEADER2;
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_HEADER2:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    header=replyBuf->at(0);
                    header <<= 8; header |= replyBuf->at(1);
                    if(header != FPM_STARTCODE)
                    {
                        state = FPM_STATE_ERROR;
                        return FPM_READ_ERROR;
                        break;
                    }
                    else
                    {
                        state = FPM_STATE_READ_ADDRESS1;
                    }
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        header=replyBuf->at(0);
                        header <<= 8; header |= replyBuf->at(1);
                        if(header != FPM_STARTCODE)
                        {
                            state = FPM_STATE_ERROR;
                            return FPM_READ_ERROR;
                            break;
                        }
                        else
                        {
                            state = FPM_STATE_READ_ADDRESS1;
                        }
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_ADDRESS1:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    state = FPM_STATE_READ_ADDRESS2;
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        state = FPM_STATE_READ_ADDRESS2;
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_ADDRESS2:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    state = FPM_STATE_READ_ADDRESS3;
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        state = FPM_STATE_READ_ADDRESS3;
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_ADDRESS3:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    state = FPM_STATE_READ_ADDRESS4;
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        state = FPM_STATE_READ_ADDRESS4;
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_ADDRESS4:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);

                    addr=replyBuf->at(2);
                    addr <<= 8; addr |= replyBuf->at(3);
                    addr <<= 8; addr |= replyBuf->at(4);
                    addr <<= 8; addr |= replyBuf->at(5);
                    if (addr != address)
                    {
                        state = FPM_STATE_ERROR;
                        return FPM_READ_ERROR;
                        break;
                    }
                    else
                    {
                        state = FPM_STATE_READ_PID;
                    }

                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);


                        addr=replyBuf->at(2);
                        addr <<= 8; addr |= replyBuf->at(3);
                        addr <<= 8; addr |= replyBuf->at(4);
                        addr <<= 8; addr |= replyBuf->at(5);
                        if (addr != address)
                        {
                            state = FPM_STATE_ERROR;
                            return FPM_READ_ERROR;
                            break;
                        }
                        else
                        {
                            state = FPM_STATE_READ_PID;
                        }
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_PID:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    pid=replyBuf->at(6);
                    if(pid==FPM_ENDDATAPACKET)
                    {
                        //qDebug()<<"bitiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii";
                        enddata=true;
                    }
                    else if(pid==FPM_DATAPACKET)
                    {
                        //qDebug()<<"basliyooorrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr!!!";
                        enddata=false;
                    }
                    chksum = pid;
                    *pktid = pid;
                    state = FPM_STATE_READ_LENGTH1;
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        pid=replyBuf->at(6);
                        chksum = pid;
                        *pktid = pid;
                        state = FPM_STATE_READ_LENGTH1;
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_LENGTH1:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    state = FPM_STATE_READ_LENGTH2;
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        state = FPM_STATE_READ_LENGTH2;
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_LENGTH2:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    length=replyBuf->at(7);
                    length <<= 8; length |= replyBuf->at(8);
                    if ((length > FPM_MAX_PACKET_LEN + 2) || ( length > buflen + 2))
                    {
                        state = FPM_STATE_ERROR;
                        return FPM_READ_ERROR;
                        break;
                    }
                    else
                    {
                        remn=length;
                        chksum += replyBuf->at(7); chksum+=replyBuf->at(8);
                        state = FPM_STATE_READ_CONTENTS;
                    }
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        length=replyBuf->at(7);
                        length <<= 8; length |= replyBuf->at(8);
                        if ((length > FPM_MAX_PACKET_LEN + 2) || ( length > buflen + 2))
                        {
                            state = FPM_STATE_ERROR;
                            return FPM_READ_ERROR;
                            break;
                        }
                        else
                        {
                            remn=length;
                            chksum += replyBuf->at(7); chksum+=replyBuf->at(8);
                            state = FPM_STATE_READ_CONTENTS;
                        }
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_CONTENTS:
            {
                if (remn <= 2)
                {
                    state = FPM_STATE_READ_CHECKSUM1;
                    break;
                }
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    chksum += replyBuf->at(9+length-remn);
                    remn--;

                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        chksum += replyBuf->at(9+length-remn);
                        remn--;

                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_CHECKSUM1:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    state = FPM_STATE_READ_CHECKSUM2;
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        state = FPM_STATE_READ_CHECKSUM2;
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_READ_CHECKSUM2:
            {
                if(SerialPort->SerialPort->read(&buffer,1))
                {
                    replyBuf->append(buffer);
                    to_check=replyBuf->at(7+length);
                    to_check <<= 8; to_check |= replyBuf->at(8+length);
                    if(to_check != chksum)
                    {
                        state = FPM_STATE_ERROR;
                        return FPM_READ_ERROR;
                        break;
                    }
                    else
                    {
                        state = FPM_STATE_FINISH;
                        int16_t tmp =-2;
                        //qDebug()<<"aldimmm"<<IncomingBuffer<<"state:"<<state<<"header:"<<header<<"addr:"<<addr<<"pid:"<<pid<<"len:"<<length<<"csum:"<<chksum<<"remn:"<<remn<<"tochk:"<<to_check;
                        return length + tmp;
                    }
                }
                else if(SerialPort->SerialPort->waitForReadyRead(FPM_DEFAULT_TIMEOUT))
                {
                    if(SerialPort->SerialPort->read(&buffer,1))
                    {
                        replyBuf->append(buffer);
                        to_check=replyBuf->at(7+length);
                        to_check <<= 8; to_check |= replyBuf->at(8+length);
                        if(to_check != chksum)
                        {
                            state = FPM_STATE_ERROR;
                            return FPM_READ_ERROR;
                            break;
                        }
                        else
                        {
                            state = FPM_STATE_FINISH;
                            int16_t tmp =-2;
                            return length + tmp;
                        }
                    }
                }
                else
                {
                    state = FPM_STATE_ERROR;
                    return FPM_TIMEOUT;
                }
                break;
            }
            case FPM_STATE_ERROR:
            {
                //qDebug()<<"hataaaaaaaa"<<replyBuf<<"state:"<<state<<"header:"<<header<<"addr:"<<addr<<"pid:"<<pid<<"len:"<<length<<"csum:"<<chksum<<"remn:"<<remn<<"tochk:"<<to_check;
                break;
            }
            case FPM_STATE_FINISH:
            {
                //qDebug()<<"aldimmm"<<replyBuf<<"state:"<<state<<"header:"<<header<<"addr:"<<addr<<"pid:"<<pid<<"len:"<<length<<"csum:"<<chksum<<"remn:"<<remn<<"tochk:"<<to_check;
                break;
            }
        }

    }
    //

    return FPM_TIMEOUT;
}
int16_t fingerprintlibrary::readParams(FPM_System_Params * user_params)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_READSYSPARAM);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 1);
    uint8_t confirm_code = 0;
    int16_t len = read_ack_get_response(&confirm_code);
    if (len < 0)
    {
        return len;
    }
    if (confirm_code != FPM_OK)
    {
            return confirm_code;
    }
    if (len != 16)
    {
        return FPM_READ_ERROR;
    }
    qDebug()<<"asdadsasd:"<<IncomingBuffer.toHex(' ');
    user_params->status_reg=IncomingBuffer.at(10);
    user_params->status_reg <<=8; user_params->status_reg |= IncomingBuffer.at(11);


    user_params->system_id=IncomingBuffer.at(12);
    user_params->system_id <<=8; user_params->system_id |= IncomingBuffer.at(13);

    user_params->capacity=IncomingBuffer.at(14);
    user_params->capacity <<=8; user_params->capacity |= IncomingBuffer.at(15);

    user_params->security_level=IncomingBuffer.at(16);
    user_params->security_level <<=8; user_params->security_level |= IncomingBuffer.at(17);

    user_params->packet_len=IncomingBuffer.at(22);
    user_params->packet_len <<=8; user_params->packet_len |= IncomingBuffer.at(23);

    user_params->baud_rate=IncomingBuffer.at(24);
    user_params->baud_rate <<=8; user_params->baud_rate |= IncomingBuffer.at(25);

    user_params->device_addr=IncomingBuffer.at(18);
    user_params->device_addr <<=8; user_params->device_addr |= IncomingBuffer.at(19);
    user_params->device_addr <<=8; user_params->device_addr |= IncomingBuffer.at(20);
    user_params->device_addr <<=8; user_params->device_addr |= IncomingBuffer.at(21);

    return confirm_code;
}
bool fingerprintlibrary::handshake(void)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_HANDSHAKE);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 1);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);
    if (rc < 0)
        return false;

    return confirm_code == FPM_HANDSHAKE_OK;
}
int16_t fingerprintlibrary::getImage(void)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_GETIMAGE);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 1);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);

    if (rc < 0)
        return rc;

    return confirm_code;
}
int16_t fingerprintlibrary::image2Tz(uint8_t slot)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_IMAGE2TZ);
    SendDataContent.append(slot);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 2);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);

    if (rc < 0)
        return rc;

    return confirm_code;
}
int16_t fingerprintlibrary::searchDatabase(uint16_t * finger_id, uint16_t * score, uint8_t slot) {
    /* search from ID 0 to 'capacity' */
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_SEARCH);
    SendDataContent.append(slot);
    uint8_t tmpint=0;
    SendDataContent.append(tmpint);
    SendDataContent.append(tmpint);

    SendDataContent.append(sys_params->capacity >> 8);
    SendDataContent.append(sys_params->capacity & 0xFF);

    writePacket(FPM_COMMANDPACKET, &SendDataContent, 6);
    uint8_t confirm_code = 0;
    int16_t len = read_ack_get_response(&confirm_code);

    if (len < 0)
        return len;

    if (confirm_code != FPM_OK)
        return confirm_code;

    if (len != 4)
        return FPM_READ_ERROR;

    *finger_id = IncomingBuffer.at(10);
    *finger_id <<= 8;
    *finger_id |= IncomingBuffer.at(11);

    *score = IncomingBuffer.at(12);
    *score <<= 8;
    *score |= IncomingBuffer.at(13);

    return confirm_code;
}
void fingerprintlibrary::FingerDetectSlot(QString gpio_val)
{
    if(watchfirst)
    {
        watchfirst=false;
    }
    else
    {
        //disconnect(FingerDetect, SIGNAL (fileChanged(QString)),this, SLOT(FingerDetectSlot(QString)));
        qDebug()<<"finger detected"<<gpio_val;
        qDebug()<<"asdasdas"<<SearchDBTask();
        QThread::msleep(500);
        qDebug()<<"ciktim!!!";
        //connect(FingerDetect, SIGNAL (fileChanged(QString)),this, SLOT(FingerDetectSlot(QString)));
    }
}
int32_t fingerprintlibrary::SearchDBTask()
{
    if(fpmstate==true)
    {
        int32_t tmp;
        int16_t p = -1;
        timer->start(FPM_FINGER_WAIT_TIMER);
        while (p != FPM_OK)
        {
            QThread::msleep(100);
            p = getImage();
            if(timer->remainingTime()==0)
            {
                return FPM_TIMEOUT;
            }
            switch (p)
            {
                case FPM_OK:
                {
                    qDebug()<<"Image Taken";
                    break;
                }
                case FPM_NOFINGER:
                {
                    qDebug()<<"Finger is missed"<<timer->remainingTime();
                    break;
                }
                case FPM_PACKETRECIEVEERR:
                    {
                    qDebug()<<"Communication error";
                    return p;
                    break;
                }
                case FPM_IMAGEFAIL:
                    {
                    qDebug()<<"Imaging error";
                    return p;
                    break;
                }
                case FPM_TIMEOUT:
                    {
                    qDebug()<<"Timeout!";
                    return p;
                    break;
                }
                case FPM_READ_ERROR:
                    {
                    qDebug()<<"Got wrong PID or length!";
                    return p;
                    break;
                }
                default:
                {
                    qDebug()<<"Unknown error";
                    return p;
                    break;
                }
            }
        }
        timer->stop();
        p = image2Tz(1);
        switch (p)
        {
            case FPM_OK:
            {
                qDebug()<<"Image converted";
                break;
            }
            case FPM_IMAGEMESS:
                {
                qDebug()<<"Image too messy";
                return p;
            }
            case FPM_PACKETRECIEVEERR:
                {
                qDebug()<<"Communication error";
                return p;
            }
            case FPM_FEATUREFAIL:
                {
                qDebug()<<"Could not find fingerprint features";
                return p;
            }
            case FPM_INVALIDIMAGE:
                {
                qDebug()<<"Could not find fingerprint features";
                return p;
            }
            case FPM_TIMEOUT:
                {
                qDebug()<<"Timeout!";
                return p;
            }
            case FPM_READ_ERROR:
                {
                qDebug()<<"Got wrong PID or length!";
                return p;
            }
            default:
            {
                qDebug()<<"Unknown error";
                return p;
            }
        }
        uint16_t fid, score;
        p = searchDatabase(&fid, &score,1);
        timer->start(FPM_FINGER_REMOVE_WAIT_TIMER);
        while (getImage() != FPM_NOFINGER)
        {
            if(timer->remainingTime()==0)
            {
                return FPM_TIMEOUT;
            }
            QThread::msleep(500);
            qDebug()<<"REMOVE FINGER"<<timer->remainingTime();
        }
        timer->stop();
        if (p == FPM_OK)
        {
            qDebug()<<"Found a print match!";
        }
        else if (p == FPM_PACKETRECIEVEERR)
        {
            qDebug()<<"Communication error";
            return p;
        }
        else if (p == FPM_NOTFOUND)
        {
            qDebug()<<"Did not find a match";
            return p;
        }
        else if (p == FPM_TIMEOUT)
        {
            qDebug()<<"Timeout!";
            return p;
        }
        else if (p == FPM_READ_ERROR)
        {
            qDebug()<<"Got wrong PID or length!";
            return p;
        }
        else
        {
            qDebug()<<"Unknown error";
            return p;
        }
        qDebug()<<"Found ID #"<<fid;
        qDebug()<<"with confidence of"<<score;
        tmp=fid;
        tmp <<=8;
        tmp |=score;
        return tmp;
    }
    else
    {
        return false;
    }
}
int32_t fingerprintlibrary::EnrollTask()
{
    uint16_t fid;
    if (get_free_id(&fid))
            enroll_finger(fid);
        else
            qDebug()<<"No free slot in flash library!";
    return 0;
}
bool fingerprintlibrary::get_free_id(uint16_t *fid)
{
    int16_t p = -1;
        for (uint8_t page = 0; page < (sys_params->capacity / FPM_TEMPLATES_PER_PAGE) + 1; page++)
        {
            p = getFreeIndex(page, fid);
            switch (p)
            {
                case FPM_OK:
                {
                    if (*fid != FPM_NOFREEINDEX) {
                        qDebug()<<"Free slot at ID :"<<*fid;
                        return true;
                    }
                }
                case FPM_PACKETRECIEVEERR:
                {
                    qDebug()<<"Communication error!";
                    return false;
                }
                case FPM_TIMEOUT:
                {
                    qDebug()<<"Timeout!";
                    return false;
                }
                case FPM_READ_ERROR:
                {
                    qDebug()<<"Got wrong PID or length!";
                    return false;
                }
                default:
                {
                    qDebug()<<"Unknown error!";
                    return false;
                }
            }
        }
        return false;
}
int16_t  fingerprintlibrary::getFreeIndex(uint8_t page, uint16_t * id)
{
    //uint16_t idu;
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_READTEMPLATEINDEX);
    SendDataContent.append(page);

    writePacket(FPM_COMMANDPACKET, &SendDataContent, 2);
    uint8_t confirm_code = 0;

    int16_t len = read_ack_get_response(&confirm_code);
    if (len < 0)
        return len;

    if (confirm_code != FPM_OK)
        return confirm_code;

    for (uint16_t group_idx = 0; group_idx < len; group_idx++)
    {
        uint8_t group = IncomingBuffer.at(10+group_idx); //buffer[1 + group_idx];
        if (group == 0xff)        // if group is all occupied
            continue;

        for (uint8_t bit_mask = 0x01, fid = 0; bit_mask != 0; bit_mask <<= 1, fid++)
        {
            if ((bit_mask & group) == 0)
            {
                *id =(FPM_TEMPLATES_PER_PAGE * page) + (group_idx * 8) + fid;
                return confirm_code;
            }
        }
    }
    *id = FPM_NOFREEINDEX;  // no free space found
    return confirm_code;
}
int16_t fingerprintlibrary::enroll_finger(uint16_t fid)
{
    int16_t p = -1;
    qDebug()<<"Waiting for valid finger to enroll";
    timer->start(FPM_FINGER_WAIT_TIMER);
    while (p != FPM_OK)
    {
        if(timer->remainingTime()==0)
        {
            return FPM_TIMEOUT;
        }
        p = getImage();
        switch (p)
        {
            case FPM_OK:
            {
                qDebug()<<"Image taken";
                break;
            }
            case FPM_NOFINGER:
            {
                qDebug()<<".";
                break;
            }
            case FPM_PACKETRECIEVEERR:
            {
                qDebug()<<"Communication error";
                break;
            }
            case FPM_IMAGEFAIL:
            {
                qDebug()<<"Imaging error";
                break;
            }
            case FPM_TIMEOUT:
            {
                qDebug()<<"Timeout!";
                break;
            }
            case FPM_READ_ERROR:
            {
                qDebug()<<"Got wrong PID or length!";
                break;
            }
            default:
            {
                qDebug()<<"Unknown error";
                break;
            }
        }
    }
    timer->stop();
    p = image2Tz(1);
    switch (p)
    {
        case FPM_OK:
        {
            qDebug()<<"Image converted";
            break;
        }
        case FPM_IMAGEMESS:
        {
            qDebug()<<"Image too messy";
            return p;
        }
        case FPM_PACKETRECIEVEERR:
        {
            qDebug()<<"Communication error";
            return p;
        }
        case FPM_FEATUREFAIL:
        {
            qDebug()<<"Could not find fingerprint features";
            return p;
        }
        case FPM_INVALIDIMAGE:
        {
            qDebug()<<"Could not find fingerprint features";
            return p;
        }
        case FPM_TIMEOUT:
        {
            qDebug()<<"Timeout!";
            return p;
        }
        case FPM_READ_ERROR:
        {
            qDebug()<<"Got wrong PID or length!";
            return p;
        }
        default:
        {
            qDebug()<<"Unknown error";
            return p;
        }
    }
    qDebug()<<"Remove finger";
    //delay2000 vardı
    p = 0;
    timer->start(FPM_FINGER_REMOVE_WAIT_TIMER);
    while (p != FPM_NOFINGER)
    {
        if(timer->remainingTime()==0)
        {
            return FPM_TIMEOUT;
        }
        p = getImage();
    }
    timer->stop();
    p = -1;
    qDebug()<<"Place same finger again";
    timer->start(FPM_FINGER_WAIT_TIMER);
    while (p != FPM_OK)
    {
        if(timer->remainingTime()==0)
        {
            return FPM_TIMEOUT;
        }
        p = getImage();
        switch (p)
        {
            case FPM_OK:
            {
                qDebug()<<"Image taken";
                break;
            }
            case FPM_NOFINGER:
            {
                qDebug()<<".";
                break;
            }
            case FPM_PACKETRECIEVEERR:
            {
                qDebug()<<"Communication error";
                break;
            }
            case FPM_IMAGEFAIL:
            {
                qDebug()<<"Imaging error";
                break;
            }
            case FPM_TIMEOUT:
            {
                qDebug()<<"Timeout!";
                break;
            }
            case FPM_READ_ERROR:
            {
                qDebug()<<"Got wrong PID or length!";
                break;
            }
            default:
            {
                qDebug()<<"Unknown error";
                break;
            }
        }
    }
    timer->stop();
    p = image2Tz(2);
    switch (p)
    {
        case FPM_OK:
        {
            qDebug()<<"Image converted";
            break;
        }
        case FPM_IMAGEMESS:
        {
            qDebug()<<"Image too messy";
            return p;
        }
        case FPM_PACKETRECIEVEERR:
        {
            qDebug()<<"Communication error";
            return p;
        }
        case FPM_FEATUREFAIL:
        {
            qDebug()<<"Could not find fingerprint features";
            return p;
        }
        case FPM_INVALIDIMAGE:
        {
            qDebug()<<"Could not find fingerprint features";
            return p;
        }
        case FPM_TIMEOUT:
        {
            qDebug()<<"Timeout!";
            return false;
        }
        case FPM_READ_ERROR:
        {
            qDebug()<<"Got wrong PID or length!";
            return false;
        }
        default:
        {
            qDebug()<<"Unknown error";
            return p;
        }
    }
    p = createModel();
    if (p == FPM_OK)
    {
        qDebug()<<"Prints matched!";
    }
    else if (p == FPM_PACKETRECIEVEERR)
    {
        qDebug()<<"Communication error";
        return p;
    }
    else if (p == FPM_ENROLLMISMATCH)
    {
        qDebug()<<"Fingerprints did not match";
        return p;
    }
    else if (p == FPM_TIMEOUT)
    {
        qDebug()<<"Timeout!";
        return p;
    }
    else if (p == FPM_READ_ERROR)
    {
        qDebug()<<"Got wrong PID or length!";
        return p;
    }
    else
    {
        qDebug()<<"Unknown error";
        return p;
    }

    qDebug()<<"ID "<<fid;
    p = storeModel(fid,1);
    if (p == FPM_OK)
    {
        qDebug()<<"Stored!";
        return 0;
    }
    else if (p == FPM_PACKETRECIEVEERR) {
        qDebug()<<"Communication error";
        return p;
    }
    else if (p == FPM_BADLOCATION) {
        qDebug()<<"Could not store in that location";
        return p;
    }
    else if (p == FPM_FLASHERR) {
        qDebug()<<"Error writing to flash";
        return p;
    }
    else if (p == FPM_TIMEOUT) {
        qDebug()<<"Timeout!";
        return p;
    }
    else if (p == FPM_READ_ERROR) {
        qDebug()<<"Got wrong PID or length!";
        return p;
    }
    else {
        qDebug()<<"Unknown error";
        return p;
    }
}
int16_t fingerprintlibrary::storeModel(uint16_t id, uint8_t slot)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_STORE);
    SendDataContent.append(slot);
    SendDataContent.append(id>>8);
    SendDataContent.append(id & 0xFF);

    writePacket(FPM_COMMANDPACKET, &SendDataContent, 4);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);

    if (rc < 0)
        return rc;

    return confirm_code;
}
int16_t fingerprintlibrary::createModel(void)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_REGMODEL);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 1);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);

    if (rc < 0)
        return rc;

    return confirm_code;
}
int16_t fingerprintlibrary::led_ctl(ledstate _led)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    if(_led ==on)
        SendDataContent.append(FPM_LEDON);
    else
        SendDataContent.append(FPM_LEDOFF);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 1);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);
    qDebug()<<IncomingBuffer;
    if (rc < 0)
        return rc;

    return confirm_code;
}
bool fingerprintlibrary::get_template_count(uint16_t * count)
{
    int16_t p = getTemplateCount(count);
    if (p == FPM_OK)
    {
        freeIndexCount= *count;
        qDebug()<<"Filled Memory:"<<freeIndexCount;
        return true;
    }
    else
    {
        qDebug()<<"Unknown error: "<<p;
        return false;
    }
}
int16_t fingerprintlibrary::getTemplateCount(uint16_t *template_cnt)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_TEMPLATECOUNT);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 1);
    uint8_t confirm_code = 0;

    int16_t len = read_ack_get_response(&confirm_code);

    if (len < 0)
        return len;

    if (confirm_code != FPM_OK)
        return confirm_code;

    if (len != 2)
        return FPM_READ_ERROR;
    *template_cnt = IncomingBuffer.at(10);
    *template_cnt <<= 8;
    *template_cnt |= IncomingBuffer.at(11);
    return confirm_code;
}
int fingerprintlibrary::deleteFingerprint(uint16_t fid)
{
    int p = -1;

    p = deleteModel(fid);

    if (p == FPM_OK)
    {
        qDebug()<<"Deleted!"<<fid;
        return p;
    }
    else if (p == FPM_PACKETRECIEVEERR)
    {
        qDebug()<<"Communication error";
        return p;
    }
    else if (p == FPM_BADLOCATION)
    {
        qDebug()<<"Could not delete in that location";
        return p;
    }
    else if (p == FPM_FLASHERR)
    {
        qDebug()<<"Error writing to flash";
        return p;
    }
    else if (p == FPM_TIMEOUT)
    {
        qDebug()<<"Timeout!";
        return p;
    }
    else if (p == FPM_READ_ERROR)
    {
        qDebug()<<"Got wrong PID or length!";
        return p;
    }
    else
    {
        qDebug()<<"Unknown error: 0x"<<p;
        return p;
    }
}
int16_t fingerprintlibrary::deleteModel(uint16_t id, uint16_t how_many)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_DELETE);
    SendDataContent.append(id>>8);
    SendDataContent.append(id & 0xFF);
    SendDataContent.append(how_many>>8);
    SendDataContent.append(how_many & 0xFF);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 5);

    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);

    if (rc < 0)
        return rc;

    return confirm_code;
}
bool fingerprintlibrary::empty_database(void)
{
    int16_t p = emptyDatabase();
    if (p == FPM_OK)
    {
        qDebug()<<"Database empty!";
        return true;
    }
    else if (p == FPM_PACKETRECIEVEERR)
    {
        qDebug()<<"Communication error!";
    }
    else if (p == FPM_DBCLEARFAIL)
    {
        qDebug()<<"Could not clear database!";
    }
    else if (p == FPM_TIMEOUT)
    {
        qDebug()<<"Timeout!";
    }
    else if (p == FPM_READ_ERROR)
    {
        qDebug()<<"Got wrong PID or length!";
    }
    else {
        qDebug()<<"Unknown error";
    }
    return false;
}
int16_t fingerprintlibrary::emptyDatabase(void)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_EMPTYDATABASE);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 1);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);

    if (rc < 0)
        return rc;

    return confirm_code;
}
bool fingerprintlibrary::stream_image(void)
{
    if(sys_params->packet_len != FPM_PLEN_256)
    {
        if (!set_packet_len_128())
        {
            qDebug()<<"Could not set packet length";
            return false;
        }
    }
    QThread::msleep(100);
    int16_t p = -1;
    qDebug()<<"Waiting for a finger...";
    timer->start(FPM_FINGER_WAIT_TIMER);
    while (p != FPM_OK)
    {
        if(timer->remainingTime()==0)
        {
            return false;
        }
        p = getImage();
        switch (p)
        {
            case FPM_OK:
            {
                qDebug()<<"Image taken";
                break;
            }
            case FPM_NOFINGER:
            {
                break;
            }
            case FPM_PACKETRECIEVEERR:
            {
                qDebug()<<"Communication error";
                break;
            }
            case FPM_IMAGEFAIL:
            {
                qDebug()<<"Imaging error";
                break;
            }
            default:
            {
                qDebug()<<"Unknown error";
                break;
            }
        }
    }
    timer->stop();

    p = downImage();
    switch (p)
    {
        case FPM_OK:
        {
            qDebug()<<"Starting image stream...";
            break;
        }
        case FPM_PACKETRECIEVEERR:
        {
            qDebug()<<"Communication error";
            return false;
        }
        case FPM_UPLOADFAIL:
        {
            qDebug()<<"Cannot transfer the image";
            return false;
        }
    }
    bool read_finished;
    uint16_t readlen = IMAGE_SZ;
    uint16_t pos = 0;
    int16_t count = 0;
    image_buffer.clear();
    while (true)
    {
        bool ret = readRaw(&read_finished, &readlen);
        if (ret)
        {
            QByteArray tmparray;
            tmparray.clear();
            tmparray.append(IncomingBuffer.remove(0,9).remove(256,2));
            int maxcount=IncomingBuffer.length();
            for (int i=0;i<maxcount;i++)
            {
                image_buffer.append(tmparray.at(i) & 0xf0);
                image_buffer.append((IncomingBuffer.at(i)&0x0f) << 4) ;
            }
            //image_buffer.append(IncomingBuffer.remove(0,9).remove(256,2));//old
            count++;
            pos += readlen;
            readlen = IMAGE_SZ - pos;
            if (read_finished)
                break;
        }
        else
        {
            qDebug()<<"\r\nError receiving packet ";
            qDebug()<<count;
            return false;
        }
    }
    qDebug()<<"Streaming was succesful!";
    return true;
}
bool fingerprintlibrary::readRaw(bool * read_complete, uint16_t * read_len )
{
    uint8_t pid;
    int16_t len;
    len = getReply(&IncomingBuffer, *read_len, &pid);
    if (len <= 0)
    {
        qDebug()<<"Wrong read length: "<<len;
        return false;
    }
    *read_complete = false;
    if (pid == FPM_DATAPACKET || pid == FPM_ENDDATAPACKET)
    {
        *read_len = (uint16_t)len;

        if (enddata == true)
        {
            *read_complete = true;
        }
        return true;
    }
    return false;
}
bool fingerprintlibrary::change_baud_rate(uint8_t value)
{
    uint8_t param = FPM_SETPARAM_BAUD_RATE;
    int16_t p = setParam(param, value);
    switch (p)
    {
        case FPM_OK:
        {
            qDebug()<<"Baud rate set to 9600 successfully";
            SerialPort->ClosePort();
            break;
        }
        case FPM_PACKETRECIEVEERR:
        {
            qDebug()<<"Comms error";
            return false;
        }
        case FPM_INVALIDREG:
        {
            qDebug()<<"Invalid settings!";
            return false;
        }
        default:
        {
            qDebug()<<"Unknown error "<<p;
            return false;
        }
    }
    return true;
}
int16_t fingerprintlibrary::setParam(uint8_t param, uint8_t value)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_SETSYSPARAM);
    SendDataContent.append(param);
    SendDataContent.append(value);

    writePacket(FPM_COMMANDPACKET, &SendDataContent, 3);
    uint8_t confirm_code = 0;
    int16_t len = read_ack_get_response(&confirm_code);

    if (len < 0)
        return len;

    if (confirm_code != FPM_OK)
        return confirm_code;

    QThread::msleep(100);
    readParams(sys_params);
    return confirm_code;
}
bool fingerprintlibrary::set_packet_len_128(void)
{
    uint8_t param = FPM_SETPARAM_PACKET_LEN;
    uint8_t value = FPM_PLEN_256;
    int16_t p = setParam(param, value);
    qDebug()<<IncomingBuffer.toHex(' ');
    switch (p)
    {
        case FPM_OK:
        {
            qDebug()<<"Packet length set to 128 bytes";
            break;
        }
        case FPM_PACKETRECIEVEERR:
        {
            qDebug()<<"Comms error";
            break;
        }
        case FPM_INVALIDREG:
        {
            qDebug()<<"Invalid settings!";
            break;
        }
        default:
        {
            qDebug()<<"Unknown error";
        }
    }

    return (p == FPM_OK);
}
int16_t fingerprintlibrary::downImage(void)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_IMGUPLOAD);
    writePacket(FPM_COMMANDPACKET, &SendDataContent, 1);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);

    if (rc < 0)
        return rc;

    return confirm_code;
}
QImage fingerprintlibrary::PrepareBitmap()
{
    QImage img(160, 160, QImage::Format_Grayscale8);
    for(int row = 0; row < img.height(); row++)
    {
        for(int col = 0; col < img.width(); col++)
        {
            int color = image_buffer[row * img.width() + col];
            img.setPixel(col, 160 - row - 1, qRgb(color, color, color));
        }
    }
    return img;
}
void fingerprintlibrary::TimeoutSlot()
{
    qDebug()<<"TimeOut!";
    TimeOutValue=true;
    timer->stop();
}
bool fingerprintlibrary::set_pwd(uint32_t pwd) {
    int16_t ret = setPassword(pwd);
    switch (ret)
    {
        case FPM_OK:
        {
            qDebug()<<"Password changed successfully. Will take hold next time you call begin().";
            SerialPort->ClosePort();
            break;
        }
        case FPM_PACKETRECIEVEERR:
        {
            qDebug()<<"Comms error!";
            break;
        }
        default:
        {
            qDebug()<<"Unknown error";
            break;
        }
    }
    return (ret == FPM_OK);
}
int16_t fingerprintlibrary::setPassword(uint32_t pwd)
{
    QByteArray SendDataContent;
    SendDataContent.clear();
    SendDataContent.append(FPM_SETPASSWORD);
    SendDataContent.append((pwd >> 24) & 0xff);
    SendDataContent.append((pwd >> 16) & 0xff);
    SendDataContent.append((pwd >> 8) & 0xff);
    SendDataContent.append(pwd & 0xff);

    writePacket(FPM_COMMANDPACKET, &SendDataContent, 5);
    uint8_t confirm_code = 0;
    int16_t rc = read_ack_get_response(&confirm_code);

    if (rc < 0)
        return rc;

    return confirm_code;
}
