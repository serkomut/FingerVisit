#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QPixmap>
#include <QImage>
#include <qfile.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    FPM = new fingerprintlibrary;
    configDB = new databasconfiglibrary;

    configDB->connectDB("./configuration.db");
    configDB->readFingerConfigsFromDB("demo");

    qDebug()<<"rowID"<<configDB->FPvalues.rowID;
    qDebug()<<"ConfigName"<<configDB->FPvalues.ConfigName;
    qDebug()<<"PortName"<<configDB->FPvalues.PortName;
    qDebug()<<"baud_rate"<<configDB->FPParams.baud_rate;
    qDebug()<<"Password"<<configDB->FPvalues.Password;
    qDebug()<<"device_addr"<<configDB->FPParams.device_addr;
    qDebug()<<"packet_len"<<configDB->FPParams.packet_len;
    qDebug()<<"security_level"<<configDB->FPParams.security_level;
    qDebug()<<"IRQPin"<<configDB->FPvalues.IRQPin;
    qDebug()<<"system_id"<<configDB->FPParams.system_id;
    qDebug()<<"capacity"<<configDB->FPParams.capacity;

    if(FPM->begin(configDB->FPvalues.Password,configDB->FPParams.device_addr,configDB->FPvalues.IRQPin,configDB->FPParams.baud_rate*9600, FPM->sys_params))
    {
        QPixmap pm1("./imageorg.jpg");
        ui->label_3->setPixmap(pm1);
        ui->label_3->setScaledContents(true);
    }

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
        emit FPM->SearchDBTask();
}

void MainWindow::on_pushButton_2_clicked()
{
    FPM->EnrollTask();
}

void MainWindow::on_pushButton_3_clicked()
{
    qDebug()<<FPM->led_ctl(on);
}

void MainWindow::on_pushButton_4_clicked()
{
    qDebug()<<FPM->led_ctl(off);
}

void MainWindow::on_pushButton_5_clicked()
{
    uint16_t template_cnt;
    FPM->get_template_count(&template_cnt);
}

void MainWindow::on_pushButton_6_clicked()
{
    uint16_t deleted;
    deleted=(uint16_t)ui->spinBox->value();
    FPM->deleteFingerprint(deleted);

}

void MainWindow::on_pushButton_7_clicked()
{
    QMessageBox msgBox;
    msgBox.setText("All datas will delete!");
    msgBox.setInformativeText("Are you sure?");
    msgBox.setStandardButtons( QMessageBox::Ok | QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Cancel);
    int ret = msgBox.exec();
    if(ret == QMessageBox::Ok)
    {
        FPM->empty_database();
    }
}

void MainWindow::on_pushButton_8_clicked()
{
    if(FPM->change_baud_rate(FPM_BAUD_115200))
    {
        if(FPM->begin(FPM_DEFAULT_PASSWORD,FPM_DEFAULT_ADDRESS,FPM_DEFAULT_FD_PIN,QSerialPort::Baud115200, FPM->sys_params))
        {
            QPixmap pm1("./imageorg.jpg");
            ui->label_3->setPixmap(pm1);
            ui->label_3->setScaledContents(true);
        }
    }
}

void MainWindow::on_pushButton_9_clicked()
{
    if(FPM->stream_image())
    {
        QPixmap tmppixmap;
        tmppixmap =QPixmap::fromImage(FPM->PrepareBitmap());
        ui->label_5->setPixmap(tmppixmap);
    }
}

void MainWindow::on_pushButton_10_clicked()
{
    QString tmp=ui->lineEdit->text().toStdString().c_str();
    tmp=tmp.rightJustified(8,'0');
    bool ok;
    uint32_t pwd=tmp.toUInt(&ok,16);
    if(FPM->set_pwd(tmp.toUInt(&ok,16)))
    {
        if(FPM->begin(pwd,FPM_DEFAULT_ADDRESS,FPM_DEFAULT_FD_PIN,QSerialPort::Baud115200, FPM->sys_params))
        {
            QPixmap pm1("./imageorg.jpg");
            ui->label_3->setPixmap(pm1);
            ui->label_3->setScaledContents(true);
        }
    }
}

void MainWindow::on_pushButton_11_clicked()
{
    uint16_t template_cnt;
    FPM->get_free_id(&template_cnt);
}

void MainWindow::on_pushButton_12_clicked()
{

        QString tmp=ui->lineEdit->text().toStdString().c_str();
        tmp=tmp.rightJustified(8,'0');
        bool ok;
        uint32_t pwd=tmp.toUInt(&ok,16);
        if(FPM->verifyPassword(pwd))
        {
            qDebug()<<"Right!";
        }
}
