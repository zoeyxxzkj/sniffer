#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QDebug>
#include <vector>
#include <iostream>
#include <QTreeWidgetItem>
#include <QColor>
#include <QDir>
#include"pcap.h"

int netDeviceNum = 0;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("zoeyzhuSniffer");
    this->setWindowIcon(QIcon(":/icon.jpg"));
    createActions();
    createMenus();
    isFileSaved = false;
    RowCount =0;

    ui->showWidget->setColumnCount(8);
    ui->showWidget->setHorizontalHeaderLabels(QStringList() << tr("序号") << tr("时间")
                                              << tr("源MAC地址") << tr("目的MAC地址")
                                              << tr("长度") << tr("协议类型")
                                              << tr("源IP地址") << tr("目的IP地址"));
    //设置为单行选中
    ui->showWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置选择模式，即选择单行
    ui->showWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    //设置为禁止修改
    ui->showWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->showWidget->setColumnWidth(0, 60);
    ui->showWidget->setColumnWidth(1, 180);
    ui->showWidget->setColumnWidth(2, 210);
    ui->showWidget->setColumnWidth(3, 210);
    ui->showWidget->setColumnWidth(4, 60);
    ui->showWidget->setColumnWidth(5, 85);
    ui->showWidget->setColumnWidth(6, 145);
    ui->showWidget->setColumnWidth(7, 145);
    connect(ui->showWidget, SIGNAL(cellClicked(int,int)), this, SLOT(showProtoTree(int,int)));

    ui->showWidget->verticalHeader()->setVisible(false);    //隐藏列表头

    ui->protoWidget->setColumnCount(1);
    //设置协议解析窗口表头
    ui->protoWidget->setHeaderLabel(QString("协议分析"));
    ui->protoWidget->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->protoWidget->header()->setStretchLastSection(false);

    //对复选框进行初始化
    ui->netDevsCombo->addItem(tr("请选择一个网卡接口（必选）"));

    ui->finishBtn->setEnabled(false);

    //初始化捕获，即获取当前设备上的网络接口
    if(sniff_initCap() < 0){
        QMessageBox::warning(this, tr("Sniffer"), tr("无法在您的机器上获取网络适配器接口"), QMessageBox::Ok);
    }
    //初始化接口列表
    for(dev=alldevs; dev; dev=dev->next)
    {
        ui->netDevsCombo->addItem(QString("%1").arg(dev->name));
    }

    npacket = (PKTCOUNT *)malloc(sizeof(PKTCOUNT));
    capthread = NULL;
}

MainWindow::~MainWindow()
{
    delete ui;
}

//初始化libcap
int MainWindow::sniff_initCap()
{
    devCount = 0;
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
        return -1;
    for(dev = alldevs; dev; dev = dev->next)
        devCount++;
    return 0;

}

//开始捕获
int MainWindow::sniff_startCap()
{
    int interface_index = 0, count;
    struct bpf_program fcode;   //bpf_program结构体在编译BPF过滤规则函数执行成功后将会被填充

    //获得接口和过滤器中写入的内容
    interface_index = ui->netDevsCombo->currentIndex();
    if(interface_index == 0){
        QMessageBox::warning(this, "Sniffer", tr("请选择一个合适的网卡接口"), QMessageBox::Ok);
        return -1;
    }
    QString filterContent = ui->filterLineEdit->text();

    //获得选中的网卡接口
    dev = alldevs;
    for(count = 0; count < interface_index - 1; count++){
        dev = dev->next;
        qDebug() << "debug information: " << dev->name << endl;
    }

    if((adhandle = pcap_open_live(dev->name,    //设备名
                                  65536,    //捕获数据包长度
                                  1,    //设置成混杂模式
                                  1000,    //读超时设置
                                  errbuf  //错误信息缓冲
                                  )) == NULL)
    {
        QMessageBox::warning(this, "open error", tr("网卡接口打开失败"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }

    //检查链路层，判断所在网络是否为以太网
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        QMessageBox::warning(this, "Sniffer", tr("只支持以太网环境"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }

    bpf_u_int32 ipaddress,ipmask;
    pcap_lookupnet(dev->name,&ipaddress,&ipmask,errbuf);


    if(filterContent == NULL)
    {
        char filter[] = "";
        if(pcap_compile(adhandle, &fcode, filter, 1, ipmask) < 0)
        {
            QMessageBox::warning(this, "Sniff", tr("无法编译包过滤器，请检查语法"), QMessageBox::Ok);
            pcap_freealldevs(alldevs);
            alldevs = NULL;
            return -1;
        }
    }
    else{
        QByteArray ba = filterContent.toLatin1();
        char *filter = NULL;
        filter = ba.data();     //上述转换中要求QString中不含有中文，否则会出现乱码
        if(pcap_compile(adhandle, &fcode, filter, 1, ipmask) < 0)
        {
            QMessageBox::warning(this, "Sniff", tr("无法编译包过滤器，请检查语法"), QMessageBox::Ok);
            pcap_freealldevs(alldevs);
            alldevs = NULL;
            return -1;
        }
    }

    //设置过滤器
    if(pcap_setfilter(adhandle, &fcode) < 0)
    {
        QMessageBox::warning(this, "Sniff", tr("设置过滤器发生错误"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }

    //获取当前路径
    QString path = QDir::currentPath();
    qDebug() << path << endl;
    //判断当前路径下文件是否存在
    QString direcPath = path + "/SavedData";
    QDir dir(direcPath);
    if(!dir.exists())
    {
        if(!dir.mkdir(direcPath))
        {
            QMessageBox::warning(this, "warning", tr("保存路径创建失败!"), QMessageBox::Ok);
            return -1;
        }
    }
    char thistime[30];
    struct tm *ltime;
    time_t nowtime;
    time(&nowtime);
    ltime = localtime(&nowtime);
    strftime(thistime,sizeof(thistime),"%Y%m%d %H%M%S",ltime);
    std::string str = direcPath.toStdString();
    strcpy(filepath, str.c_str());
    strcat(filepath, "/");
    strcat(filepath, thistime);
    strcat(filepath, ".pcap");      //保存为pcap格式能够被wireshark识别

    qDebug() << "data saved path is:" + QString(filepath) << endl;
    //将开始捕获数据包的时间作为保存数据包的文件名
    dumpfile =  pcap_dump_open(adhandle, filepath);
    if(dumpfile == NULL)
    {
        QMessageBox::warning(this, "warning", tr("脱机堆文件打开错误"), QMessageBox::Ok);
        return -1;
    }

    pcap_freealldevs(alldevs);
    alldevs = NULL;

    capthread = new CapThread(adhandle, npacket, datapktLink, dataCharLink, dumpfile);
    connect(capthread, SIGNAL(addOneCaptureLine(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(updateTableWidget(QString,QString,QString,QString,QString,QString,QString)));
    connect(capthread, SIGNAL(updatePktCount()), SLOT(updateCapCalculate()));
    capthread->start();
    return 1;

}

void MainWindow::on_startBtn_clicked()
{
    //如果已经有数据了，提示保存数据
    if(isFileSaved == false && RowCount != 0){
        int ret;
        ret = QMessageBox::information(this, "Sniffer", tr("当前捕获数据尚未保存，是否进行保存:)"), QMessageBox::Save, QMessageBox::Cancel);
        if(ret == QMessageBox::Save){
            QString filename = QFileDialog::getSaveFileName(this,
                                                            tr("另存为"),
                                                            ".", tr("Sniffer 捕获数据文件(*.pcap)"));
            if(!filename.isEmpty()){
                saveFile(filename);
            }
        }
        else if(ret == QMessageBox::Cancel){
            //do nothing
        }
    }

    //每次重新开始进行数据包捕获（包括读取本地数据包的时候）的时候要将对应容器中的结构体释放掉，否则会造成内存泄漏
    std::vector<DATAPKT *>::iterator it;
    for(it = datapktLink.begin(); it != datapktLink.end(); it++){
        free((*it)->eth_header);
        free((*it)->arp_header);
        free((*it)->ip_header);
        free((*it)->ip_option);
        free((*it)->icmp_header);
        free((*it)->igmp_header);
        free((*it)->udp_header);
        free((*it)->tcp_header);
        free((*it)->app_header);

        free(*it);
    }
    std::vector<u_char *>::iterator kt;
    for(kt = dataCharLink.begin(); kt != dataCharLink.end(); kt++){
        free(*kt);
    }

    //通过swap构造函数释放内存
    datapktVec().swap(datapktLink);
    dataVec().swap(dataCharLink);

    ui->protoWidget->clear();
    ui->textEdit->clear();
    saveAction->setEnabled(false);


    //需要重新获取网络接口信息，这里有bug,因为在上一步的释放操作中并没有将指针值重新设置为0，因此会导致程序崩溃
    if(alldevs == NULL){
        if(sniff_initCap() < 0){
            QMessageBox::warning(this, tr("Sniffer"), tr("无法在您的机器上获取网络适配器接口"), QMessageBox::Ok);
            return;
        }
    }
    //这里出现段错误也是因为没有将capthread赋为null导致其变成野指针
    if(capthread != NULL){
        delete capthread;
        capthread = NULL;
    }
    memset(npacket, 0, sizeof(struct _pktcount));

    if(sniff_startCap() < 0)
        return;

    //清空QTableWidget控件中的内容
    ui->showWidget->clearContents();
    ui->showWidget->setRowCount(0);
    ui->finishBtn->setEnabled(true);
    ui->startBtn->setEnabled(false);
    //当点击开始捕获时设置文件保存标志为false
    isFileSaved = false;
}

void MainWindow::updateTableWidget(QString timestr, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP)
{
    RowCount = ui->showWidget->rowCount();
    ui->showWidget->insertRow(RowCount);
    QString orderNumber = QString::number(RowCount, 10);
    ui->showWidget->setItem(RowCount, 0, new QTableWidgetItem(orderNumber));
    ui->showWidget->setItem(RowCount, 1, new QTableWidgetItem(timestr));
    ui->showWidget->setItem(RowCount, 2, new QTableWidgetItem(srcMac));
    ui->showWidget->setItem(RowCount, 3, new QTableWidgetItem(destMac));
    ui->showWidget->setItem(RowCount, 4, new QTableWidgetItem(len));
    ui->showWidget->setItem(RowCount, 5, new QTableWidgetItem(protoType));
    ui->showWidget->setItem(RowCount, 6, new QTableWidgetItem(srcIP));
    ui->showWidget->setItem(RowCount, 7, new QTableWidgetItem(dstIP));

    if(RowCount > 1)
    {
        ui->showWidget->scrollToItem(ui->showWidget->item(RowCount, 0), QAbstractItemView::PositionAtBottom);
    }

    QColor color;
    if(protoType == "TCP" || protoType == "HTTP"){
        color = QColor(228,255,199);
    }
    else if(protoType == "UDP"){
        color = QColor(218,238,255);
    }
    else if(protoType == "ARP" || protoType == "RARP"){
        color = QColor(250,240,215);
    }
    else if(protoType == "ICMP"){
        color = QColor(252,224,255);
    }
    else if(protoType == "IGMP"){
        color = QColor(254,200,255);
    }
    for(int i = 0; i < 8 ; i ++){
        ui->showWidget->item(RowCount,i)->setBackground(color);
    }
}

void MainWindow::updateCapCalculate()
{
    ui->tcpEdit->setText(QString::number(npacket->n_tcp));
    ui->udpEdit->setText(QString::number(npacket->n_udp));
    ui->icmpEdit->setText(QString::number(npacket->n_icmp));
    ui->httpEdit->setText(QString::number(npacket->n_http));
    ui->arpEdit->setText(QString::number(npacket->n_arp+npacket->n_rarp));
    ui->ipv4Edit->setText(QString::number(npacket->n_ip));
    ui->otherEdit->setText(QString::number(npacket->n_other));
    ui->totalEdit->setText(QString::number(npacket->n_sum));
    ui->igmpEdit->setText(QString::number(npacket->n_igmp));
}

void MainWindow::on_finishBtn_clicked()
{
    qDebug() << datapktLink.size() << endl;
    qDebug() << dataCharLink.size() << endl;

    //设置按钮状态
    ui->startBtn->setEnabled(true);
    ui->finishBtn->setEnabled(false);
    //当点击停止捕获按钮时开始菜单栏中的保存设置为可以点击
    saveAction->setEnabled(true);
    //停止线程
    capthread->stop();
    //关闭libcap会话句柄，并释放其资源
    pcap_close(adhandle);
}

void MainWindow::showProtoTree(int row, int column)
{
    qDebug() << row << column << endl;
    //清空控件中的内容
    ui->protoWidget->clear();
    ui->textEdit->clear();

    struct _datapkt *mem_data = (struct _datapkt *)datapktLink[row];
    //在编辑栏中要显示的数据包内容
    u_char *print_data = (u_char *)dataCharLink[row];
    int print_len = mem_data->len;
    showHexData(print_data, print_len);

    QString showStr;
    char buf[100];
    sprintf(buf, "接收到的第%d个数据包", row + 1);
    showStr = QString(buf);

    QTreeWidgetItem *root = new QTreeWidgetItem(ui->protoWidget);
    root->setText(0, showStr);

    //处理帧数据
    showStr = QString("链路层数据");
    QTreeWidgetItem *level1 = new QTreeWidgetItem(root);
    level1->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->eth_header->SrcMac[0], mem_data->eth_header->SrcMac[1],
            mem_data->eth_header->SrcMac[2], mem_data->eth_header->SrcMac[3], mem_data->eth_header->SrcMac[4], mem_data->eth_header->SrcMac[5]);
    showStr = "源MAC: " + QString(buf);
    QTreeWidgetItem *srcEtherMac = new QTreeWidgetItem(level1);
    srcEtherMac->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->eth_header->DestMac[0], mem_data->eth_header->DestMac[1],
            mem_data->eth_header->DestMac[2], mem_data->eth_header->DestMac[3], mem_data->eth_header->DestMac[4], mem_data->eth_header->DestMac[5]);
    showStr = "目的MAC: " + QString(buf);
    QTreeWidgetItem *destEtherMac = new QTreeWidgetItem(level1);
    destEtherMac->setText(0, showStr);

    sprintf(buf, "%04x", mem_data->eth_header->Etype);
    showStr = "类型:0x" + QString(buf);
    QTreeWidgetItem *etherType = new QTreeWidgetItem(level1);
    etherType->setText(0, showStr);

    //处理IP,ARP类型的数据包
    if(mem_data->eth_header->Etype == 0x0806 || mem_data->eth_header->Etype == 0x0835)      //ARP
    {
        //添加ARP协议头
        if(mem_data->eth_header->Etype == 0x0806)
        {
            showStr = QString("ARP协议头");
        }
        else
        {
            showStr = QString("RARP协议头");
        }
        QTreeWidgetItem *level2 = new QTreeWidgetItem(root);
        level2->setText(0, showStr);

        sprintf(buf, "硬件类型: 0x%04x", mem_data->arp_header->arp_hrd);
        showStr = QString(buf);
        QTreeWidgetItem *arpHtype = new QTreeWidgetItem(level2);
        arpHtype->setText(0, showStr);

        sprintf(buf, "协议类型: 0x%04x", mem_data->arp_header->arp_pro);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrtype = new QTreeWidgetItem(level2);
        arpPrtype->setText(0, showStr);

        sprintf(buf, "硬件地址长度: %d", mem_data->arp_header->arp_hlen);
        showStr = QString(buf);
        QTreeWidgetItem *arpHsize = new QTreeWidgetItem(level2);
        arpHsize->setText(0, showStr);

        sprintf(buf, "协议地址长度: %d", mem_data->arp_header->arp_plen);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrsize = new QTreeWidgetItem(level2);
        arpPrsize->setText(0, showStr);

        sprintf(buf, "操作码: %d", mem_data->arp_header->arp_op);
        showStr = QString(buf);
        QTreeWidgetItem *arpCode = new QTreeWidgetItem(level2);
        arpCode->setText(0, showStr);

        if(mem_data->arp_header->arp_op == 1)
            sprintf(buf, "ARP request (%d)", mem_data->arp_header->arp_op);
        else if(mem_data->arp_header->arp_op == 2)
            sprintf(buf, "ARP reply (%d)", mem_data->arp_header->arp_op);
        else if(mem_data->arp_header->arp_op == 3)
            sprintf(buf, "RARP request (%d)", mem_data->arp_header->arp_op);
        else
            sprintf(buf, "RARP reply (%d)", mem_data->arp_header->arp_op);
        showStr = QString(buf);
        QTreeWidgetItem *arpCode_flag = new QTreeWidgetItem(arpCode);
        arpCode_flag->setText(0, showStr);


        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arp_header->arp_shd[0], mem_data->arp_header->arp_shd[1],
                mem_data->arp_header->arp_shd[2], mem_data->arp_header->arp_shd[3], mem_data->arp_header->arp_shd[4], mem_data->arp_header->arp_shd[5]);
        showStr = "发送方MAC: " + QString(buf);
        QTreeWidgetItem *srcArpMac = new QTreeWidgetItem(level2);
        srcArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arp_header->arp_sip[0], mem_data->arp_header->arp_sip[1], mem_data->arp_header->arp_sip[2]
                ,mem_data->arp_header->arp_sip[3]);
        showStr = "发送方IP: " + QString(buf);
        QTreeWidgetItem *srcArpIp = new QTreeWidgetItem(level2);
        srcArpIp->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arp_header->arp_dhd[0], mem_data->arp_header->arp_dhd[1],
                mem_data->arp_header->arp_dhd[2], mem_data->arp_header->arp_dhd[3], mem_data->arp_header->arp_dhd[4], mem_data->arp_header->arp_dhd[5]);
        showStr = "接收方MAC: " + QString(buf);
        QTreeWidgetItem *destArpMac = new QTreeWidgetItem(level2);
        destArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arp_header->arp_dip[0], mem_data->arp_header->arp_dip[1], mem_data->arp_header->arp_dip[2]
                ,mem_data->arp_header->arp_dip[3]);
        showStr = "接收方IP: " + QString(buf);
        QTreeWidgetItem *destArpIp = new QTreeWidgetItem(level2);
        destArpIp->setText(0, showStr);
    }
    else if(mem_data->eth_header->Etype == 0x0800)     //IP
    {
        //添加IP协议头
        showStr = QString("IP协议头");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, showStr);

        sprintf(buf, "版本: %d", mem_data->ip_header->version);
        showStr = QString(buf);
        QTreeWidgetItem *ipVersion = new QTreeWidgetItem(level3);
        ipVersion->setText(0, showStr);

        sprintf(buf, "IP首部长度: %d", mem_data->ip_header->header_len);
        showStr = QString(buf);
        QTreeWidgetItem *ipHeaderLen = new QTreeWidgetItem(level3);
        ipHeaderLen->setText(0, showStr);

        sprintf(buf, "服务类型: %d", mem_data->ip_header->tos);
        showStr = QString(buf);
        QTreeWidgetItem *ipTos = new QTreeWidgetItem(level3);
        ipTos->setText(0, showStr);

        sprintf(buf, "总长度: %d", mem_data->ip_header->total_len);
        showStr = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, showStr);

        sprintf(buf, "标识: 0x%04x", mem_data->ip_header->ident);
        showStr = QString(buf);
        QTreeWidgetItem *ipIdentify = new QTreeWidgetItem(level3);
        ipIdentify->setText(0, showStr);

        sprintf(buf, "标志(Reserved Fragment Flag): %d", (mem_data->ip_header->flags & IP_RF) >> 15);
        showStr = QString(buf);
        QTreeWidgetItem *flag0 = new QTreeWidgetItem(level3);
        flag0->setText(0, showStr);

        sprintf(buf, "标志(Don't fragment Flag): %d", (mem_data->ip_header->flags & IP_DF) >> 14);
        showStr = QString(buf);
        QTreeWidgetItem *flag1 = new QTreeWidgetItem(level3);
        flag1->setText(0, showStr);

        sprintf(buf, "标志(More Fragment Flag): %d", (mem_data->ip_header->flags & IP_MF) >> 13);
        showStr = QString(buf);
        QTreeWidgetItem *flag3 = new QTreeWidgetItem(level3);
        flag3->setText(0, showStr);

        sprintf(buf, "段偏移: %d", mem_data->ip_header->flags & IP_OFFMASK);
        showStr = QString(buf);
        QTreeWidgetItem *ipOffset = new QTreeWidgetItem(level3);
        ipOffset->setText(0, showStr);

        sprintf(buf, "生存期: %d", mem_data->ip_header->ttl);
        showStr = QString(buf);
        QTreeWidgetItem *ipTTL = new QTreeWidgetItem(level3);
        ipTTL->setText(0, showStr);

        sprintf(buf, "协议: %d", mem_data->ip_header->proto);
        showStr = QString(buf);
        QTreeWidgetItem *ipProto = new QTreeWidgetItem(level3);
        ipProto->setText(0, showStr);

        sprintf(buf, "首部校验和: 0x%04x", mem_data->ip_header->checksum);
        showStr = QString(buf);
        QTreeWidgetItem *ipHCheckSum = new QTreeWidgetItem(level3);
        ipHCheckSum->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->ip_header->sourceIP[0], mem_data->ip_header->sourceIP[1], mem_data->ip_header->sourceIP[2]
                ,mem_data->ip_header->sourceIP[3]);
        showStr = "源IP: " + QString(buf);
        QTreeWidgetItem *ipSrcIp = new QTreeWidgetItem(level3);
        ipSrcIp->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->ip_header->destIP[0], mem_data->ip_header->destIP[1], mem_data->ip_header->destIP[2]
                ,mem_data->ip_header->destIP[3]);
        showStr = "目的IP: " + QString(buf);
        QTreeWidgetItem *ipDestIp = new QTreeWidgetItem(level3);
        ipDestIp->setText(0, showStr);

        //处理传输层udp, icmp, tcp, igmp
        if(mem_data->ip_header->proto == PROTO_ICMP)  //ICMP协议
        {
            //添加ICMP协议头
            showStr = QString("ICMP协议头");
            QTreeWidgetItem *level4 = new QTreeWidgetItem(root);
            level4->setText(0, showStr);

            //解释常见的类型
            if(mem_data->icmp_header->icmp_type == 0)
                sprintf(buf, "类型: %d (Echo Reply)", mem_data->icmp_header->icmp_type);
            else if(mem_data->icmp_header->icmp_type == 8)
                sprintf(buf, "类型: %d (Echo Request)", mem_data->icmp_header->icmp_type);
            else if(mem_data->icmp_header->icmp_type == 3)
                sprintf(buf, "类型: %d (Unreachable)", mem_data->icmp_header->icmp_type);
            else
                sprintf(buf, "类型: %d", mem_data->icmp_header->icmp_type);
            showStr = QString(buf);
            QTreeWidgetItem *icmpType = new QTreeWidgetItem(level4);
            icmpType->setText(0, showStr);

            sprintf(buf, "代码: %d", mem_data->icmp_header->icmp_code);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCode = new QTreeWidgetItem(level4);
            icmpCode->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->icmp_header->icmp_checksum);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCheck = new QTreeWidgetItem(level4);
            icmpCheck->setText(0, showStr);

            sprintf(buf, "标识: 0x%04x", mem_data->icmp_header->icmp_identifier);
            showStr = QString(buf);
            QTreeWidgetItem *icmpIdentify = new QTreeWidgetItem(level4);
            icmpIdentify->setText(0, showStr);

            sprintf(buf, "序列号: 0x%04x", mem_data->icmp_header->icmp_seqnum);
            showStr = QString(buf);
            QTreeWidgetItem *icmpSeq = new QTreeWidgetItem(level4);
            icmpSeq->setText(0, showStr);
        }
        else if(mem_data->ip_header->proto == PROTO_IGMP)
        {
            showStr = QString("IGMP协议头");
            QTreeWidgetItem *level7 = new QTreeWidgetItem(root);
            level7->setText(0, showStr);

            showStr = QString("IGMP Version: 2");
            QTreeWidgetItem *igmpVersion = new QTreeWidgetItem(level7);
            igmpVersion->setText(0, showStr);

            sprintf(buf, "类型: 0x%02x", mem_data->igmp_header->igmp_type);
            switch(mem_data->igmp_header->igmp_type)
            {
                case 0x11:
                    sprintf(buf, "类型: 0x%02x(Membership Query)", mem_data->igmp_header->igmp_type);
                    break;

                case 0x12:
                    sprintf(buf, "类型: 0x%02x(Membership Report)", mem_data->igmp_header->igmp_type);
                    break;

                case 0x16:
                    sprintf(buf, "类型: 0x%02x(Membership Report)", mem_data->igmp_header->igmp_type);
                    break;

                case 0x17:
                    sprintf(buf, "类型: 0x%02x(Membership Leave)", mem_data->igmp_header->igmp_type);
                    break;

                default:
                    sprintf(buf, "类型: 0x%02x(Membership Leave)", mem_data->igmp_header->igmp_type);
                    break;
            }

            showStr = QString(buf);
            QTreeWidgetItem *igmpType = new QTreeWidgetItem(level7);
            igmpType->setText(0, showStr);

            sprintf(buf, "最大响应时间: %.1f sec", float(mem_data->igmp_header->igmp_max_response_time)/10);
            showStr = QString(buf);
            QTreeWidgetItem *igmpMrt = new QTreeWidgetItem(level7);
            igmpMrt->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->igmp_header->igmp_checksum);
            showStr = QString(buf);
            QTreeWidgetItem *igmpCheck = new QTreeWidgetItem(level7);
            igmpCheck->setText(0, showStr);

            sprintf(buf, "%d.%d.%d.%d", mem_data->igmp_header->igmp_group_address[0], mem_data->igmp_header->igmp_group_address[1], mem_data->igmp_header->igmp_group_address[2]
                    ,mem_data->igmp_header->igmp_group_address[3]);
            showStr = "组播IP: " + QString(buf);
            QTreeWidgetItem *igmpGIp = new QTreeWidgetItem(level7);
            igmpGIp->setText(0, showStr);
        }
        else if(mem_data->ip_header->proto == PROTO_TCP)  //TCP协议
        {
            showStr = QString("TCP协议头");
            QTreeWidgetItem *level5 = new QTreeWidgetItem(root);
            level5->setText(0, showStr);

            sprintf(buf, "源端口: %d", mem_data->tcp_header->tcp_src_port);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSrcPort = new QTreeWidgetItem(level5);
            tcpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->tcp_header->tcp_des_port);
            showStr = QString(buf);
            QTreeWidgetItem *tcpDestPort = new QTreeWidgetItem(level5);
            tcpDestPort->setText(0, showStr);

            sprintf(buf, "序列号: 0x%08x", mem_data->tcp_header->tcp_seq_num);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(level5);
            tcpSeq->setText(0, showStr);

            sprintf(buf, "确认号: 0x%08x", mem_data->tcp_header->tcp_ack);
            showStr = QString(buf);
            QTreeWidgetItem *tcpAck = new QTreeWidgetItem(level5);
            tcpAck->setText(0, showStr);

            sprintf(buf, "首部长度: %d bytes (%d)", mem_data->tcp_header->tcp_header_len * 4, mem_data->tcp_header->tcp_header_len);
            showStr = QString(buf);
            QTreeWidgetItem *tcpOFF = new QTreeWidgetItem(level5);
            tcpOFF->setText(0, showStr);

            sprintf(buf, "FLAG: 0x%02x", mem_data->tcp_header->tcp_code_bits);
            showStr = QString(buf);
            QTreeWidgetItem *tcpFlag = new QTreeWidgetItem(level5);
            tcpFlag->setText(0, showStr);

            sprintf(buf, "CWR: %d", (mem_data->tcp_header->tcp_code_bits & TH_CWR) >> 7);
            showStr = QString(buf);
            QTreeWidgetItem *cwrflag = new QTreeWidgetItem(tcpFlag);
            cwrflag->setText(0, showStr);

            sprintf(buf, "ECE: %d", (mem_data->tcp_header->tcp_code_bits & TH_ECE) >> 6);
            showStr = QString(buf);
            QTreeWidgetItem *eceflag = new QTreeWidgetItem(tcpFlag);
            eceflag->setText(0, showStr);

            sprintf(buf, "URG: %d", (mem_data->tcp_header->tcp_code_bits & TH_URG) >> 5);
            showStr = QString(buf);
            QTreeWidgetItem *urgflag = new QTreeWidgetItem(tcpFlag);
            urgflag->setText(0, showStr);

            sprintf(buf, "ACK: %d", (mem_data->tcp_header->tcp_code_bits & TH_ACK) >> 4);
            showStr = QString(buf);
            QTreeWidgetItem *ackflag = new QTreeWidgetItem(tcpFlag);
            ackflag->setText(0, showStr);

            sprintf(buf, "PUSH: %d", (mem_data->tcp_header->tcp_code_bits & TH_PUSH) >> 3);
            showStr = QString(buf);
            QTreeWidgetItem *pushflag = new QTreeWidgetItem(tcpFlag);
            pushflag->setText(0, showStr);

            sprintf(buf, "RST: %d", (mem_data->tcp_header->tcp_code_bits & TH_RST) >> 2);
            showStr = QString(buf);
            QTreeWidgetItem *rstflag = new QTreeWidgetItem(tcpFlag);
            rstflag->setText(0, showStr);

            sprintf(buf, "SYN: %d", (mem_data->tcp_header->tcp_code_bits & TH_SYN) >> 1);
            showStr = QString(buf);
            QTreeWidgetItem *synflag = new QTreeWidgetItem(tcpFlag);
            synflag->setText(0, showStr);

            sprintf(buf, "FIN: %d", (mem_data->tcp_header->tcp_code_bits & TH_FIN));
            showStr = QString(buf);
            QTreeWidgetItem *finflag = new QTreeWidgetItem(tcpFlag);
            finflag->setText(0, showStr);

            sprintf(buf, "窗口大小: %d", mem_data->tcp_header->tcp_window_size);
            showStr = QString(buf);
            QTreeWidgetItem *tcpWndSize = new QTreeWidgetItem(level5);
            tcpWndSize->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->tcp_header->tcp_checksum);
            showStr = QString(buf);
            QTreeWidgetItem *tcpCheck = new QTreeWidgetItem(level5);
            tcpCheck->setText(0, showStr);

            sprintf(buf, "紧急指针: %d", mem_data->tcp_header->tcp_urgent_pointer);
            showStr = QString(buf);
            QTreeWidgetItem *tcpUrgPtr = new QTreeWidgetItem(level5);
            tcpUrgPtr->setText(0, showStr);

            if(mem_data->isHttp == true)
            {
                showStr = QString("HTTP协议头");
                QTreeWidgetItem *level8 = new QTreeWidgetItem(root);
                level8->setText(0, showStr);

                QString content = "";
                u_char *httpps = mem_data->app_header;

                qDebug() << QString(*httpps) << QString(*(httpps + 1)) << QString(*(httpps + 2)) << endl;

                u_char *httpps2 = NULL;

                const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
                for(int i = 0 ; i < 4 ; i ++){
                    httpps2 = (u_char *)strstr((char *)httpps,token[i]);
                    if(httpps2){
                        break;
                    }
                }
                int size = mem_data->httpsize - (httpps2 - httpps);

                for(int i = 0 ; i < size; i++){
                    if(httpps2[i] == 0x0d){
                        // 0x0d = '\r' 0x0a = '\n'
                        //如果到达http正文结尾
                        if(httpps2[i+1] == 0x0a && httpps2[i+2] == 0x0d && httpps2[i+3] == 0x0a){
                            content += "\\r\\n";
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content)));
                            level8->addChild(new QTreeWidgetItem(level8,QStringList("\\r\\n")));
                            break;
                        }
                        //http分割符
                        else if(httpps2[i+1] == 0x0a){
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content + "\\r\\n")));
                            content = "";
                            i ++;
                            continue;
                        }
                    }
                    content += httpps2[i];
                }
                level8->addChild(new QTreeWidgetItem(level8,QStringList("(Data)(Data)")));
            }
        }
        else if(mem_data->ip_header->proto == PROTO_UDP)  //UDP协议
        {
            //添加UDP协议头
            showStr = QString("UDP协议头");
            QTreeWidgetItem *level6 = new QTreeWidgetItem(root);
            level6->setText(0, showStr);

            sprintf(buf, "源端口: %d", mem_data->udp_header->udp_src_port);
            showStr = QString(buf);
            QTreeWidgetItem *udpSrcPort = new QTreeWidgetItem(level6);
            udpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->udp_header->udp_tar_port);
            showStr = QString(buf);
            QTreeWidgetItem *udpDestPort = new QTreeWidgetItem(level6);
            udpDestPort->setText(0, showStr);

            sprintf(buf, "总长度: %d", mem_data->udp_header->udp_len);
            showStr = QString(buf);
            QTreeWidgetItem *udpLen = new QTreeWidgetItem(level6);
            udpLen->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->udp_header->udp_checksum);
            showStr = QString(buf);
            QTreeWidgetItem *udpCrc = new QTreeWidgetItem(level6);
            udpCrc->setText(0, showStr);
        }
    }
}

void MainWindow::showHexData(u_char *print_data, int print_len)
{
    QString tempnum,tempchar;
    QString oneline;
    int i;
    tempchar = "  ";
    oneline = "";
    for(i = 0 ; i < print_len ; i ++){
        if(i % 16 == 0){
            //输出行号
            oneline += tempnum.asprintf("%04x  ",i);
        }
        oneline += tempnum.asprintf("%02x ",print_data[i]);
        if(isprint(print_data[i])){     //判断是否为可打印字符
            tempchar += print_data[i];
        }
        else{
            tempchar += ".";
        }
        if((i+1)%16 == 0){
            ui->textEdit->append(oneline + tempchar);
            tempchar = "  ";
            oneline = "";
        }
    }
    i %= 16;
    for(; i < 16 ; i ++){
        oneline += "   ";
    }
    ui->textEdit->append(oneline + tempchar);
}

void MainWindow::createActions()
{
    openAction = new QAction(tr("打开"), this);
    openAction->setIcon(QIcon(":/open.png"));
    openAction->setShortcut(QKeySequence::Open);
    openAction->setStatusTip(tr("打开历史的一个捕获记录"));
    connect(openAction, SIGNAL(triggered()), this, SLOT(slotopen()));

    saveAction = new QAction(tr("保存"), this);
    saveAction->setIcon(QIcon(":/save.png"));
    saveAction->setShortcut(QKeySequence::Save);
    saveAction->setStatusTip(tr("保存本次捕获信息到文件"));
    saveAction->setEnabled(false);
    connect(saveAction, SIGNAL(triggered()), this, SLOT(slotsave()));

    exitAction = new QAction(tr("退出"), this);
    exitAction->setShortcut(tr("Ctrl+Q"));
    exitAction->setStatusTip(tr("退出程序"));
    exitAction->setIcon(QIcon(":/end.png"));
    connect(exitAction, SIGNAL(triggered()), this, SLOT(close()));
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    int ret = QMessageBox::information(this, "Sniffer", tr("是否退出?)"), QMessageBox::Ok, QMessageBox::No);
    if(ret == QMessageBox::Ok){
        if(isFileSaved == false && RowCount != 0){
            int ret;
            ret = QMessageBox::information(this, "Sniffer", tr("当前捕获数据尚未保存，是否进行保存:)"), QMessageBox::Save, QMessageBox::Cancel);
            if(ret == QMessageBox::Save){
                QString filename = QFileDialog::getSaveFileName(this,
                                                                tr("另存为"),
                                                                ".", tr("Sniffer 捕获数据文件(*.pcap)"));
                if(!filename.isEmpty()){
                    saveFile(filename);
                }
            }
            else if(ret == QMessageBox::Cancel){
                //do nothing
            }
        }
        //释放内存，避免内存泄漏
        std::vector<DATAPKT *>::iterator it;
        for(it = datapktLink.begin(); it != datapktLink.end(); it++){
            free((*it)->eth_header);
            free((*it)->arp_header);
            free((*it)->ip_header);
            free((*it)->ip_option);
            free((*it)->icmp_header);
            free((*it)->igmp_header);
            free((*it)->udp_header);
            free((*it)->tcp_header);
            free((*it)->app_header);

            free(*it);
        }
        std::vector<u_char *>::iterator kt;
        for(kt = dataCharLink.begin(); kt != dataCharLink.end(); kt++){
            free(*kt);
        }
        datapktVec().swap(datapktLink);
        dataVec().swap(dataCharLink);
        event->accept();
    }
    else{
        event->ignore();
    }
}

void MainWindow::createMenus()
{
    fileMenu = this->menuBar()->addMenu(tr("文件"));
    fileMenu->addAction(openAction);
    fileMenu->addAction(saveAction);
    fileMenu->addAction(exitAction);

}

//从本地打开文件首先需要将控件中的内容清空,并重置某些全局变量
void MainWindow::slotopen()
{
    //首先判断当前捕获到的数据包是否保存
    if(isFileSaved == false && RowCount != 0){
        int ret;
        ret = QMessageBox::information(this, "Sniffer", tr("当前捕获数据尚未保存，是否进行保存:)"), QMessageBox::Save, QMessageBox::Cancel);
        if(ret == QMessageBox::Save){
            QString filename = QFileDialog::getSaveFileName(this,
                                                            tr("另存为"),
                                                            ".", tr("Sniffer 捕获数据文件(*.pcap)"));
            if(!filename.isEmpty()){
                saveFile(filename);
            }
        }
        else if(ret == QMessageBox::Cancel){
            //do nothing
        }
    }
    isFileSaved = true;     //由于是打开已经保存的文件，因此置isFileSaved标志为true
    //清空容器中的数据包信息
    std::vector<DATAPKT *>::iterator it;
    for(it = datapktLink.begin(); it != datapktLink.end(); it++){
        free((*it)->eth_header);
        free((*it)->arp_header);
        free((*it)->ip_header);
        free((*it)->ip_option);
        free((*it)->icmp_header);
        free((*it)->igmp_header);
        free((*it)->udp_header);
        free((*it)->tcp_header);
        free((*it)->app_header);

        free(*it);
    }
    std::vector<u_char *>::iterator kt;
    for(kt = dataCharLink.begin(); kt != dataCharLink.end(); kt++){
        free(*kt);
    }
    datapktVec().swap(datapktLink);
    dataVec().swap(dataCharLink);
    memset(npacket, 0, sizeof(struct _pktcount));

    ui->showWidget->clearContents();
    ui->showWidget->setRowCount(0);
    ui->protoWidget->clear();
    ui->textEdit->clear();
    ui->startBtn->setEnabled(true);
    ui->finishBtn->setEnabled(false);
    saveAction->setEnabled(false);



    pcap_t *fp;

    //获取要打开文件的文件名
    QString openfilename = QFileDialog::getOpenFileName(this, tr("打开文件"), ".", "Sniffer pkt(*.pcap)");
    std::string filestr = openfilename.toStdString();
    const char *openstr = filestr.c_str();
    qDebug() << openstr << endl;
    if((fp=pcap_open_offline(openstr,errbuf))==NULL)
    {
        QMessageBox::warning(this, "warning", tr("无法打开本地捕获文件！"), QMessageBox::Ok);
        return ;
    }

    //add
    struct bpf_program fcode;
    QString filterContent = ui->filterLineEdit->text();

    if(filterContent == NULL)
    {
        char filter[] = "";
        if(pcap_compile(fp, &fcode, filter, 1, 0) < 0)
        {
            QMessageBox::warning(this, "Sniff", tr("无法编译包过滤器，请检查语法"), QMessageBox::Ok);
            return ;
        }
    }
    else{
        QByteArray ba = filterContent.toLatin1();
        char *filter = NULL;
        filter = ba.data();     //上述转换中要求QString中不含有中文，否则会出现乱码
        if(pcap_compile(fp, &fcode, filter, 1, 0) < 0)
        {
            QMessageBox::warning(this, "Sniff", tr("无法编译包过滤器，请检查语法"), QMessageBox::Ok);
            return ;
        }
    }

    //设置过滤器
    if(pcap_setfilter(fp, &fcode) < 0)
    {
        QMessageBox::warning(this, "Sniff", tr("设置过滤器发生错误"), QMessageBox::Ok);
        return ;
    }

    capthread = new CapThread(fp, npacket, datapktLink, dataCharLink, NULL);
    connect(capthread, SIGNAL(addOneCaptureLine(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(updateTableWidget(QString,QString,QString,QString,QString,QString,QString)));
    connect(capthread, SIGNAL(updatePktCount()), SLOT(updateCapCalculate()));
    capthread->start();

}

void MainWindow::slotsave()
{
    QString filename = QFileDialog::getSaveFileName(this,
                                                    tr("另存为"),
                                                    ".", tr("Sniffer 捕获数据文件(*.pcap)"));
    if(!filename.isEmpty()){
        saveFile(filename);
    }
}

bool MainWindow::saveFile(const QString &filename)
{
    QString curFile = QString(filepath);
    pcap_dump_flush(dumpfile);
    pcap_dump_close(dumpfile);
    if(curFile.isEmpty()){
        return false;
    }
    QFile::setPermissions(curFile,QFileDevice::ReadOther|QFileDevice::WriteOther);
    qDebug() << curFile << endl;
    if(!QFile::copy(curFile,filename)){
        QMessageBox::warning(this, "Sniffer", tr("文件保存失败!"), QMessageBox::Ok);
        return false;
    }
    QMessageBox::information(this, "File Save", tr("文件保存成功!"), QMessageBox::Ok);
    qDebug() << filename << endl;
    //设置当前文件保存标志为true

    isFileSaved = true;
    return true;
}

