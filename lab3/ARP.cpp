#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib,"ws2_32.lib")
#pragma once
#include "pcap.h"
#include<iostream>
#include<cstring>
using namespace std;
#pragma pack(1)
typedef struct FrameHeader_t {//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

typedef struct ARPFrame_t {//IP首部
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;


#pragma pack()



pcap_if_t* alldevs;//指向设备链表首部的指针
pcap_if_t* d;
pcap_addr_t* a;


int main()
{	
	//学弟的公网ip10.136.127.108
	ARPFrame_t ARPFrame;
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
	ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	ARPFrame.FrameHeader.SrcMAC[0] = 0x78;
	ARPFrame.FrameHeader.SrcMAC[1] = 0x2b;
	ARPFrame.FrameHeader.SrcMAC[2] = 0x46;
	ARPFrame.FrameHeader.SrcMAC[3] = 0x51;
	ARPFrame.FrameHeader.SrcMAC[4] = 0x17;
	ARPFrame.FrameHeader.SrcMAC[5] = 0x25;


	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求

	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x66;//设置MAC地址，这里用一个假MAC地址。

	ARPFrame.SendIP = inet_addr("112.112.112.112");//sendip是本机网卡绑定的IP地址，按老师说的设个假IP

	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//RecvHa设置为0

	char errbuf[PCAP_ERRBUF_SIZE];//函数得定义一个错误信息缓冲区
	//获取设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, //获取本机的接口设备
		NULL, //无需认证
		&alldevs,//指向设备列表首部
		errbuf//出错信息保存缓冲区
	) == -1)
	{
		cout << "获取设备失败";
		return 0;
	}
	int number = 0;
	for (d = alldevs; d != NULL; d = d->next)  //简单输出网卡名称
	{
		number++;
		cout << number << " |";
		cout << d->name << " |";
		cout << d->description << " |";
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)//再找其中有IP地址的网卡
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)//
			{
				cout << "IP地址：" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
			}
		}
		cout << endl;
	}

	cout << "请选择一个网卡：";
	int devices_id;
	cin >> devices_id;

	pcap_if_t* target_device;
	target_device = alldevs;

	for (int i = 0; i < devices_id - 1; i++)
		target_device = target_device->next;//列表遍历到该网卡处

	char device_ip[INET_ADDRSTRLEN];
	unsigned char device_mac[48];
	if (target_device->addresses->addr->sa_family == AF_INET)//判断该地址是否为IP地址
	{
		strcpy(device_ip, inet_ntoa(((struct sockaddr_in*)target_device->addresses->addr)->sin_addr));  //直接用inet_ntop
	}
	cout << "所选设备的IP地址：" << device_ip << endl;

	ARPFrame.RecvIP = inet_addr(device_ip);//ARPFrame.RecvIP设置为请求网卡的IP地址

	pcap_t* p = pcap_open(target_device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);//打开网络接口


	if (p == NULL)
	{
		cout << "本地模拟打开网络接口失败！" << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}

	while (1)
	{
		//抓包
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int capture = pcap_next_ex(p, &pkt_header, &pkt_data);//抓包
		//发送ARP
		if (pcap_sendpacket(p, (u_char*)&ARPFrame, sizeof(ARPFrame_t)-1) != 0) {//该部分不止-1，更多的缺省也是可以的，能够得到ARP响应。
			//cout << "本地模拟发送数据包失败！" << endl;
			//pcap_freealldevs(alldevs);
			//return 0;
		}
		if (capture == 1)
		{
			ARPFrame_t* ARP_response1 = (ARPFrame_t*)pkt_data;//转成定义好的数据结构，方便读取信息
			//0806是ARP协议，0002是ARP响应，响应IP是请求IP
			if ((ntohs(ARP_response1->FrameHeader.FrameType) == 0x0806) && (ntohs(ARP_response1->Operation) == 0x0002) && (ARP_response1->SendIP == ARPFrame.RecvIP))
			{
				cout << "所选设备的MAC地址为：";

				for (int i = 0; i < 6; i++)
				{
					printf("%02x.", ARP_response1->FrameHeader.SrcMAC[i]);
					device_mac[i] = ARP_response1->FrameHeader.SrcMAC[i];
				}
				break;
			}
		}
	}
	//下面用所选设备的mac构建新的arp包
	cout << endl;
	cout << "===============================================================================";
	cout << endl;
	cout << "开始针对局域网其他主机的IP、MAC捕获：" << endl;
	cout << "请输入目标主机的IP地址：";
	char target_ip[INET_ADDRSTRLEN];
	cin >> target_ip;

	ARPFrame_t ARPFrame_again;
	ARPFrame_again.RecvIP = inet_addr(target_ip);
	for (int i = 0; i < 6; i++) {
		ARPFrame_again.FrameHeader.DesMAC[i] = 0xff;
		ARPFrame_again.RecvHa[i] = 0x00;
		ARPFrame_again.FrameHeader.SrcMAC[i] = device_mac[i];
		ARPFrame_again.SendHa[i] = device_mac[i];
	}
	ARPFrame_again.FrameHeader.FrameType = htons(0x0806);
	ARPFrame_again.HardwareType = htons(0x0001);
	ARPFrame_again.ProtocolType = htons(0x0800);
	ARPFrame_again.HLen = 6;
	ARPFrame_again.PLen = 4;
	ARPFrame_again.Operation = htons(0x0001);
	ARPFrame_again.SendIP = inet_addr(device_ip);



	while (1)
	{
		//先开抓包
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int capture = pcap_next_ex(p, &pkt_header, &pkt_data);//抓包
		//发送ARP
		if (pcap_sendpacket(p, (u_char*)&ARPFrame_again, sizeof(ARPFrame_t)) != 0) {
			cout << "针对其他主机发送数据包失败！" << endl;
			pcap_freealldevs(alldevs);
			return 0;
		}
		if (capture == 1)
		{
			ARPFrame_t* ARP_response2 = (ARPFrame_t*)pkt_data;//转成定义好的数据结构，方便读取信息
			if ((ntohs(ARP_response2->FrameHeader.FrameType) == 0x0806) && (ntohs(ARP_response2->Operation) == 0x0002) && (ARP_response2->SendIP == ARPFrame_again.RecvIP))
			{
				cout << "目标主机的MAC地址为：";

				for (int i = 0; i < 6; i++)
				{
					printf("%02x.", ARP_response2->FrameHeader.SrcMAC[i]);
				}
				break;
			}
		}
	}

	pcap_freealldevs(alldevs);
	return 0;

}


// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
