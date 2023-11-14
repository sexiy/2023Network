// networktec-lab2.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#pragma (1)
#pragma comment(lib,"ws2_32.lib")
#include "pcap.h"
#include<iostream>
#include<thread>
#include<mutex>
using namespace std;
mutex mtx;
//感谢老师给的类定义模板，模版取自
//感谢博客https://blog.csdn.net/lyshark_csdn/article/details/126688509 基本数据结构及对应过程
//感谢博客https://dandelioncloud.cn/article/details/1560542885714305025 过程对应结果展示
//感谢RTFM 完美的完备的
char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
//思路：借助alldevs获取接口设备，
typedef struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

typedef struct IPHeader_t  //IP首部
{
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol; //协议
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
}IPHeader_t;

typedef struct Data_t //包含帧首部和IP首部的数据包
{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;
#pragma pack()//恢复默认对齐方式 4字节对齐




DWORD WINAPI handlerRequest(LPVOID lparam)
{
	
	char* name = (char*)lparam;
	// PCAP_OPENFLAG_PROMISCUOUS = 网卡设置为混杂模式
	// 1000 => 1000毫秒如果读不到数据直接返回超时
	pcap_t* p = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//打开网络接口
	if (p == NULL)
	{
		//cout << "error" << endl;
		return 0;
	}
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int capture = pcap_next_ex(p, &pkt_header, &pkt_data);//直接捕获，read_timeout到时返回
	mtx.lock();
	if (capture == 1)//抓到数据包
	{
		Data_t* IPPacket;//数据包
		IPPacket = (Data_t*)pkt_data;//u_char转换为Data_t

		//cout << "协议类型： ";
		////输出协议类型
		//for (int i = 0; i < 1; i++)
		//{
		//	printf("%02x", IPPacket->IPHeader.Protocol);
		//}
		//cout << " ";

		cout << "源MAC地址：";
		//输出源MAC地址
		for (int i = 0; i < 6; i++)
		{
			printf("%02x", IPPacket->FrameHeader.SrcMAC[i]);
		}
		cout << " ";

		//输出目的MAC地址
		cout << "目的MAC地址：";
		for (int i = 0; i < 6; i++)
		{
			printf("%02x", IPPacket->FrameHeader.DesMAC[i]);
		}
		cout << " ";

		cout << "帧类型/长度：";
		//ntohs((u_short)IPPacket->FrameHeader.FrameType);
		printf("%02x", ntohs(IPPacket->FrameHeader.FrameType));//网络序转为主机序
		cout << "H";
		cout << endl;
	}
	mtx.unlock();
	return 0;
}

pcap_if_t* alldevs;//所有网卡设备保存
pcap_if_t* d;//用于遍历的指针
pcap_addr_t* a;

//struct pcap_if {
//	struct pcap_if* next;
//	char* name;        /* name to hand to "pcap_open_live()" */
//	char* description;    /* textual description of interface, or NULL */
//	struct pcap_addr* addresses;
//	bpf_u_int32 flags;    /* PCAP_IF_ interface flags */
//};
//typedef struct pcap_if pcap_if_t;


int main()
{
	ios::sync_with_stdio(false);
	//调用过程pcap_findalldevs_ex() 获取本地机器设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, //获取本机的接口设备
		NULL, //无需认证
		&alldevs,//指向设备列表首部
		errbuf//出错信息保存缓冲区
	) == -1)
	{
		cout << "error";
	}
	//HANDLE MyThread;
	DWORD ThreadGetId;
	int index = 0;
	// 根据之前获得的本地设备，输出相关信息。
	for (d = alldevs; d != NULL; d = d->next)  //简单输出网卡名称
	{
		++index;
		cout << "ID: "<<index<<"Name: "<<d->description << endl;
	}
	//根据之前获得的本地设备，输出数据
	while (1)
	{

		for (d = alldevs; d != NULL; d = d->next)  //遍历每个接口，进行数据报捕获，一般只有一两个接口有网，所以需要遍历到有网络的接口时才会有输出。
		{
			CreateThread(NULL, 0, handlerRequest, LPVOID(d->name), 0, &ThreadGetId);//打开这一个接口，并捕获数据报
			//Sleep(500);
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
