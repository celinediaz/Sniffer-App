
// SnifferProjectDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "SnifferProject.h"
#include "SnifferProjectDlg.h"
#include "afxdialogex.h"
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <bitset>
#include <regex>
#include <numeric>
#include <json/json.h>
#include <fstream>

#define LINE_LEN 16

#include <tchar.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BOOL stop;
CString Dest, Source, FlowLabel, PayloadLength, NextHeader, HopLimit, SourceIP, DestinationIP, SourcePort, DestinationPort, SeqNum, AckNum, WinSizeVal, Checksum, Version, HeaderLength, DiffServ, TotalLength, Ident, Flags, FragOffset;
CString TTL, HeaderChecksum, HardwareType, HardwareSize, ProtocolType, ProtocolSize, Opcode, sourceMac, destMac, Type;
CString protocol;
std::vector<int> dump;
UINT MyThreadProc(LPVOID Param);

// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSnifferProjectDlg dialog



CSnifferProjectDlg::CSnifferProjectDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFERPROJECT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSnifferProjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_ALL, m_listAll);
	DDX_Control(pDX, IDC_DUMP, m_listPacket);
	DDX_Control(pDX, IDC_INFO, m_listInf);
	DDX_Control(pDX, IDC_COMBO2, m_comboFilter);
	DDX_Control(pDX, IDC_COMBO1, m_comboInterface);
	DDX_Control(pDX, IDC_COMBO3, m_comboBox);
	DDX_Control(pDX, IDC_LIST1, m_listStats);
	DDX_Control(pDX, IDC_COMBO_FORMAT, m_comboFormat);
	DDX_Control(pDX, IDC_STATIC_PKT, m_PicPkt);
}

BEGIN_MESSAGE_MAP(CSnifferProjectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START, &CSnifferProjectDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_STOP, &CSnifferProjectDlg::OnBnClickedStop)
	ON_BN_CLICKED(IDC_FILTER, &CSnifferProjectDlg::OnBnClickedFilter)
	ON_BN_CLICKED(IDC_MOSTRAR, &CSnifferProjectDlg::OnBnClickedMostrar)
	ON_NOTIFY(LVN_ITEMACTIVATE, IDC_LIST_ALL, &CSnifferProjectDlg::OnLvnItemActivateListAll)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_ALL, &CSnifferProjectDlg::OnCustomDrawList)
	ON_BN_CLICKED(IDC_STATS, &CSnifferProjectDlg::OnBnClickedStats)
END_MESSAGE_MAP()


// CSnifferProjectDlg message handlers

BOOL CSnifferProjectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	for (int i = 0; i < 16; i++) {
		m_listPacket.InsertColumn(i, _T(" "), LVCFMT_LEFT, 60);
	}
	// Column creation
	m_listInf.InsertColumn(1, _T("Nombre"), LVCFMT_LEFT, 130);
	m_listInf.InsertColumn(2, _T("Valor"), LVCFMT_LEFT, 200);
	m_listAll.InsertColumn(1, _T("No."), LVCFMT_LEFT, 40);
	m_listAll.InsertColumn(2, _T("Source"), LVCFMT_LEFT, 200);
	m_listAll.InsertColumn(3, _T("Destination"), LVCFMT_LEFT, 200);
	m_listAll.InsertColumn(4, _T("Length"), LVCFMT_LEFT, 80);
	m_listAll.InsertColumn(5, _T("Header Type"), LVCFMT_LEFT, 100);
	m_comboFilter.AddString(_T("Show all"));
	m_comboFilter.AddString(_T("IP address"));
	m_comboFilter.AddString(_T("Type"));
	m_comboFilter.AddString(_T("Size"));
	m_comboFilter.SetCurSel(0);
	chooseInt();
	m_comboInterface.SetCurSel(0);
	m_listStats.InsertColumn(1, _T("Max"), LVCFMT_LEFT, 80);
	m_listStats.InsertColumn(2, _T("Min"), LVCFMT_LEFT, 80);
	m_listStats.InsertColumn(3, _T("Mean"), LVCFMT_LEFT, 100);
	m_listStats.InsertColumn(4, _T("Median"), LVCFMT_LEFT, 100);
	m_listStats.InsertColumn(5, _T("Q1"), LVCFMT_LEFT, 75);
	m_listStats.InsertColumn(5, _T("Q3"), LVCFMT_LEFT, 75);
	m_listStats.InsertColumn(5, _T("IQR"), LVCFMT_LEFT, 75);
	m_comboFormat.AddString(_T("Hex"));
	m_comboFormat.AddString(_T("Binary"));
	m_comboFormat.AddString(_T("ASCII"));
	m_comboFormat.SetCurSel(0);

	border.CreatePen(PS_SOLID, 1, 0x00303552);
	fill.CreateSolidBrush(0x00ffffff);
	board = m_PicPkt.GetDC();
	board->SelectObject(&border);
	board->SelectObject(&fill);
	board->SetTextColor(RGB(195, 70, 70));

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CSnifferProjectDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CSnifferProjectDlg::OnPaint()
{
	CPaintDC dc(this);
	CRect rect;
	GetClientRect(&rect);
	CBrush col;
	col.CreateSolidBrush(RGB(255, 230, 200));
	dc.FillRect(&rect, &col);
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CSnifferProjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/**
 *  Load Npcap and it's functions.
 */
BOOL CSnifferProjectDlg::LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}

/**
 *  Choose the interface.
 */
int CSnifferProjectDlg::chooseInt() {
	pcap_if_t* alldevs, * d;
	u_int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		exit(1);
	}
	for (d = alldevs; d; d = d->next)
	{
		m_comboInterface.AddString(toLPCSTRun(++i) + d->name);
		if (i == 0)
		{
			return -1;
		}
	}
}


/**
* Method used to capture a package and write it into a plain text file.
* 
* Original source code used to make this function belongs to:
* Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
* Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
* 
*/
int  CSnifferProjectDlg::captura()
{
	pcap_if_t* alldevs, * d;
	pcap_t* fp;
	u_int i = 0;
	u_int inum = interf;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	FILE* f = fopen("hexdump.txt", "w");
	if (f == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
#ifdef WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif


	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next);

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);


	//Do not check for the switch type ('-s') 
	if ((fp = pcap_open_live(d->name,	// name of the device
		65536,							// portion of the packet to capture. 
										// 65536 grants that the whole packet will be captured on all the MACs.
		1,								// promiscuous mode (nonzero means promiscuous)
		1000,							// read timeout
		errbuf							// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		return -1;
	}


	/* Read the packets */
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
			/* Timeout elapsed */
			continue;


		/* Print the packet */
		for (i = 1; (i < header->caplen + 1); i++)
		{
			fprintf(f, "0x%.2x, ", pkt_data[i - 1]);
		}

		break;

	}

	if (res == -1)
	{
		return -1;
	}

	pcap_close(fp);
	fclose(f);
	return 0;
}

/**
 *  Read the plain text file to a vector
 */
void CSnifferProjectDlg::getDump() {
	std::ifstream File;
	File.open("hexdump.txt");
	std::string str;
	dump.clear();
	while (std::getline(File, str, ' '))
	{
		dump.push_back(std::stoi(str, 0, 16));
	}
	File.close();

}

/**
 *  Set dump into a list control
 */
void CSnifferProjectDlg::setDump(int formato) {
	m_listPacket.DeleteAllItems();

	int rows = (dump.size() / 16);
	int w = 0;

	for (int i = 0; i < rows; i++) {
		CString str;
		int nIndex = m_listPacket.InsertItem(i, _T("0"));

		for (int j = 0; j < 16; j++) {
			std::bitset<8> x(dump[w]);
			if (formato == 0) { //hexadecimal
				str.Format(_T("%x"), dump[w]);
			}
			else if (formato == 1) { // binary
				std::string stro = x.to_string();
				str = stro.c_str();
			}
			else if (formato == 2) { //ASCII
				char W = static_cast<char>(dump[w]);
				const char* b;
				std::string tempstr{ W };
				b = tempstr.c_str();
				//replaces characters that aren't part of basic latin with a dot
				std::regex alph("([^\u0020-\u007e])");
				std::string stro = std::regex_replace(b, alph, ".");
				str = stro.c_str();
			}
			m_listPacket.SetItemText(nIndex, j, str);
			w++;
		}
	}
}

/**
 *  Convert number to an unsigned integer with a CString type.
 * @param i number being converted
 */
CString CSnifferProjectDlg::toLPCSTRhex(int i) {
	CString str;
	str.Format(_T("%x"), i);
	return str;
}

/**
 *  Convert number to hexadecimal with a CString type.
 * @param i number being converted
 */
CString CSnifferProjectDlg::toLPCSTRun(int i) {
	CString str;
	str.Format(_T("%u"), i);
	return str;
}
/**
 *  Convert double into a CString type.
 * @param i number being converted
 */
CString CSnifferProjectDlg::toLPCSTRdb(double i) {
	CString str;
	str.Format(_T("%g"), i);
	return str;
}

/**
* check the header's format, calls the find methods that assign the
* header's values according to its type.
*/

void CSnifferProjectDlg::chooseType() {
	if ((dump[12] << 8 | dump[13]) == 2048) {
		header = 1;
		findipv4();
	}
	else if ((dump[12] << 8 | dump[13]) == 34525) {
		header = 2;
		findipv6();
	}
	else if ((dump[12] << 8 | dump[13]) == 2054) {
		header = 3;
		findarp();
	}
}


/**
* finds the information of IPv6 packets
*/
void CSnifferProjectDlg::findipv6() {
	Dest = toLPCSTRhex(dump[0]) + _T(":") + toLPCSTRhex(dump[1]) + _T(":") + toLPCSTRhex(dump[2]) + _T(":") + toLPCSTRhex(dump[3]) + _T(":") + toLPCSTRhex(dump[4]) + _T(":") + toLPCSTRhex(dump[5]);
	Source = toLPCSTRhex(dump[6]) + _T(":") + toLPCSTRhex(dump[7]) + _T(":") + toLPCSTRhex(dump[8]) + _T(":") + toLPCSTRhex(dump[9]) + _T(":") + toLPCSTRhex(dump[10]) + _T(":") + toLPCSTRhex(dump[11]);
	Type = _T("IPV6");
	FlowLabel = _T("0x") + toLPCSTRhex((((dump[15] << 16)) | (dump[16] << 8)) | dump[17]);
	PayloadLength = toLPCSTRun((dump[18] << 8) | dump[19]);
	if (dump[20] == 6) {
		protocol = "TCP";
	}
	else if (dump[20] == 17) {
		protocol = "UDP";
	}
	else if (dump[20] == 2) {
		protocol = "IGMP";
	}
	NextHeader = protocol + _T(" (") + toLPCSTRun(dump[20]) + _T(")");
	HopLimit = toLPCSTRun(dump[21]);
	SourceIP = toLPCSTRhex((dump[22] << 8 | dump[23])) + _T(":") + toLPCSTRhex(dump[24] << 8 | dump[25]) + _T(":") + toLPCSTRhex(dump[26] << 8 | dump[27]) + _T(":") + toLPCSTRhex(dump[28] << 8 | dump[29]) + _T(":") + toLPCSTRhex(dump[30] << 8 | dump[31]) + _T(":") + toLPCSTRhex(dump[32] << 8 | dump[33]) + _T(":") + toLPCSTRhex(dump[34] << 8 | dump[35]) + _T(":") + toLPCSTRhex(dump[36] << 8 | dump[37]);
	DestinationIP = toLPCSTRhex((dump[38] << 8 | dump[39])) + _T(":") + toLPCSTRhex(dump[40] << 8 | dump[41]) + _T(":") + toLPCSTRhex(dump[42] << 8 | dump[43]) + _T(":") + toLPCSTRhex(dump[44] << 8 | dump[45]) + _T(":") + toLPCSTRhex(dump[46] << 8 | dump[47]) + _T(":") + toLPCSTRhex(dump[48] << 8 | dump[49]) + _T(":") + toLPCSTRhex(dump[50] << 8 | dump[51]) + _T(":") + toLPCSTRhex(dump[52] << 8 | dump[53]);
	SourcePort = toLPCSTRun((dump[54] << 8) | dump[55]);
	DestinationPort = toLPCSTRun((dump[56] << 8) | dump[57]);
	toJsonipv6();
}
/**
* finds the information of IPv6 packets
*/
void  CSnifferProjectDlg::findipv4() {
	Dest = toLPCSTRhex(dump[0]) + _T(":") + toLPCSTRhex(dump[1]) + _T(":") + toLPCSTRhex(dump[2]) + _T(":") + toLPCSTRhex(dump[3]) + _T(":") + toLPCSTRhex(dump[4]) + _T(":") + toLPCSTRhex(dump[5]);
	Source = toLPCSTRhex(dump[6]) + _T(":") + toLPCSTRhex(dump[7]) + _T(":") + toLPCSTRhex(dump[8]) + _T(":") + toLPCSTRhex(dump[9]) + _T(":") + toLPCSTRhex(dump[10]) + _T(":") + toLPCSTRhex(dump[11]);
	Type = _T("IPV4");
	Version = toLPCSTRun(dump[14] >> 4);
	HeaderLength = toLPCSTRun(4 * ((dump[14]) & ((1 << (4))) - 1));
	DiffServ = toLPCSTRhex(dump[15]);
	TotalLength = toLPCSTRun(((dump[16] << 8) | dump[17]));
	Ident = toLPCSTRhex((dump[18] << 8) | dump[19]);
	Flags = _T("0x") + toLPCSTRhex(dump[20] << 8);
	FragOffset = toLPCSTRun(((dump[20] << 8) | dump[21]) & ((1 << (13)) - 1));
	TTL = toLPCSTRun(dump[22]);
	HeaderChecksum = _T("0x") + toLPCSTRhex(((dump[24] << 8) | dump[25]));
	if (dump[23] == 6) {
		protocol = "TCP";
	}
	else if (dump[23] == 17) {
		protocol = "UDP";
	}
	else if (dump[23] == 2) {
		protocol = "IGMP";
	}
	else { protocol = "otro protocolo"; }

	SourceIP = toLPCSTRun(dump[26]) + _T(".") + toLPCSTRun(dump[27]) + _T(".") + toLPCSTRun(dump[28]) + _T(".") + toLPCSTRun(dump[29]);
	DestinationIP = toLPCSTRun(dump[30]) + _T(".") + toLPCSTRun(dump[31]) + _T(".") + toLPCSTRun(dump[32]) + _T(".") + toLPCSTRun(dump[33]);
	SourcePort = toLPCSTRun(((dump[34] << 8) | dump[35]));
	DestinationPort = toLPCSTRun(((dump[36] << 8) | dump[37]));
	SeqNum = toLPCSTRun((((dump[38] << 24) | (dump[39] << 16)) | (dump[40] << 8)) | dump[41]);
	AckNum = toLPCSTRun((((dump[42] << 24) | (dump[42] << 16)) | (dump[44] << 8)) | dump[45]);
	toJsonipv4();
}
/**
* finds the information of ARP packets
*/
void  CSnifferProjectDlg::findarp() {
	Dest = toLPCSTRhex(dump[0]) + _T(":") + toLPCSTRhex(dump[1]) + _T(":") + toLPCSTRhex(dump[2]) + _T(":") + toLPCSTRhex(dump[3]) + _T(":") + toLPCSTRhex(dump[4]) + _T(":") + toLPCSTRhex(dump[5]);
	Source = toLPCSTRhex(dump[6]) + _T(":") + toLPCSTRhex(dump[7]) + _T(":") + toLPCSTRhex(dump[8]) + _T(":") + toLPCSTRhex(dump[9]) + _T(":") + toLPCSTRhex(dump[10]) + _T(":") + toLPCSTRhex(dump[11]);
	Type = _T("ARP");
	HardwareType = toLPCSTRun((dump[14] << 8) | dump[15]); //HTYPE
	ProtocolType = _T("0x") + toLPCSTRhex((dump[16] << 8) | dump[17]); // PTYPE
	HardwareSize = toLPCSTRun(dump[18]); //HLEN
	ProtocolSize = toLPCSTRun(dump[19]); //PLEN

	Opcode = toLPCSTRun(dump[20] << 8 | dump[21]);
	if ((dump[20] << 8 | dump[21]) == 1) {
		Opcode = +"request";
	}
	else if ((dump[20] << 8 | dump[21]) == 2) {
		Opcode = +"reply";
	}
	sourceMac = toLPCSTRhex(dump[22]) + _T(":") + toLPCSTRhex(dump[23]) + _T(":") + toLPCSTRhex(dump[24]) + _T(":") + toLPCSTRhex(dump[25]) + _T(":") + toLPCSTRhex(dump[26]) + _T(":") + toLPCSTRhex(dump[27]);
	SourceIP = toLPCSTRun(dump[28]) + _T(".") + toLPCSTRun(dump[29]) + _T(".") + toLPCSTRun(dump[30]) + _T(".") + toLPCSTRun(dump[31]);
	destMac = toLPCSTRhex(dump[32]) + _T(":") + toLPCSTRhex(dump[33]) + _T(":") + toLPCSTRhex(dump[34]) + _T(":") + toLPCSTRhex(dump[35]) + _T(":") + toLPCSTRhex(dump[36]) + _T(":") + toLPCSTRhex(dump[37]);
	DestinationIP = toLPCSTRun(dump[38]) + _T(".") + toLPCSTRun(dump[39]) + _T(".") + toLPCSTRun(dump[40]) + _T(".") + toLPCSTRun(dump[41]);
	toJsonARP();

}

// the 3 following methods insert the values previously found into a list control

/**
* Inserts the values found with findipv6() into a list control
*/
void  CSnifferProjectDlg::ipv6() {
	int nIndex;
	nIndex = m_listInf.InsertItem(0, _T("Eth II Destination"));
	m_listInf.SetItemText(nIndex, 1, Dest);
	nIndex = m_listInf.InsertItem(1, _T("Eth II Source"));
	m_listInf.SetItemText(nIndex, 1, Source);
	nIndex = m_listInf.InsertItem(2, _T("Flow label"));
	m_listInf.SetItemText(nIndex, 1, FlowLabel);
	nIndex = m_listInf.InsertItem(3, _T("Payload Length"));
	m_listInf.SetItemText(nIndex, 1, PayloadLength);
	nIndex = m_listInf.InsertItem(4, _T("Next Header"));
	m_listInf.SetItemText(nIndex, 1, NextHeader);
	nIndex = m_listInf.InsertItem(5, _T("Hop Limit"));
	m_listInf.SetItemText(nIndex, 1, HopLimit);
	nIndex = m_listInf.InsertItem(6, _T("Source IP"));
	m_listInf.SetItemText(nIndex, 1, SourceIP);
	nIndex = m_listInf.InsertItem(7, _T("Destination IP"));
	m_listInf.SetItemText(nIndex, 1, DestinationIP);
	nIndex = m_listInf.InsertItem(8, _T("Source Port"));
	m_listInf.SetItemText(nIndex, 1, SourcePort);
	nIndex = m_listInf.InsertItem(9, _T("Destination Port"));
	m_listInf.SetItemText(nIndex, 1, DestinationPort);


}
/**
* Inserts the values found with findipv4() into a list control
*/
void  CSnifferProjectDlg::ipv4() {
	int nIndex;
	nIndex = m_listInf.InsertItem(0, _T("Eth II Destination"));
	m_listInf.SetItemText(nIndex, 1, Dest);
	nIndex = m_listInf.InsertItem(1, _T("Eth II Source"));
	m_listInf.SetItemText(nIndex, 1, Source);
	nIndex = m_listInf.InsertItem(2, _T("Version"));
	m_listInf.SetItemText(nIndex, 1, Version);
	nIndex = m_listInf.InsertItem(3, _T("Header Length"));
	m_listInf.SetItemText(nIndex, 1, HeaderLength);
	nIndex = m_listInf.InsertItem(4, _T("Servicios diferenciados"));
	m_listInf.SetItemText(nIndex, 1, DiffServ);
	nIndex = m_listInf.InsertItem(5, _T("Total length"));
	m_listInf.SetItemText(nIndex, 1, TotalLength);
	nIndex = m_listInf.InsertItem(6, _T("Identificación"));
	m_listInf.SetItemText(nIndex, 1, Ident);
	nIndex = m_listInf.InsertItem(7, _T("Flags: "));
	m_listInf.SetItemText(nIndex, 1, Flags);
	nIndex = m_listInf.InsertItem(8, _T("Fragment offset"));
	m_listInf.SetItemText(nIndex, 1, FragOffset);
	nIndex = m_listInf.InsertItem(9, _T("Time to live"));
	m_listInf.SetItemText(nIndex, 1, TTL);
	nIndex = m_listInf.InsertItem(10, _T("Protocolo"));
	m_listInf.SetItemText(nIndex, 1, protocol + _T("(") + toLPCSTRun(dump[23]) + _T(")"));
	nIndex = m_listInf.InsertItem(11, _T("Header checksum"));
	m_listInf.SetItemText(nIndex, 1, HeaderChecksum);
	nIndex = m_listInf.InsertItem(12, _T("ip origen"));
	m_listInf.SetItemText(nIndex, 1, SourceIP);
	nIndex = m_listInf.InsertItem(13, _T("ip destino"));
	m_listInf.SetItemText(nIndex, 1, DestinationIP);
	nIndex = m_listInf.InsertItem(14, _T("Source port"));
	m_listInf.SetItemText(nIndex, 1, SourcePort);
	nIndex = m_listInf.InsertItem(15, _T("Destination port"));
	m_listInf.SetItemText(nIndex, 1, DestinationPort);
	nIndex = m_listInf.InsertItem(16, _T("Sequence number (raw): "));
	m_listInf.SetItemText(nIndex, 1, SeqNum);
	nIndex = m_listInf.InsertItem(17, _T("Acknowledgement number (raw): "));
	m_listInf.SetItemText(nIndex, 1, AckNum);

}
/**
* Inserts the values found with findarp() into a list control
*/
void  CSnifferProjectDlg::arp() {
	int nIndex;
	nIndex = m_listInf.InsertItem(0, _T("Eth II Destination"));
	m_listInf.SetItemText(nIndex, 1, Dest);
	nIndex = m_listInf.InsertItem(1, _T("Eth II Source"));
	m_listInf.SetItemText(nIndex, 1, Source);
	nIndex = m_listInf.InsertItem(2, _T("Hardware Type"));
	m_listInf.SetItemText(nIndex, 1, HardwareType);
	nIndex = m_listInf.InsertItem(3, _T("Protocol Type"));
	m_listInf.SetItemText(nIndex, 1, ProtocolType);
	nIndex = m_listInf.InsertItem(4, _T("Hardware Size"));
	m_listInf.SetItemText(nIndex, 1, HardwareSize);
	nIndex = m_listInf.InsertItem(5, _T("Protocol Size"));
	m_listInf.SetItemText(nIndex, 1, ProtocolSize);
	nIndex = m_listInf.InsertItem(6, _T("Opcode"));
	m_listInf.SetItemText(nIndex, 1, Opcode + _T("(") + toLPCSTRun(dump[20] << 8 | dump[21]) + _T(")"));
	nIndex = m_listInf.InsertItem(7, _T("Sender Mac Address:"));
	m_listInf.SetItemText(nIndex, 1, sourceMac);
	nIndex = m_listInf.InsertItem(8, _T("Sender IP Address"));
	m_listInf.SetItemText(nIndex, 1, SourceIP);
	nIndex = m_listInf.InsertItem(9, _T("Target Mac Address"));
	m_listInf.SetItemText(nIndex, 1, destMac);
	nIndex = m_listInf.InsertItem(10, _T("Target IP Address"));
	m_listInf.SetItemText(nIndex, 1, DestinationIP);

}

/**
* multithreading method, reads dump into txt, writes it into vector, chooses its type
* inserts the vector with the dump into a vector of vectors to save all headers
* Sets into the general List Control. 
*/
UINT MyThreadProc(LPVOID Param) {
	CSnifferProjectDlg* pObject = (CSnifferProjectDlg*)Param;
	int i = 0;
	int nIndex;
	while (!stop) {
		pObject->captura();
		pObject->getDump();
		pObject->chooseType();
		pObject->size.push_back(dump.size());
		pObject->dumpAll.push_back(dump);
		nIndex = pObject->m_listAll.InsertItem(i, pObject->toLPCSTRun(i + 1));
		pObject->setAll(nIndex);
		i++;
	}
	return TRUE;
}


/**
 *  Sets the general list control with some info of each packet.
 * 
 * @param nIndex Index of the item being set (row).
 */
void CSnifferProjectDlg::setAll(int nIndex) {
	m_listAll.SetItemText(nIndex, 1, SourceIP);
	m_listAll.SetItemText(nIndex, 2, DestinationIP);
	m_listAll.SetItemText(nIndex, 3, toLPCSTRun(dump.size()));
	m_listAll.SetItemText(nIndex, 4, Type);
}

// the four following methods are for filtering according to their type, address and size, or to show all.

/**
 *  Filtering by type (ARP, IPv4, IPv6).
 * 
 * @param c CString of the type that you want to filter by.
 */
void CSnifferProjectDlg::showType(CString c) {
	m_listAll.DeleteAllItems();
	int nIndex;
	int j = 0;
	if (c == _T("ARP") || c == _T("arp")) {
		for (int i = 0; i < dumpAll.size(); i++) {
			dump = dumpAll[i];
			if ((dump[12] << 8 | dump[13]) == 2054) {
				findarp();
				nIndex = m_listAll.InsertItem(j, toLPCSTRun(i + 1));
				setAll(nIndex);
				j++;
			}
		}
	}
	else if (c == _T("IPV4") || c == _T("ipv4")) {
		for (int i = 0; i < dumpAll.size(); i++) {
			dump = dumpAll[i];
			if ((dump[12] << 8 | dump[13]) == 2048) {
				findipv4();
				nIndex = m_listAll.InsertItem(j, toLPCSTRun(i + 1));
				setAll(nIndex);
				j++;
			}
		}
	}
	else if (c == _T("IPV6") || c == _T("ipv6")) {
		for (int i = 0; i < dumpAll.size(); i++) {
			dump = dumpAll[i];
			if ((dump[12] << 8 | dump[13]) == 34525) {
				findipv6();
				nIndex = m_listAll.InsertItem(j, toLPCSTRun(i + 1));
				setAll(nIndex);
				j++;
			}
		}
	}


}

/**
 *  Filtering by address.
 * 
 * @param c CString of the address that you want to filter by.
 */

void CSnifferProjectDlg::showIP(CString c) {
	m_listAll.DeleteAllItems();
	int nIndex;
	int j = 0;
	for (int i = 0; i < dumpAll.size(); i++) {
		dump = dumpAll[i];
		chooseType();
		if ((c == SourceIP) || (c == DestinationIP)) {
			nIndex = m_listAll.InsertItem(j, toLPCSTRun(i + 1));
			setAll(nIndex);
			j++;
		}
	}
}

/**
 *  Filtering by size.
 * 
 * @param c CString of the size that you want to filter by.
 */

void CSnifferProjectDlg::showSize(CString c) {
	m_listAll.DeleteAllItems();
	int size = _wtoi(c);
	int nIndex;
	int j = 0;
	for (int i = 0; i < dumpAll.size(); i++) {
		dump = dumpAll[i];
		chooseType();
		if (size == dump.size()) {
			nIndex = m_listAll.InsertItem(j, toLPCSTRun(i + 1));
			setAll(nIndex);
			j++;
		}
	}
}

/**
 *  Show all packets captured
 */

void CSnifferProjectDlg::showAll() {
	m_listAll.DeleteAllItems();
	int nIndex;
	int j = 0;
	for (int i = 0; i < dumpAll.size(); i++) {
		dump = dumpAll[i];
		chooseType();
		nIndex = m_listAll.InsertItem(i, toLPCSTRun(i + 1));
		setAll(nIndex);
	}
}


/**
 * Show the details of the selected packet
 */
void CSnifferProjectDlg::showDetails() {
	m_listInf.DeleteAllItems();
	UpdateData(TRUE);
	Invalidate();
	UpdateWindow();
	switch (header) {
	case 1:
		ipv4();
		headerIPV4();
		break;
	case 2:
		ipv6();
		headerIPV6();
		break;
	case 3:
		arp();
		headerARP();
		break;

	}
}

/**
 *  Button to start the thread
 */
void CSnifferProjectDlg::OnBnClickedStart()
{
	stop = false;
	interf = (int)m_comboInterface.GetCurSel() + 1;
	m_listAll.DeleteAllItems();
	size.clear();
	int nIndex;
	dumpAll.clear();
	m_comboBox.ResetContent();
	AfxBeginThread(MyThreadProc, this);

}
/**
 *  Button to stop the thread
 */
void CSnifferProjectDlg::OnBnClickedStop()
{
	stop = TRUE;
	for (int i = 0; i < dumpAll.size() + 1; i++) {
		m_comboBox.AddString(toLPCSTRun(i + 1));
	}
	m_comboBox.SetCurSel(0);
}
/**
 *  Button for filtering
 */
void CSnifferProjectDlg::OnBnClickedFilter()
{
	CString c;
	GetDlgItemText(IDC_EDIT1, c);
	int option = (int)m_comboFilter.GetCurSel();
	if (option == 0) {
		showAll();
	}
	else if (option == 1) {
		showIP(c);
	}
	else if (option == 2) {
		showType(c);
	}
	else if (option == 3) {
		showSize(c);
	}
}


/**
 *  Button to change the format of the shown hexdump
 */
void CSnifferProjectDlg::OnBnClickedMostrar()
{
	int formt = (int)m_comboFormat.GetCurSel();
	setDump(formt);
}

/**
 *  Method to select a packet with a click in the CListControl.
 */

void CSnifferProjectDlg::OnLvnItemActivateListAll(NMHDR* pNMHDR, LRESULT* pResult)
{

	LPNMITEMACTIVATE pNMIA = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
	index = m_listAll.GetSelectionMark();
	m_listAll.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_BORDERSELECT);

	int n = _wtoi(m_listAll.GetItemText(index, 0)) - 1;
	dump = dumpAll[n];
	int formt = (int)m_comboFormat.GetCurSel();
	setDump(formt);
	chooseType();
	showDetails();
	m_comboBox.SetCurSel(n);
}

/**
 * Method to change the general List Control's colors
 */
void CSnifferProjectDlg::OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult) {
	NMLVCUSTOMDRAW* pLV = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	int rowIndex = static_cast<int>(pLV->nmcd.dwItemSpec);
	*pResult = 0;

	switch (pLV->nmcd.dwDrawStage)
	{
	case CDDS_PREPAINT:
		*pResult = CDRF_NOTIFYITEMDRAW;
		break;

	case CDDS_ITEMPREPAINT:
		if (rowIndex % 2 == 0) {
			pLV->clrTextBk = RGB(255, 230, 200);
			pLV->clrText = RGB(195, 70, 70);
		}
		else {
			pLV->clrTextBk = RGB(255, 255, 255);
			pLV->clrText = RGB(0, 0, 0);
		}

		*pResult = CDRF_DODEFAULT;
		break;
	}
}


/**
 *  Show the statistics found by findStats()
 */
void CSnifferProjectDlg::OnBnClickedStats()
{
	m_listStats.DeleteAllItems();
	findStats();
	int nIndex = m_listStats.InsertItem(0, toLPCSTRun(1));
	m_listStats.SetItemText(nIndex, 0, toLPCSTRun(max));
	m_listStats.SetItemText(nIndex, 1, toLPCSTRun(min));
	m_listStats.SetItemText(nIndex, 2, toLPCSTRdb(mean));
	m_listStats.SetItemText(nIndex, 3, toLPCSTRdb(media));
	m_listStats.SetItemText(nIndex, 4, toLPCSTRdb(q1));
	m_listStats.SetItemText(nIndex, 5, toLPCSTRdb(iqr));
	m_listStats.SetItemText(nIndex, 6, toLPCSTRdb(q3));
}


/**
 *  Find the summary of descriptive statistics of Size.
 */
void  CSnifferProjectDlg::findStats() {
	max = *std::max_element(size.begin(), size.end());
	min = *std::min_element(size.begin(), size.end());
	double sum = std::accumulate(size.begin(), size.end(), 0.0);
	mean = sum / size.size();
	std::vector<int> sortedsize = size;
	std::sort(sortedsize.begin(), sortedsize.end());
	//  if there's an even amount of packets
	if ((size.size() % 2) == 0) {
		media = (sortedsize[size.size() / 2] + sortedsize[(size.size() / 2) - 1]) / 2.0;
		//if half of the numbers are even
		if ((size.size() / 2) % 2 == 0) {
			q1 = (sortedsize[(size.size() / 4)] + sortedsize[((size.size() - 1) / 4)]) / 2.0;
			q3 = (sortedsize[(size.size() * 3 / 4)] + sortedsize[((size.size() - 1) * 3 / 4)]) / 2.0;
		}
		else {
			q1 = sortedsize[(size.size()) / 4];
			q3 = sortedsize[(size.size() * 3) / 4];
		}
	}
	else {
		media = sortedsize[size.size() / 2];
		//if after taking the middle element out and dividing by half it's an even number
		if (((size.size() - 1) / 2) % 2 == 1) {
			q1 = sortedsize[size.size() / 4];
			q3 = sortedsize[((size.size()) * 3) / 4];
		}
		else {
			q1 = (sortedsize[(size.size() / 4)] + sortedsize[((size.size() / 4) - 1)]) / 2.0;
			q3 = (sortedsize[(size.size() * 3 / 4)] + sortedsize[((size.size() * 3 / 4) + 1)]) / 2.0;
		}
	}
	iqr = q3 - q1;
}



/**
 *  save the values found by findipv6() as a json file
 */
void CSnifferProjectDlg::toJsonipv6() {
	Json::Value root;
	std::ofstream f("jsonInfo.json", std::ofstream::binary);
	Json::Value objv(Json::objectValue);
	Json::Value objva(Json::objectValue);
	objva["Flow Label"] = toString(FlowLabel);
	objva["Payload Length"] = toString(PayloadLength);
	objva["Next Header"] = toString(NextHeader);
	objva["Hop Limit"] = toString(HopLimit);
	objva["Source IP"] = toString(SourceIP);
	objva["DestinationIP"] = toString(DestinationIP);
	objva["Source Port"] = toString(SourcePort);
	objva["Destination Port"] = toString(DestinationPort);
	objv["IPV6"] = objva;
	f << objv;
	f.close();
}


/**
 *  save the values found by findipv4() as a json file
 */
void CSnifferProjectDlg::toJsonipv4() {
	Json::Value root;
	std::ofstream f("jsonInfo.json", std::ofstream::binary);
	Json::Value objv(Json::objectValue);
	Json::Value objva(Json::objectValue);
	objva["Version"] = toString(Version);
	objva["Header Length"] = toString(HeaderLength);
	objva["Differentiated Services"] = toString(DiffServ);
	objva["Total Length"] = toString(TotalLength);
	objva["Identification"] = toString(Ident);
	objva["Flags"] = toString(Flags);
	objva["Fragment Offset"] = toString(FragOffset);
	objva["Time to live"] = toString(TTL);
	objva["Protocolo"] = toString(protocol);
	objva["Header Checksum"] = toString(HeaderChecksum);
	objva["IP origen"] = toString(SourceIP);
	objva["IP destino"] = toString(DestinationIP);
	objva["Source Port"] = toString(SourcePort);
	objva["Destination Port"] = toString(DestinationPort);
	objva["Sequence number (raw)"] = toString(SeqNum);
	objva["Acknowledgement number (raw)"] = toString(AckNum);
	objv["IPV4"] = objva;
	f << objv;
	f.close();
}

/**
 *  save the values found by findarp() as a json file
 */
void CSnifferProjectDlg::toJsonARP() {
	Json::Value root;
	std::ofstream f("jsonInfo.json", std::ofstream::binary);
	Json::Value objv(Json::objectValue);
	Json::Value objva(Json::objectValue);

	objva["Hardware"] = toString(HardwareType);
	objva["Protocol Type"] = toString(ProtocolType);
	objva["Hardware Size"] = toString(HardwareSize);
	objva["Protocol Size"] = toString(ProtocolSize);
	objva["Opcode"] = toString(Opcode + _T("(") + toLPCSTRun(dump[20] << 8 | dump[21]) + _T(")"));
	objva["Sender Mac Address"] = toString(sourceMac);
	objva["Sender IP Address"] = toString(SourceIP);
	objva["Target Mac Address"] = toString(destMac);
	objva["Target IP Address"] = toString(DestinationIP);

	objv["ARP"] = objva;
	f << objv;
	f.close();
}

/**
 *  convert CString to std::string, used in the JSON methods.
 * @param str CString or LPCWSTR you want to convert.
 */
std::string CSnifferProjectDlg::toString(LPCWSTR str) {
	std::string A = CW2A(str);
	return A;
}


/**
 *  Show the values visually by showing the ARP header structure
 */
void CSnifferProjectDlg::headerARP() {
	double i = 4;
	board->Rectangle(0 * i, 0, 125 * i, 20);
	board->TextOut(5 * i, 3, _T("HTYPE: ") + HardwareType);
	board->Rectangle(250 * i, 0, 125 * i, 20);
	board->TextOut(130 * i, 3, _T("PTYPE: ") + ProtocolType);
	board->Rectangle(0 * i, 20, 63 * i, 40);
	board->Rectangle(125 * i, 20, 63 * i, 40);
	board->TextOut(5 * i, 23, _T("HLEN: ") + HardwareSize);
	board->TextOut(66 * i, 23, _T("PLEN: ") + ProtocolSize);
	board->Rectangle(250 * i, 20, 125 * i, 40);
	board->TextOut(130 * i, 23, _T("OPCODE: ") + Opcode);
	board->Rectangle(0, 40, 250 * i, 80);
	board->TextOut(10, 53, _T("SHA: ") + sourceMac);
	board->Rectangle(250 * i, 60, 125 * i, 80);
	board->TextOut(126 * i, 63, _T("SPA: ") + SourceIP);
	board->Rectangle(0, 80, 250 * i, 120);
	board->Rectangle(0, 80, 125 * i, 100);
	board->TextOut(5 * i, 83, _T("SPA: ") + SourceIP);
	board->Rectangle(0, 120, 250 * i, 140);
	board->TextOut(130 * i, 93, _T("THA: ") + destMac);
	board->TextOut(5 * i, 123, _T("TPA: ") + DestinationIP);


}
/**
 *  Show the values visually by showing the IPv4 header structure
 */
void CSnifferProjectDlg::headerIPV4() {
	double i = 4;
	board->Rectangle(0, 0, 31 * i, 20);
	board->Rectangle(31 * i, 0, 62 * i, 20);
	board->Rectangle(62 * i, 0, 125 * i, 20);
	board->TextOut(2 * i, 3, _T("Ver: ") + Version);
	board->TextOut(32 * i, 3, _T("IHL: ") + HeaderLength);
	board->TextOut(70 * i, 3, _T("TOS: ") + DiffServ);
	board->Rectangle(250 * i, 0, 125 * i, 20);
	board->TextOut(135 * i, 3, _T("Total Length: ") + TotalLength);
	board->Rectangle(0, 20, 125 * i, 40);
	board->Rectangle(125 * i, 20, 142 * i, 40);
	board->Rectangle(142 * i, 20, 250 * i, 40);
	board->TextOut(2 * i, 22, _T("Identification: ") + Ident);
	board->TextOut(125 * i, 22, _T("F: ") + Flags);
	board->TextOut(143 * i, 22, _T("Fragment Offset: ") + FragOffset);
	board->Rectangle(0, 40, 62.5 * i, 60);
	board->Rectangle(62.5 * i, 40, 125 * i, 60);
	board->Rectangle(250 * i, 40, 125 * i, 60);
	board->Rectangle(0 * i, 60, 250 * i, 80);
	board->Rectangle(0 * i, 80, 250 * i, 100);
	board->TextOut(2 * i, 42, _T("TTL: ") + TTL);
	board->TextOut(63 * i, 42, _T("Protocol: ") + protocol);
	board->TextOut(126 * i, 42, _T("Header Checksum: ") + HeaderChecksum);
	board->TextOut(100 * i, 62, _T("Source IP: ") + SourceIP);
	board->TextOut(100 * i, 82, _T("Destination IP: ") + DestinationIP);
}
/**
 *  Show the values visually by showing the IPv6 header structure
 */
void CSnifferProjectDlg::headerIPV6() {
	double i = 4;
	board->Rectangle(0, 0, 31.25 * i, 20);
	board->Rectangle(31.25 * i, 0, 93.75 * i, 20);
	board->Rectangle(93.75 * i, 0, 250 * i, 20);
	board->Rectangle(0, 20, 125 * i, 40);
	board->Rectangle(125 * i, 20, 187.5 * i, 40);
	board->Rectangle(187.5 * i, 20, 250 * i, 40);
	board->Rectangle(0 * i, 40, 250 * i, 60);
	board->Rectangle(0 * i, 60, 250 * i, 80);
	board->TextOut(2 * i, 3, _T("Ver: ") + toLPCSTRun(dump[14] >> 4));
	board->TextOut(33 * i, 3, _T("Traffic class: 0x") + toLPCSTRhex(dump[14] & 0x0F) + _T("0"));
	board->TextOut(94 * i, 3, _T("Flow label: ") + FlowLabel);
	board->TextOut(2 * i, 23, _T("Payload Length: ") + PayloadLength);
	board->TextOut(126 * i, 23, _T("Next Header: ") + NextHeader);
	board->TextOut(188 * i, 23, _T("Hop Limit: ") + HopLimit);
	board->TextOut(80 * i, 43, _T("Source Address: ") + SourceIP);
	board->TextOut(80 * i, 63, _T("Destination Address: ") + DestinationIP);
}