
// SnifferProjectDlg.h : header file
//

#pragma once
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include <string>
#include <iterator>
#include <fstream>


// CSnifferProjectDlg dialog
class CSnifferProjectDlg : public CDialogEx
{
// Construction
public:
	CSnifferProjectDlg(CWnd* pParent = nullptr);	// standard constructor


// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFERPROJECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult);

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_listAll;
	CListCtrl m_listPacket;
	CListCtrl m_listInf;
	afx_msg void OnBnClickedStart();
	afx_msg void OnBnClickedStop();
	afx_msg void OnBnClickedFilter();
	afx_msg void OnBnClickedMostrar();
	int chooseInt();
	void ipv6();
	void ipv4();
	void arp();
	void toJsonipv6();
	void toJsonipv4();
	void toJsonARP();
	int index;
	BOOL LoadNpcapDlls();
	int captura();
	void getDump();
	void chooseType();
	std::vector<std::vector<int>> dumpAll;
	int header = 0; // 1 = ipv4, 2= ipv6, 3 = ARP
	void findipv6();
	void findipv4();
	void findarp();
	void findStats();
	void headerIPV4();
	void headerIPV6();
	void headerARP();
	std::string toString(LPCWSTR str);
	double media;
	CString toLPCSTRhex(int i);
	CString toLPCSTRun(int i);
	CString toLPCSTRdb(double i);
	void setAll(int nIndex);
	void setDump(int formato);
	void showType(CString c);
	void showIP(CString c);
	void showSize(CString c);
	void showAll();
	void showDetails();
	int interf;
	double q1, q3, max, min, mean, iqr;
	std::vector<int> size;
	CComboBox m_comboFilter;
	CComboBox m_comboInterface;
	CComboBox m_comboBox;
	afx_msg void OnLvnItemActivateListAll(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedStats();
	CListCtrl m_listStats;
	CComboBox m_comboFormat;
	CStatic m_PicPkt;
	CDC* board;
	CPen border;
	CBrush fill;
};
