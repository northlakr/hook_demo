/********************************************************************

 File name : nf_sockopte.h

 Description :
----------------------------------------------
 v0.1, 2015-03-14, Wang Zili, creat file
********************************************************************/

#ifndef _NF_SOCKOPTE_H
#define _NF_SOCKOPTE_H

#define SOE_BANDIP 0x6001
#define SOE_BANDPORT 0x6002
#define SOE_BANDPING 0x6003

typedef struct nf_bandport
{
	unsigned short protocol;
	unsigned short port;
}nf_bandport;

typedef struct band_status
{
	/* 需禁止的ip，0为未设置 */
	unsigned int band_ip;
	/* 端口禁止，协议和端口均为0时未设置 */
	nf_bandport band_port;
	/* 禁止ping，0为响应，1为禁止 */
	unsigned char band_ping;
}band_status;

#endif /* end of _NF_SOCKOPTE_H */

