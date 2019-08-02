/*
 *    ||          ____  _ __                           
 * +------+      / __ )(_) /_______________ _____  ___ 
 * | 0xBC |     / __  / / __/ ___/ ___/ __ `/_  / / _ \
 * +------+    / /_/ / / /_/ /__/ /  / /_/ / / /_/  __/
 *  ||  ||    /_____/_/\__/\___/_/   \__,_/ /___/\___/
 *
 * Crazyflie control firmware
 *
 * Copyright (C) 2011-2012 Bitcraze AB
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, in version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * radiolink.c - Radio link layer
 */

/*
 * This file has been modified by the Wireless Innovation and Cybersecurity Lab of George Mason University
 * This project was overseen by Dr. Kai Zeng from the Department of Electrical and Computer Engineering
 * Contributing Members: David Rudo, Brandon Fogg, Thomas Lu, Matthew Chang, Yaqi He, Shrinath Iyer
 */

#include <string.h>
#include <stdint.h>

/*FreeRtos includes*/
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "queue.h"

#include "config.h"
#include "radiolink.h"
#include "syslink.h"
#include "crtp.h"
#include "configblock.h"
#include "log.h"
#include "led.h"
#include "ledseq.h"
#include "queuemonitor.h"

#include "xtea.h"

//#include "../init/main.c"

#define RADIOLINK_TX_QUEUE_SIZE (1)
#define RADIO_ACTIVITY_TIMEOUT_MS (1000)



static xQueueHandle  txQueue;
static xQueueHandle crtpPacketDelivery;

static bool isInit;

static int radiolinkSendCRTPPacket(CRTPPacket *p);
static int radiolinkSetEnable(bool enable);
static int radiolinkReceiveCRTPPacket(CRTPPacket *p);

//Local RSSI variable used to enable logging of RSSI values from Radio
static uint8_t rssi;
static uint32_t lastPacketTick;

//static uint8_t key[16] = {(uint8_t) 0x1b, (uint8_t) 0x4f, (uint8_t) 0x9d, (uint8_t) 0x87, (uint8_t) 0x01, (uint8_t) 0x65, (uint8_t) 0x10, (uint8_t) 0xfd, (uint8_t) 0xab, (uint8_t) 0xcd, (uint8_t) 0x16, (uint8_t) 0xaf, (uint8_t) 0xe9, (uint8_t) 0x63, (uint8_t) 0x28, (uint8_t) 0xd5};
static uint32_t teaKey[4] = {(uint32_t) 0x1b4f9d87, (uint32_t) 0x016510fd, (uint32_t) 0xabcd16af, (uint32_t) 0xe96328d5};
bool match = false;

static bool radiolinkIsConnected(void) {
  return (xTaskGetTickCount() - lastPacketTick) < M2T(RADIO_ACTIVITY_TIMEOUT_MS);
}

static struct crtpLinkOperations radiolinkOp =
{
  .setEnable         = radiolinkSetEnable,
  .sendPacket        = radiolinkSendCRTPPacket,
  .receivePacket     = radiolinkReceiveCRTPPacket,
  .isConnected       = radiolinkIsConnected
};

void radiolinkInit(void)
{
  if (isInit)
    return;
  //memcpy(teaKey, &key[0], 16);
  txQueue = xQueueCreate(RADIOLINK_TX_QUEUE_SIZE, sizeof(SyslinkPacket));
  DEBUG_QUEUE_MONITOR_REGISTER(txQueue);
  crtpPacketDelivery = xQueueCreate(5, sizeof(CRTPPacket));
  DEBUG_QUEUE_MONITOR_REGISTER(crtpPacketDelivery);


  ASSERT(crtpPacketDelivery);

  syslinkInit();

  radiolinkSetChannel(configblockGetRadioChannel());
  radiolinkSetDatarate(configblockGetRadioSpeed());
  radiolinkSetAddress(configblockGetRadioAddress());

  isInit = true;
}

bool radiolinkTest(void)
{
  return syslinkTest();
}

void radiolinkSetChannel(uint8_t channel)
{
  SyslinkPacket slp;

  slp.type = SYSLINK_RADIO_CHANNEL;
  slp.length = 1;
  slp.data[0] = channel;
  syslinkSendPacket(&slp);
}

void radiolinkSetDatarate(uint8_t datarate)
{
  SyslinkPacket slp;

  slp.type = SYSLINK_RADIO_DATARATE;
  slp.length = 1;
  slp.data[0] = datarate;
  syslinkSendPacket(&slp);
}

void radiolinkSetAddress(uint64_t address)
{
  SyslinkPacket slp;

  slp.type = SYSLINK_RADIO_ADDRESS;
  slp.length = 5;
  memcpy(&slp.data[0], &address, 5);
  syslinkSendPacket(&slp);
}

void radiolinkSetPowerDbm(int8_t powerDbm)
{
  SyslinkPacket slp;

  slp.type = SYSLINK_RADIO_POWER;
  slp.length = 1;
  slp.data[0] = powerDbm;
  syslinkSendPacket(&slp);
}


void radiolinkSyslinkDispatch(SyslinkPacket *slp)
{
  static SyslinkPacket txPacket;

  if (slp->type == SYSLINK_RADIO_RAW || slp->type == SYSLINK_RADIO_RAW_BROADCAST) {
    lastPacketTick = xTaskGetTickCount();
  }

  if (slp->type == SYSLINK_RADIO_RAW)
  {
    slp->length--; // Decrease to get CRTP size.
    xQueueSend(crtpPacketDelivery, &slp->length, 0);
    ledseqRun(LINK_LED, seq_linkup);
    // If a radio packet is received, one can be sent
    if (xQueueReceive(txQueue, &txPacket, 0) == pdTRUE)
    {
      ledseqRun(LINK_DOWN_LED, seq_linkup);
      syslinkSendPacket(&txPacket);
    }
  } else if (slp->type == SYSLINK_RADIO_RAW_BROADCAST)
  {
    slp->length--; // Decrease to get CRTP size.
    xQueueSend(crtpPacketDelivery, &slp->length, 0);
    ledseqRun(LINK_LED, seq_linkup);
    // no ack for broadcasts
  } else if (slp->type == SYSLINK_RADIO_RSSI)
	{
		//Extract RSSI sample sent from radio
		memcpy(&rssi, slp->data, sizeof(uint8_t));
	}
}

static int radiolinkReceiveCRTPPacket(CRTPPacket *p)
{
  if (xQueueReceive(crtpPacketDelivery, p, M2T(100)) == pdTRUE)
  {
	uint8_t bytes[]  = {(uint8_t)0x03, (uint8_t)0x05, (uint8_t)'\n'};

	if(!match) {
		bool m = true;
		for(int i = 0; i<3; i++) {
			if(p->data[i] != bytes[i])
				m = false;
		}
		if(m) {
			match = true;
		}
		return 0;
	}

	uint8_t data[24];
	memcpy(data, &p->data[0], 24);
	for(int i = 0; i<3; i++) {
		XTeaDecrypt(data+(i*8), teaKey);
	}
	memcpy(p->data, &data[0], 24);
	return 0;
  }
  return -1;
}

static int radiolinkSendCRTPPacket(CRTPPacket *p)
{
  static SyslinkPacket slp;

  ASSERT(p->size <= CRTP_MAX_DATA_SIZE);

  if(!match) {
	  slp.type = SYSLINK_RADIO_RAW;
	  slp.length = p->size + 1;
	  memcpy(slp.data, &p->header, p->size + 1);
	  if (xQueueSend(txQueue, &slp, M2T(100)) == pdTRUE)
	   {
	     return true;
	   }

	   return false;
  }

  if(p->size < 24){
    p->size = 24;
  }

  uint8_t data[24];
  memcpy(data, &p->data[0], 24);
  for(int i = 0; i<3; i++) {
  	XTeaEncrypt(data+(i*8), teaKey);
  }
  memcpy(p->data, &data[0], 24);
  slp.type = SYSLINK_RADIO_RAW;
  slp.length = p->size + 1;
  memcpy(slp.data, &p->header, p->size + 1);
  if (xQueueSend(txQueue, &slp, M2T(100)) == pdTRUE)
  {
    return true;
  }

  return false;
}

struct crtpLinkOperations * radiolinkGetLink()
{
  return &radiolinkOp;
}

static int radiolinkSetEnable(bool enable)
{
  return 0;
}

LOG_GROUP_START(radio)
LOG_ADD(LOG_UINT8, rssi, &rssi)
LOG_GROUP_STOP(radio)
