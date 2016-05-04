#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include <winevt.h>

#include <string>
#include "tinyxml2.h"
#include "EventCop.h"

using namespace tinyxml2;
using namespace std;

#pragma comment(lib, "wevtapi.lib")

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);
DWORD PrintEvent(EVT_HANDLE hEvent);
void CaptureLoginDetails(ACC_EVENT_DATA eve);

int SIZE_DATA = 4096;
TCHAR XMLData[4096];



void main(void)
{
	ACC_EVENT_DATA eve = {0};
	CaptureLoginDetails(eve);

}

void CaptureLoginDetails(ACC_EVENT_DATA eve)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hSubscription = NULL;
	LPWSTR pwsPath = L"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	LPWSTR pwsQuery = L"Event/System[EventID=1149]";

	// Subscribe to events beginning with the oldest event in the channel. The subscription
	// will return all current events in the channel and any future events that are raised
	// while the application is active.
	hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL,
		(EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeStartAtOldestRecord);
	if (NULL == hSubscription)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			wprintf(L"Channel %s was not found.\n", pwsPath);
		else if (ERROR_EVT_INVALID_QUERY == status)
			// You can call EvtGetExtendedStatus to get information as to why the query is not valid.
			wprintf(L"The query \"%s\" is not valid.\n", pwsQuery);
		else
			wprintf(L"EvtSubscribe failed with %lu.\n", status);

		if (hSubscription)
			EvtClose(hSubscription);
		return;
	}

	for (int i = 0; i < 10; i++)
	{
		Sleep(100);
	}

	std::wstring wdataxml(XMLData);
	std::string adataxml(wdataxml.begin(), wdataxml.end());
	tinyxml2::XMLDocument xmlDocRead;
	xmlDocRead.Parse(adataxml.c_str());

	strcpy_s(eve.Computer, xmlDocRead.FirstChildElement("Event")->FirstChildElement("System")->FirstChildElement("Computer")->GetText());
	strcpy_s(eve.ProcessID, xmlDocRead.FirstChildElement("Event")->FirstChildElement("System")->FirstChildElement("Execution")->Attribute("ProcessID"));
	strcpy_s(eve.ThreadID, xmlDocRead.FirstChildElement("Event")->FirstChildElement("System")->FirstChildElement("Execution")->Attribute("ThreadID"));
	strcpy_s(eve.UserID, xmlDocRead.FirstChildElement("Event")->FirstChildElement("System")->FirstChildElement("Security")->Attribute("UserID")); 
	strcpy_s(eve.TimeCreated, xmlDocRead.FirstChildElement("Event")->FirstChildElement("System")->FirstChildElement("TimeCreated")->Attribute("SystemTime"));
	strcpy_s(eve.EventRecordID, xmlDocRead.FirstChildElement("Event")->FirstChildElement("System")->FirstChildElement("EventRecordID")->GetText());
	strcpy_s(eve.UserName, xmlDocRead.FirstChildElement("Event")->FirstChildElement("UserData")->FirstChildElement("EventXML")->FirstChildElement("Param1")->GetText());
	strcpy_s(eve.UserDomain, xmlDocRead.FirstChildElement("Event")->FirstChildElement("UserData")->FirstChildElement("EventXML")->FirstChildElement("Param2")->GetText());
	strcpy_s(eve.UserIP, xmlDocRead.FirstChildElement("Event")->FirstChildElement("UserData")->FirstChildElement("EventXML")->FirstChildElement("Param3")->GetText());

	if (hSubscription)
		EvtClose(hSubscription);
}

// The callback that receives the events that match the query criteria. 
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
	UNREFERENCED_PARAMETER(pContext);

	DWORD status = ERROR_SUCCESS;

	switch (action)
	{
		// You should only get the EvtSubscribeActionError action if your subscription flags 
		// includes EvtSubscribeStrict and the channel contains missing event records.
	case EvtSubscribeActionError:
		if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
		{
			wprintf(L"The subscription callback was notified that event records are missing.\n");
			// Handle if this is an issue for your application.
		}
		else
		{
			wprintf(L"The subscription callback received the following Win32 error: %lu\n", (DWORD)hEvent);
		}
		break;

	case EvtSubscribeActionDeliver:
		if (ERROR_SUCCESS != (status = PrintEvent(hEvent)))
		{
			goto cleanup;
		}
		break;

	default:
		wprintf(L"SubscriptionCallback: Unknown action.\n");
	}

cleanup:

	if (ERROR_SUCCESS != status)
	{
		// End subscription - Use some kind of IPC mechanism to signal
		// your application to close the subscription handle.
	}

	return status; // The service ignores the returned status.
}

// Render the event as an XML string and print it.
DWORD PrintEvent(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	LPWSTR pRenderedContent = NULL;

	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedContent = (LPWSTR)malloc(dwBufferSize);
			if (pRenderedContent)
			{
				EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
			}
			else
			{
				wprintf(L"malloc failed\n");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", status);
			goto cleanup;
		}
	}

	//wprintf(L"%s\n\n", pRenderedContent);

	ZeroMemory(XMLData, SIZE_DATA);
	lstrcpyW(XMLData, pRenderedContent);

cleanup:

	if (pRenderedContent)
		free(pRenderedContent);

	return status;
}

