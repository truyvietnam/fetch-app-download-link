package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Respone struct {
	XMLName xml.Name `xml:"Envelope"`
	Text    string   `xml:",chardata"`
	S       string   `xml:"s,attr"`
	A       string   `xml:"a,attr"`
	U       string   `xml:"u,attr"`
	Header  struct {
		Text   string `xml:",chardata"`
		Action struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
		} `xml:"Action"`
		RelatesTo string `xml:"RelatesTo"`
		Security  struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
			O              string `xml:"o,attr"`
			Timestamp      struct {
				Text    string `xml:",chardata"`
				ID      string `xml:"Id,attr"`
				Created string `xml:"Created"`
				Expires string `xml:"Expires"`
			} `xml:"Timestamp"`
		} `xml:"Security"`
	} `xml:"Header"`
	Body struct {
		Text                           string `xml:",chardata"`
		Xsi                            string `xml:"xsi,attr"`
		Xsd                            string `xml:"xsd,attr"`
		GetExtendedUpdateInfo2Response struct {
			Text                         string `xml:",chardata"`
			Xmlns                        string `xml:"xmlns,attr"`
			GetExtendedUpdateInfo2Result struct {
				Text          string `xml:",chardata"`
				FileLocations struct {
					Text         string `xml:",chardata"`
					FileLocation []struct {
						Text       string `xml:",chardata"`
						FileDigest string `xml:"FileDigest"`
						URL        string `xml:"Url"`
					} `xml:"FileLocation"`
				} `xml:"FileLocations"`
			} `xml:"GetExtendedUpdateInfo2Result"`
		} `xml:"GetExtendedUpdateInfo2Response"`
	} `xml:"Body"`
}

type TicketType struct {
	Name    string `xml:"Name,attr"`
	Version string `xml:"Version,attr"`
	Policy  string `xml:"Policy,attr"`
}

type WUTicket struct {
	XMLName xml.Name `xml:"wuws:WindowsUpdateTicketsToken"`

	Id   string `xml:"wsu:id,attr"`
	WSU  string `xml:"xmlns:wsu,attr"`
	WUWS string `xml:"xmlns:wuws,attr"`

	TicketType []TicketType `xml:"TicketType"`
}

type Action struct {
	MustUnderstand string `xml:"s:mustUnderstand,attr"`
	Link           string `xml:",chardata"`
}

type To struct {
	MustUnderstand string `xml:"s:mustUnderstand,attr"`
	Link           string `xml:",chardata"`
}

type OSecurity struct {
	MustUnderstand string   `xml:"s:mustUnderstand,attr"`
	XmlnsO         string   `xml:"xmlns:o,attr"`
	Timestamp      Time     `xml:"Timestamp"`
	WUTicket       WUTicket `xml:""`
}

type Time struct {
	Xmlns   string `xml:"xmlns,attr"`
	Created string `xml:"Created"`
	Expires string `xml:"Expires"`
}

type MessageID struct {
	Data string `xml:",chardata"`
}

type Header struct {
	Action    Action    `xml:"a:Action"`
	MessageID MessageID `xml:"a:MessageID"`
	To        To        `xml:"a:To"`
	Security  OSecurity `xml:"o:Security"`
}

type InfoTypes struct {
	XmlUpdateFragmentType string `xml:"XmlUpdateFragmentType"`
}

type UpdateIdentity struct {
	UpdateID       string `xml:"UpdateID"`
	RevisionNumber int    `xml:"RevisionNumber"`
}

type UpdateIDs struct {
	UpdateIdentity UpdateIdentity `xml:"UpdateIdentity"`
}

type GetExtendedUpdateInfo struct {
	Xmlns            string    `xml:"xmlns,attr"`
	UpdateIDs        UpdateIDs `xml:"updateIDs"`
	InfoTypes        InfoTypes `xml:"infoTypes"`
	DeviceAttributes string    `xml:"deviceAttributes"`
}

type Body struct {
	GetExtendedUpdateInfo GetExtendedUpdateInfo `xml:"GetExtendedUpdateInfo2"`
}

type Envelope struct {
	XMLName xml.Name `xml:"s:Envelope"`
	XmlA    string   `xml:"xmlns:a,attr"`
	XmlS    string   `xml:"xmlns:s,attr"`
	Header  Header   `xml:"s:Header"`
	Body    Body     `xml:"s:Body"`
}

const (
	downloadUrl = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured"

	soap       = "http://www.w3.org/2003/05/soap-envelope"
	addressing = "http://www.w3.org/2005/08/addressing"
	secext     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	secutil    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	wuclient   = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"
	wuws       = "http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"
)

func BuildUpdateTickets() WUTicket {
	e := WUTicket{
		Id:   "ClientMSA",
		WSU:  secutil,
		WUWS: wuws,
		TicketType: []TicketType{
			{
				Name:    "MSA",
				Version: "1.0",
				Policy:  "MBI_SSL",
			},
			{
				Name:    "AAD",
				Version: "1.0",
				Policy:  "MBI_SSL",
			},
		},
	}

	return e
}

func BuildHeader(url string, method string) Header {
	header := Header{
		Action: Action{
			MustUnderstand: "1",
			Link:           "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/" + method,
		},
		MessageID: MessageID{
			Data: "urn:uuid:5754a03d-d8d5-489f-b24d-efc31b3fd32d",
		},
		To: To{
			MustUnderstand: "1",
			Link:           url,
		},
		Security: OSecurity{
			MustUnderstand: "1",
			XmlnsO:         secext,
			Timestamp: Time{
				Xmlns:   secutil,
				Created: time.Now().UTC().Format(time.RFC3339Nano),
				Expires: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano),
			},
			WUTicket: BuildUpdateTickets(),
		},
	}

	return header
}

func BuildDownloadRequest(updateId string) []byte {
	abc := Envelope{
		XmlA:   addressing,
		XmlS:   soap,
		Header: BuildHeader(downloadUrl, "GetExtendedUpdateInfo2"),
		Body: Body{
			GetExtendedUpdateInfo: GetExtendedUpdateInfo{
				Xmlns: wuclient,
				UpdateIDs: UpdateIDs{
					UpdateIdentity: UpdateIdentity{
						UpdateID:       updateId,
						RevisionNumber: 1,
					},
				},
				InfoTypes: InfoTypes{
					XmlUpdateFragmentType: "FileUrl",
				},
				DeviceAttributes: "E:BranchReadinessLevel=CBB&DchuNvidiaGrfxExists=1&ProcessorIdentifier=Intel64%20Family%206%20Model%2063%20Stepping%202&CurrentBranch=rs4_release&DataVer_RS5=1942&FlightRing=Retail&AttrDataVer=57&InstallLanguage=en-US&DchuAmdGrfxExists=1&OSUILocale=en-US&InstallationType=Client&FlightingBranchName=&Version_RS5=10&UpgEx_RS5=Green&GStatus_RS5=2&OSSkuId=48&App=WU&InstallDate=1529700913&ProcessorManufacturer=GenuineIntel&AppVer=10.0.17134.471&OSArchitecture=AMD64&UpdateManagementGroup=2&IsDeviceRetailDemo=0&HidOverGattReg=C%3A%5CWINDOWS%5CSystem32%5CDriverStore%5CFileRepository%5Chidbthle.inf_amd64_467f181075371c89%5CMicrosoft.Bluetooth.Profiles.HidOverGatt.dll&IsFlightingEnabled=0&DchuIntelGrfxExists=1&TelemetryLevel=1&DefaultUserRegion=244&DeferFeatureUpdatePeriodInDays=365&Bios=Unknown&WuClientVer=10.0.17134.471&PausedFeatureStatus=1&Steam=URL%3Asteam%20protocol&Free=8to16&OSVersion=10.0.17134.472&DeviceFamily=Windows.Desktop",
			},
		},
	}

	output, err := xml.MarshalIndent(abc, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	return output
}

func GetDownloadLink(updateId string) string {
	resp, err := http.Post(downloadUrl, "application/soap+xml", bytes.NewReader(BuildDownloadRequest(updateId)))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var a Respone
	if err := xml.Unmarshal([]byte(b), &a); err != nil {
		log.Fatal(err)
	}

	if len(a.Body.GetExtendedUpdateInfo2Response.GetExtendedUpdateInfo2Result.FileLocations.FileLocation) >= 1 {
		for _, a := range a.Body.GetExtendedUpdateInfo2Response.GetExtendedUpdateInfo2Result.FileLocations.FileLocation {
			if strings.Contains(a.URL, "http://tlu.dl.delivery.mp.microsoft.com") {
				return a.URL
			}
		}
	}

	return "Not Found"
}

func main() {
	var id string
	fmt.Print("Type update ID (uuid version 4): ")
	fmt.Scan(&id)

	fmt.Printf("\nDownload link: %s\n\n", GetDownloadLink(id))
	fmt.Print("Press Enter to close")
	fmt.Scanln()
	fmt.Scanln()
}
