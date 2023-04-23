package model

type OcUser struct {
	ID                 int           `json:"ID"`
	Username           string        `json:"Username"`
	Groupname          string        `json:"Groupname"`
	State              string        `json:"State"`
	Vhost              string        `json:"vhost"`
	Device             string        `json:"Device"`
	MTU                string        `json:"MTU"`
	RemoteIP           string        `json:"Remote IP"`
	Location           string        `json:"Location"`
	LocalDeviceIP      string        `json:"Local Device IP"`
	IPv4               string        `json:"IPv4"`
	PTPIPv4            string        `json:"P-t-P IPv4"`
	UserAgent          string        `json:"User-Agent"`
	RX                 string        `json:"RX"`
	TX                 string        `json:"TX"`
	RX1                string        `json:"_RX"`
	TX1                string        `json:"_TX"`
	AverageRX          string        `json:"Average RX"`
	AverageTX          string        `json:"Average TX"`
	DPD                string        `json:"DPD"`
	KeepAlive          string        `json:"KeepAlive"`
	ConnectedAt        string        `json:"Connected at"`
	ConnectedAt1       string        `json:"_Connected at"`
	FullSession        string        `json:"Full session"`
	Session            string        `json:"Session"`
	TLSCiphersuite     string        `json:"TLS ciphersuite"`
	DNS                []interface{} `json:"DNS"`
	NBNS               []interface{} `json:"NBNS"`
	SplitDNSDomains    []interface{} `json:"Split-DNS-Domains"`
	Routes             []string      `json:"Routes"`
	NoRoutes           []interface{} `json:"No-routes"`
	IRoutes            []interface{} `json:"iRoutes"`
	RestrictedToRoutes string        `json:"Restricted to routes"`
	RestrictedToPorts  []interface{} `json:"Restricted to ports"`
}

type OcUsers []OcUser
