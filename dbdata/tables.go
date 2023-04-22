package dbdata

import "time"

type AccessAudit struct {
	Id          int       `json:"id" xorm:"pk autoincr not null"`
	Username    string    `json:"username" xorm:"varchar(60) not null"`
	Protocol    uint8     `json:"protocol" xorm:"not null"`
	Src         string    `json:"src" xorm:"varchar(60) not null"`
	SrcPort     uint16    `json:"src_port" xorm:"not null"`
	Dst         string    `json:"dst" xorm:"varchar(60) not null"`
	DstPort     uint16    `json:"dst_port" xorm:"not null"`
	AccessProto uint8     `json:"access_proto" xorm:"default 0"`                // 访问协议
	Info        string    `json:"info" xorm:"varchar(255) not null default ''"` // 详情
	CreatedAt   time.Time `json:"created_at" xorm:"DateTime"`
}
