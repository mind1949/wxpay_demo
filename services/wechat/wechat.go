package wechat

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	MD5                    = "MD5" // 默认加密方式
	HMACSHA256             = "HMAC-SHA256"
	SUCCESS                = "SUCCESS"
	bodyType               = "application/xml; charset=utf-8"
	SandboxGetSignKeyUrl   = "https://api.mch.weixin.qq.com/sandboxnew/pay/getsignkey"   // 获取沙箱签名秘钥api
	SandboxUnifiedOrderUrl = "https://api.mch.weixin.qq.com/sandboxnew/pay/unifiedorder" // 统一下单api(沙箱)
	SandboxOrderQueryUrl   = "https://api.mch.weixin.qq.com/sandboxnew/pay/orderquery"   // 查询订单api
	UnifiedOrderUrl        = "https://api.mch.weixin.qq.com/pay/unifiedorder"            // 统一下单api
	OrderQueryUrl          = "https://api.mch.weixin.qq.com/pay/orderquery"              // 查询订单api

)

// =======================

type Map map[string]string

func (p Map) SetString(k, s string) Map {
	p[k] = s
	return p
}

func (p Map) GetString(k string) string {
	s, _ := p[k]
	return s
}

func (p Map) SetInt64(k string, i int64) Map {
	p[k] = strconv.FormatInt(i, 10)
	return p
}

func (p Map) GetInt64(k string) int64 {
	i, _ := strconv.ParseInt(p.GetString(k), 10, 64)
	return i
}

// 判断key是否存在
func (p Map) ContainsKey(key string) bool {
	_, ok := p[key]
	return ok
}

// 转换为xml字符串
func (m Map) ToXML() XML {
	var buf bytes.Buffer
	buf.WriteString(`<xml>`)
	for k, v := range m {
		buf.WriteString(`<`)
		buf.WriteString(k)
		buf.WriteString(`><![CDATA[`)
		buf.WriteString(v)
		buf.WriteString(`]]></`)
		buf.WriteString(k)
		buf.WriteString(`>`)
	}
	buf.WriteString(`</xml>`)

	return XML(buf.String())
}

// =======================

type XML string

// 转换为Map
func (x XML) ToMap() Map {
	_map := make(Map)
	xmlStr := string(x)
	decoder := xml.NewDecoder(strings.NewReader(xmlStr))

	var (
		key   string
		value string
	)

	for t, err := decoder.Token(); err == nil; t, err = decoder.Token() {
		switch token := t.(type) {
		case xml.StartElement: // 开始标签
			key = token.Name.Local
		case xml.CharData: // 标签内容
			content := string([]byte(token))
			value = content
		}
		if key != "xml" {
			if value != "\n" {
				_map.SetString(key, value)
			}
		}
	}

	return _map
}

func (x XML) Compact() XML {
	xmlStr := string(x)
	// 去除换行符
	xmlStr = strings.ReplaceAll(xmlStr, "\n", "")
	// 去除空格
	xmlStr = strings.ReplaceAll(xmlStr, " ", "")
	return XML(xmlStr)
}

func (x XML) String() string {
	// TODO(添加缩进,换行)
	return string(x)
}

// =======================

type Account struct {
	appID     string
	mchID     string
	apiKey    string
	certData  []byte
	isSandbox bool
}

type Client struct {
	account              *Account // 支付账号
	signType             string   // 签名类型
	httpConnectTimeoutMs int      // 连接超时时间
	httpReadTimeoutMs    int      // 读取超时时间
}

// 创建微信支付账号
func NewAccount(appID string, mchID string, apiKey string, isSanbox bool) *Account {
	return &Account{
		appID:     appID,
		mchID:     mchID,
		apiKey:    apiKey,
		isSandbox: isSanbox,
	}
}

// 创建微信支付客户端
func NewClient(account *Account) *Client {
	return &Client{
		account:              account,
		signType:             MD5,
		httpConnectTimeoutMs: 2000,
		httpReadTimeoutMs:    1000,
	}
}

// 用时间戳生成随机字符串
func nonceStr() string {
	return strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
}

// 生成支付签名参数
func (c *Client) PayParams(nonceStr, prepayID string) Map {
	//payStringTemp := "appId=%s&nonceStr=%s&package=prepay_id=%s&signType=%s&timeStamp=%s&key=%s"
	params := make(Map)
	return params.SetString("appId", c.account.appID).
		SetString("nonceStr", nonceStr).
		SetString("package", "prepay_id="+prepayID).
		SetString("signType", c.signType).
		SetInt64("timeStamp", time.Now().Unix())
}

// 签名
func (c *Client) Sign(params Map) string {
	// 创建切片
	var keys = make([]string, 0, len(params))
	// 遍历签名参数
	for k := range params {
		if k != "sign" { // 排除sign字段
			keys = append(keys, k)
		}
	}

	// 由于切片的元素顺序是不固定，所以这里强制给切片元素加个顺序
	sort.Strings(keys)

	//创建字符缓冲
	var buf bytes.Buffer
	for _, k := range keys {
		if len(params.GetString(k)) > 0 {
			buf.WriteString(k)
			buf.WriteString(`=`)
			buf.WriteString(params.GetString(k))
			buf.WriteString(`&`)
		}
	}
	// 加入apiKey作加密密钥
	buf.WriteString(`key=`)
	buf.WriteString(c.account.apiKey)

	var (
		dataMd5    [16]byte
		dataSha256 []byte
		str        string
	)

	switch c.signType {
	case MD5:
		dataMd5 = md5.Sum(buf.Bytes())
		str = hex.EncodeToString(dataMd5[:]) //需转换成切片
	case HMACSHA256:
		h := hmac.New(sha256.New, []byte(c.account.apiKey))
		h.Write(buf.Bytes())
		dataSha256 = h.Sum(nil)
		str = hex.EncodeToString(dataSha256[:])
	}

	return strings.ToUpper(str)
}

// 统一下单
func (c *Client) UnifiedOrder(params Map) (Map, error) {
	// 指定url
	var url string
	if c.account.isSandbox {
		url = SandboxUnifiedOrderUrl
	} else {
		url = UnifiedOrderUrl
	}
	// 填充account中的参数
	params = params.SetString("appid", c.account.appID).
		SetString("mch_id", c.account.mchID).
		SetString("nonce_str", nonceStr()).
		SetString("sign_type", c.signType).
		SetString("sign", c.Sign(params))
	// 发送下单请求
	h := &http.Client{}
	response, err := h.Post(url, bodyType, strings.NewReader(params.ToXML().String()))
	if err != nil {
		return nil, err
	}
	// 读取结果
	_res, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	res := XML(_res).Compact().ToMap()
	return res, nil
}

// 查询订单
func (c *Client) OrderQuery(params Map) (Map, error) {
	// 指定url
	var url string
	if c.account.isSandbox {
		url = SandboxOrderQueryUrl
	} else {
		url = OrderQueryUrl
	}
	// 填充account中的数据
	params = params.SetString("appid", c.account.appID).
		SetString("mch_id", c.account.mchID).
		SetString("nonce_str", nonceStr()).
		SetString("sign_type", c.signType).
		SetString("sign", c.Sign(params))
	// 发送查询订单请求
	h := &http.Client{}
	response, err := h.Post(url, bodyType, strings.NewReader(params.ToXML().String()))
	if err != nil {
		return nil, err
	}
	// 读取结果
	_res, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	res := XML(_res).Compact().ToMap()
	return res, nil
}

// =======================
