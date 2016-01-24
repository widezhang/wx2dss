// wx2dss project main.go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	token          = "a1MpMNep2eM7Cdur"
	corpID         = "wx42ba1bcec2ab9a19"
	encodingAESKey = "AqUa64n3KGcu889bYebTLcITjjPU1N9MTHJhlWLbLCT"
)

var aesKey []byte

func encodingAESKey2AESKey(encodingKey string) []byte {
	data, _ := base64.StdEncoding.DecodeString(encodingKey + "=")
	return data
}

func init() {
	aesKey = encodingAESKey2AESKey(encodingAESKey)
}
func decodeString(src string) (dst []byte, err error) {

	cipherData, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return nil, err
	}
	// AES Decrypt
	plainData, err := aesDecrypt(cipherData, aesKey)
	if err != nil {
		return nil, err
	}
	dst = parseEncryptTextRequestBody(plainData)
	return dst, nil
}

type XMLRequest struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string
	Encrypt      string
	AgentID      string `xml:",omitempty"`
	MsgSignature string `xml:",omitempty"`
	TimeStamp    string `xml:",omitempty"`
	Nonce        string `xml:",omitempty"`
}

type XMLResponse struct {
	XMLName      xml.Name `xml:"xml"`
	Encrypt      CDATAText
	MsgSignature CDATAText
	TimeStamp    time.Duration
	Nonce        CDATAText
}
type CDATAText struct {
	Text string `xml:",innerxml"`
}
type Message struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string
	FromUserName string
	CreateTime   time.Duration
	MsgType      string
	Content      string
	MsgId        int    `xml:",omitempty"`
	AgentID      string `xml:",omitempty"`
} //`xml:"xml"`

type RspMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   CDATAText
	FromUserName CDATAText
	CreateTime   time.Duration
	MsgType      CDATAText
	Content      CDATAText
} //`xml:"xml"`

//<xml>
//   <Encrypt><![CDATA[msg_encrypt]]></Encrypt>
//   <MsgSignature><![CDATA[msg_signature]]></MsgSignature>
//   <TimeStamp>timestamp</TimeStamp>
//   <Nonce><![CDATA[nonce]]></Nonce>
//</xml>
func readMessage(r io.Reader) (m *Message, e error) {
	body, _ := ioutil.ReadAll(r)
	req := XMLRequest{}
	err := xml.Unmarshal(body, &req)
	if err != nil {
		return nil, err
	}
	fmt.Println(req.ToUserName, req.AgentID)
	msgStr, err := decodeString(req.Encrypt)
	if err != nil {
		return nil, err
	}
	msg := Message{}
	err = xml.Unmarshal(msgStr, &msg)
	return &msg, err

}

func encodeString(src []byte) (dst string, err error) {
	// Encrypt part2: Length bytes
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, int32(len(src)))
	if err != nil {
		fmt.Println("Binary write err:", err)
	}
	bodyLength := buf.Bytes()

	// Encrypt part1: Random bytes
	randomBytes := []byte("abcdefghijklmnop")

	// Encrypt Part, with part4 - appID
	plainData := bytes.Join([][]byte{randomBytes, bodyLength, src, []byte(corpID)}, nil)
	cipherData, err := aesEncrypt(plainData, aesKey)
	if err != nil {
		return "", errors.New("aesEncrypt error")
	}

	return base64.StdEncoding.EncodeToString(cipherData), nil
}

func writeMessage(w io.Writer, m *RspMessage) error {
	rspmsgstr, err := xml.MarshalIndent(m, " ", "  ")
	fmt.Println("rspmsgstr=", string(rspmsgstr))
	resp := XMLResponse{}
	resp.TimeStamp = time.Duration(time.Now().Unix())
	fmt.Println(fmt.Sprintf("time[%v]", time.Now().Unix()))

	resp.Encrypt.Text, err = encodeString(rspmsgstr)
	resp.Nonce.Text = "12345566"
	resp.MsgSignature.Text = makeMsgSignature(fmt.Sprintf("%v", time.Now().Unix()), resp.Nonce.Text, resp.Encrypt.Text)
	resp.MsgSignature.Text = "<![CDATA[" + resp.MsgSignature.Text + "]]>"
	resp.Nonce.Text = "<![CDATA[" + resp.Nonce.Text + "]]>"
	resp.Encrypt.Text = "<![CDATA[" + resp.Encrypt.Text + "]]>"

	rspbody, err := xml.MarshalIndent(resp, " ", "  ")
	fmt.Println("rspbody=", string(rspbody))
	w.Write(rspbody)

	// check
	checkreq := XMLRequest{}

	xml.Unmarshal(rspbody, &checkreq)

	msgSignatureGen := makeMsgSignature(checkreq.TimeStamp, checkreq.Nonce, checkreq.Encrypt)
	fmt.Println("compare1", msgSignatureGen)
	fmt.Println("compare2", checkreq.MsgSignature)
	//	if msgSignatureGen != msgSignatureIn {
	fmt.Println("checkreq", checkreq)
	decStr, err := decodeString(checkreq.Encrypt)
	fmt.Println("decStr", decStr)
	msg := Message{}
	err = xml.Unmarshal(decStr, &msg)
	fmt.Println("msg", msg)

	//fmt.Println("msg=", string(rspmsgstr), "err=", err)
	return err

}

func procRequest(w http.ResponseWriter, r *http.Request) {
	// 第一次鉴权逻辑
	if r.URL.Query().Get("echostr") != "" {
		echostr, err := decodeString(r.URL.Query().Get("echostr"))
		if err != nil {
			fmt.Println("第一次鉴权失败", err)
		} else {
			w.Write(echostr)
		}
		return
	}
	// 正常流程
	msg, _ := readMessage(r.Body)
	rspmsg := RspMessage{}
	rspmsg.ToUserName.Text = "<![CDATA[" + msg.FromUserName + "]]>"
	rspmsg.FromUserName.Text = "<![CDATA[" + msg.ToUserName + "]]>"
	rspmsg.MsgType.Text = "<![CDATA[" + msg.MsgType + "]]>"
	rspmsg.Content.Text = "<![CDATA[" + "企业号后台测试" + msg.Content + msg.FromUserName + "]]>"
	rspmsg.CreateTime = msg.CreateTime
	writeMessage(w, &rspmsg)

}

func main() {

	http.HandleFunc("/", procRequest)

	err := http.ListenAndServe(":80", nil)
	fmt.Println(err)
	for {
		time.Sleep(10 * time.Second)
		fmt.Println("aaa")
	}

}

func aesDecrypt(cipherData []byte, aesKey []byte) ([]byte, error) {
	k := len(aesKey) //PKCS#7
	if len(cipherData)%k != 0 {
		return nil, errors.New("crypto/cipher: ciphertext size is not multiple of aes key length")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainData := make([]byte, len(cipherData))
	blockMode.CryptBlocks(plainData, cipherData)
	return plainData, nil
}
func parseEncryptTextRequestBody(plainText []byte) []byte {
	// Read length
	buf := bytes.NewBuffer(plainText[16:20])
	var length int32
	binary.Read(buf, binary.BigEndian, &length)
	fmt.Println("msg[", string(plainText[20:20+length]), "]")

	xmlstr := plainText[20 : 20+length]

	return xmlstr
}

func makeMsgSignature(timestamp, nonce, msg_encrypt string) string {
	fmt.Println("makeMsgSignature", timestamp, nonce, msg_encrypt)
	sl := []string{token, timestamp, nonce, msg_encrypt}
	sort.Strings(sl)
	s := sha1.New()
	io.WriteString(s, strings.Join(sl, ""))
	return fmt.Sprintf("%x", s.Sum(nil))
}

//func validateMsg(timestamp, nonce, msgEncrypt, msgSignatureIn string) bool {
//	msgSignatureGen := makeMsgSignature(timestamp, nonce, msgEncrypt)
//	if msgSignatureGen != msgSignatureIn {
//		return false
//	}
//	return true
//}

func PKCS7Pad(data []byte) []byte {
	dataLen := len(data)

	var validLen int
	if dataLen%32 == 0 {
		validLen = dataLen
	} else {
		validLen = int(dataLen/32+1) * 32
	}

	paddingLen := validLen - dataLen
	// The length of the padding is used as the byte we will
	// append as a pad.
	bitCode := byte(paddingLen)
	padding := make([]byte, paddingLen)
	for i := 0; i < paddingLen; i++ {
		padding[i] = bitCode
	}
	return append(data, padding...)
}

func aesEncrypt(plainData []byte, aesKey []byte) ([]byte, error) {
	k := len(aesKey)
	if len(plainData)%k != 0 {
		plainData = PKCS7Pad(plainData)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cipherData := make([]byte, len(plainData))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(cipherData, plainData)

	return cipherData, nil
}
