package main

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/pat"
	"github.com/jansemmelink/kripsie/lib/encryption"
	"github.com/jansemmelink/log"
	uuid "github.com/satori/go.uuid"
	qrcode "github.com/skip2/go-qrcode"
)

func main() {
	log.DebugOn()
	if err := http.ListenAndServe("0.0.0.0:80", app()); err != nil {
		log.Debugf("Failed: %v", err)
	}
}

func app() http.Handler {
	r := pat.New()
	r.Get("/encrypt", EncryptForm)
	r.Post("/encrypt", Encrypt)
	r.Get("/decrypt/{text:[a-zA-Z0-9=]+}", DecryptForm)
	r.Get("/decrypt", DecryptForm)
	r.Post("/decrypt", Decrypt)
	r.NewRoute().PathPrefix("/gen/").Handler(http.StripPrefix("/gen/", http.FileServer(http.Dir("./gen"))))
	return r
}

//EncryptForm ...
func EncryptForm(res http.ResponseWriter, req *http.Request) {
	data := map[string]string{
		"text": req.URL.Query().Get("text"),
	}
	t, err := template.ParseFiles(
		"./templates/encryptForm.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html")
	if err != nil {
		Message(res, "Sorry. Please try again later.")
		log.Errorf("Failed to parse templates: %v", err)
		return
	}
	err = t.Execute(res, data)
	if err != nil {
		Message(res, "Sorry. Please try again later.")
		log.Errorf("Failed to execute template: %v", err)
		return
	}
}

//Encrypt ...
func Encrypt(res http.ResponseWriter, req *http.Request) {
	log.Debugf("%s %s %s", req.Host, req.Method, req.URL)

	req.ParseForm()
	data := map[string]string{
		"key":  req.FormValue("key"),
		"text": req.FormValue("text"),
	}

	//encryption:
	log.Debugf("Text=%s", data["text"])
	log.Debugf("Key=%s", data["key"])
	encryptedData := encryption.Encrypt([]byte(data["text"]), data["key"])
	log.Debugf("Encrypted Data: %+v", encryptedData)
	data["EncryptedText"] = base64.StdEncoding.EncodeToString(encryptedData)
	log.Debugf("Encrypted BASE64: %s", data["EncryptedText"])

	//the '=' character gets added at the end with base64 encoding...
	//when decoded in the QR Scanner, the URL looks like: text=....= (ending with a '=')
	//and I found some phones (like my iPhone) and its apps does not treat it correctly
	//throwing it away... so to be safe, we replace it with another printable character
	//and before be base64 decode again, we put it back
	data["EncryptedText"] = strings.Replace(data["EncryptedText"], "=", "#", -1)
	log.Debugf("Replaced = with #: %s", data["EncryptedText"])

	//the QR Value is the link to this server's decrypt page
	//that will include the encrypted text so the user
	//only has to enter the key
	urlParams := url.Values{}
	urlParams.Add("text", data["EncryptedText"])
	data["Hyperlink"] = fmt.Sprintf("http://%s/decrypt?%s", req.Host, urlParams.Encode())
	log.Debugf("Hyperlink: %s", data["Hyperlink"])

	//make QRCode image using a unique key for this image
	//imageFile name is used in HTML for img ref in url,
	//and on disk to save image at ./... which resuls in ./gen/<qrid>.png
	//where the file server can find it to render it in the browser
	os.Mkdir("./gen", 0770)
	qrid := uuid.NewV1()
	data["imageFile"] = fmt.Sprintf("/gen/%s.png", qrid)
	if err := qrcode.WriteFile(data["Hyperlink"], qrcode.Medium, 256, "."+data["imageFile"]); err != nil {
		Message(res, "Sorry. Failed to generate your image.")
		log.Errorf("Failed to generate QR Image file: %v", err)
		return
	}

	t, err := template.ParseFiles(
		"./templates/encryptResult.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html",
	)
	if err != nil {
		Message(res, "Sorry. Please try again later.")
		log.Errorf("Failed to parse templates: %v", err)
		return
	}
	err = t.Execute(res, data)
	if err != nil {
		Message(res, "Sorry. Please try again later.")
		log.Errorf("Failed to execute template: %v", err)
		return
	}

	//todo: schedule image for deletion, or would even be better if file server
	//can be wrapped to delete after use...

	log.Debugf("Encrypted %s with key %s into image %s",
		data["text"],
		data["key"],
		data["imageFile"])
} //Encrypt()

//DecryptForm ...
func DecryptForm(res http.ResponseWriter, req *http.Request) {
	data :=
		map[string]string{
			"text": req.URL.Query().Get("text"),
		}
	t, err := template.ParseFiles(
		"./templates/decryptForm.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html",
	)
	if err != nil {
		Message(res, "Sorry. Please try again later.")
		log.Errorf("Failed to parse templates: %v", err)
		return
	}
	err = t.Execute(res, data)
	if err != nil {
		Message(res, "Sorry. Please try again later.")
		log.Errorf("Failed to execute templates: %v", err)
		return
	}
}

//Decrypt ...
func Decrypt(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	data := map[string]string{
		"key":  req.FormValue("key"),
		"text": req.FormValue("text"), //this is base64 encoded
		"msg":  req.FormValue("msg"),
	}

	//put the = back before we can do base64 decoding
	//log.Debugf("Text to decrypt: %s", data["text"])
	data["text"] = strings.Replace(data["text"], "#", "=", -1)
	//log.Debugf("Replaced # with =: %s", data["text"])

	//decryption:
	// 	plaintext := decrypt(ciphertext, "password")
	// 	fmt.Printf("Decrypted: %s", plaintext)
	encryptedData, err := base64.StdEncoding.DecodeString(data["text"])
	if err != nil {
		//some phones do not do URL decryption correctly,
		//so in cose text is still containing URL encoding,
		//lets try to decode it properly
		u, err := url.Parse("http://fakehost/decrypt?text=" + data["text"])
		if err == nil {
			fixedText := u.Query().Get("text")
			//log.Debugf("Decoded URL text %s -> %s", data["text"], fixedText)
			fixedText = strings.Replace(fixedText, "#", "=", -1)
			//log.Debugf("Replaced # with =: %s", fixedText)
			encryptedData, err = base64.StdEncoding.DecodeString(fixedText)
			if err != nil {
				Message(res, "Sorry. Please try again later.")
				log.Errorf("Failed to base64 decode fixedText=%s: %v", fixedText, err)
				return
			}
		} else {
			Message(res, "Sorry. Please try again later.")
			log.Errorf("Failed to parse fixedURL: %v", err)
			return
		}
	}

	//log.Debugf("Encrypted Data: %+v", encryptedData)
	decryptedData, err := encryption.Decrypt(encryptedData, data["key"])
	if err != nil {
		Message(res, "Failed to decrypt")
		log.Errorf("Decryption failed: %v", err)
		return
	}
	data["DecryptedText"] = string(decryptedData)
	t, err := template.ParseFiles(
		"./templates/decryptResult.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html",
	)
	if err != nil {
		Message(res, "Sorry. Please try again later.")
		log.Errorf("Failed to parse templates: %v", err)
		return
	}
	err = t.Execute(res, data)
	if err != nil {
		Message(res, "Sorry. Please try again later.")
		log.Errorf("Failed to execute templates: %v", err)
		return
	}

	log.Debugf("Decoded successfully text=%s with key=%s", data["text"], data["key"])
}

//Message writes a HTML page with a message
func Message(res http.ResponseWriter, format string, args ...interface{}) {
	data := map[string]string{
		"message": fmt.Sprintf(format, args...),
	}

	t, err := template.ParseFiles(
		"./templates/message.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html",
	)
	if err != nil {
		panic(err)
	}
	err = t.Execute(res, data)
	if err != nil {
		panic(err)
	}
}
