package main

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"
	"path"

	"github.com/gorilla/pat"
	"github.com/jansemmelink/kripsie/lib/encryption"
	"github.com/jansemmelink/log"
	uuid "github.com/satori/go.uuid"
	qrcode "github.com/skip2/go-qrcode"
)

func main() {
	log.DebugOn()
	addr := "0.0.0.0:80"
	if len(os.Args) > 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <addr>\n",path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\te.g. %s localhost:8080\n", path.Base(os.Args[0]))
		os.Exit(1)
	}
	if len(os.Args) == 2 {
		addr = os.Args[1]
	}

	if err := http.ListenAndServe(addr, app()); err != nil {
		panic (log.Wrapf(err, "HTTP Server Failed"))
	}
}

func app() http.Handler {
	r := pat.New()
	r.Get("/encrypt", EncryptForm)
	r.Post("/encrypt", Encrypt)
	r.Get("/decrypt/{text:[a-zA-Z0-9=]+}", DecryptForm)
	r.Get("/decrypt", DecryptForm)
	r.Post("/decrypt", Decrypt)
	//static files:
	r.Add(http.MethodGet, "/gen", http.StripPrefix("/gen/", http.FileServer(http.Dir("./gen"))))
	r.Add(http.MethodGet, "/resources", http.StripPrefix("/resources/", http.FileServer(http.Dir("./resources"))))
	//default/home page:
	r.Get("/", DecryptForm)
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
		log.Errorf("Failed to parse templates: %v", err)
		Message(res, req, "Sorry. Please try again later.")
		return
	}
	err = t.Execute(res, data)
	if err != nil {
		log.Errorf("Failed to execute template: %v", err)
		Message(res, req, "Sorry. Please try again later.")
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
		log.Errorf("Failed to generate QR Image file: %v", err)
		Message(res, req, "Sorry. Failed to generate your image.")
		return
	}

	t, err := template.ParseFiles(
		"./templates/encryptResult.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html",
	)
	if err != nil {
		log.Errorf("Failed to parse templates: %v", err)
		Message(res, req, "Sorry. Please try again later.")
		return
	}
	err = t.Execute(res, data)
	if err != nil {
		log.Errorf("Failed to execute template: %v", err)
		Message(res, req, "Sorry. Please try again later.")
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
			"msg":  req.FormValue("msg"),
		}
		log.Debugf("Decrypt: %+v", data)

		t, err := template.ParseFiles(
		"./templates/decryptForm.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html",
	)
	if err != nil {
		log.Errorf("Failed to parse templates: %v", err)
		Message(res, req, "Sorry. Please try again later.")
		return
	}
	err = t.Execute(res, data)
	if err != nil {
		log.Errorf("Failed to execute templates: %v", err)
		Message(res, req, "Sorry. Please try again later.")
		return
	}
}

//Decrypt ...
func Decrypt(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	data := map[string]string{
		"key":  req.FormValue("key"),
		"text": req.FormValue("text"), //this is base64 encoded
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
				log.Errorf("Failed to base64 decode fixedText=%s: %v", fixedText, err)
				Message(res, req, "Sorry. Please try again later.")
				return
			}
		} else {
			log.Errorf("Failed to parse fixedURL: %v", err)
			Message(res, req, "Sorry. Please try again later.")
			return
		}
	}

	//log.Debugf("Encrypted Data: %+v", encryptedData)
	decryptedData, err := encryption.Decrypt(encryptedData, data["key"])
	if err != nil {
		log.Errorf("Decryption failed: %v", err)
		Message(res, req, "%v", err)
		return
	}
	data["DecryptedText"] = string(decryptedData)
	t, err := template.ParseFiles(
		"./templates/decryptResult.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html",
	)
	if err != nil {
		log.Errorf("Failed to parse templates: %v", err)
		Message(res, req, "Sorry. Please try again later.")
		return
	}
	err = t.Execute(res, data)
	if err != nil {
		log.Errorf("Failed to execute templates: %v", err)
		Message(res, req, "Sorry. Please try again later.")
		return
	}

	log.Debugf("Decoded successfully text=%s with key=%s", data["text"], data["key"])
}

//Message writes a HTML page with a message
func Message(res http.ResponseWriter, req *http.Request, format string, args ...interface{}) {
	data := map[string]string{
		"message": fmt.Sprintf(format, args...),
	}

	//if req is specified, redirect to the same page but put msg=... in as a URL param
	if req != nil {
		newURL := req.URL.Query()
		newURL.Set("msg", data["message"])
		newAddr := fmt.Sprintf("http://%s%s?%s", req.Host, req.URL.Path, newURL.Encode())
		log.Debugf("Redirect: %s", newAddr)
		http.Redirect(res, req, newAddr, http.StatusOK)
		return
	}

	t, err := template.ParseFiles(
		"./templates/message.html",
		"./templates/pageHeader.html",
		"./templates/pageFooter.html",
	)
	if err != nil {
		panic(log.Wrapf(err, "failed to parse template"))
	}

	err = t.Execute(res, data)
	if err != nil {
		panic(log.Wrapf(err, "failed to execute template"))
	}
}
