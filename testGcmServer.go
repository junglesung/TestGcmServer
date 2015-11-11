package main

import (
	"appengine"
	"appengine/datastore"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"
	"strings"
	"fmt"
)

type Member struct {
	Id string `json:"id"`
	Token string `json:"token"`
	Message string `json:"message"`
	CreateTime time.Time `json:"createtime"`
}

type HelloMessage struct {
	Message string `json:"message"`
}

const BaseUrl = "/api/0.1/"
const MemberKind = "Member"
const MemberRoot = "Member root"

// GCM server
const GcmURL = "https://gcm-http.googleapis.com/gcm/send"
const GcmApiKey = "AIzaSyAODu6tKbQp8sAwEBDNLzW9uDCBmmluQ4A"

func init() {
	http.HandleFunc(BaseUrl, rootPage)
	http.HandleFunc(BaseUrl+"members", members)
	http.HandleFunc(BaseUrl+"tokens/", EchoMessage)
}

func rootPage(rw http.ResponseWriter, req *http.Request) {
	c := appengine.NewContext(req)
	c.Debugf("This is root")
}

func members(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		listMember(rw, req)
	case "POST":
		addMember(rw, req)
//	case "PUT":
//		updateMember(rw, req)
	case "DELETE":
		clearMember(rw, req)
	default:
		listMember(rw, req)
	}
}

// Reply the received message
// https://testgcmserver-1120.appspot.com/api/0.1/tokens/xxxxxx/messages"
func EchoMessage(rw http.ResponseWriter, req *http.Request) {
	// Appengine
	var c appengine.Context = appengine.NewContext(req)
	// Result, 0: success, 1: failed
	var r int = 0

	// Return code
	defer func() {
		// Return status. WriteHeader() must be called before call to Write
		if r == 0 {
			// Changing the header after a call to WriteHeader (or Write) has no effect.
//			rw.Header().Set("Location", req.URL.String() + "/" + cKey.Encode())
			rw.WriteHeader(http.StatusCreated)
		} else {
//			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			http.Error(rw, "Please follow https://aaa.appspot.com/api/0.1/tokens/xxxxxx/messages", http.StatusBadRequest)
		}
	}()

	// Parse URL into tokens
	var tokens []string = strings.Split(req.URL.Path, "/")
	var indexToken int = 0
	var indexMessage int = 0
	for i, v := range tokens {
		if v == "tokens" {
			indexToken = i + 1
			indexMessage = i + 2
			break
		}
	}

	// Check tokens
	if indexMessage >= len(tokens) || tokens[indexMessage] != "messages" {
		c.Errorf("Please follow https://aaa.appspot.com/api/0.1/tokens/xxxxxx/messages")
		r = 1
		return
	}

	// Registration token
	var token string = tokens[indexToken]

	// Get the message from body
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		c.Errorf("%s in reading body %s", err, b)
		r = 1
		return
	}
	var message HelloMessage
	if err = json.Unmarshal(b, &message); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = 1
		return
	}

	// Make GCM message body
	var bodyString string = fmt.Sprintf(`
		{
			"to":"%s",
			"notification": {
				"body":"Body %s",
				"title":"Title %s",
				"icon":"ic_stat_ic_notification"
			},
			"data": {
				"message":"%s"
			}
		}`, token, message, message, message)

	// Make a POST request for GCM
	pReq, err := http.NewRequest("POST", GcmURL, strings.NewReader(bodyString))
	if err != nil {
		c.Errorf("%s in makeing a HTTP request", err)
		r = 1
		return
	}
	pReq.Header.Add("Content-Type", "application/json")
	pReq.Header.Add("Authorization", "key="+GcmApiKey)

	// Send request
	var client = &http.Client{}
	resp, err := client.Do(pReq)
	if err != nil {
		c.Errorf("%s in sending request", err)
		r = 1
		return
	}
	defer resp.Body.Close()

	// Check response
	c.Infof("%d %s", resp.StatusCode, resp.Status)

	// Get response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Errorf("%s in reading response body", err)
		r = 1
		return
	}
	c.Infof("%s", respBody)
}

// Register a client and reply "Hello~"
func addMember(rw http.ResponseWriter, req *http.Request) {
	// Appengine
	var c appengine.Context = appengine.NewContext(req)
	// Result, 0: success, 1: failed
	var r int = 0
	var cKey *datastore.Key = nil
	defer func() {
		// Return status. WriteHeader() must be called before call to Write
		if r == 0 {
			// Changing the header after a call to WriteHeader (or Write) has no effect.
			rw.Header().Set("Location", req.URL.String()+"/"+cKey.Encode())
			rw.WriteHeader(http.StatusCreated)
		} else {
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
	}()

	// Get data from body
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		c.Errorf("%s in reading body %s", err, b)
		r = 1
		return
	}
	var member Member
	if err = json.Unmarshal(b, &member); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = 1
		return
	}

	// Set now as the creation time. Precision to a second.
	member.CreateTime = time.Unix(time.Now().Unix(), 0)

	// Vernon debug
	c.Debugf("Store member %s", b)

	// Store item into datastore
	pKey := datastore.NewKey(c, MemberKind, MemberRoot, 0, nil)
	cKey, err = datastore.Put(c, datastore.NewIncompleteKey(c, MemberKind, pKey), &member)
	if err != nil {
		c.Errorf("%s in storing to datastore", err)
		r = 1
		return
	}
}

//func queryMember(rw http.ResponseWriter, req *http.Request) {
//	// To log messages
//	c := appengine.NewContext(req)
//
//	if len(req.URL.Query()) == 0 {
//		// Get key from URL
//		tokens := strings.Split(req.URL.Path, "/")
//		var keyIndexInTokens int = 0
//		for i, v := range tokens {
//			if v == "members" {
//				keyIndexInTokens = i + 1
//			}
//		}
//		if keyIndexInTokens >= len(tokens) {
//			c.Debugf("Key is not given so that list all members")
//			listMember(rw, req)
//			return
//		}
//		keyString := tokens[keyIndexInTokens]
//		if keyString == "" {
//			c.Debugf("Key is empty so that list all members")
//			listMember(rw, req)
//		} else {
//			queryOneMember(rw, req, keyString)
//		}
//	} else {
//		searchMember(rw, req)
//	}
//}

func listMember(rw http.ResponseWriter, req *http.Request) {
	// To access datastore and to log
	c := appengine.NewContext(req)
	c.Debugf("listMember()")

	// Get all entities
	var dst []Member
	r := 0
	k, err := datastore.NewQuery(MemberKind).Order("-CreateTime").GetAll(c, &dst)
	if err != nil {
		c.Errorf("%s", err)
		r = 1
	}

	// Map keys and items
	for i, v := range k {
		dst[i].Id = v.Encode()
	}

	// Return status. WriteHeader() must be called before call to Write
	if r == 0 {
		rw.WriteHeader(http.StatusOK)
	} else {
		http.Error(rw, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Return body
	encoder := json.NewEncoder(rw)
	if err = encoder.Encode(dst); err != nil {
		c.Errorf("%s in encoding result %v", err, dst)
	} else {
		c.Infof("listMember() returns %d members", len(dst))
	}
}

func clearMember(rw http.ResponseWriter, req *http.Request) {
	// To access datastore and to log
	c := appengine.NewContext(req)
	c.Infof("clearMember()")

	// Delete root entity after other entities
	r := 0
	pKey := datastore.NewKey(c, MemberKind, MemberRoot, 0, nil)
	if keys, err := datastore.NewQuery(MemberKind).KeysOnly().GetAll(c, nil); err != nil {
		c.Errorf("%s", err)
		r = 1
	} else if err := datastore.DeleteMulti(c, keys); err != nil {
		c.Errorf("%s", err)
		r = 1
	} else if err := datastore.Delete(c, pKey); err != nil {
		c.Errorf("%s", err)
		r = 1
	}

	// Return status. WriteHeader() must be called before call to Write
	if r == 0 {
		rw.WriteHeader(http.StatusOK)
	} else {
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
