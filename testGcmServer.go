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
	"appengine/urlfetch"
	"errors"
)

// HTTP body of user registration or token update
// Datastore User Kind
type UserRegistration struct {
	RegistrationToken    string    `json:"registrationtoken      datastore:"-"`
	InstanceId           string    `json:"instanceid`
	NewRegistrationToken string    `json:"newregistrationtoken   datastore:"RegistrationToken"`
	LastUpdateTime       time.Time `json:"lastupdatetime`
}

// User unregistration
type UserUnregistration struct {
	RegistrationToken    string    `json:"registrationtoken      datastore:"-"`
	InstanceId           string    `json:"instanceid`
}

type HelloMessage struct {
	RegistrationToken    string    `json:"registrationtoken      datastore:"-"`
	Message              string    `json:"message"`
}

const BaseUrl = "/api/0.1/"
const UserKind = "User"
const UserRoot = "User root"

// GCM server
const GcmURL = "https://gcm-http.googleapis.com/gcm/send"
const GcmApiKey = "AIzaSyAODu6tKbQp8sAwEBDNLzW9uDCBmmluQ4A"

func init() {
	http.HandleFunc(BaseUrl, rootPage)
	http.HandleFunc(BaseUrl+"users", users)
	http.HandleFunc(BaseUrl+"tokens/", EchoMessage)
}

func rootPage(rw http.ResponseWriter, req *http.Request) {
	c := appengine.NewContext(req)
	c.Debugf("This is root")
}

func users(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
//	case "GET":
//		listMember(rw, req)
	// To avoid duplicate users, use PUT to search the existing one before adding a new one
//	case "POST":
//		addUser(rw, req)
	case "PUT":
		UpdateUser(rw, req)
//	case "DELETE":
//		clearMember(rw, req)
	default:
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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
		}`, token, message.Message, message.Message, message.Message)


	// Make a POST request for GCM
	pReq, err := http.NewRequest("POST", GcmURL, strings.NewReader(bodyString))
	if err != nil {
		c.Errorf("%s in makeing a HTTP request", err)
		r = 1
		return
	}
	pReq.Header.Add("Content-Type", "application/json")
	pReq.Header.Add("Authorization", "key="+GcmApiKey)
	// Debug
	c.Infof("%s", *pReq)

	// Send request
	var client = urlfetch.Client(c)
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

func UpdateUser(rw http.ResponseWriter, req *http.Request) {
	// Appengine
	var c appengine.Context = appengine.NewContext(req)
	// Result, 0: success, 1: failed
	var r int = 0
	var cKey, pKey *datastore.Key = nil, nil
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

	// Vernon debug
	c.Debugf("Got body %s", b)

	var user UserRegistration
	if err = json.Unmarshal(b, &user); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = 1
		return
	}

	// Set now as the creation time. Precision to a second.
	user.LastUpdateTime = time.Unix(time.Now().Unix(), 0)

	// Search for existing user
	pKey, err = searchUser(user, c)
	if err != nil {
		c.Errorf("%s in searching existing user %v", err, user)
		r = 1
		return
	}
	if pKey == nil {
		// Add new user into datastore
		pKey = datastore.NewKey(c, UserKind, UserRoot, 0, nil)
		cKey, err = datastore.Put(c, datastore.NewIncompleteKey(c, UserKind, pKey), &user)
		if err != nil {
			c.Errorf("%s in storing to datastore", err)
			r = 1
			return
		}
		c.Debugf("Add user %v", user)
	} else {
		// Update existing user in datastore
		cKey, err = datastore.Put(c, pKey, &user)
		if err != nil {
			c.Errorf("%s in storing to datastore", err)
			r = 1
			return
		}
		c.Debugf("Update user %v", user)
	}

}

func searchUser(user UserRegistration, c appengine.Context) (key *datastore.Key, err error) {
	// Initial variables
	key = nil
	err = nil

	// Query
	f := datastore.NewQuery(UserKind)
	f = f.Filter("InstanceId=", user.InstanceId).KeysOnly()
	k, err := f.GetAll(c, nil)
	if err != nil {
		c.Errorf("%s in getting data from datastore\n", err)
		err = errors.New("Datastore is temporary unavailable")
		return
	}

	if k == nil || len(k) == 0 {
		return
	}

	key = k[0]
	return
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

//func listMember(rw http.ResponseWriter, req *http.Request) {
//	// To access datastore and to log
//	c := appengine.NewContext(req)
//	c.Debugf("listMember()")
//
//	// Get all entities
//	var dst []UserRegistration
//	r := 0
//	k, err := datastore.NewQuery(UserKind).Order("-CreateTime").GetAll(c, &dst)
//	if err != nil {
//		c.Errorf("%s", err)
//		r = 1
//	}
//
//	// Map keys and items
//	for i, v := range k {
//		dst[i].Id = v.Encode()
//	}
//
//	// Return status. WriteHeader() must be called before call to Write
//	if r == 0 {
//		rw.WriteHeader(http.StatusOK)
//	} else {
//		http.Error(rw, http.StatusText(http.StatusNotFound), http.StatusNotFound)
//		return
//	}
//
//	// Return body
//	encoder := json.NewEncoder(rw)
//	if err = encoder.Encode(dst); err != nil {
//		c.Errorf("%s in encoding result %v", err, dst)
//	} else {
//		c.Infof("listMember() returns %d members", len(dst))
//	}
//}
//
//func clearMember(rw http.ResponseWriter, req *http.Request) {
//	// To access datastore and to log
//	c := appengine.NewContext(req)
//	c.Infof("clearMember()")
//
//	// Delete root entity after other entities
//	r := 0
//	pKey := datastore.NewKey(c, UserKind, UserRoot, 0, nil)
//	if keys, err := datastore.NewQuery(UserKind).KeysOnly().GetAll(c, nil); err != nil {
//		c.Errorf("%s", err)
//		r = 1
//	} else if err := datastore.DeleteMulti(c, keys); err != nil {
//		c.Errorf("%s", err)
//		r = 1
//	} else if err := datastore.Delete(c, pKey); err != nil {
//		c.Errorf("%s", err)
//		r = 1
//	}
//
//	// Return status. WriteHeader() must be called before call to Write
//	if r == 0 {
//		rw.WriteHeader(http.StatusOK)
//	} else {
//		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
//	}
//}
