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

// Data structure got from datastore user kind
type User struct {
	InstanceId           string    `json:"instanceid"`
	RegistrationToken    string    `json:"registrationtoken"`
	LastUpdateTime       time.Time `json:"lastupdatetime"`
}

// HTTP body of sending a message to a user
type UserMessage struct {
	// To authentication
	InstanceId           string    `json:"instanceid"`
	RegistrationToken    string    `json:"registrationtoken"`
	// To the target user
	Message              string    `json:"message"`
}

// HTTP response body from Google Instance ID authenticity service
type InstanceIdAuthenticity struct {
	Application string             `json:"application"`
	AuthorizedEntity string        `json:"authorizedEntity"`
	// Other properties in the response body are "don't care"
}

type HelloMessage struct {
	RegistrationToken    string    `json:"registrationtoken"      datastore:"-"`
	Message              string    `json:"message"`
}

const BaseUrl = "/api/0.1/"
const UserKind = "User"
const UserRoot = "User root"
const AppNamespace = "com.vernonsung.testgcmapp"

// GCM server
const GcmURL = "https://gcm-http.googleapis.com/gcm/send"
const InstanceIdVerificationUrl = "https://iid.googleapis.com/iid/info/"
const GcmApiKey = "AIzaSyAODu6tKbQp8sAwEBDNLzW9uDCBmmluQ4A"

func init() {
	http.HandleFunc(BaseUrl, rootPage)
	http.HandleFunc(BaseUrl+"myself", UpdateMyself)
	http.HandleFunc(BaseUrl+"users/", users)
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
	case "POST":
		SendMessage(rw, req)
//	case "PUT":
//		UpdateUser(rw, req)
//	case "DELETE":
	// Users won't delete themselves.
	// Please write other function to clean unused users periodically.
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

// Receive a message from an APP instance.
// Check it's registration token.
// Send the message back.
// POST https://testgcmserver-1120.appspot.com/api/0.1/users/xxxxxx/messages"
// xxxxxx: Android APP instance ID
// Success: 204 No Content
// Failure: 400 Bad Request, 403 Forbidden
func SendMessage(rw http.ResponseWriter, req *http.Request) {
	// Appengine
	var c appengine.Context = appengine.NewContext(req)
	// Result, 0: success, 1: failed
	var r int = 0

	// Return code
	defer func() {
		// Return status. WriteHeader() must be called before call to Write
		if r == 0 {
			// Changing the header after a call to WriteHeader (or Write) has no effect.
			rw.WriteHeader(http.StatusNoContent)
		} else if r == 2 {
			http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		} else if r == 3 {
			http.Error(rw, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		} else {
			//			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			http.Error(rw, "Please follow https://aaa.appspot.com/api/0.1/tokens/xxxxxx/messages", http.StatusBadRequest)
		}
	}()

	// Parse URL into tokens
	var tokens []string = strings.Split(req.URL.Path, "/")
	var indexInstanceId int = 0
	var indexMessage int = 0
	for i, v := range tokens {
		if v == "users" {
			indexInstanceId = i + 1
			indexMessage = i + 2
			break
		}
	}

	// Check tokens
	if indexMessage >= len(tokens) || tokens[indexMessage] != "messages" {
		c.Errorf("Please follow https://aaa.appspot.com/api/0.1/users/xxxxxx/messages")
		r = 1
		return
	}

	// Registration token
	var targetInstanceId string = tokens[indexInstanceId]

	// Get the message from body
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		c.Errorf("%s in reading body %s", err, b)
		r = 1
		return
	}
	var message UserMessage
	if err = json.Unmarshal(b, &message); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = 1
		return
	}

	// Authenticate registration token
	var isValid bool = false
	isValid, err = verifyRequest(message.InstanceId, message.RegistrationToken, c)
	if err != nil {
		c.Errorf("%s in authenticating request", err)
		r = 1
		return
	}
	if isValid == false {
		c.Warningf("Invalid request, ignore")
		r = 2
		return
	}

	// Search for target user's latest registration token
	var pUser *User
	_, pUser, err = searchUser(targetInstanceId, c)
	if err != nil {
		c.Errorf("%s in searching the user %s", err, targetInstanceId)
		r = 1
		return
	}
	if pUser == nil {
		c.Errorf("User %s doesn't exist", targetInstanceId)
		r = 3
		return
	}

	// Make GCM message body
	var bodyString string = fmt.Sprintf(`
		{
			"to":"%s",
			"data": {
				"message":"%s"
			}
		}`, pUser.RegistrationToken, message.Message)


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

// PUT https://testgcmserver-1120.appspot.com/api/0.1/users/xxxxxx"
// xxxxxx: Android APP instance ID
// Success: 204 No Content
// Failure: 400 Bad Request
func UpdateMyself(rw http.ResponseWriter, req *http.Request) {
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
			rw.WriteHeader(http.StatusNoContent)
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

	var user User
	if err = json.Unmarshal(b, &user); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = 1
		return
	}
	if user.InstanceId == "" {
		c.Warningf("Instance ID is empty")
		r = 1
		return
	}

	// Verify authenticity
	pClient := urlfetch.Client(c)
	var resp *http.Response
	var sleepTime int
	// A Google APP Engine process must end within 60 seconds. So sleep no more than 16 seconds each retry.
	for sleepTime = 1; sleepTime <= 16; sleepTime *= 2 {
		resp, err = pClient.Get(InstanceIdVerificationUrl + user.InstanceId)
		if err != nil {
			c.Errorf("%s in verifying instance ID %s", err, user.InstanceId)
			r = 1
			return
		}
		// Retry while server is temporary invalid
		if resp.StatusCode != http.StatusServiceUnavailable {
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Check response code
	if resp.StatusCode != http.StatusOK {
		c.Warningf("Invalid instance ID with response code %d %s", resp.StatusCode, resp.Status)
		r = 1
		return
	}

	// Get body
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Errorf("%s in reading HTTP response body")
		r = 1
		return
	}

	// Decode body as JSON
	var authenticity InstanceIdAuthenticity
	if err := json.Unmarshal(body, &authenticity); err != nil {
		c.Warningf("%s in decoding HTTP response body")
		r = 1
		return
	}
	if authenticity.Application != AppNamespace || authenticity.AuthorizedEntity != appengine.AppID(c) {
		c.Warningf("Invalid instance ID with authenticity application %s and authorized entity %s",
		           authenticity.Application, authenticity.AuthorizedEntity)
		r = 1
		return
	}

	// Set now as the creation time. Precision to a second.
	user.LastUpdateTime = time.Unix(time.Now().Unix(), 0)

	// Search for existing user
	var pKey *datastore.Key
	var pOldUser *User
	pKey, pOldUser, err = searchUser(user.InstanceId, c)
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
		c.Infof("Add user %+v", user)
	} else if user.RegistrationToken == pOldUser.RegistrationToken {
		// Duplicate request. Do nothing to datastore and return existing key
		cKey = pKey
	} else {
		cKey, err = datastore.Put(c, pKey, &user)
		if err != nil {
			c.Errorf("%s in storing to datastore", err)
			r = 1
			return
		}
		c.Infof("Update user %+v", user)
	}
}

func searchUser(instanceId string, c appengine.Context) (key *datastore.Key, user *User, err error) {
	var v []User
	// Initial variables
	key = nil
	user = nil
	err = nil

	// Query
	f := datastore.NewQuery(UserKind)
	f = f.Filter("InstanceId=", instanceId)
	k, err := f.GetAll(c, &v)
	if err != nil {
		c.Errorf("%s in getting data from datastore\n", err)
		err = errors.New("Datastore is temporary unavailable")
		return
	}

	if k == nil || len(k) == 0 {
		return
	}

	key = k[0]
	user = &v[0]
	return
}

func verifyRequest(instanceId string, registrationToken string, c appengine.Context) (isValid bool, err error) {
	// Search for user from datastore
	var pUser *User

	// Initial variables
	isValid = false
	err = nil

	_, pUser, err = searchUser(instanceId, c)
	if err != nil {
		c.Errorf("%s in searching user %v", err, instanceId)
		return
	}

	// Verify registration token
	if pUser == nil || registrationToken != pUser.RegistrationToken {
		c.Warningf("Invalid instance ID %s with registration token %s. Correct registration token should be %s",
			instanceId, registrationToken, pUser.RegistrationToken)
		return
	}
	isValid = true
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
