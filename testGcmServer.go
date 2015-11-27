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
	// To the target user
	UserId               string    `json:"userid"`      // Datastore user kind key string
	Message              string    `json:"message"`
}

// HTTP response body from Google Instance ID authenticity service
type UserRegistrationTokenAuthenticity struct {
	Application string             `json:"application"`
	AuthorizedEntity string        `json:"authorizedEntity"`
	// Other properties in the response body are "don't care"
}

// HTTP response body to user registration
type UserRegistrationResponseBody struct {
	UserId string                  `json:"userid"`
}

type HelloMessage struct {
	RegistrationToken    string    `json:"registrationtoken"      datastore:"-"`
	Message              string    `json:"message"`
}

const BaseUrl = "/api/0.1/"
const UserKind = "User"
const UserRoot = "User root"
const AppNamespace = "com.vernonsung.testgcmapp"
const GaeProjectNumber = "846181647582"

// GCM server
const GcmURL = "https://gcm-http.googleapis.com/gcm/send"
const InstanceIdVerificationUrl = "https://iid.googleapis.com/iid/info/"
const GcmApiKey = "AIzaSyAODu6tKbQp8sAwEBDNLzW9uDCBmmluQ4A"

func init() {
	http.HandleFunc(BaseUrl, rootPage)
	http.HandleFunc(BaseUrl+"myself", UpdateMyself)  // PUT
	http.HandleFunc(BaseUrl+"users/", users)
	http.HandleFunc(BaseUrl+"user-messages", SendUserMessage)  // POST
	http.HandleFunc(BaseUrl+"tokens/", EchoMessage)  // POST
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
//		SendMessage(rw, req)
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

	// Check response
	c.Infof("%d %s", resp.StatusCode, resp.Status)

	// Get response body
	defer resp.Body.Close()
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
func SendUserMessage(rw http.ResponseWriter, req *http.Request) {
	// Appengine
	var c appengine.Context = appengine.NewContext(req)
	// Result, 0: success, 1: failed
	var r int = http.StatusNoContent

	// Return code
	defer func() {
		// Return status. WriteHeader() must be called before call to Write
		if r == http.StatusNoContent {
			// Changing the header after a call to WriteHeader (or Write) has no effect.
			rw.WriteHeader(http.StatusNoContent)
		} else if r == http.StatusBadRequest {
			//			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			http.Error(rw, `Please follow https://aaa.appspot.com/api/0.1/user-messages\n
			                {
			                    "instanceid":""
			                    "userid":""
			                    "message":""
			                }`, http.StatusBadRequest)
		} else {
			http.Error(rw, http.StatusText(r), r)
		}
	}()

	// Get body
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		c.Errorf("%s in reading body %s", err, b)
		r = http.StatusBadRequest
		return
	}
	var message UserMessage
	if err = json.Unmarshal(b, &message); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = http.StatusBadRequest
		return
	}

	// Authenticate registration token
	var isValid bool = false
	isValid, err = verifyRequest(message.InstanceId, c)
	if err != nil {
		c.Errorf("%s in authenticating request", err)
		r = http.StatusBadRequest
		return
	}
	if isValid == false {
		c.Warningf("Invalid request, ignore")
		r = http.StatusForbidden
		return
	}

	// Decode datastore key from string
	key, err := datastore.DecodeKey(message.UserId)
	if err != nil {
		c.Errorf("%s in decoding key string", err)
		r = http.StatusBadRequest
		return
	}

	// Get target user from datastore
	var dst User
	if err := datastore.Get(c, key, &dst); err != nil {
		c.Errorf("%s in getting entity from datastore by key %s", err, message.UserId)
		r = http.StatusNotFound
		return
	}

	// Make GCM message body
	var bodyString string = fmt.Sprintf(`
		{
			"to":"%s",
			"data": {
				"message":"%s"
			}
		}`, dst.RegistrationToken, message.Message)


	// Make a POST request for GCM
	pReq, err := http.NewRequest("POST", GcmURL, strings.NewReader(bodyString))
	if err != nil {
		c.Errorf("%s in makeing a HTTP request", err)
		r = http.StatusInternalServerError
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
		r = http.StatusInternalServerError
		return
	}
	defer resp.Body.Close()

	// Check response
	c.Infof("%d %s", resp.StatusCode, resp.Status)

	// Get response body
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Errorf("%s in reading response body", err)
		r = http.StatusInternalServerError
		return
	}
	c.Infof("%s", respBody)
}

// PUT https://testgcmserver-1120.appspot.com/api/0.1/myself"
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
			// Return status. WriteHeader() must be called before call to Write
			rw.WriteHeader(http.StatusOK)
			// Return body
			var dst UserRegistrationResponseBody = UserRegistrationResponseBody{ UserId:cKey.Encode() }
			if err := json.NewEncoder(rw).Encode(dst); err != nil {
				c.Errorf("%s in encoding result %v", err, dst)
			}
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

	// Check registration token starts with instance ID. That's the rule of Google API service authenticity
	// Also check registration token is official-signed by sending the token to Google token authenticity check service
	if user.RegistrationToken[0:len(user.InstanceId)] != user.InstanceId || isRegistrationTokenValid(user.RegistrationToken, c) == false {
		c.Errorf("Instance ID %s is invalid", user.InstanceId)
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

// Send APP instance ID to Google server to verify its authenticity
func isRegistrationTokenValid(token string, c appengine.Context) (isValid bool) {
	if token == "" {
		c.Warningf("Instance ID is empty")
		return false
	}

	// Make a GET request for Google Instance ID service
	pReq, err := http.NewRequest("GET", InstanceIdVerificationUrl + token, nil)
	if err != nil {
		c.Errorf("%s in makeing a HTTP request", err)
		return false
	}
	pReq.Header.Add("Authorization", "key="+GcmApiKey)
	// Debug
	c.Infof("%s", *pReq)

	// Send request
	pClient := urlfetch.Client(c)
	var resp *http.Response
	var sleepTime int
	// A Google APP Engine process must end within 60 seconds. So sleep no more than 16 seconds each retry.
	for sleepTime = 1; sleepTime <= 16; sleepTime *= 2 {
		resp, err = pClient.Do(pReq)
		if err != nil {
			c.Errorf("%s in verifying instance ID %s", err, token)
			return false
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
		return false
	}

	// Get body
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Errorf("%s in reading HTTP response body")
		return false
	}

	// Decode body as JSON
	var authenticity UserRegistrationTokenAuthenticity
	if err := json.Unmarshal(body, &authenticity); err != nil {
		c.Warningf("%s in decoding HTTP response body %s", body)
		return false
	}
	if authenticity.Application != AppNamespace || authenticity.AuthorizedEntity != GaeProjectNumber {
		c.Warningf("Invalid instance ID with authenticity application %s and authorized entity %s",
			authenticity.Application, authenticity.AuthorizedEntity)
		return false
	}

	return true
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

func verifyRequest(instanceId string, c appengine.Context) (isValid bool, err error) {
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
	if pUser == nil {
		c.Warningf("Invalid instance ID %s is not found in datastore", instanceId)
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
