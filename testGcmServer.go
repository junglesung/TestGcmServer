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
	"bytes"
)

// Data structure got from datastore user kind
type User struct {
	InstanceId           string    `json:"instanceid"`
	RegistrationToken    string    `json:"registrationtoken"`
	LastUpdateTime       time.Time `json:"lastupdatetime"`
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

// Data structure got from datastore group kind
type Group struct {
	Name                 string    `json:"name"`
	Owner                string    `json:"owner"`       // Instance ID
	Members            []string    `json:"members"`     // Instance ID list
	NotificationKey      string    `json:"notificationkey"`  // GCM device group unique ID
}

// HTTP body of joining or leaving group requests from users
type GroupUser struct {
	// To authentication
	InstanceId           string    `json:"instanceid"`
	// The group
	GroupName            string    `json:"groupname"`
}

// HTTP body to send to Google Cloud Messaging server to manage device groups
type GroupOperation struct {
	Operation            string    `json:"operation"`              // "create", "add", "remove"
	Notification_key_name string   `json:"notification_key_name"`  // A unique group name in a Google project
	Notification_key     string    `json:"notification_key,omitempty"`       // A unique key to identify a group
	Registration_ids   []string    `json:"registration_ids"`       // APP registration tokens in the group
}

// HTTP body received from Google Cloud Messaging server
type GroupOperationResponse struct {
	Notification_key     string    `json:"notification_key"`       // A unique key to identify a group
	Error                string    `json:"error"`                  // Error message
}

// HTTP body of sending a message to a user
type UserMessage struct {
	// To authentication
	InstanceId           string    `json:"instanceid"`
	// To the target user
	UserId               string    `json:"userid"`      // Datastore user kind key string
	Message              string    `json:"message"`
}

// HTTP body of sending a message to a topic
type TopicMessage struct {
	// To authentication
	InstanceId           string    `json:"instanceid"`
	// To the target user
	Topic                string    `json:"topic"`
	Message              string    `json:"message"`
}

// HTTP body of sending a message to a group
type GroupMessage struct {
	// To authentication
	InstanceId           string    `json:"instanceid"`
	// To the target user
	GroupName            string    `json:"groupname"`
	Message              string    `json:"message"`
}

const BaseUrl = "/api/0.1/"
const UserKind = "User"
const UserRoot = "User root"
const GroupKind = "Group"
const GroupRoot = "Group root"
const AppNamespace = "com.vernonsung.testgcmapp"
const GaeProjectId = "testgcmserver-1120"
const GaeProjectNumber = "846181647582"

// GCM server
const GcmURL = "https://gcm-http.googleapis.com/gcm/send"
const GcmGroupURL = "https://android.googleapis.com/gcm/notification"
const InstanceIdVerificationUrl = "https://iid.googleapis.com/iid/info/"
const GcmApiKey = "AIzaSyAODu6tKbQp8sAwEBDNLzW9uDCBmmluQ4A"

func init() {
	http.HandleFunc(BaseUrl, rootPage)
	http.HandleFunc(BaseUrl+"myself", UpdateMyself)  // PUT
	http.HandleFunc(BaseUrl+"groups", groups)  // PUT
	http.HandleFunc(BaseUrl+"groups/", groups)  // DELETE
	http.HandleFunc(BaseUrl+"user-messages", SendUserMessage)  // POST
	http.HandleFunc(BaseUrl+"topic-messages", SendTopicMessage)  // POST
	http.HandleFunc(BaseUrl+"group-messages", SendGroupMessage)  // POST
}

func rootPage(rw http.ResponseWriter, req *http.Request) {
	c := appengine.NewContext(req)
	c.Debugf("This is root")
}

func groups(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
//	case "GET":
//		listMember(rw, req)
//	case "POST":
//		SendMessage(rw, req)
	case "PUT":
		JoinGroup(rw, req)
	case "DELETE":
		LeaveGroup(rw, req)
	default:
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

// Receive a message from an APP instance.
// Check it's instancd ID.
// Send the message back.
// POST https://testgcmserver-1120.appspot.com/api/0.1/user-messages"
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
			http.Error(rw, `Please follow https://aaa.appspot.com/api/0.1/user-messages
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

	// Authenticate sender
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

// Receive a message from an APP instance.
// Check it's instancd ID.
// Send the message to the topic.
// POST https://testgcmserver-1120.appspot.com/api/0.1/topic-messages"
// Success: 204 No Content
// Failure: 400 Bad Request, 403 Forbidden, 404 NotFound, 500 InternalError
func SendTopicMessage(rw http.ResponseWriter, req *http.Request) {
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
			http.Error(rw, `Please follow https://aaa.appspot.com/api/0.1/topic-messages
			                {
			                    "instanceid":""
			                    "topic":""
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
	var message TopicMessage
	if err = json.Unmarshal(b, &message); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = http.StatusBadRequest
		return
	}

	// Authenticate sender
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

	// Make GCM message body
	var bodyString string = fmt.Sprintf(`
		{
			"to":"/topics/%s",
			"data": {
				"message":"%s"
			}
		}`, message.Topic, message.Message)


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

// Receive a message from an APP instance.
// Check it's instancd ID.
// Send the message to the gruop.
// POST https://testgcmserver-1120.appspot.com/api/0.1/group-messages"
// Success: 204 No Content
// Failure: 400 Bad Request, 403 Forbidden, 404 NotFound, 500 InternalError
func SendGroupMessage(rw http.ResponseWriter, req *http.Request) {
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
			http.Error(rw, `Please follow https://aaa.appspot.com/api/0.1/group-messages
			                {
			                    "instanceid":""
			                    "groupName":""
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
	var message GroupMessage
	if err = json.Unmarshal(b, &message); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = http.StatusBadRequest
		return
	}

	// Authenticate sender
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

	// Search for existing group
	var cKey *datastore.Key
	var pGroup *Group
	cKey, pGroup, err = searchGroup(message.GroupName, c)
	if err != nil {
		c.Errorf("%s in searching existing group %s", err, message.GroupName)
		r = http.StatusInternalServerError
		return
	}
	if cKey == nil {
		c.Warningf("Group %s is not found", message.GroupName)
		r = http.StatusBadRequest
		return
	}

	// Make GCM message body
	var bodyString string = fmt.Sprintf(`
		{
			"to":"%s",
			"data": {
				"message":"%s"
			}
		}`, pGroup.NotificationKey, message.Message)


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
	c.Infof("Send request to GCM server %s", *pReq)

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
// Success: 200 OK
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

// PUT https://testgcmserver-1120.appspot.com/api/0.1/groups"
// Success: 204 No Content
// Failure: 400 Bad Request, 403 Forbidden, 500 Internal Server Error
func JoinGroup(rw http.ResponseWriter, req *http.Request) {
	// Appengine
	var c appengine.Context = appengine.NewContext(req)
	// Result, 0: success, 1: failed
	var r int = http.StatusNoContent
	var cKey *datastore.Key = nil
	defer func() {
		if r == http.StatusNoContent {
			// Changing the header after a call to WriteHeader (or Write) has no effect.
			rw.Header().Set("Location", req.URL.String()+"/"+cKey.Encode())
			// Return status. WriteHeader() must be called before call to Write
			rw.WriteHeader(r)
		} else {
			http.Error(rw, http.StatusText(r), r)
		}
	}()

	// Get data from body
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		c.Errorf("%s in reading body %s", err, b)
		r = http.StatusInternalServerError
		return
	}

	// Vernon debug
	c.Debugf("Got body %s", b)

	var user GroupUser
	if err = json.Unmarshal(b, &user); err != nil {
		c.Errorf("%s in decoding body %s", err, b)
		r = http.StatusBadRequest
		return
	}

	// Authenticate sender & Search for user registration token
	var pUser *User
	var token string
	_, pUser, err = searchUser(user.InstanceId, c)
	if err != nil {
		c.Errorf("%s in searching user %v", err, user.InstanceId)
		r = http.StatusInternalServerError
		return
	}
	if pUser == nil {
		c.Errorf("User %s not found. Invalid request. Ignore.", user.InstanceId)
		r = http.StatusForbidden
		return
	}
	token = pUser.RegistrationToken

	// Search for existing group
	var pKey *datastore.Key
	var pGroup *Group
	pKey, pGroup, err = searchGroup(user.GroupName, c)
	if err != nil {
		c.Errorf("%s in searching existing group %s", err, user.GroupName)
		r = http.StatusInternalServerError
		return
	}

	// Make GCM message body
	var operation GroupOperation
	if pKey == nil {
		// Create a new group on GCM server
		operation.Operation = "create"
		operation.Notification_key_name = user.GroupName
		operation.Registration_ids = []string{token}
		if r = sendGroupOperationToGcm(&operation, c); r != http.StatusOK {
			c.Errorf("Send group operation to GCM failed")
			return
		}
		r = http.StatusNoContent

		// Add new group to the datastore
		pGroup = &Group {
			Name: user.GroupName,
			Owner: user.InstanceId,
			Members: []string {user.InstanceId},
			NotificationKey: operation.Notification_key,
		}
		pKey = datastore.NewKey(c, GroupKind, GroupRoot, 0, nil)
		cKey, err = datastore.Put(c, datastore.NewIncompleteKey(c, GroupKind, pKey), pGroup)
		if err != nil {
			c.Errorf("%s in storing to datastore", err)
			r = http.StatusInternalServerError
			return
		}
		c.Infof("Create group %+v", pGroup)
	} else {
		// Add the new user to the existing group on GCM server
		operation.Operation = "add"
		operation.Notification_key_name = user.GroupName
		operation.Notification_key = pGroup.NotificationKey
		operation.Registration_ids = []string{token}
		if r = sendGroupOperationToGcm(&operation, c); r != http.StatusOK {
			c.Errorf("Send group operation to GCM failed")
			return
		}
		r = http.StatusNoContent

		// Modify datastore
		pGroup.Members = append(pGroup.Members, token)
		cKey, err = datastore.Put(c, pKey, pGroup)
		if err != nil {
			c.Errorf("%s in storing to datastore", err)
			r = http.StatusInternalServerError
			return
		}
		c.Infof("Add user %s to group %s", user.InstanceId, user.GroupName)
	}
}

// DELETE https://testgcmserver-1120.appspot.com/api/0.1/groups/xxx", xxx: Group name
// Header {"Instance-Id":"..."}
// Success returns 204 No Content
// Failure returns 400 Bad Request, 403 Forbidden, 500 Internal Server Error
func LeaveGroup(rw http.ResponseWriter, req *http.Request) {
	// Appengine
	var c appengine.Context = appengine.NewContext(req)
	// Result, 0: success, 1: failed
	var r int = http.StatusNoContent
	// Sender instance ID
	var instanceId string
	// Sender registration token
	var registrationToken string
	// Group name to leave
	var groupName string
	// Then operation sent to GCM server
	var operation GroupOperation
	// Group in datastore
	var cKey *datastore.Key
	var pGroup *Group
	// Error
	var err error
	// Function to write response header
	defer func() {
		if r == http.StatusNoContent {
			// Return status. WriteHeader() must be called before call to Write
			rw.WriteHeader(r)
		} else {
			http.Error(rw, http.StatusText(r), r)
		}
	}()

	// Get instance ID from header
	instanceId = req.Header.Get("Instance-Id")
	if instanceId == "" {
		c.Warningf("Missing instance ID. Ignore the request.")
		r = http.StatusBadRequest
		return
	}

	// Authenticate sender & Search for user registration token
	var pUser *User
	_, pUser, err = searchUser(instanceId, c)
	if err != nil {
		c.Errorf("%s in searching user %v", err, instanceId)
		r = http.StatusInternalServerError
		return
	}
	if pUser == nil {
		c.Errorf("User %s not found. Invalid request. Ignore.", instanceId)
		r = http.StatusForbidden
		return
	}
	registrationToken = pUser.RegistrationToken

	// Get group name from URL
	var tokens []string
	tokens = strings.Split(req.URL.Path, "/")
	for i, v := range tokens {
		if v == "groups" && i + 1 < len(tokens) {
			groupName = tokens[i + 1]
			break
		}
	}
	if groupName == "" {
		c.Warningf("Missing group name. Ignore the request.")
		r = http.StatusBadRequest
		return
	}

	// Vernon debug
	c.Debugf("User %s is going to leave group %s", instanceId, groupName)

	// Search for existing group
	cKey, pGroup, err = searchGroup(groupName, c)
	if err != nil {
		c.Errorf("%s in searching existing group %s", err, groupName)
		r = http.StatusInternalServerError
		return
	}
	if cKey == nil {
		c.Infof("Group %s has been deleted already", groupName)
		return
	}

	var returnCode int = http.StatusOK
	if instanceId == pGroup.Owner {
		// Vernon debug
		c.Debugf("User %s owns the group %s", instanceId, groupName)

		// Remove all user from GCM server so that the group will be removed at the same time
		for _, v := range pGroup.Members {
			// Search user registration token
			_, pUser, err = searchUser(v, c)
			if err != nil {
				c.Warningf("%s in searching user %v", err, v)
				continue
			}
			if pUser == nil {
				c.Warningf("User %s not found. Ignore.", v)
				continue
			}
			registrationToken = pUser.RegistrationToken

			// Make operation structure
			operation.Operation = "remove"
			operation.Notification_key_name = pGroup.Name
			operation.Notification_key = pGroup.NotificationKey
			operation.Registration_ids = []string{registrationToken}
			if returnCode = sendGroupOperationToGcm(&operation, c); returnCode != http.StatusOK {
				c.Warningf("Failed to remove user %s from group %s because sending group operation to GCM failed", v, groupName)
				r = returnCode
				continue
			}
			c.Infof("User %s is removed from group %s", pUser.InstanceId, groupName)
		}

		// Modify datastore
		if err = datastore.Delete(c, cKey); err != nil {
			c.Errorf("%s in delete group %s from datastore", err, groupName)
			r = http.StatusInternalServerError
			return
		}
		c.Infof("User %s removed group %s", instanceId, groupName)
	} else {
		// Vernon debug
		c.Debugf("User %s doesn't own the group %s", instanceId, groupName)

		// Remove the user from the existing group on GCM server
		operation.Operation = "remove"
		operation.Notification_key_name = groupName
		operation.Notification_key = pGroup.NotificationKey
		operation.Registration_ids = []string{registrationToken}
		if returnCode = sendGroupOperationToGcm(&operation, c); returnCode != http.StatusOK {
			c.Errorf("Send group operation to GCM failed")
			r = returnCode
			return
		}

		// Modify datastore
		a := pGroup.Members
		for i, x := range a {
			if x == instanceId {
				a[i] = a[len(a)-1]
				a[len(a)-1] = ""
				a = a[:len(a)-1]
				break
			}
		}
		pGroup.Members = a
		cKey, err = datastore.Put(c, cKey, pGroup)
		if err != nil {
			c.Errorf("%s in storing to datastore", err)
			r = http.StatusInternalServerError
			return
		}
		c.Infof("Remove user %s from group %s", instanceId, groupName)
	}
}

// Send a Google Cloud Messaging Device Group operation to GCM server
// Success: 200 OK. Store the notification key from server to the operation structure
// Failure: 400 Bad Request, 403 Forbidden, 500 Internal Server Error
func sendGroupOperationToGcm(pOperation *GroupOperation, c appengine.Context) (r int) {
	// Initial variables
	var err error = nil
	r = http.StatusOK

	// Check parameters
	if pOperation == nil {
		c.Errorf("Parameter pOperation is nil")
		r = http.StatusInternalServerError
		return
	}

	// Make a POST request for GCM
	var b []byte
	b, err = json.Marshal(pOperation)
	if err != nil {
		c.Errorf("%s in encoding an operation as JSON", err)
		r = http.StatusBadRequest
		return
	}
	pReq, err := http.NewRequest("POST", GcmGroupURL, bytes.NewReader(b))
	if err != nil {
		c.Errorf("%s in makeing a HTTP request", err)
		r = http.StatusInternalServerError
		return
	}
	pReq.Header.Add("Content-Type", "application/json")
	pReq.Header.Add("Authorization", "key="+GcmApiKey)
	pReq.Header.Add("project_id", GaeProjectNumber)
	// Debug
	c.Debugf("Send request to GCM server %s", *pReq)
	c.Debugf("Send body to GCM server %s", b)

	// Send request
	var client = urlfetch.Client(c)
	resp, err := client.Do(pReq)
	if err != nil {
		c.Errorf("%s in sending request", err)
		r = http.StatusInternalServerError
		return
	}

	// Get response body
	var respBody GroupOperationResponse
	defer resp.Body.Close()
	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Errorf("%s in reading response body", err)
		r = http.StatusInternalServerError
		return
	}
	c.Infof("%s", b)
	if err = json.Unmarshal(b, &respBody); err != nil {
		c.Errorf("%s in decoding JSON response body", err)
		r = http.StatusInternalServerError
		return
	}

	// Check response
	c.Infof("%d %s", resp.StatusCode, resp.Status)
	if resp.StatusCode == http.StatusOK {
		// Success. Write Notification Key to operation structure
		pOperation.Notification_key = respBody.Notification_key
		return
	} else {
		c.Errorf("GCM server replied that %s", respBody.Error)
		r = http.StatusBadRequest
		return
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

func searchGroup(name string, c appengine.Context) (key *datastore.Key, group *Group, err error) {
	var v []Group
	// Initial variables
	key = nil
	group = nil
	err = nil

	// Query
	f := datastore.NewQuery(GroupKind)
	f = f.Filter("Name=", name)
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
	group = &v[0]
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
