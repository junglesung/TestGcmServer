package main

import (
	"appengine"
	"io/ioutil"
	"net/http"

	"github.com/pborman/uuid"
	gcscontext   "golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gcsappengine "google.golang.org/appengine"
	gcsfile      "google.golang.org/appengine/file"
	gcsurlfetch  "google.golang.org/appengine/urlfetch"
	"google.golang.org/cloud"
	"google.golang.org/cloud/storage"
)

const BaseUrl = "/api/0.1/"

func init() {
	http.HandleFunc(BaseUrl, rootPage)
	http.HandleFunc(BaseUrl+"storeImage", storeImage)
	http.HandleFunc(BaseUrl+"images", images)
}

func rootPage(rw http.ResponseWriter, req *http.Request) {
	//
}

func images(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	// case "GET":
		// queryImage(rw, req)
	case "POST":
		storeImage(rw, req)
	// case "DELETE":
	// 	deleteImage(rw, req)
	default:
		// queryAll(rw, req)
	}
}

func storeImage(rw http.ResponseWriter, req *http.Request) {
	// Appengine
	var c appengine.Context
	// Google Cloud Storage authentication
	var cc gcscontext.Context
	// Google Cloud Storage bucket name
	var bucket string = ""
	// User uploaded image file name
	var fileName string = uuid.New()
	// User uploaded image file type
	var contentType string = ""
	// User uploaded image file raw data
	var b []byte
	// Result, 0: success, 1: failed
	var r int = 0

	// Set response in the end
	defer func() {
		// Return status. WriteHeader() must be called before call to Write
		if r == 0 {
			// Changing the header after a call to WriteHeader (or Write) has no effect.
			// rw.Header().Set("Location", req.URL.String()+"/"+cKey.Encode())
			rw.Header().Set("Location", "http://"+bucket+".storage.googleapis.com/"+fileName)
			rw.WriteHeader(http.StatusCreated)
		} else {
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
	}()

	// To log information in Google APP Engine console
	c = appengine.NewContext(req)

	// Get data from body
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		c.Errorf("%s in reading body", err)
		r = 1
		return
	}
	c.Infof("Body length %d bytes, read %d bytes", req.ContentLength, len(b))

	// Determine filename extension from content type
	contentType = req.Header["Content-Type"][0]
	switch contentType {
	case "image/jpeg":
		fileName += ".jpg"
	default:
		c.Errorf("Unknown or unsupported content type '%s'. Valid: image/jpeg", contentType)
		r = 1
		return
	}
	c.Infof("Content type %s is received, %s is detected.", contentType, http.DetectContentType(b))

	// Get default bucket name
	cc = gcsappengine.NewContext(req)
	if bucket, err = gcsfile.DefaultBucketName(cc); err != nil {
		c.Errorf("%s in getting default GCS bucket name", err)
		r = 1
		return
	}
	c.Infof("APP Engine Version: %s", gcsappengine.VersionID(cc))
	c.Infof("Using bucket name: %s", bucket)

	// Prepare Google Cloud Storage authentication
	hc := &http.Client{
		Transport: &oauth2.Transport{
			Source: google.AppEngineTokenSource(cc, storage.ScopeFullControl),
			// Note that the App Engine urlfetch service has a limit of 10MB uploads and
			// 32MB downloads.
			// See https://cloud.google.com/appengine/docs/go/urlfetch/#Go_Quotas_and_limits
			// for more information.
			Base: &gcsurlfetch.Transport{Context: cc},
		},
	}
	ctx := cloud.NewContext(gcsappengine.AppID(cc), hc)

	// Change default object ACLs
	err = storage.PutDefaultACLRule(ctx, bucket, "allUsers", storage.RoleReader)
	// err = storage.PutACLRule(ctx, bucket, fileName, "allUsers", storage.RoleReader)
	if err != nil {
		c.Errorf("%v in saving ACL rule for bucket %q", err, bucket)
		return
	}

	// Store file in Google Cloud Storage
	wc := storage.NewWriter(ctx, bucket, fileName)
	wc.ContentType = contentType
	// wc.Metadata = map[string]string{
	// 	"x-goog-meta-foo": "foo",
	// 	"x-goog-meta-bar": "bar",
	// }
	if _, err := wc.Write(b); err != nil {
		c.Errorf("CreateFile: unable to write data to bucket %q, file %q: %v", bucket, fileName, err)
		r = 1
		return
	}
	if err := wc.Close(); err != nil {
		c.Errorf("CreateFile: unable to close bucket %q, file %q: %v", bucket, fileName, err)
		r = 1
		return
	}
	c.Infof("/%v/%v\n created", bucket, fileName)
}
