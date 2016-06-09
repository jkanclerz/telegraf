package http_client

import (
	"fmt"
    "io/ioutil"
    "net/http"
    "bytes"
    "encoding/json"
    "errors"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/outputs"
	"github.com/influxdata/telegraf/plugins/serializers"
)

type HttpClient struct {
    Endpoint string
    ClientId string
    ClientSecret string

    authorizationContext AuthorizationContext

	serializer serializers.Serializer
}

var sampleConfig = `
  ## Files to write to, "stdout" is a specially handled file.
  endpoint = "http://127.0.0.1:5000"
  clientId = "123"
  clientSecret = "abc"

  ## Data format to output.
  ## Each data format has it's own unique set of configuration options, read
  ## more about them here:
  ## https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_OUTPUT.md
  data_format = "json"
`

func (s *HttpClient) SetSerializer(serializer serializers.Serializer) {
	s.serializer = serializer
}

func (s *HttpClient) Description() string {
    return "a demo output"
}

func (s *HttpClient) SampleConfig() string {
    return sampleConfig
}

func (s *HttpClient) Connect() error {
    s.authorizationContext = AuthorizationContext{}
    return nil
}

func (s *HttpClient) Close() error {
    // Close connection to the URL here
    return nil
}

func (s *HttpClient) Write(metrics []telegraf.Metric) error {
	if len(metrics) == 0 {
		return nil
	}

	for _, metric := range metrics {
		values, err := s.serializer.Serialize(metric)
		if err != nil {
			return err
		}

		for _, value := range values {
			s.writeContent(&s.authorizationContext, value)
			fmt.Println("Token", s.authorizationContext.token.value)
		}
	}
	return nil
}

type AccessToken struct {
    value string
}

type Authorization struct {
    AccessTokenValue string `json:"access_token"`
}

type AuthorizationContext struct {
    token AccessToken
}

func (s *HttpClient) writeContent(context *AuthorizationContext, metric string) (error) {
    endpoint := s.Endpoint
    url := fmt.Sprintf("%s%s?access_token=%s&index=macosgo", endpoint, "/api/collect-telegraf", context.token.value)

    var jsonStr = []byte(metric)
    fmt.Println("url:", url)
    
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}

    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }

    if resp.StatusCode == 401 {
    	s.authorize(context)
    	s.writeContent(context, metric)
        return errors.New("API NOT AUTHORIZED")
    }

    if resp.StatusCode != 200 {
        return errors.New("API ERROR")
    }

    defer resp.Body.Close()

    fmt.Println("Write response Status:", resp.Status)

    return nil
}

func (s *HttpClient) authorize(context *AuthorizationContext) *AuthorizationContext {
    client_id := s.ClientId
    client_secret := s.ClientSecret
    endpoint := s.Endpoint

    url := fmt.Sprintf("%s%s?client_id=%s&client_secret=%s&grant_type=%s", endpoint, "/oauth/token", client_id, client_secret, "client_credentials")

    var jsonStr = []byte(``)
    req, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonStr))
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}

    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }

    defer resp.Body.Close()

    // fmt.Println("response Status:", resp.Status)
    // fmt.Println("response Headers:", resp.Header)
    body, _ := ioutil.ReadAll(resp.Body)
    bytes := []byte(string(body))
    var authorization Authorization
    json.Unmarshal(bytes, &authorization)

    context.token = AccessToken{}
    context.token.value = authorization.AccessTokenValue

    return context
}

func init() {
    outputs.Add("http_client", func() telegraf.Output { return &HttpClient{} })
}
