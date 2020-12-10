package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	"github.com/sensu-community/sensu-plugin-sdk/templates"
	v2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/types"
)

// CheckTemplate struct
type CheckTemplate struct {
	Name          string            `json:"name"`
	Command       string            `json:"command"`
	Arguments     []string          `json:"arguments"`
	Options       map[string]string `json:"options"`
	BoolOptions   []string          `json:"bool_options"`
	MatchLabels   map[string]string `json:"match_labels"`
	ExcludeLabels map[string]string `json:"exclude_labels"`
	SensuAssets   []string          `json:"sensu_assets"`
}

// Auth represents the authentication info
type Auth struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// RemediationConfig from sensu-remediation-handler
type RemediationConfig struct {
	Request       string   `json:"request"`
	Occurrences   []int    `json:"occurrences"`
	Severities    []int    `json:"severities"`
	Subscriptions []string `json:"subscriptions"`
}

// Config represents the mutator plugin config.
type Config struct {
	sensu.PluginConfig
	CheckConfig                  string
	CommandArgumentsTemplate     string
	CommandBoolArgumentsTemplate string
	APIBackendPass               string
	APIBackendUser               string
	APIBackendKey                string
	APIBackendHost               string
	APIBackendPort               int
	Secure                       bool
	TrustedCAFile                string
	InsecureSkipVerify           bool
	Protocol                     string
	DefaultCheckSuffixName       string
}

var (
	tlsConfig tls.Config

	mutatorConfig = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "sensu-dynamic-check-mutator",
			Short:    "Sensu Dynamic Check Mutator creates sensu check based on template",
			Keyspace: "sensu.io/plugins/sensu-dynamic-check-mutator/config",
		},
	}

	options = []*sensu.PluginConfigOption{
		{
			Path:      "check-config",
			Env:       "",
			Argument:  "check-config",
			Shorthand: "c",
			Default:   "",
			Usage:     "Json template for Sensu Check",
			Value:     &mutatorConfig.CheckConfig,
		},
		{
			Path:      "command-arguments-template",
			Env:       "",
			Argument:  "command-arguments-template",
			Shorthand: "",
			Default:   "{{ range $key, $value := . }} {{ $key }} {{ $value }}{{ end }}",
			Usage:     "Template for Sensu Check Command",
			Value:     &mutatorConfig.CommandArgumentsTemplate,
		},
		{
			Path:      "command-bool-arguments-template",
			Env:       "",
			Argument:  "command-bool-arguments-template",
			Shorthand: "",
			Default:   "{{ range $value := . }} {{ $value }}{{ end }}",
			Usage:     "Template for Sensu Check Command",
			Value:     &mutatorConfig.CommandBoolArgumentsTemplate,
		},
		{
			Path:      "command-handler",
			Env:       "",
			Argument:  "command-handler",
			Shorthand: "",
			Default:   "default",
			Usage:     "Handler used to post the result",
			Value:     &mutatorConfig.CommandBoolArgumentsTemplate,
		},
		{
			Path:      "api-backend-user",
			Env:       "SENSU_API_USER",
			Argument:  "api-backend-user",
			Shorthand: "u",
			Default:   "admin",
			Usage:     "Sensu Go Backend API User",
			Value:     &mutatorConfig.APIBackendUser,
		},
		{
			Path:      "api-backend-pass",
			Env:       "SENSU_API_PASSWORD",
			Argument:  "api-backend-pass",
			Shorthand: "P",
			Default:   "P@ssw0rd!",
			Usage:     "Sensu Go Backend API Password",
			Value:     &mutatorConfig.APIBackendPass,
		},
		{
			Path:      "api-backend-key",
			Env:       "SENSU_API_KEY",
			Argument:  "api-backend-key",
			Shorthand: "k",
			Default:   "",
			Usage:     "Sensu Go Backend API Key",
			Value:     &mutatorConfig.APIBackendKey,
		},
		{
			Path:      "api-backend-host",
			Env:       "",
			Argument:  "api-backend-host",
			Shorthand: "B",
			Default:   "127.0.0.1",
			Usage:     "Sensu Go Backend API Host (e.g. 'sensu-backend.example.com')",
			Value:     &mutatorConfig.APIBackendHost,
		},
		{
			Path:      "api-backend-port",
			Env:       "",
			Argument:  "api-backend-port",
			Shorthand: "p",
			Default:   8080,
			Usage:     "Sensu Go Backend API Port (e.g. 4242)",
			Value:     &mutatorConfig.APIBackendPort,
		},
		{
			Path:      "secure",
			Env:       "",
			Argument:  "secure",
			Shorthand: "s",
			Default:   false,
			Usage:     "Use TLS connection to API",
			Value:     &mutatorConfig.Secure,
		},
		{
			Path:      "insecure-skip-verify",
			Env:       "",
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "skip TLS certificate verification (not recommended!)",
			Value:     &mutatorConfig.InsecureSkipVerify,
		},
		{
			Path:      "trusted-ca-file",
			Env:       "",
			Argument:  "trusted-ca-file",
			Shorthand: "t",
			Default:   "",
			Usage:     "TLS CA certificate bundle in PEM format",
			Value:     &mutatorConfig.TrustedCAFile,
		},
		{
			Path:      "default-check-suffic-name",
			Env:       "",
			Argument:  "default-check-suffix-name",
			Shorthand: "",
			Default:   "dynamic",
			Usage:     "Default suffix name for unpublished checks",
			Value:     &mutatorConfig.DefaultCheckSuffixName,
		},
	}
)

func main() {
	mutator := sensu.NewGoMutator(&mutatorConfig.PluginConfig, options, checkArgs, executeMutator)
	mutator.Execute()
}

func checkArgs(_ *types.Event) error {
	if len(mutatorConfig.CheckConfig) == 0 {
		return fmt.Errorf("--check-config is required")
	}
	// For Sensu Backend Connections
	if mutatorConfig.Secure {
		mutatorConfig.Protocol = "https"
	} else {
		mutatorConfig.Protocol = "http"
	}
	if len(mutatorConfig.TrustedCAFile) > 0 {
		caCertPool, err := v2.LoadCACerts(mutatorConfig.TrustedCAFile)
		if err != nil {
			return fmt.Errorf("Error loading specified CA file")
		}
		tlsConfig.RootCAs = caCertPool
	}
	tlsConfig.InsecureSkipVerify = mutatorConfig.InsecureSkipVerify

	tlsConfig.CipherSuites = v2.DefaultCipherSuites

	return nil
}

func executeMutator(event *types.Event) (*types.Event, error) {
	// log.Println("executing mutator with --check-config", mutatorConfig.CheckConfig)
	checkTemplate := []CheckTemplate{}
	err := json.Unmarshal([]byte(mutatorConfig.CheckConfig), &checkTemplate)
	if err != nil {
		return event, err
	}
	for _, v := range checkTemplate {
		if searchLabels(event, v.ExcludeLabels) {
			return event, nil
		}
		if searchLabels(event, v.MatchLabels) {
			// fmt.Printf("Check Name: %s\n", v.Name)

			var flags, args, boolFlags string
			if v.Options != nil {
				tempArgs := make(map[string]string)
				for key, value := range v.Options {
					temp, valid := extractLabels(event, value)
					if valid {
						tempArgs[key] = temp
					}
				}
				flags = parseCommandOptions(tempArgs)
			}
			if len(v.Arguments) != 0 {
				tempArgs := make(map[string]string)
				for _, value := range v.Arguments {
					temp, valid := extractLabels(event, value)
					if valid {
						tempArgs[value] = temp
					}
				}
				args = parseCommandOptions(tempArgs)
			}
			if len(v.BoolOptions) != 0 {
				boolFlags = parseCommandBoolFlags(v.BoolOptions)
			}
			command := v.Command
			if flags != "" {
				command += flags
			}
			if args != "" {
				command += args
			}
			if boolFlags != "" {
				command += boolFlags
			}
			tempName := fmt.Sprintf("%s-%s-%s", event.Check.Name, v.Name, mutatorConfig.DefaultCheckSuffixName)
			var autherr error
			auth := Auth{}
			if len(mutatorConfig.APIBackendKey) == 0 {
				auth, autherr = authenticate()

				if autherr != nil {
					return event, autherr
				}
			}
			entity := fmt.Sprintf("entity:%s", event.Entity.ObjectMeta.Name)
			assets := []string{}
			if len(v.SensuAssets) != 0 {
				assets = v.SensuAssets
			}
			err := postCheck(auth, tempName, command, event.Namespace, entity, assets)
			if err != nil {
				return event, err
			}

			remediation := []RemediationConfig{
				{
					Request:       tempName,
					Occurrences:   []int{1},
					Severities:    []int{2},
					Subscriptions: []string{entity},
				},
			}
			s, _ := json.Marshal(remediation)
			// fmt.Println(string(s))
			annotations := make(map[string]string)
			annotations["io.sensu.remediation.config.actions"] = string(s)
			// copy all annotations from event.check
			if event.Check.Annotations != nil {
				for k, v := range event.Check.Annotations {
					annotations[k] = v
				}
			}
			// add new annotations map with grafana URLs
			event.Check.Annotations = annotations

			// fmt.Println(command)
		}

	}

	return event, nil
}

func parseCommandOptions(arguments map[string]string) (title string) {
	title, err := templates.EvalTemplate("title", mutatorConfig.CommandArgumentsTemplate, arguments)
	if err != nil {
		return ""
	}
	return title
}

func parseCommandBoolFlags(arguments []string) (title string) {
	title, err := templates.EvalTemplate("title", mutatorConfig.CommandBoolArgumentsTemplate, arguments)
	if err != nil {
		return ""
	}
	return title
}

func extractLabels(event *types.Event, label string) (string, bool) {
	labelFound := ""
	if event.Labels != nil {
		for k, v := range event.Labels {
			if k == label {
				labelFound = v
			}
		}
	}
	if event.Entity.Labels != nil {
		for k, v := range event.Entity.Labels {
			if k == label {
				labelFound = v
			}
		}
	}
	if event.Check.Labels != nil {
		for k, v := range event.Check.Labels {
			if k == label {
				labelFound = v
			}
		}
	}
	if labelFound == "" {
		return labelFound, false
	}
	return labelFound, true
}

func searchLabels(event *types.Event, labels map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	count := 0
	for key, value := range labels {
		if event.Labels != nil {
			for k, v := range event.Labels {
				if k == key && v == value {
					count++
				}
			}
		}
		if event.Entity.Labels != nil {
			for k, v := range event.Entity.Labels {
				if k == key && v == value {
					count++
				}
			}
		}
		if event.Check.Labels != nil {
			for k, v := range event.Check.Labels {
				if k == key && v == value {
					count++
				}
			}
		}
		if count == len(labels) {
			return true
		}
	}

	return false
}

// authenticate funcion to wotk with api-backend-* flags
func authenticate() (Auth, error) {
	var auth Auth
	client := http.DefaultClient
	client.Transport = http.DefaultTransport

	if mutatorConfig.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s://%s:%d/auth", mutatorConfig.Protocol, mutatorConfig.APIBackendHost, mutatorConfig.APIBackendPort),
		nil,
	)
	if err != nil {
		return auth, fmt.Errorf("error generating auth request: %v", err)
	}

	req.SetBasicAuth(mutatorConfig.APIBackendUser, mutatorConfig.APIBackendPass)

	resp, err := client.Do(req)
	if err != nil {
		return auth, fmt.Errorf("error executing auth request: %v", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return auth, fmt.Errorf("error reading auth response: %v", err)
	}

	if strings.HasPrefix(string(body), "Unauthorized") {
		return auth, fmt.Errorf("authorization failed for user %s", mutatorConfig.APIBackendUser)
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&auth)

	if err != nil {
		trim := 64
		return auth, fmt.Errorf("error decoding auth response: %v\nFirst %d bytes of response: %s", err, trim, trimBody(body, trim))
	}

	return auth, err
}

// post check to sensu-backend-api
func postCheck(auth Auth, name, command, namespace, entity string, assets []string) error {
	client := http.DefaultClient
	client.Transport = http.DefaultTransport
	// /api/core/v2/namespaces/NAMESPACE/checks/:check_name and PUT
	url := fmt.Sprintf("%s://%s:%d/api/core/v2/namespaces/%s/checks/%s", mutatorConfig.Protocol, mutatorConfig.APIBackendHost, mutatorConfig.APIBackendPort, namespace, name)

	if mutatorConfig.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}
	check := &v2.Check{
		Subscriptions: []string{entity},
		Command:       command,
		Interval:      uint32(10),
		Publish:       false,
		RuntimeAssets: assets,
		ObjectMeta: v2.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				mutatorConfig.Name: "owner",
			},
			CreatedBy: mutatorConfig.Name,
		},
	}

	// s, err := json.MarshalIndent(check, "", "\t")
	// fmt.Println(string(s), url)
	encoded, _ := json.Marshal(check)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(encoded))
	if err != nil {
		return fmt.Errorf("Failed to post event to %s failed: %v", url, err)
	}
	if len(mutatorConfig.APIBackendKey) == 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Key %s", mutatorConfig.APIBackendKey))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error executing POST request for %s: %v", url, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("POST of event to %s failed with status %v\nevent: %s", url, resp.Status, string(encoded))
	}

	defer resp.Body.Close()

	return err
}

// used to clean errors output
func trimBody(body []byte, maxlen int) string {
	if len(string(body)) < maxlen {
		maxlen = len(string(body))
	}

	return string(body)[0:maxlen]
}
