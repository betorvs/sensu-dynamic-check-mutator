package main

import (
	"testing"

	v2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/stretchr/testify/assert"
)

func TestCheckArgs(t *testing.T) {
	assert := assert.New(t)
	event := v2.FixtureEvent("entity1", "check1")
	err := checkArgs(event)
	assert.Error(err)
	event2 := v2.FixtureEvent("entity2", "check2")
	mutatorConfig.CheckConfig = "[{\"name\":\"describe-resource\",\"command\":\"${{assetPath \\\"kubectl\\\"}}/kubernetes/client/bin/kubectl describe\",\"bool_args\":[\"--no-headers\"],\"arguments\":[\"daemonset\",\"deployment\",\"pod\",\"statefulset\",\"node\"],\"options\":{\"--namespace\":\"namespace\"},\"match_labels\":{\"sensu-alertmanager-events\":\"owner\"},\"sensu_assets\":[\"kubectl\"]}]"
	err2 := checkArgs(event2)
	assert.NoError(err2)
}

func TestExtractLabels(t *testing.T) {
	event1 := v2.FixtureEvent("entity1", "check1")
	event1.Labels["test1"] = "value1"
	value1, result1 := extractLabels(event1, "test1")
	assert.Contains(t, value1, "value1")
	assert.True(t, result1)
	event2 := v2.FixtureEvent("entity2", "check2")
	_, result2 := extractLabels(event2, "test2")
	assert.False(t, result2)
}

func TestSearchLabels(t *testing.T) {
	event1 := v2.FixtureEvent("entity1", "check1")
	event1.Labels["testa"] = "valuea"
	event1.Labels["testb"] = "valueb"
	event1.Labels["testc"] = "valuec"
	labels := make(map[string]string)
	res1 := searchLabels(event1, labels)
	assert.False(t, res1)

	labels["testa"] = "valuea"
	labels["testc"] = "valuec"
	res2 := searchLabels(event1, labels)
	assert.True(t, res2)

	excludeLabels := make(map[string]string)
	excludeLabels["testc"] = "valuec"
	res3 := searchLabels(event1, excludeLabels)
	assert.True(t, res3)
}

func TestParseCommandOptions(t *testing.T) {
	test1 := make(map[string]string)
	test1["foo"] = "bar"
	test1["test1"] = "test-1"
	mutatorConfig.CommandArgumentsTemplate = "{{ range $key, $value := . }} {{ $key }} {{ $value }}{{ end }}"
	result1 := parseCommandOptions(test1)
	assert.Contains(t, result1, "test1 test-1")
}

func TestParseCommandBoolFlags(t *testing.T) {
	test1 := []string{"-A", "-k"}
	mutatorConfig.CommandBoolArgumentsTemplate = "{{ range $value := . }} {{ $value }}{{ end }}"
	result1 := parseCommandBoolFlags(test1)
	assert.Contains(t, result1, "-A")
}
