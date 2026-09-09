//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"bufio"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtRenderEventXML        = 1
	evtBatchSize             = 64
	errorNoMoreItems         = syscall.Errno(259)
	errorInsufficientBuffer  = syscall.Errno(122)
)

var (
	wevtapi      = syscall.NewLazyDLL("wevtapi.dll")
	procEvtQuery = wevtapi.NewProc("EvtQuery")
	procEvtNext  = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose = wevtapi.NewProc("EvtClose")
)

type config struct {
	Service serviceConfig `yaml:"service"`
	Input   inputConfig   `yaml:"input"`
	Outputs []outputConfig `yaml:"outputs"`
}

type serviceConfig struct {
	Flush    string `yaml:"flush"`
	LogLevel string `yaml:"log_level"`
}

type inputConfig struct {
	Type                 string   `yaml:"type"`
	Tag                  string   `yaml:"tag"`
	Channels             []string `yaml:"channels"`
	Interval             string   `yaml:"interval"`
	Lookback             string   `yaml:"lookback"`
	RenderEventAsText    bool     `yaml:"render_event_as_text"`
	RenderEventTextKey   string   `yaml:"render_event_text_key"`
}

type outputConfig struct {
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`
	Enabled       bool   `yaml:"enabled"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	TimeAsInteger bool   `yaml:"time_as_integer"`
}

type eventRecord struct {
	Timestamp    time.Time
	Provider     string
	EventID      string
	Channel      string
	Computer     string
	RenderedText string
	Fields       map[string]string
}

type forwardOutput struct {
	config outputConfig
	conn   net.Conn
}

type agent struct {
	config       config
	interval     time.Duration
	lookback     time.Duration
	forward      []*forwardOutput
	seen         map[string]time.Time
}

func main() {
	configPath := flag.String("config", "agent.yaml", "YAML configuration path")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.Input.Type != "winevtlog" {
		log.Fatalf("unsupported input type %q; only winevtlog is supported", cfg.Input.Type)
	}
	if len(cfg.Input.Channels) == 0 {
		log.Fatal("input.channels must contain at least one Windows event channel")
	}

	interval, err := parseDuration(cfg.Input.Interval, time.Second)
	if err != nil { log.Fatalf("input.interval: %v", err) }
	lookback, err := parseDuration(cfg.Input.Lookback, 5*time.Second)
	if err != nil { log.Fatalf("input.lookback: %v", err) }

	agent := &agent{config: cfg, interval: interval, lookback: lookback, seen: make(map[string]time.Time)}
	for _, output := range cfg.Outputs {
		if !output.Enabled { continue }
		switch strings.ToLower(output.Type) {
		case "terminal":
			log.Printf("output %s: terminal enabled", output.Name)
		case "forward":
			if output.Host == "" || output.Port == 0 { log.Fatalf("output %s: forward requires host and port", output.Name) }
			agent.forward = append(agent.forward, &forwardOutput{config: output})
			log.Printf("output %s: forward enabled at %s:%d", output.Name, output.Host, output.Port)
		default:
			log.Fatalf("output %s: unsupported type %q", output.Name, output.Type)
		}
	}

	log.Printf("sentinel-agent starting: config=%s channels=%s interval=%s lookback=%s", *configPath, strings.Join(cfg.Input.Channels, ","), interval, lookback)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer agent.close()
	for {
		select {
		case <-ticker.C:
			agent.poll()
		case <-stop:
			log.Println("sentinel-agent stopped")
			return
		}
	}
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !filepath.IsAbs(path) {
			if executable, exeErr := os.Executable(); exeErr == nil {
				data, err = os.ReadFile(filepath.Join(filepath.Dir(executable), path))
			}
		}
		if err != nil { return config{}, fmt.Errorf("read config %q: %w", path, err) }
	}
	cfg, err := parseConfigYAML(string(data))
	if err != nil { return config{}, fmt.Errorf("parse config %q: %w", path, err) }
	if cfg.Input.RenderEventTextKey == "" { cfg.Input.RenderEventTextKey = "rendered_text" }
	return cfg, nil
}

// parseConfigYAML parses the intentionally small, documented agent.yaml schema.
func parseConfigYAML(contents string) (config, error) {
	var cfg config
	scanner := bufio.NewScanner(strings.NewReader(contents))
	section := ""
	outputIndex := -1
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "-") {
			if line == "channels:" { continue }
			section = strings.TrimSuffix(line, ":")
			if section == "outputs" { outputIndex = -1 }
			continue
		}
		if strings.HasPrefix(line, "- ") {
			if section == "input" { cfg.Input.Channels = append(cfg.Input.Channels, strings.TrimSpace(strings.TrimPrefix(line, "- "))); continue }
			if section != "outputs" { return config{}, fmt.Errorf("list entry outside outputs") }
			cfg.Outputs = append(cfg.Outputs, outputConfig{Enabled: true})
			outputIndex = len(cfg.Outputs) - 1
			line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		}
		key, value, found := strings.Cut(line, ":")
		if !found { continue }
		key = strings.TrimSpace(key); value = strings.Trim(strings.TrimSpace(value), "\"'")
		switch section {
		case "service":
			if key == "flush" { cfg.Service.Flush = value }; if key == "log_level" { cfg.Service.LogLevel = value }
		case "input":
			switch key { case "type": cfg.Input.Type = value; case "tag": cfg.Input.Tag = value; case "interval": cfg.Input.Interval = value; case "lookback": cfg.Input.Lookback = value; case "render_event_as_text": cfg.Input.RenderEventAsText = value == "true"; case "render_event_text_key": cfg.Input.RenderEventTextKey = value; case "channels": continue }
		case "outputs":
			if outputIndex < 0 { return config{}, fmt.Errorf("output property without output entry") }
			output := &cfg.Outputs[outputIndex]
			switch key { case "name": output.Name = value; case "type": output.Type = value; case "enabled": output.Enabled = value != "false"; case "host": output.Host = value; case "port": output.Port, _ = strconv.Atoi(value); case "time_as_integer": output.TimeAsInteger = value == "true" }
		}
	}
	if err := scanner.Err(); err != nil { return config{}, err }
	return cfg, nil
}

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" { return fallback, nil }
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 { return 0, fmt.Errorf("%q must be a positive duration such as 1s or 500ms", value) }
	return duration, nil
}

func (a *agent) poll() {
	a.pruneSeen()
	for _, channel := range a.config.Input.Channels {
		events, err := queryEvents(channel, a.lookback)
		if err != nil { log.Printf("input %s: %v", channel, err); continue }
		for _, event := range events {
			key := event.Provider + "|" + event.EventID + "|" + event.Timestamp.UTC().Format(time.RFC3339Nano) + "|" + event.RenderedText
			if _, exists := a.seen[key]; exists { continue }
			a.seen[key] = time.Now()
			record := a.record(event)
			a.emit(event.Timestamp, record)
		}
	}
}

func (a *agent) record(event eventRecord) map[string]any {
	record := map[string]any{
		"provider": event.Provider,
		"event_id": event.EventID,
		"channel": event.Channel,
		"computer": event.Computer,
	}
	if a.config.Input.RenderEventAsText {
		record[a.config.Input.RenderEventTextKey] = event.RenderedText
	}
	for key, value := range event.Fields { record[key] = value }
	return record
}

func (a *agent) emit(timestamp time.Time, record map[string]any) {
	for _, output := range a.config.Outputs {
		if !output.Enabled { continue }
		switch strings.ToLower(output.Type) {
		case "terminal":
			payload, _ := json.Marshal(map[string]any{"tag": a.config.Input.Tag, "time": timestamp.Unix(), "record": record})
			fmt.Println(string(payload))
		case "forward":
			for _, forward := range a.forward {
				if forward.config.Name == output.Name {
					if err := forward.send(a.config.Input.Tag, timestamp.Unix(), record); err != nil { log.Printf("output %s: %v", output.Name, err) } else { log.Printf("output %s: sent event", output.Name) }
				}
			}
		}
	}
}

func queryEvents(channel string, lookback time.Duration) ([]eventRecord, error) {
	path, err := syscall.UTF16PtrFromString(channel); if err != nil { return nil, err }
	queryText := fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", lookback.Milliseconds())
	query, err := syscall.UTF16PtrFromString(queryText); if err != nil { return nil, err }
	handle, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(query)), evtQueryChannelPath|evtQueryForwardDirection)
	if handle == 0 { return nil, fmt.Errorf("EvtQuery: %w", callErr) }
	defer procEvtClose.Call(handle)
	result := make([]eventRecord, 0, evtBatchSize)
	for {
		handles := make([]uintptr, evtBatchSize)
		var returned uint32
		r, _, callErr := procEvtNext.Call(handle, evtBatchSize, uintptr(unsafe.Pointer(&handles[0])), 0, 0, uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			if errno, ok := callErr.(syscall.Errno); ok && errno == errorNoMoreItems { break }
			break
		}
		for i := uint32(0); i < returned; i++ {
			event, renderErr := renderEvent(handles[i]); procEvtClose.Call(handles[i])
			if renderErr == nil { result = append(result, event) } else { log.Printf("input %s: render event failed: %v", channel, renderErr) }
		}
	}
	return result, nil
}

func renderEvent(handle uintptr) (eventRecord, error) {
	var needed uint32
	r, _, callErr := procEvtRender.Call(0, handle, evtRenderEventXML, 0, 0, uintptr(unsafe.Pointer(&needed)), 0)
	if r == 0 && callErr != errorInsufficientBuffer { return eventRecord{}, fmt.Errorf("EvtRender size: %w", callErr) }
	if needed == 0 { return eventRecord{}, errors.New("EvtRender returned zero size") }
	buffer := make([]uint16, (needed+1)/2); var used uint32
	r, _, callErr = procEvtRender.Call(0, handle, evtRenderEventXML, uintptr(len(buffer)*2), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&used)), 0)
	if r == 0 { return eventRecord{}, fmt.Errorf("EvtRender: %w", callErr) }
	return parseEventXML(syscall.UTF16ToString(buffer[:used/2]))
}

func parseEventXML(data string) (eventRecord, error) {
	var event struct {
		System struct {
			Provider struct { Name string `xml:"Name,attr"` } `xml:"Provider"`
			EventID string `xml:"EventID"`; Channel string `xml:"Channel"`; Computer string `xml:"Computer"`
			Level string `xml:"Level"`; EventRecordID string `xml:"EventRecordID"`
			Execution struct { ProcessID string `xml:"ProcessID,attr"` } `xml:"Execution"`
			Correlation struct { ActivityID string `xml:"ActivityID,attr"` } `xml:"Correlation"`
			TimeCreated struct { SystemTime string `xml:"SystemTime,attr"` } `xml:"TimeCreated"`
		} `xml:"System"`
		EventData struct { Data []struct { Name string `xml:"Name,attr"`; Value string `xml:",chardata"` } `xml:"Data"` } `xml:"EventData"`
	}
	if err := xml.Unmarshal([]byte(data), &event); err != nil { return eventRecord{}, err }
	timestamp, err := time.Parse(time.RFC3339Nano, event.System.TimeCreated.SystemTime); if err != nil { timestamp = time.Now().UTC() }
	fields := make(map[string]string)
	var body strings.Builder
	for _, item := range event.EventData.Data {
		if item.Name != "" {
			fields[item.Name] = item.Value
			fmt.Fprintf(&body, "%s: %s\n", renderedFieldName(event.System.EventID, item.Name), item.Value)
		}
	}
	var text strings.Builder
	fmt.Fprintf(&text, "ProviderName=%s\nEventID=%s\nChannel=%s\nComputer=%s\nProcessID=%s\nLevel=%s\nEventRecordID=%s\nActivityID=%s\nMessage=\n%s", event.System.Provider.Name, event.System.EventID, event.System.Channel, event.System.Computer, event.System.Execution.ProcessID, event.System.Level, event.System.EventRecordID, event.System.Correlation.ActivityID, body.String())
	return eventRecord{Timestamp: timestamp, Provider: event.System.Provider.Name, EventID: event.System.EventID, Channel: event.System.Channel, Computer: event.System.Computer, RenderedText: text.String(), Fields: fields}, nil
}

func renderedFieldName(eventID, field string) string {
	aliases := map[string]map[string]string{
		"4624": {"SubjectUserName": "Account Name", "TargetUserName": "Account Name_2", "IpAddress": "Source Network Address", "LogonType": "Logon Type"},
		"4625": {"SubjectUserName": "Account Name", "TargetUserName": "Account Name_2", "IpAddress": "Source Network Address", "LogonType": "Logon Type"},
		"4634": {"SubjectUserName": "Account Name", "LogonType": "Logon Type"},
		"4648": {"SubjectUserName": "Account Name", "TargetUserName": "Account Name_2", "IpAddress": "Network Address"},
		"4798": {"SubjectUserName": "Account Name", "TargetUserName": "Account Name_2"},
	}
	if alias := aliases[eventID][field]; alias != "" { return alias }
	return field
}

func (f *forwardOutput) send(tag string, timestamp int64, record map[string]any) error {
	if f.conn == nil { conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", f.config.Host, f.config.Port), 5*time.Second); if err != nil { return err }; f.conn = conn }
	entries := [][]any{{timestamp, record}}
	frame := encode([]any{tag, entries, map[string]any{}})
	if err := f.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil { return err }
	if _, err := f.conn.Write(frame); err != nil { _ = f.conn.Close(); f.conn = nil; return err }
	return nil
}

func (a *agent) close() { for _, output := range a.forward { if output.conn != nil { _ = output.conn.Close() } } }
func (a *agent) pruneSeen() { cutoff := time.Now().Add(-2 * time.Minute); for key, seenAt := range a.seen { if seenAt.Before(cutoff) { delete(a.seen, key) } } }

func encode(value any) []byte { var buffer bytes.Buffer; writeValue(&buffer, value); return buffer.Bytes() }
func writeValue(b *bytes.Buffer, value any) { switch v := value.(type) { case string: writeString(b, v); case int64: writeInt(b, v); case [][]any: writeArrayHeader(b, len(v)); for _, item := range v { writeValue(b, item) }; case []any: writeArrayHeader(b, len(v)); for _, item := range v { writeValue(b, item) }; case map[string]any: writeMapHeader(b, len(v)); for key, item := range v { writeString(b, key); writeValue(b, item) } } }
func writeString(b *bytes.Buffer, value string) { n := len(value); if n < 32 { b.WriteByte(byte(0xa0|n)) } else if n < 256 { b.WriteByte(0xd9); b.WriteByte(byte(n)) } else { b.WriteByte(0xda); _ = binary.Write(b, binary.BigEndian, uint16(n)) }; b.WriteString(value) }
func writeInt(b *bytes.Buffer, value int64) { if value >= 0 && value < 128 { b.WriteByte(byte(value)); return }; if value >= -32 { b.WriteByte(byte(value)); return }; if value >= -128 { b.WriteByte(0xd0); b.WriteByte(byte(int8(value))); return }; b.WriteByte(0xd3); _ = binary.Write(b, binary.BigEndian, value) }
func writeArrayHeader(b *bytes.Buffer, n int) { if n < 16 { b.WriteByte(byte(0x90|n)) } else { b.WriteByte(0xdc); _ = binary.Write(b, binary.BigEndian, uint16(n)) } }
func writeMapHeader(b *bytes.Buffer, n int) { if n < 16 { b.WriteByte(byte(0x80|n)) } else { b.WriteByte(0xde); _ = binary.Write(b, binary.BigEndian, uint16(n)) } }
