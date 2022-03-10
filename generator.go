package cvecsvgenerator

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type CsvData interface {
	ToString() string
}

type Content struct {
	Result Result `json:"result"`
}

type Result struct {
	CveItems []Item `json:"CVE_Items"`
}

type Item struct {
	Cve           CveDefinition `json:"cve"`
	PublishedDate string        `json:"publishedDate"`
}

type CveDefinition struct {
	Metadata    CveMetadata    `json:"CVE_data_meta"`
	References  CveReferences  `json:"references"`
	Description CveDescription `json:"description"`
}

type CveMetadata struct {
	Id string `json:"ID"`
}

type CveReferences struct {
	ReferenceData []CveReferenceData `json:"reference_data"`
}

type CveReferenceData struct {
	Url string `json:"url"`
}

type CveDescription struct {
	DescriptionData []CveDescriptionData `json:"description_data"`
}

type CveDescriptionData struct {
	Value string `json:"value"`
}

type CveCsvElement struct {
	CveId             string
	PublishedDate     string
	FirstReferenceUrl string
	Description       string
}

func (c *CveCsvElement) ToString() string {
	var data bytes.Buffer
	data.WriteString(c.CveId)
	data.WriteString(",")
	data.WriteString(c.PublishedDate)
	data.WriteString(",")
	data.WriteString(c.FirstReferenceUrl)
	data.WriteString(",")
	data.WriteString(normalizeDescription(c.Description))
	data.WriteString("\n")
	return data.String()
}

func normalizeDescription(description string) string {
	description = strings.TrimSpace(description)
	return strconv.Quote(description)
}

func WriteCveCsvData(w *bufio.Writer, data []CveCsvElement) {
	for i := 0; i < len(data); i++ {
		w.WriteString(data[i].ToString())
	}
	w.Flush()
}

func GetCveCsvData() ([]CveCsvElement, error) {
	content, err := getCveContent()
	if err != nil {
		return []CveCsvElement{}, err
	}
	return convertToCveCsvElement(content.Result.CveItems), nil
}

func convertToCveCsvElement(items []Item) []CveCsvElement {
	var data []CveCsvElement
	for i := 0; i < len(items); i++ {
		cve := CveCsvElement{
			items[i].Cve.Metadata.Id,
			items[i].PublishedDate,
			items[i].Cve.References.ReferenceData[0].Url,
			items[i].Cve.Description.DescriptionData[0].Value,
		}
		data = append(data, cve)
	}
	return data
}

func getCveContent() (Content, error) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://services.nvd.nist.gov/rest/json/cves/1.0/?resultsPerPage=40")
	if err != nil {
		return Content{}, err
	}
	defer resp.Body.Close()
	var content Content
	err = json.NewDecoder(resp.Body).Decode(&content)
	if err != nil {
		return Content{}, err
	}
	return content, nil
}
