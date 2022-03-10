package cvecsvgenerator

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Generator interface {
	GetData() (Data, error)
	Generate()
}

type CveCsvGenerator struct {
	Data CveCsvData
}

func (c *CveCsvGenerator) GetData() error {
	content, err := getCveContent()
	if err != nil {
		return err
	}
	c.Data = convertToCveCsvElement(content.Result.CveItems)
	return nil
}

func (c *CveCsvGenerator) OutputData(w *bufio.Writer) {
	w.WriteString(c.Data.OutputString())
	w.Flush()
}

func convertToCveCsvElement(items []Item) CveCsvData {
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
	return CveCsvData{data}
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

func normalizeDescription(description string) string {
	description = strings.TrimSpace(description)
	return strconv.Quote(description)
}
