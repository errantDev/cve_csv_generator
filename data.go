package cvecsvgenerator

import "bytes"

type Data interface {
	OutputString() string
}

type CveCsvData struct {
	Data []CveCsvElement
}

func (d *CveCsvData) OutputString() string {
	var output bytes.Buffer
	for i := 0; i < len(d.Data); i++ {
		output.WriteString(d.Data[i].OutputString())
	}
	return output.String()
}

type CveCsvElement struct {
	CveId             string
	PublishedDate     string
	FirstReferenceUrl string
	Description       string
}

func (c *CveCsvElement) OutputString() string {
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
