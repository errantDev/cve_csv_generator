package cvecsvgenerator

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
