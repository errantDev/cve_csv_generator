package cvecsvgenerator

import (
	"strings"
	"testing"
)

func TestConvertingCveCsvElementToString(t *testing.T) {
	data := CveCsvElement{
		"CVE-2022-0697",
		"2022-03-06T23:15Z",
		"https://huntr.dev/bounties/2d0301a2-10ff-48f4-a346-5a0e8707835b",
		"Open Redirect in GitHub repository archivy/archivy prior to 1.7.0.",
	}
	got := data.ToString()
	expect := `CVE-2022-0697,2022-03-06T23:15Z,https://huntr.dev/bounties/2d0301a2-10ff-48f4-a346-5a0e8707835b,"Open Redirect in GitHub repository archivy/archivy prior to 1.7.0."`
	if strings.Compare(got, expect) == 0 {
		t.Errorf("expected `%s`, got `%s`", expect, got)
	}
}

func TestConvertContentToCveCsvElement(t *testing.T) {
	content := Content{
		Result{
			[]Item{
				{
					CveDefinition{
						CveMetadata{"CVE-2022-0697"},
						CveReferences{
							[]CveReferenceData{
								{"https://huntr.dev/bounties/2d0301a2-10ff-48f4-a346-5a0e8707835b"},
							},
						},
						CveDescription{
							[]CveDescriptionData{
								{"Open Redirect in GitHub repository archivy/archivy prior to 1.7.0."},
							},
						},
					},
					"2022-03-06T23:15Z",
				},
			},
		},
	}
	got := convertToCveCsvElement(content.Result.CveItems)

	if len(got) == 0 {
		t.Error("CveCsvElement Conversion failed")
		return
	}

	expect := CveCsvElement{
		"CVE-2022-0697",
		"2022-03-06T23:15Z",
		"https://huntr.dev/bounties/2d0301a2-10ff-48f4-a346-5a0e8707835b",
		"Open Redirect in GitHub repository archivy/archivy prior to 1.7.0.",
	}
	checkEqualCveCsvElement(t, got[0], expect)
}

func checkEqualCveCsvElement(t testing.TB, got, expect CveCsvElement) {
	if got.ToString() != expect.ToString() {
		t.Errorf("expected CveCsvElement of %s, got %s", expect.ToString(), got.ToString())
	}
}
