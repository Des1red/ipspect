package recog

import "strings"

type identity struct {
	vendor  string
	product string
	version string

	osVendor  string
	osProduct string
	osVersion string

	hwVendor  string
	hwProduct string

	matched   string
	certainty string
}

func (id identity) identified() bool {
	return id.vendor != "" ||
		id.product != "" ||
		id.version != "" ||
		id.osVendor != "" ||
		id.osProduct != "" ||
		id.hwVendor != "" ||
		id.hwProduct != ""
}

func (id identity) productName() string {
	product := id.product

	if id.vendor != "" &&
		!strings.EqualFold(
			id.vendor,
			id.product,
		) {

		product = strings.TrimSpace(
			id.vendor + " " + id.product,
		)
	}

	if id.version != "" &&
		product != "" {

		product += " " + id.version
	}

	return product
}

func (id identity) evidence(
	key string,
) string {
	evidence := "Rapid7 Recog [" + key + "]"

	if id.matched != "" {
		evidence += ": " + id.matched
	}

	if id.certainty != "" {
		evidence += " (signature certainty " +
			id.certainty + ")"
	}

	if id.osVendor != "" ||
		id.osProduct != "" {

		evidence += "; OS hint: " +
			strings.TrimSpace(
				id.osVendor+" "+
					id.osProduct+" "+
					id.osVersion,
			)
	}

	if id.hwVendor != "" ||
		id.hwProduct != "" {

		evidence += "; hardware hint: " +
			strings.TrimSpace(
				id.hwVendor+" "+
					id.hwProduct,
			)
	}

	return evidence
}
