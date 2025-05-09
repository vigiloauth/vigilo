package constants

const (
	DisplayPage  string = "page"
	DisplayPopup string = "popup"
	DisplayTouch string = "touch"
	DisplayWap   string = "wap"
)

var ValidAuthenticationDisplays = map[string]bool{
	DisplayPage:  true,
	DisplayPopup: true,
	DisplayTouch: true,
	DisplayWap:   true,
}
