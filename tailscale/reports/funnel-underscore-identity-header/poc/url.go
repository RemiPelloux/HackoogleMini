package main
import "net/url"
type urlURL = url.URL
func parseURL(s string) (*url.URL, error) { return url.Parse(s) }
