// Package ui ships the Passvault frontend assets so consumers can embed
// them via Wails' assetserver without vendoring a copy of the files.
package ui

import "embed"

//go:embed index.html app.css app.js
var Assets embed.FS
