# passvault

Shared Wails frontend and domain logic for password-manager apps backed
by different vault sources. Consumed by
[Passman](https://git.hrafn.xyz/aether/ncpassui) (Nextcloud Passwords)
and [Passbox](https://github.com/DelphicOkami/passbox) (USB hardware
device). One UI, two backends.

## Status

Pre-1.0. API shape, capability flags, and nav structure are still
moving. Tags are `v0.x.y`; no compatibility guarantees between minor
versions until `v1.0.0`.

Current contents: `ui/` only. The shared domain packages
(`tree`, `audit`, `passgen`, `breach`, `search`) and the bound `App`
interface land in subsequent commits.

## Packages

| Package | Status | What it owns |
|---|---|---|
| `ui` | ✅ shipped | Wails frontend assets (`index.html`, `app.css`, `app.js`) exposed as an `embed.FS`. |
| `tree` | planned | Canonical vault schema: `Tree`/`Node`/`Cred` types, `Parse`/`Serialize`, `ParsePath`/`Resolve`, `Mkdir`/`Rm`/`Mv`/`Cp`/`Set`, `Validate`. |
| `audit` | planned | Structural analysis: duplicates, reused passwords, weak, stale. |
| `passgen` | planned | Password generator (character classes + diceware wordlist). |
| `breach` | planned | HIBP k-anonymity client. |
| `search` | planned | Tree filter for the search-as-you-type UI. |
| _root_ | planned | `App` interface and `Capabilities` struct that both consumers implement. |

## Consuming the frontend assets

```go
import (
    "github.com/DelphicOkami/passvault/ui"
    "github.com/wailsapp/wails/v2"
    "github.com/wailsapp/wails/v2/pkg/options"
    "github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

func main() {
    err := wails.Run(&options.App{
        Title: "Your App",
        AssetServer: &assetserver.Options{
            Assets: ui.Assets,
        },
        // ...bind your App struct as usual
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

That's it — no local `frontend/` directory, no copy-pasted HTML/CSS/JS.
`go get -u github.com/DelphicOkami/passvault` to pick up UI updates.

## Canonical data model

Vaults are nested trees keyed by display name. Folders carry a
`children` map; credentials are leaves with `password`, `username`,
`url`, `notes`, `totp` fields. Paths are arrays of names:
`["Work", "github.com"]`.

```jsonc
{
  "children": {
    "Work": {
      "children": {
        "github.com": {
          "username": "alice",
          "password": "...",
          "url": "https://github.com"
        }
      }
    }
  }
}
```

Backends that don't natively store data this way (e.g. Nextcloud's
UUID-keyed flat list) translate to and from this shape inside their
provider implementation. The frontend and the shared domain packages
only ever see the tree.

## Development

```bash
# Run the test suite (gates tag releases).
go test ./...

# Run go vet to catch obvious issues.
go vet ./...
```

### Co-developing with a consumer

When you're changing `passvault` and a consumer at the same time, point
the consumer's `go.mod` at your local checkout with a `replace`
directive:

```
// in Passman/go.mod or Passbox/companion/go.mod
replace github.com/DelphicOkami/passvault => ../passvault
```

Remove the directive (and the corresponding `go.sum` change) before
tagging the consumer.

### Tagging a release

1. Land changes on `main`.
2. `go test ./...` and `go vet ./...` from the module root — both must pass.
3. `git tag vX.Y.Z && git push --tags`.
4. In each consumer: `go get github.com/DelphicOkami/passvault@vX.Y.Z`.

Pre-1.0 versioning is intentionally loose. Once both consumers are on
the module and the bound `App` interface settles, `v1.0.0` locks in
SemVer: major = bound API signature change, minor = additive
(`Capabilities` field or new bound method), patch = below the bound
surface.

## License

TBD.
