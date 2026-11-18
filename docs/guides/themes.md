# Theme contract v1

A skin owns its brand, type, colors and proportions. The application owns the templates, keyboard flow, form validation and access policy.

1. Copy `public/assets/themes/standard` to a new slug such as `studio`.
2. Set `"version": 1` and `"name": "Studio Access"` in `brand.json`. Optionally set `logo` to a local image filename, such as `logo.svg`. The name appears in page titles and account emails.
3. Override CSS custom properties in the new `theme.css`. Select it with `PD_THEME=studio`. Store or mount the skin independently from the release directory so it survives image changes.

The application loads shared token defaults, the selected skin and the shared component layout in that order. A skin may import its own foundation CSS using a relative URL. Use licensed local fonts, logos and artwork. The page policy allows same-origin styles, fonts and images.

| Token family | Contract |
| --- | --- |
| `--access-background`, `--access-panel` | Page and panel surfaces |
| `--access-text`, `--access-muted`, `--access-error` | Primary, supporting and error text |
| `--access-accent`, `--access-action-text`, `--access-focus`, `--access-border` | Links and primary actions, action ink, keyboard focus and control boundaries |
| `--access-body`, `--access-heading`, `--access-color-scheme` | Font stacks and native light or dark rendering preference |
| `--fs-body`, `--fs-h2`, `--lh-body`, `--lh-heading` | Shared type sizes and line heights |
| `--access-section-size`, `--access-subsection-size` | User manager headings |
| `--sp-1` through `--sp-7` | Ascending spacing scale used in fields, panels and user lists |
| `--access-radius`, `--access-rule`, `--access-accent-rule` | Corners and rule thickness |
| `--access-focus-width`, `--access-focus-offset`, `--access-link-offset` | Focus outline geometry and link underline position |
| `--access-panel-width`, `--access-admin-width`, `--access-column-width` | Layout limits and responsive field grid |
| `--access-control-height`, `--access-logo-height` | Minimum form-control height and maximum logo height |

A skin can build on its own design system by defining its palette and type tokens and mapping them to these roles. For example:

```css
:root {
  --studio-paper: #fffaf1;
  --studio-ink: #352433;
  --studio-plum: #65345c;
  --access-background: var(--studio-paper);
  --access-text: var(--studio-ink);
  --access-accent: var(--studio-plum);
  --access-heading: Georgia, serif;
  --access-radius: 0.2rem;
}
```

Before release, test login, signup, setup and reset, account settings, approval and user editing in the skin. Check errors, focus rings, action contrast, form controls and narrow layouts. Preserve the token names and manifest schema within major contract version 1. Introduce new tokens with defaults so older skins keep working.
