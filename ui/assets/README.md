# Rnetch icon

Created for this project on 2026-10-03 with the built-in ImageGen tool.

The mark depicts a routing path with a diverted cobalt packet. The sidebar uses
the standalone graphite mark. The Windows icon uses a pearl-grey fill and a
substantial graphite contour so it remains visible on light and dark surfaces.

- `source/rnetch-mark.png`: original transparent generated mark.
- `source/rnetch-icon.png`: final generated application icon.
- `rnetch-mark.png`: 128 px PNG used by the React sidebar.
- `rnetch-icon.png`: 256 px PNG used by Electron and the browser favicon.
- `rnetch.ico`: Windows ICO with 16, 20, 24, 32, 40, 48, 64, 128 and 256 px frames.

Exports use Pillow's Lanczos resizing and ICO encoding; the generated shapes,
colors and transparency are preserved. Masters remain available for new sizes.
View `/preview/icon-proof.html` on the Vite server to inspect the actual assets.

## Generation prompt

Use case: logo-brand.
Create ONE final original application logomark for Rnetch, a Windows utility that selects individual processes and splits their network traffic into proxy versus direct paths.
Asset type: production app icon and sidebar brand mark. Square 1024 x 1024 PNG on a genuinely transparent background.
Creative direction: a compact bold asymmetric routing switch, whose silhouette subtly reads as a lowercase r. Make it feel like a carefully designed industrial wayfinding symbol with character, rather than an off-the-shelf network pictogram or a startup monogram.
Specific geometry: a thick dark graphite vertical spine on the left and a broad upper horizontal arm that bends out to the right; a single generous clean negative-space channel runs through the body and exits diagonally; one short cobalt-blue rectangular packet is visibly diverted out of the upper-right exit. The main mark is one cohesive, confident blocky silhouette with an unusual 45-degree cut, not thin lines, not disconnected decorative pieces. The negative-space bypass path should make the selective routing concept legible.
Colors: main body solid near-black graphite #252d3d, one flat cobalt #3563e9 accent packet. Flat solid colors only.
Composition: centered mark filling about 84 percent of the square canvas with balanced transparent safe margins; large thick forms and clear open space, recognizable at 16 and 32 pixels. Orthographic flat graphic, crisp precise edges, minimal geometry, no shading or textures.
No outer tile or enclosing badge, no rounded blue square, no cable or plug, no shield, no globe, no Wi-Fi, no circle network nodes, no rocket, no lightning bolt, no arrows with conventional arrowheads, no gradient, no 3D, no glow, no cast shadow, no text, no wordmark, no lettering around the mark, no watermark. Output the icon asset alone, without mockup, comparison board, caption, UI frame or background.

## Final application icon treatment

Edit only the color treatment of the provided Rnetch icon for Windows light and dark backgrounds. Its current graphite body becomes invisible on dark taskbars.
Keep the exact silhouette, routing channel, diagonal cut, two stems, detached diverted packet, relative positions, overall proportions, and genuinely transparent background.
Make the entire main body an OPAQUE flat pearl-blue-grey fill #a4b2cd, with a substantial OPAQUE graphite #252d3d contour about 42 pixels thick at this 1254px square resolution. The contour is a real solid stroke, not a halo or shadow; preserve open transparent channels. The light grey fill must remain opaque, not fade toward the background. Fill the detached packet with cobalt blue #3563e9 and give it the same graphite contour. There must be NO white line, white fill, white background or white border. Keep sufficient margins around the complete glyph.
This is a compact production application icon, optimized for 16–64 pixel rendering: thick clean boundaries, solid uniform fills, no grain, no gradient, no texture, no lighting, no added background plate or enclosing tile. Output the single square transparent icon alone.
