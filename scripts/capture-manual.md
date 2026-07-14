# Manual Screenshot Capture Guide

If you prefer manual screenshots or browser extension methods:

---

## Method 1 - Browser DevTools (Free, Built-in)

### Chrome/Edge DevTools

1. Open page in browser: `http://localhost:5175/`
2. Press F12 to open DevTools
3. Press Ctrl+Shift+P (Command Palette)
4. Type "Capture full size screenshot"
5. Press Enter → PNG saved to Downloads

**Responsive Testing:**

1. Toggle device toolbar (Ctrl+Shift+M)
2. Select preset: iPhone 12, iPad, etc.
3. Capture screenshot (Ctrl+Shift+P → "Capture screenshot")

---

## Method 2 - Browser Extensions (Easy)

### Recommended Extensions

#### Awesome Screenshot (Chrome/Firefox)

- Capture visible area, full page, or selected region
- Annotate and blur sensitive data
- Export PNG/JPG/PDF

#### GoFullPage (Chrome)

- One-click full-page capture
- High-resolution PNG
- No scrolling artifacts

#### Nimbus Screenshot (Chrome/Firefox)

- Capture + video recording
- Built-in editor
- Multiple export formats

---

## Method 3 - Built-in OS Tools (Quick)

### Windows

- **Snipping Tool**: Win+Shift+S → Select area
- **Game Bar**: Win+Alt+PrtScn → Saves to Videos/Captures

### macOS

- **Full screen**: Cmd+Shift+3
- **Selection**: Cmd+Shift+4
- **Window**: Cmd+Shift+4, then Space, click window

### Linux

- **GNOME**: PrtScn key
- **KDE**: Spectacle (built-in tool)

---

## Method 4 - Professional Mockup Tools

### For Presentation and Portfolio

#### Screely (screely.com)

- Add browser chrome
- Custom backgrounds
- Instant mockups

#### Cleanshot (Mac only)

- Scrolling capture
- Hide desktop icons
- Add annotations

#### Mockuuups Studio

- Device mockups (laptop/phone frames)
- Professional presentation

---

## Recommended Viewport Sizes for Export

| Device  | Width  | Height | Use Case         |
| ------- | ------ | ------ | ---------------- |
| Desktop | 1440px | 900px  | Primary demo     |
| Laptop  | 1280px | 800px  | Standard display |
| Tablet  | 768px  | 1024px | iPad view        |
| Mobile  | 375px  | 812px  | iPhone view      |

---

## Best Practices

**DO:**

- Capture at 2x scale (retina) for presentations
- Use PNG for UI (lossless)
- Include full-page scroll captures for landing/docs
- Take both light/dark versions if applicable (SafeWeb is dark-only)
- Clear browser cache before capturing (fresh load)

**DON'T:**

- Use JPG for UI screenshots (artifacts)
- Capture with browser extensions/toolbars visible
- Forget to hide password managers/autocomplete popups
- Capture with console errors visible

---

## For Academic Thesis and Defense

**Required Screenshots:**

1. Landing page hero (full viewport)
2. Dashboard with scan results
3. Vulnerability details page
4. Mobile responsive views (stacked)
5. Admin panel (if presenting backend)

**Recommended Formats:**

- **Slides**: PNG at 1920x1080 (16:9)
- **Document**: PNG at 1440x900, compressed to ~500KB
- **Portfolio**: High-res PNG (2x scale) + WebP fallback

---

## Quick Command (Single Page)

Chrome DevTools full screenshot:

```text
F12 → Ctrl+Shift+P → "Capture full size screenshot"
```

Firefox full screenshot:

```text
F12 → Shift+F2 → :screenshot --fullpage
```
