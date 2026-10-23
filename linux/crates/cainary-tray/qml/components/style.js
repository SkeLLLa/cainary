.pragma library

// Level colours as light/dark pairs (the system palette has no yellow/orange). `dark` comes from
// the caller's palette: palette.window.hslLightness < 0.5.
const colors = {
    "high": ["#c62828", "#ff6b6b"],
    "medium": ["#c25e00", "#ffa04d"],
    "low": ["#9a7b00", "#f2c94c"],
    "opted-out": ["#1f6fb5", "#6cb6ff"],
    "ok": ["#1b7f3b", "#5fd38d"]
};

// The colour for a coloured level, or `fallback` for not-installed and unknown.
function levelColor(level, dark, fallback) {
    const pair = colors[level];
    return pair ? pair[dark ? 1 : 0] : fallback;
}

// Warning-orange text, as used for "couldn't be read" lines and banners.
function warningColor(dark) {
    return colors["medium"][dark ? 1 : 0];
}

// Opens a web link in the desktop's browser; anything else is ignored.
function openExternal(url) {
    if (/^https?:\/\//i.test(url))
        Qt.openUrlExternally(url);
}

function parse(text) {
    if (!text || text.length === 0)
        return null;
    try {
        return JSON.parse(text);
    } catch (e) {
        console.warn("cAInary: bad view JSON: " + e);
        return null;
    }
}
