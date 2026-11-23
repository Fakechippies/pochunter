# POC-Hunter demo — rendered with vhs (https://github.com/charmbracelet/vhs)
#
#   vhs assets/demo.tape
#
# All commands hit the local SQLite cache, so every frame is snappy.
# Requires the cache to be warm: run `pochunter update` once beforehand.

Output assets/demo.gif

Set Shell "zsh"
Set FontSize 24
Set FontFamily "JetBrains Mono"
Set Width 1600
Set Height 800
Set Padding 20
Set WindowBar Rings
Set BorderRadius 8
Set MarginFill "#2d243a"
Set Margin 10

Set Theme "catppuccin-mocha"
Set TypingSpeed 40ms

# -- intro ----------------------------------------------------------------
Type@80ms "pochunter --help" Enter
Sleep 1.5s

# -- free-form search: version auto-detected, CPE-resolved NVD query ------
Type@80ms "pochunter --search curl 7.0" Enter
Sleep 4s

# -- direct POC mode: stacked sources, local CVE cache enrichment ---------
Type@80ms "pochunter -poc CVE-2024-22198" Enter
Sleep 3s

# -- delta log: freshest CVEs from cvelistV5 ------------------------------
Type@80ms "pochunter recent -n 8" Enter
Sleep 2.5s

# -- cache maintenance: revision-checked refresh of bulk indexes ----------
Type@80ms "pochunter update" Enter
Sleep 6s

# -- plain piped output stays stable (no colors, fixed width) -------------
Type@80ms "pochunter --search curl 7.0 | cat" Enter
Sleep 3s

Sleep 2s
