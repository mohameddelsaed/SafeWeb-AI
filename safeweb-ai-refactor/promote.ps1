New-Item -ItemType Directory -Force -Path "03-specs"
Get-ChildItem -Path "02-agents\outputs\11-specs-draft\*.md" -Exclude "CURRENT.md" | ForEach-Object {
    $content = Get-Content $_.FullName
    $content = $content -replace "Status: draft", "Status: approved"
    $newName = "03-specs\" + $_.Name
    Set-Content -Path $newName -Value $content
}
