Build to EXE with icon - package
================================

Files in this package:
 - build_to_exe_with_icon.bat   -> Universal builder that tries to embed an icon
 - add_build_context_with_icon.reg -> Registry entry to add "Build to EXE" in right-click (with icon)
 - rcedit_download.ps1          -> PowerShell script to download rcedit.exe to C:\DevTools (optional)
 - README.txt                   -> this file

Quick install steps (safe, non-destructive):
1) Create folder C:\DevTools (if not exists).
2) Copy build_to_exe_with_icon.bat into C:\DevTools\.
3) Create folder C:\DevTools\icons and put your icons there (optional). You can also place myscript.ico next to your script.
4) Double-click add_build_context_with_icon.reg (requires Admin) to add the right-click menu. This only adds a new entry and won't remove or modify other context menu items.
5) (Optional) Run rcedit_download.ps1 as Administrator to download rcedit.exe to C:\DevTools for embedding icons into EXE outputs.
   - Run in elevated PowerShell: .\rcedit_download.ps1
6) Right-click any supported file (.py, .ps1, .bat, .js, .go etc.) and choose "Build to EXE". The script will run and open the output folder when finished.

Notes & safety:
 - The registry file only creates a new context menu key (HKEY_CLASSES_ROOT\*\shell\BuildToEXE) and will not delete or overwrite other keys.
 - If you ever want to remove the menu, delete the key: reg delete "HKCR\*\shell\BuildToEXE" /f
 - For icon embedding into EXE where the builder doesn't support --icon, rcedit.exe is recommended.
 - All actions are local; no files are uploaded anywhere.

