# H4C-WEB
#!/bin/bash

# ===============================================
# 🛡️ Full GitHub Web Scanner Repo Setup (Bash)
# ===============================================

# 🔹 Paketləri yenilə və quraşdır
pkg update -y && pkg upgrade -y
pkg install git python gh -y

# 🔹 GitHub CLI ilə login (interactive)
echo "GitHub CLI login..."
gh auth login

# 🔹 Yeni repo qovluğu yarat
mkdir -p web-scanner && cd web-scanner

# 🔹 README.md yarat
cat > README.md << 'EOF'
# 🛡️ Advanced Web Vulnerability Scanner

Python ilə hazırlanmış güclü və yüngül **veb zəiflik skaneri**. Bu alət yalnız **etik və icazəli təhlükəsizlik testləri** üçün nəzərdə tutulub.

---

## 🚀 Xüsusiyyətlər

- 💉 SQL Injection (error & boolean)
- ⚡ XSS (Cross-Site Scripting)
- 🔁 Open Redirect
- 🌐 SSRF
- 📂 Directory discovery
- 📄 Sensitive file detection (.env, config və s.)
- 🍪 Cookie təhlükəsizlik analizi
- 🛡️ Security headers yoxlanışı
- 🚧 WAF aşkarlanması
- 📊 JSON / CSV / HTML report
- 💾 Session save/load

---

## ⚙️ Quraşdırma (Termux / Linux)

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install colorama aiohttp beautifulsoup4
python scanner.py
