Skyveda Scan for Azure Cloud Shell
==================================

What it does
  Reads your Azure configuration with Azure Resource Graph and writes a report
  (report.html) and the raw results (findings.json) into your Cloud Shell home.
  For resources the cost checks flag, and only those, it also reads what each
  was billed over the last 30 days (Azure Cost Management), so the report can
  show billed figures. Add --cost-source estimate to skip that read and use
  list prices instead.

What it never does
  It never creates, changes or deletes anything in Azure, and never reads your
  data (no blob contents, no secrets, no database rows). It sends nothing to
  Skyveda or anyone else: the files stay in your Cloud Shell until you choose
  to download or share them. The Reader role is enough.

Install (about one minute)
  1. Open Cloud Shell (Bash) in the Azure portal.
  2. Manage files > Upload > choose this zip, and wait for the upload notice
     (bottom right). Check it arrived:  ls ~/*.zip
  3. Run:  unzip -o skyveda-cloudshell-*.zip && bash skyveda-cloudshell/install.sh
     (Elsewhere on Linux without unzip, use: python3 -m zipfile -e skyveda-cloudshell-*.zip .)

Scan
  skyveda scopes                                   # what you can scan
  skyveda scan --out ~/skyveda-out --pdf           # every readable subscription
  skyveda scan -s <subscription-id> --out ~/skyveda-out --pdf

Then Manage files > Download > skyveda-out/report.pdf (or report.html)

Remove
  rm -rf ~/.skyveda ~/.local/bin/skyveda ~/skyveda-out
