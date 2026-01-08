## simple link crawler
check links from argv[0] write to argv[1]
  - urls.txt -> report.csv

## install
```bash
python -m venv .venv
source .venv/bin/activate
pip install aiohttp beautifulsoup4 lxml requests
```

## run
```bash
# reachable, valid core seo
$ python crawlable.py urls.txt -o report.csv

# visibility, indexibility
$ python audit.py urls.txt report.csv

# indexibility
$ python seo_mini.py urls.txt report.csv

# check no accidental noindex for public pages
$ . ./no_noindex.sh

# ua preview
$ . ./check_what_ua_sees.sh
# bot view
$ curl -A "Googlebot" https://domain.com/

# try to guess/evaluate rendering strategy
$ python guess_render_strategy_4seo.py https://example.com

# analize seo tags
$ python seo_audit_head.py urls.txt report.csv

# audit page structure/headings from input file
$ python seo_audit_headings.py --in urls.txt --out report.csv

# audit images from page links in input file
$ python seo_audit_images.py --in urls.txt --out report.csv

# audit internal link structure
$ python seo_audit_internal_links.py urls.txt --out report
```

