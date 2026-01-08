## simple link crawler
Reads links from argv[0] writes to argv[1]
  - urls.txt -> report.csv


## install
```bash
python -m venv .venv

source .venv/bin/activate

pip install aiohttp beautifulsoup4 lxml
```

## run
```bash
$ python ./audit.py urls.txt report.csv
```

