"""Destination intelligence for web_fetch.

  ALLOWED  -> well-known sites, fetched normally
  BLOCKED  -> known exfiltration / paste / tunnelling endpoints, always DENY
  anything else is "unvetted" -> requires human REVIEW
Subdomains match their parent (news.bbc.co.uk matches bbc.co.uk).
"""
ALLOWED_DOMAINS: dict[str, list[str]] = {
    "Reference": [
        "wikipedia.org", "wikimedia.org", "britannica.com", "wiktionary.org", "archive.org",
        "dictionary.com", "merriam-webster.com", "worldbank.org", "un.org", "data.gov",
    ],
    "News": [
        "bbc.com", "bbc.co.uk", "reuters.com", "apnews.com", "theguardian.com", "nytimes.com",
        "cnn.com", "npr.org", "aljazeera.com", "thehindu.com", "indianexpress.com",
        "hindustantimes.com", "timesofindia.indiatimes.com", "ndtv.com", "livemint.com",
        "economictimes.indiatimes.com", "cnbc.com", "bloomberg.com", "forbes.com", "ft.com",
    ],
    "Technology": [
        "github.com", "githubusercontent.com", "gitlab.com", "stackoverflow.com",
        "stackexchange.com", "developer.mozilla.org", "docs.python.org", "python.org", "pypi.org",
        "npmjs.com", "nodejs.org", "learn.microsoft.com", "microsoft.com", "cloud.google.com",
        "developers.google.com", "aws.amazon.com", "docs.aws.amazon.com", "kubernetes.io",
        "docker.com", "react.dev", "nextjs.org", "fastapi.tiangolo.com", "postgresql.org",
        "w3schools.com", "geeksforgeeks.org", "freecodecamp.org", "medium.com", "dev.to",
        "theverge.com", "techcrunch.com", "wired.com", "arstechnica.com",
    ],
    "AI & Research": [
        "arxiv.org", "huggingface.co", "openai.com", "anthropic.com", "deepmind.google",
        "pytorch.org", "tensorflow.org", "kaggle.com", "paperswithcode.com", "nature.com",
        "science.org", "sciencedirect.com", "springer.com", "ieee.org", "acm.org",
        "semanticscholar.org", "ollama.com", "qwenlm.github.io",
    ],
    "Security": [
        "owasp.org", "nist.gov", "cve.org", "mitre.org", "cisa.gov", "cert-in.org.in",
        "sans.org", "krebsonsecurity.com", "bleepingcomputer.com",
    ],
    "Government & Health": [
        "who.int", "cdc.gov", "nih.gov", "nasa.gov", "noaa.gov", "gov.uk", "usa.gov",
        "india.gov.in", "mygov.in", "rbi.org.in", "imd.gov.in", "europa.eu",
    ],
    "Finance & Business": [
        "investopedia.com", "moneycontrol.com", "finance.yahoo.com", "nseindia.com",
        "bseindia.com", "sec.gov", "wsj.com", "economist.com",
    ],
    "Weather & Maps": [
        "openweathermap.org", "open-meteo.com", "weather.com", "accuweather.com", "timeanddate.com",
        "openstreetmap.org", "weather.gov",
    ],
    "Education": [
        "coursera.org", "edx.org", "khanacademy.org", "mit.edu", "stanford.edu", "harvard.edu",
        "ox.ac.uk", "cam.ac.uk", "iitb.ac.in", "nptel.ac.in",
    ],
    "Sports & Culture": [
        "espn.com", "espncricinfo.com", "cricbuzz.com", "imdb.com", "rottentomatoes.com",
        "goodreads.com", "fifa.com", "olympics.com",
    ],
}

BLOCKED_DOMAINS: list[str] = [
    "pastebin.com", "paste.ee", "ghostbin.com", "hastebin.com", "0x0.st", "transfer.sh",
    "file.io", "anonfiles.com", "gofile.io", "webhook.site", "requestbin.com", "pipedream.net",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "localtunnel.me",
    "burpcollaborator.net", "oastify.com", "interact.sh", "canarytokens.com", "dnslog.cn",
]

_ALLOWED_FLAT = {d for group in ALLOWED_DOMAINS.values() for d in group}


def _matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def classify_host(host: str) -> str:
    host = (host or "").lower().strip(".")
    if not host:
        return "blocked"
    if any(_matches(host, d) for d in BLOCKED_DOMAINS):
        return "blocked"
    if any(_matches(host, d) for d in _ALLOWED_FLAT):
        return "known_external"
    return "unvetted"
