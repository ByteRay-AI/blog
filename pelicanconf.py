AUTHOR = "ByteRay"
SITENAME = "ByteRay Blog"
SITESUBTITLE = "Security and engineering"
SITEURL = ""

PATH = "content"

# Each Markdown file under content/posts/ becomes one blog post.
ARTICLE_PATHS = ["posts"]

TIMEZONE = "America/Los_Angeles"

DEFAULT_LANG = "en"

# --- Custom theme ---------------------------------------------------------
THEME = "themes/argus"

# Clean URLs for each post, e.g. /blog/welcome-to-argus-blog.html
ARTICLE_URL = "blog/{slug}.html"
ARTICLE_SAVE_AS = "blog/{slug}.html"

# Newest posts first (Pelican default; set explicitly for clarity).
ARTICLE_ORDER_BY = "reversed-date"

DEFAULT_DATE_FORMAT = "%Y-%m-%d"

# --- Feeds ----------------------------------------------------------------
# Disabled during development; enable in publishconf.py for production.
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

# --- Navigation -----------------------------------------------------------
LINKS = (
    ("Home", "/"),
)

SOCIAL = ()

DEFAULT_PAGINATION = 25

# Uncomment following line if you want document-relative URLs when developing
# RELATIVE_URLS = True
