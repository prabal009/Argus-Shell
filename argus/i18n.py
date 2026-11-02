"""Small, packaged UI catalogs with explicit language and English fallback."""

from functools import lru_cache
from importlib.resources import files
import json
import os

SUPPORTED_LOCALES = ('en', 'es')
_locale = None


def normalize_locale(value):
    value = str(value or 'en').split('.', 1)[0].split('@', 1)[0]
    language = value.replace('-', '_').split('_', 1)[0].lower()
    return language if language in SUPPORTED_LOCALES else 'en'


def set_locale(value):
    global _locale
    _locale = normalize_locale(value)
    return _locale


def get_locale():
    return _locale or normalize_locale(os.environ.get('ARGUS_LOCALE') or os.environ.get('LC_ALL')
                                       or os.environ.get('LC_MESSAGES') or os.environ.get('LANG'))


@lru_cache(maxsize=len(SUPPORTED_LOCALES))
def _catalog(locale):
    resource = files('argus').joinpath('locales', locale + '.json')
    return json.loads(resource.read_text(encoding='utf-8'))


def translate(key, locale=None, **values):
    language = normalize_locale(locale) if locale else get_locale()
    text = _catalog(language).get(key, _catalog('en').get(key, key))
    return text.format_map(values) if values else text


_ = translate
