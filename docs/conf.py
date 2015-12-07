# -*- coding: utf-8 -*-

project = u'alcohol'
copyright = u'2015, Marc Brinkmann'
version = '0.5'
release = '0.5'

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.intersphinx', 'alabaster']
source_suffix = '.rst'
master_doc = 'index'
exclude_patterns = ['_build']
pygments_style = 'monokai'

html_theme = 'alabaster'
html_theme_options = {
    'github_user': 'mbr',
    'github_repo': 'alcohol',
    'description': 'User authentication and authorization',
    'github_banner': True,
    'github_button': False,
    'show_powered_by': False,
    # required for monokai:
    'pre_bg': '#292429',
}
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
        'relations.html',
        'searchbox.html',
        'donate.html',
    ]
}

intersphinx_mapping = {'http://docs.python.org/': None,
                       'https://pythonhosted.org/blinker/': None,
                       'http://docs.sqlalchemy.org/en/rel_1_0': None,
                       'http://pythonhosted.org/itsdangerous/': None,
                       'https://pythonhosted.org/passlib/': None, }
