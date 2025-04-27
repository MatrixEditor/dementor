# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Dementor"
copyright = "2025-Present, MatrixEditor"
author = "MatrixEditor"
release = "1.0.0.dev6"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.extlinks",
    "sphinx.ext.todo",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinx_tabs.tabs",
]

templates_path = ["_templates"]
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "shibuya"
html_static_path = ["_static"]

html_copy_source = False
html_show_sourcelink = False

html_favicon = "_static/favicon.ico"
html_css_files = [
    "theme.css",
]
html_baseurl = "https://matrixeditor.github.io/dementor/"

html_sidebars = {
    "**": [
        "sidebars/localtoc.html",
        "sidebars/edit-this-page.html",
    ]
}

html_context = {
    "source_type": "github",
    "source_user": "MatrixEditor",
    "source_repo": "dementor",
}

html_theme_options = {
    "accent_color": "cyan",
    "color_mode": "dark",

    "github_url": "https://github.com/MatrixEditor/Dementor",
    # Logo configuration
    "light_logo": "_static/logo-new-big-transparent.png",
    "dark_logo": "_static/logo-new-circle.ico",
    "logo_target": "https://matrixeditor.github.io/dementor/",
    "globaltoc_expand_depth": 1,
    # navbar
    "nav_links": [
        {
            "title": "Examples",
            "url": "examples/multicast",
            "children": [
                {
                    "title": "Multicast Poisoing",
                    "url": "examples/multicast",
                    "summary": "mDNS, LLMNR and NBT-NS Poisoning",
                },
                {
                    "title": "Rogue KDC",
                    "url": "examples/kdc",
                    "summary": "Rogue Kerberos KDC for ASREQroasting",
                },
                {
                    "title": "SMTP Downgrade Attack",
                    "url": "examples/smtp_downgrade",
                    "summary": "Downgrade NTLM auth to LOGIN or PLAIN",
                },
            ],
        },
        {
            "title": "Configuration",
            "url": "config/index",
            "children": [
                {
                    "title": "Main Configuration",
                    "url": "config/main",
                    "summary": "Main configuration for Dementor",
                },
                {
                    "title": "Database Configuration",
                    "url": "config/database",
                    "summary": "Database directory and name",
                },
                {
                    "title": "Globals",
                    "url": "config/globals",
                    "summary": "Global settings for protocol servers",
                },
                {
                    "title": "Protocols",
                    "url": "config/protocols",
                    "summary": "Inidividual protocol configuration",
                },
            ],
        },
        {
            "title": "Compatibility",
            "url": "compat",
        },
    ],
}
