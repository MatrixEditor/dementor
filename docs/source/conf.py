# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Dementor"
copyright = "2025, MatrixEditor"
author = "MatrixEditor"
release = "0.1.0"

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

html_theme_options = {
    "accent_color": "cyan",
    "github_url": "https://github.com/MatrixEditor/Dementor",
    "color_mode": "dark",

    # Logo configuration
    "light_logo": "_static/logo-new-big-transparent.png",
    "dark_logo": "_static/logo-new-circle.ico",
    "logo_target": "/",

    "globaltoc_expand_depth": 1,

    # navbar
    "nav_links": [
        {
            "title": "Examples",
            "url": "examples/index",
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
                }
            ],
        },
        {
            "title": "API Reference",
            "url": "api/index",
        },
        {
            "title": "Configuration",
            "url": "config/index",
        }
    ]
}
