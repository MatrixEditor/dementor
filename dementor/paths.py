import os
import dementor

DEMENTOR_PATH = os.path.expanduser("~/.dementor")
CONFIG_PATH = os.path.join(DEMENTOR_PATH, "Dementor.conf")
ASSETS_PATH = os.path.join(os.path.dirname(dementor.__file__), "assets")
