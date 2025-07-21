# test_config.py
from config import Config
import os

print("Current working directory:", os.getcwd())
print("SQLALCHEMY_DATABASE_URI:", Config.SQLALCHEMY_DATABASE_URI)
print("Config attributes:", dir(Config))