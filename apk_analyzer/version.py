"""APK Analyzer version metadata shared by the launcher and submodules."""


TOOL_VERSION = "1.7.3"

# Google Play requirement for new apps and updates as of 2026-08-31.
# Existing phone apps stay visible to new users at the floor below.
# Change these together when Play raises the bar.
CURRENT_PLAY_TARGET_SDK = 36
EXISTING_APP_TARGET_SDK_FLOOR = 35
