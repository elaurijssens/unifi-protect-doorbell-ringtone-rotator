from setuptools import setup

setup(
    name="unifi-doorbell-rotation",
    version="0.1.0",
    description="Rotate UniFi Protect doorbell visitor tones by uploading random MP3 files.",
    long_description=(
        "A small CLI tool that uploads a random MP3 as a UniFi Protect "
        "doorbell ringtone and assigns it to one or more G4 doorbells. "
        "Supports configuration mode and rotation using cron."
    ),
    long_description_content_type="text/plain",
    author="Your Name",
    python_requires=">=3.9",
    py_modules=["doorbell_tone_rotator"],
    install_requires=[
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            # so you can just run `unifi-doorbell-rotation` from PATH
            "unifi-doorbell-rotation=doorbell_tone_rotator:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
