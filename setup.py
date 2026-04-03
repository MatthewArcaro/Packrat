from setuptools import setup, find_packages

setup(
    name="packrat-cli",
    version="1.0.2",
    packages=find_packages(),
    install_requires=[
        "scapy",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "packrat=packrat.main:main",
        ],
    },
    author="Matthew Arcaro",
    author_email="matthewarcaro@gmail.com",
    description="🐀 A clean, human-readable CLI packet analyzer for .pcap files",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/MatthewArcaro/packrat",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
)