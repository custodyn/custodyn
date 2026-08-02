from setuptools import setup, find_packages

setup(
    name="custodyn",
    version="1.0.0",
    description="AI trust and security infrastructure — audit, block, and approve every agent action",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Custodyn",
    author_email="hello@custodyn.app",
    url="https://github.com/custodyn/custodyn",
    license="MIT",
    packages=find_packages(),
    py_modules=["custodyn"],
    install_requires=[
        "requests>=2.28.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
    python_requires=">=3.8",
    keywords="ai agents security audit llm openai anthropic langchain governance",
)
