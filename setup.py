from setuptools import find_packages, setup

setup(
    name="chainsolver-mcp",
    version="0.2.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=["mcp>=1.2.0", "web3>=7.0.0"],
    entry_points={"console_scripts": ["chainsolver-mcp=chainsolver_mcp.server:main"]},
)
