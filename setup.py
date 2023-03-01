from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='machocli',
    version='0.1.1',
    description='Mach-o analysis tool based on LIEF',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Te-k/machocli',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='malware',
    include_package_data=True,
    install_requires=[
        "lief",
        "asn1crypto==1.4.0"
    ],
    license='MIT',
    python_requires='>=3.5',
    packages=['machocli', 'machocli.plugins', 'machocli.lib', 'machocli.data'],
    package_dir={'machocli.lib': 'machocli/lib'},
    package_data={'machocli': ['machocli/data/*.yar']},
    entry_points={
        'console_scripts': ['machocli=machocli.main:main']
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
