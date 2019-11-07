# Admin Notes


## PyPI Release How-To

Notes and information on how to do the PyPI release for the ZAT project. For full details on packaging you can reference this page
[Packaging](https://packaging.python.org/tutorials/packaging-projects/#packaging-your-project)

The following instructions should work, but things change :)

### Package Requirements

-   pip install tox
-   pip install \--upgrade setuptools wheel
-   pip install twine

### Setup pypirc

The easiest thing to do is setup a \~/.pypirc file with the following
contents

``` {.bash}
[distutils]
index-servers =
  pypi
  testpypi

[pypi]
repository=https://upload.pypi.org/legacy/
username=<pypi username>
password=<pypi password>

[testpypi]
repository=https://test.pypi.org/legacy/
username=<pypi username>
password=<pypi password>
```

### Tox Background

Tox will install the ZAT package into a blank virtualenv and then execute all the tests against the newly installed package. So if everything goes okay, you know the pypi package installed fine and the tests (which pull from the installed ZAT package) also ran okay.

### Make sure ALL tests pass

``` {.bash}
$ cd zat
$ tox 
```

If ALL the test above pass\...

### Create the TEST PyPI Release

``` {.bash}
$ vi zat/__init__.py and bump the version
$ python setup.py sdist bdist_wheel
$ twine upload dist/* -r testpypi
```

### Install the TEST PyPI Release

``` {.bash}
$ pip install --index-url https://test.pypi.org/simple zat
```

### Create the REAL PyPI Release

``` {.bash}
$ twine upload dist/* -r pypi
```

### Push changes to Github

``` {.bash}
$ git add zat/__init__.py
$ get commit -m "zat version 1.8.7 (or whatever)"
$ git tag v1.8.7 (or whatever)
$ git push --tags
$ git push
```

### Git Releases (discussion)

Note: This is an opinion, we/I could certainly be convinced otherwise.

You can also do a 'release' on GitHub (the tags above are perfect for that). In general this is discouraged, people should always do a 

```$pip install zat``` 

If people want older releases they can do a

```$pip install zat==<old version>```

Providing tarballs/zip file on GitHub will just
confuse new users and they'll have a 'bad experience' when trying to deal with a tarball.
